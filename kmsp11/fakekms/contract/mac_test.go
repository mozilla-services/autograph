// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package contract

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

var ignoreMacAndMacCRC = protocmp.IgnoreFields(new(kmspb.MacSignResponse),
	protoreflect.Name("mac"), protoreflect.Name("mac_crc32c"))

var ignoreSuccessAndVerifiedSuccessIntegrity = protocmp.IgnoreFields(new(kmspb.MacVerifyResponse),
	protoreflect.Name("success"), protoreflect.Name("verified_success_integrity"))

func TestMacSignVerify(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	data := []byte("Here is some data to authenticate")

	got, err := client.MacSign(ctx, &kmspb.MacSignRequest{
		Name:       ckv.Name,
		Data:       data,
		DataCrc32C: crc32c(data),
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, got.Mac, got.MacCrc32C)

	want := &kmspb.MacSignResponse{
		Name:               ckv.Name,
		VerifiedDataCrc32C: true,
		ProtectionLevel:    kmspb.ProtectionLevel_HSM,
	}

	opts := append(ProtoDiffOpts(), ignoreMacAndMacCRC)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	resp, err := client.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name:       ckv.Name,
		Data:       data,
		DataCrc32C: crc32c(data),
		Mac:        got.Mac,
		MacCrc32C:  crc32c(got.Mac),
	})
	if err != nil {
		t.Fatal(err)
	}

	wantVerify := &kmspb.MacVerifyResponse{
		Name:               ckv.Name,
		VerifiedDataCrc32C: true,
		VerifiedMacCrc32C:  true,
		ProtectionLevel:    kmspb.ProtectionLevel_HSM,
	}

	optsVerify := append(ProtoDiffOpts(), ignoreSuccessAndVerifiedSuccessIntegrity)
	if diff := cmp.Diff(wantVerify, resp, optsVerify...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	if resp.Success != resp.VerifiedSuccessIntegrity || !resp.Success {
		t.Errorf("MAC verification failed")
	}
}

func TestMacSignVerifyWithoutChecksums(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	data := []byte("Here is some data to authenticate")

	got, err := client.MacSign(ctx, &kmspb.MacSignRequest{
		Name: ckv.Name,
		Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, got.Mac, got.MacCrc32C)

	want := &kmspb.MacSignResponse{
		Name:               ckv.Name,
		VerifiedDataCrc32C: false,
		ProtectionLevel:    kmspb.ProtectionLevel_HSM,
	}

	opts := append(ProtoDiffOpts(), ignoreMacAndMacCRC)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	resp, err := client.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name: ckv.Name,
		Data: data,
		Mac:  got.Mac,
	})
	if err != nil {
		t.Fatal(err)
	}

	wantVerify := &kmspb.MacVerifyResponse{
		Name:               ckv.Name,
		VerifiedDataCrc32C: false,
		VerifiedMacCrc32C:  false,
		ProtectionLevel:    kmspb.ProtectionLevel_HSM,
	}

	optsVerify := append(ProtoDiffOpts(), ignoreSuccessAndVerifiedSuccessIntegrity)
	if diff := cmp.Diff(wantVerify, resp, optsVerify...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	if resp.Success != resp.VerifiedSuccessIntegrity || !resp.Success {
		t.Errorf("MAC verification failed")
	}
}

func TestMacSignNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.MacSign(ctx, &kmspb.MacSignRequest{
		Name: location + "/keyRings/foo/cryptoKeys/bar/cryptoKeyVersions/1",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}

func TestMacVerifyNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name: location + "/keyRings/foo/cryptoKeys/bar/cryptoKeyVersions/1",
		Data: []byte("testdata"),
		Mac:  []byte("mac"),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}

func TestMacSignWrongPurpose(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	data := []byte("here is some data")

	_, err := client.MacSign(ctx, &kmspb.MacSignRequest{
		Name: ck.Primary.Name,
		Data: data,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestMacVerifyWrongPurpose(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	data := []byte("here is some data")
	mac := []byte("here is a mac tag")

	_, err := client.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name: ck.Primary.Name,
		Data: data,
		Mac:  mac,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestMacSignKeyDisabled(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	ckv.State = kmspb.CryptoKeyVersion_DISABLED

	_, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
		UpdateMask:       &fieldmaskpb.FieldMask{Paths: []string{"state"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.MacSign(ctx, &kmspb.MacSignRequest{
		Name: ckv.Name,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestMacVerifyKeyDisabled(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	ckv.State = kmspb.CryptoKeyVersion_DISABLED

	_, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
		UpdateMask:       &fieldmaskpb.FieldMask{Paths: []string{"state"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name: ckv.Name,
		Data: []byte("testdata"),
		Mac:  []byte("mac"),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestMacSignInvalidDataChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.MacSign(ctx, &kmspb.MacSignRequest{
		Name:       ckv.Name,
		Data:       []byte("data"),
		DataCrc32C: crc32c([]byte("cosmicray")),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestMacVerifyInvalidDataChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name:       ckv.Name,
		Data:       []byte("data"),
		DataCrc32C: crc32c([]byte("cosmicray")),
		Mac:        []byte("mac"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestMacVerifyInvalidMacChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_MAC,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_HMAC_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.MacVerify(ctx, &kmspb.MacVerifyRequest{
		Name:      ckv.Name,
		Data:      []byte("data"),
		Mac:       []byte("mac"),
		MacCrc32C: crc32c([]byte("cosmicray")),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}
