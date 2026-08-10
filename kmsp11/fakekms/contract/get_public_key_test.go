// Copyright 2021 Google LLC
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

var ignorePEMAndPEMCRC = protocmp.IgnoreFields(new(kmspb.PublicKey),
	protoreflect.Name("pem"), protoreflect.Name("pem_crc32c"))

func unmarshalPublicKeyPem(t *testing.T, pubPem string) crypto.PublicKey {
	t.Helper()

	blk, _ := pem.Decode([]byte(pubPem))
	if blk.Type != "PUBLIC KEY" {
		t.Fatalf("blk.Type=%s, want PUBLIC KEY", blk.Type)
	}

	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatalf("error parsing public key: %v", err)
	}
	return pub
}

func TestGetPublicKeyEC(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	got, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ckv.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.PublicKey{
		Name:            ckv.Name,
		Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	}

	opts := append(ProtoDiffOpts(), ignorePEMAndPEMCRC, protocmp.IgnoreUnknown())
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	key := unmarshalPublicKeyPem(t, got.Pem).(*ecdsa.PublicKey)
	if !elliptic.P256().IsOnCurve(key.X, key.Y) {
		t.Errorf("public key curve mismatch (got %s, want P-256)", key.Curve.Params().Name)
	}

	verifyCRC32C(t, []byte(got.Pem), got.PemCrc32C)
}

func TestGetPublicKeyRSA(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm:       kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	got, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ckv.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.PublicKey{
		Name:            ckv.Name,
		Algorithm:       kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
	}

	opts := append(ProtoDiffOpts(), ignorePEMAndPEMCRC, protocmp.IgnoreUnknown())
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	key := unmarshalPublicKeyPem(t, got.Pem).(*rsa.PublicKey)
	if key.Size()*8 != 2048 {
		t.Errorf("public key length mismatch (got %d, want 2048)", key.Size()*8)
	}

	verifyCRC32C(t, []byte(got.Pem), got.PemCrc32C)
}

func TestGetPublicKeyMalformedName(t *testing.T) {
	ctx := context.Background()

	_, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: "malformed name",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestGetPublicKeyNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: location + "/keyRings/foo/cryptoKeys/bar/cryptoKeyVersions/1",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}

func TestGetPublicKeySymmetric(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	_, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ck.Primary.Name,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestGetPublicKeyDisabled(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
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

	_, err = client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ckv.Name,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}
