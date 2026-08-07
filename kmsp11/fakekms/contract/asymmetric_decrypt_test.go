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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"hash/crc32"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestAsymmetricDecrypt(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ckv.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	pub := unmarshalPublicKeyPem(t, pubResp.Pem).(*rsa.PublicKey)
	pt := []byte("the quick brown fox jumped over the lazy dog")

	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:             ckv.Name,
		Ciphertext:       ct,
		CiphertextCrc32C: crc32c(ct),
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.AsymmetricDecryptResponse{
		Plaintext:                pt,
		PlaintextCrc32C:          wrapperspb.Int64(int64(crc32.Checksum(pt, crc32CTable))),
		VerifiedCiphertextCrc32C: true,
		ProtectionLevel:          kmspb.ProtectionLevel_SOFTWARE,
	}

	if diff := cmp.Diff(want, got, ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestAsymmetricDecryptWihtoutChecksums(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: ckv.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	pub := unmarshalPublicKeyPem(t, pubResp.Pem).(*rsa.PublicKey)
	pt := []byte("the quick brown fox jumped over the lazy dog")

	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       ckv.Name,
		Ciphertext: ct,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.AsymmetricDecryptResponse{
		Plaintext:       pt,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32.Checksum(pt, crc32CTable))),
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	}

	if diff := cmp.Diff(want, got, ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestAsymmetricDecryptMalformedName(t *testing.T) {
	ctx := context.Background()

	_, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name: "malformed name",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricDecryptMalformedCiphertext(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       ckv.Name,
		Ciphertext: []byte("malformed ciphertext"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricDecryptNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       location + "/keyRings/foo/cryptoKeys/bar/cryptoKeyVersions/1",
		Ciphertext: []byte("foo"),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}

func TestAsymmetricDecryptWrongPurpose(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	_, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       ck.Primary.Name,
		Ciphertext: []byte("foo"),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestAsymmetricDecryptDisabled(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
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

	_, err = client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:       ckv.Name,
		Ciphertext: []byte("foo"),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestAsymmetricDecryptInvalidCiphertextChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{
		Name:             ckv.Name,
		Ciphertext:       []byte("ciphertext"),
		CiphertextCrc32C: crc32c([]byte("cosmicray")),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}
