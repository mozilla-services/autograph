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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

var ignoreSignatureAndSignatureCRC = protocmp.IgnoreFields(new(kmspb.AsymmetricSignResponse),
	protoreflect.Name("signature"), protoreflect.Name("signature_crc32c"))

func TestECSign(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
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

	pub := unmarshalPublicKeyPem(t, pubResp.Pem).(*ecdsa.PublicKey)

	data := []byte("Here is some data to authenticate")
	digest := sha512.Sum384(data)

	got, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest[:],
			},
		},
		DigestCrc32C: crc32c(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.AsymmetricSignResponse{
		Name:                 ckv.Name,
		VerifiedDigestCrc32C: true,
		ProtectionLevel:      kmspb.ProtectionLevel_HSM,
	}

	opts := append(ProtoDiffOpts(), ignoreSignatureAndSignatureCRC)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	sig := struct{ R, S *big.Int }{}
	if _, err := asn1.Unmarshal(got.Signature, &sig); err != nil {
		t.Fatal(err)
	}

	if !ecdsa.Verify(pub, digest[:], sig.R, sig.S) {
		t.Error("signature verification failed")
	}

	verifyCRC32C(t, got.Signature, got.SignatureCrc32C)
}

func TestECSignData(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
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

	pub := unmarshalPublicKeyPem(t, pubResp.Pem).(*ecdsa.PublicKey)

	data := []byte("Here is some data to authenticate")

	got, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:       ckv.Name,
		Data:       data,
		DataCrc32C: crc32c(data),
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.AsymmetricSignResponse{
		Name:               ckv.Name,
		VerifiedDataCrc32C: true,
		ProtectionLevel:    kmspb.ProtectionLevel_HSM,
	}

	opts := append(ProtoDiffOpts(), ignoreSignatureAndSignatureCRC)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	sig := struct{ R, S *big.Int }{}
	if _, err := asn1.Unmarshal(got.Signature, &sig); err != nil {
		t.Fatal(err)
	}

	digest := sha512.Sum384(data)
	if !ecdsa.Verify(pub, digest[:], sig.R, sig.S) {
		t.Error("signature verification failed")
	}

	verifyCRC32C(t, got.Signature, got.SignatureCrc32C)
}

func TestRSASignPKCS1(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
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

	data := []byte("Here is some data to authenticate")
	digest := sha256.Sum256(data)

	got, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.AsymmetricSignResponse{
		Name:                 ckv.Name,
		VerifiedDigestCrc32C: false,
		ProtectionLevel:      kmspb.ProtectionLevel_SOFTWARE,
	}

	opts := append(ProtoDiffOpts(), ignoreSignatureAndSignatureCRC)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], got.Signature); err != nil {
		t.Error(err)
	}

	verifyCRC32C(t, got.Signature, got.SignatureCrc32C)
}

func TestRSASignRawPKCS1(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048,
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

	data := []byte("Here is some data to authenticate")

	got, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Data: data,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.AsymmetricSignResponse{
		Name:               ckv.Name,
		VerifiedDataCrc32C: false,
		ProtectionLevel:    kmspb.ProtectionLevel_HSM,
	}

	opts := append(ProtoDiffOpts(), ignoreSignatureAndSignatureCRC)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	if err := rsa.VerifyPKCS1v15(pub, 0, data[:], got.Signature); err != nil {
		t.Error(err)
	}

	verifyCRC32C(t, got.Signature, got.SignatureCrc32C)
}

// TODO(b/156736940): Implement additional contract tests for raw PKCS#1 signing:
// * Ensuring our behavior is right when both `data` and `digest` are supplied.
// * Ensuring our behavior is right when `data` is too large.

func TestRSASignPSS(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
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

	data := []byte("Here is some data to authenticate")
	digest := sha512.Sum512(data)

	got, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{
				Sha512: digest[:],
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.AsymmetricSignResponse{
		Name:            ckv.Name,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
	}

	opts := append(ProtoDiffOpts(), ignoreSignatureAndSignatureCRC)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	if err := rsa.VerifyPSS(pub, crypto.SHA512, digest[:], got.Signature, pssOpts); err != nil {
		t.Error(err)
	}

	verifyCRC32C(t, got.Signature, got.SignatureCrc32C)
}

func TestAsymmetricSignMalformedName(t *testing.T) {
	ctx := context.Background()

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: "malformed name",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricSignWrongDigest(t *testing.T) {
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

	digest := sha256.Sum256([]byte("here is some data"))

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricSignIncorrectDigestLength(t *testing.T) {
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

	digest := sha256.Sum256([]byte("here is some data"))

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest[:],
			},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricSignBothDigestAndData(t *testing.T) {
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

	digest := sha256.Sum256([]byte("here is some data"))

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
		Data: []byte("here is some data"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestRawAsymmetricSignDigestInvalid(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	digest := sha256.Sum256([]byte("here is some data"))

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricSignNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: location + "/keyRings/foo/cryptoKeys/bar/cryptoKeyVersions/1",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}

func TestAsymmetricSignWrongPurpose(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	digest := sha256.Sum256([]byte("here is some data"))

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ck.Primary.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestAsymmetricSignDisabled(t *testing.T) {
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

	ckv.State = kmspb.CryptoKeyVersion_DISABLED

	_, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
		UpdateMask:       &fieldmaskpb.FieldMask{Paths: []string{"state"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestAsymmetricSignInvalidDigestChecksum(t *testing.T) {
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

	digest := sha256.Sum256([]byte("here is some data"))

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name: ckv.Name,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest[:],
			},
		},
		DigestCrc32C: crc32c([]byte("cosmicray")),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestAsymmetricSignInvalidDataChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:       ckv.Name,
		Data:       []byte("here is some data"),
		DataCrc32C: crc32c([]byte("cosmicray")),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}
