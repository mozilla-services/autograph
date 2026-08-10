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
	"hash/crc32"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32c(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, crc32cTable)))
}

var ignoreCiphertextAndIVAndTagLength = protocmp.IgnoreFields(new(kmspb.RawEncryptResponse),
	protoreflect.Name("ciphertext"), protoreflect.Name("ciphertext_crc32c"), protoreflect.Name("initialization_vector"), protoreflect.Name("initialization_vector_crc32c"))

func TestRawEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	plaintext := []byte("Here is a plaintext to encrypt, 48 bytes long...")

	gotEncrypt, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:            ckv.Name,
		Plaintext:       plaintext,
		PlaintextCrc32C: crc32c(plaintext),
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, gotEncrypt.Ciphertext, gotEncrypt.CiphertextCrc32C)

	wantEncrypt := &kmspb.RawEncryptResponse{
		Name:                    ckv.Name,
		ProtectionLevel:         kmspb.ProtectionLevel_HSM,
		TagLength:               16,
		VerifiedPlaintextCrc32C: true,
	}

	opts := append(ProtoDiffOpts(), ignoreCiphertextAndIVAndTagLength)
	if diff := cmp.Diff(wantEncrypt, gotEncrypt, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	gotDecrypt, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                       ckv.Name,
		Ciphertext:                 gotEncrypt.Ciphertext,
		CiphertextCrc32C:           crc32c(gotEncrypt.Ciphertext),
		InitializationVector:       gotEncrypt.InitializationVector,
		InitializationVectorCrc32C: crc32c(gotEncrypt.InitializationVector),
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, gotDecrypt.Plaintext, gotDecrypt.PlaintextCrc32C)

	wantDecrypt := &kmspb.RawDecryptResponse{
		Plaintext:                          plaintext,
		PlaintextCrc32C:                    wrapperspb.Int64(int64(crc32.Checksum(plaintext, crc32CTable))),
		VerifiedCiphertextCrc32C:           true,
		VerifiedInitializationVectorCrc32C: true,
		ProtectionLevel:                    kmspb.ProtectionLevel_HSM,
	}

	if diff := cmp.Diff(wantDecrypt, gotDecrypt, ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestRawEncryptDecryptWithoutChecksums(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	plaintext := []byte("Here is some data to encrypt")
	aad := []byte("aad")

	gotEncrypt, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                        ckv.Name,
		Plaintext:                   plaintext,
		AdditionalAuthenticatedData: aad,
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, gotEncrypt.Ciphertext, gotEncrypt.CiphertextCrc32C)

	wantEncrypt := &kmspb.RawEncryptResponse{
		Name:                    ckv.Name,
		ProtectionLevel:         kmspb.ProtectionLevel_HSM,
		TagLength:               16,
		VerifiedPlaintextCrc32C: false,
		VerifiedAdditionalAuthenticatedDataCrc32C: false,
		VerifiedInitializationVectorCrc32C:        false,
	}

	opts := append(ProtoDiffOpts(), ignoreCiphertextAndIVAndTagLength)
	if diff := cmp.Diff(wantEncrypt, gotEncrypt, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	gotDecrypt, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                        ckv.Name,
		Ciphertext:                  gotEncrypt.Ciphertext,
		AdditionalAuthenticatedData: aad,
		InitializationVector:        gotEncrypt.InitializationVector,
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, gotDecrypt.Plaintext, gotDecrypt.PlaintextCrc32C)

	wantDecrypt := &kmspb.RawDecryptResponse{
		Plaintext:                plaintext,
		PlaintextCrc32C:          wrapperspb.Int64(int64(crc32.Checksum(plaintext, crc32CTable))),
		VerifiedCiphertextCrc32C: false,
		VerifiedAdditionalAuthenticatedDataCrc32C: false,
		VerifiedInitializationVectorCrc32C:        false,
		ProtectionLevel:                           kmspb.ProtectionLevel_HSM,
	}

	if diff := cmp.Diff(wantDecrypt, gotDecrypt, ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestRawEncryptDecryptCbcCtr(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_AES_256_CTR,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	plaintext := []byte("Here is a plaintext to encrypt, 48 bytes long...")
	iv := []byte("my_custom_iv_123")

	gotEncrypt, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                       ckv.Name,
		Plaintext:                  plaintext,
		PlaintextCrc32C:            crc32c(plaintext),
		InitializationVector:       iv,
		InitializationVectorCrc32C: crc32c(iv),
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, gotEncrypt.Ciphertext, gotEncrypt.CiphertextCrc32C)

	wantEncrypt := &kmspb.RawEncryptResponse{
		Name:                               ckv.Name,
		ProtectionLevel:                    kmspb.ProtectionLevel_HSM,
		VerifiedPlaintextCrc32C:            true,
		VerifiedInitializationVectorCrc32C: true,
	}

	opts := append(ProtoDiffOpts(), ignoreCiphertextAndIVAndTagLength)
	if diff := cmp.Diff(wantEncrypt, gotEncrypt, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	gotDecrypt, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                       ckv.Name,
		Ciphertext:                 gotEncrypt.Ciphertext,
		CiphertextCrc32C:           crc32c(gotEncrypt.Ciphertext),
		InitializationVector:       gotEncrypt.InitializationVector,
		InitializationVectorCrc32C: crc32c(gotEncrypt.InitializationVector),
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, gotDecrypt.Plaintext, gotDecrypt.PlaintextCrc32C)

	wantDecrypt := &kmspb.RawDecryptResponse{
		Plaintext:                          plaintext,
		PlaintextCrc32C:                    wrapperspb.Int64(int64(crc32.Checksum(plaintext, crc32CTable))),
		VerifiedCiphertextCrc32C:           true,
		VerifiedInitializationVectorCrc32C: true,
		ProtectionLevel:                    kmspb.ProtectionLevel_HSM,
	}

	if diff := cmp.Diff(wantDecrypt, gotDecrypt, ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestRawEncryptDecryptCbcCtrWithoutChecksums(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				ProtectionLevel: kmspb.ProtectionLevel_HSM,
				Algorithm:       kmspb.CryptoKeyVersion_AES_128_CBC,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	plaintext := []byte("Here is a plaintext to encrypt, 48 bytes long...")
	iv := []byte("my_custom_iv_123")

	gotEncrypt, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                 ckv.Name,
		Plaintext:            plaintext,
		InitializationVector: iv,
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, gotEncrypt.Ciphertext, gotEncrypt.CiphertextCrc32C)

	wantEncrypt := &kmspb.RawEncryptResponse{
		Name:                               ckv.Name,
		ProtectionLevel:                    kmspb.ProtectionLevel_HSM,
		VerifiedPlaintextCrc32C:            false,
		VerifiedInitializationVectorCrc32C: false,
	}

	opts := append(ProtoDiffOpts(), ignoreCiphertextAndIVAndTagLength)
	if diff := cmp.Diff(wantEncrypt, gotEncrypt, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	gotDecrypt, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                 ckv.Name,
		Ciphertext:           gotEncrypt.Ciphertext,
		InitializationVector: gotEncrypt.InitializationVector,
	})
	if err != nil {
		t.Fatal(err)
	}

	verifyCRC32C(t, gotDecrypt.Plaintext, gotDecrypt.PlaintextCrc32C)

	wantDecrypt := &kmspb.RawDecryptResponse{
		Plaintext:                          plaintext,
		PlaintextCrc32C:                    wrapperspb.Int64(int64(crc32.Checksum(plaintext, crc32CTable))),
		VerifiedCiphertextCrc32C:           false,
		VerifiedInitializationVectorCrc32C: false,
		ProtectionLevel:                    kmspb.ProtectionLevel_HSM,
	}

	if diff := cmp.Diff(wantDecrypt, gotDecrypt, ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestRawEncryptNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:      location + "/keyRings/foo/cryptoKeys/bar/cryptoKeyVersions/1",
		Plaintext: []byte("Here is a plaintext to encrypt, 48 bytes long..."),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}

func TestRawDecryptNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                        location + "/keyRings/foo/cryptoKeys/bar/cryptoKeyVersions/1",
		Ciphertext:                  []byte("testdata"),
		AdditionalAuthenticatedData: []byte("aad"),
		InitializationVector:        []byte("iv"),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}

func TestRawEncryptWrongPurpose(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	_, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                        ck.Primary.Name,
		Plaintext:                   []byte("testdata"),
		AdditionalAuthenticatedData: []byte("aad"),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestRawDecryptWrongPurpose(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	_, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                        ck.Primary.Name,
		Ciphertext:                  []byte("testdata"),
		AdditionalAuthenticatedData: []byte("aad"),
		InitializationVector:        []byte("iv"),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestRawEncryptKeyDisabled(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
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

	_, err = client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:      ckv.Name,
		Plaintext: []byte("Here is a plaintext to encrypt, 48 bytes long..."),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestRawDecryptKeyDisabled(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
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

	_, err = client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                        ckv.Name,
		Ciphertext:                  []byte("testdata"),
		AdditionalAuthenticatedData: []byte("aad"),
		InitializationVector:        []byte("iv"),
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestRawEncryptInvalidPlaintextChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                        ckv.Name,
		Plaintext:                   []byte("testdata"),
		PlaintextCrc32C:             crc32c([]byte("cosmicray")),
		AdditionalAuthenticatedData: []byte("aad"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestRawEncryptInvalidAadChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                              ckv.Name,
		Plaintext:                         []byte("testdata"),
		AdditionalAuthenticatedData:       []byte("aad"),
		AdditionalAuthenticatedDataCrc32C: crc32c([]byte("cosmicray")),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestRawDecryptInvalidCiphertextChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                        ckv.Name,
		Ciphertext:                  []byte("testdata"),
		CiphertextCrc32C:            crc32c([]byte("cosmicray")),
		AdditionalAuthenticatedData: []byte("aad"),
		InitializationVector:        []byte("iv"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestRawDecryptInvalidAadChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                              ckv.Name,
		Ciphertext:                        []byte("testdata"),
		AdditionalAuthenticatedData:       []byte("aad"),
		AdditionalAuthenticatedDataCrc32C: crc32c([]byte("cosmicray")),
		InitializationVector:              []byte("iv"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestRawDecryptInvalidIvChecksum(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                        ckv.Name,
		Ciphertext:                  []byte("testdata"),
		AdditionalAuthenticatedData: []byte("aad"),
		InitializationVector:        []byte("iv"),
		InitializationVectorCrc32C:  crc32c([]byte("cosmicray")),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestRawEncryptAesGcmCustomIvFails(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_GCM,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                        ckv.Name,
		Plaintext:                   []byte("testdata"),
		AdditionalAuthenticatedData: []byte("aad"),
		InitializationVector:        []byte("my_custom_iv_123"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestRawEncryptAesCbcCtrInvalidIvLength(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_CBC,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                 ckv.Name,
		Plaintext:            []byte("testdata"),
		InitializationVector: []byte("this_is_not_16_bytes"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestRawEncryptAesCbcCtrAadSpecifiedFails(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_128_CBC,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.RawEncrypt(ctx, &kmspb.RawEncryptRequest{
		Name:                        ckv.Name,
		Plaintext:                   []byte("testdata"),
		AdditionalAuthenticatedData: []byte("aad"),
		InitializationVector:        []byte("my_custom_iv_123"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestRawDecryptAesCbcCtrAadSpecifiedFails(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_AES_256_CTR,
			},
		},
		SkipInitialVersionCreation: true,
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.RawDecrypt(ctx, &kmspb.RawDecryptRequest{
		Name:                        ckv.Name,
		Ciphertext:                  []byte("testdata"),
		AdditionalAuthenticatedData: []byte("aad"),
		InitializationVector:        []byte("my_custom_iv_123"),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}
