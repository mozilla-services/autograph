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
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCreateCryptoKeyVersionSequential(t *testing.T) {
	ctx := context.Background()

	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})

	req := &kmspb.CreateCryptoKeyVersionRequest{Parent: ck.Name}

	got, err := client.CreateCryptoKeyVersion(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	want := kmspb.CryptoKeyVersion{
		Name:            ck.Name + "/cryptoKeyVersions/1",
		CreateTime:      timestamppb.Now(),
		GenerateTime:    timestamppb.Now(),
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
		State:           kmspb.CryptoKeyVersion_ENABLED,
	}

	if diff := cmp.Diff(want, got, ProtoDiffOpts()...); diff != "" {
		t.Errorf("unexpected version 1 diff (-want, +got): %s", diff)
	}

	got, err = client.CreateCryptoKeyVersion(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	want.Name = ck.Name + "/cryptoKeyVersions/2"
	want.CreateTime = timestamppb.Now()

	if diff := cmp.Diff(want, got, ProtoDiffOpts()...); diff != "" {
		t.Errorf("unexpected version 2 diff (-want, +got): %s", diff)
	}
}

func TestCreateCryptoKeyVersionAsync(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	var cases = []struct {
		Name            string
		Purpose         kmspb.CryptoKey_CryptoKeyPurpose
		Algorithm       kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		ProtectionLevel kmspb.ProtectionLevel
	}{
		{
			Name:            "SIGN_P256_HSM",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
		{
			Name:            "SIGN_P384_SOFTWARE",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		{
			Name:            "SIGN_RSA3072PKCS1_SOFTWARE",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Algorithm:       kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		{
			Name:            "SIGN_RSAPSS4096SHA512_HSM",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Algorithm:       kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
		{
			Name:            "ASYMM_DECRYPT_OAEP2048_SOFTWARE",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			Algorithm:       kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		{
			Name:            "ASYMM_DECRYPT_OAEP4096SHA256_HSM",
			Purpose:         kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			Algorithm:       kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256,
			ProtectionLevel: kmspb.ProtectionLevel_HSM,
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
				Parent: kr.Name,
				CryptoKey: &kmspb.CryptoKey{
					Purpose: c.Purpose,
					VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
						ProtectionLevel: c.ProtectionLevel,
						Algorithm:       c.Algorithm,
					},
				},
				SkipInitialVersionCreation: true,
			})

			got, err := client.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{
				Parent: ck.Name,
			})

			want := &kmspb.CryptoKeyVersion{
				Name:            fmt.Sprintf("%s/cryptoKeyVersions/1", ck.Name),
				CreateTime:      timestamppb.Now(),
				ProtectionLevel: c.ProtectionLevel,
				Algorithm:       c.Algorithm,
				State:           kmspb.CryptoKeyVersion_PENDING_GENERATION,
			}

			if diff := cmp.Diff(want, got, ProtoDiffOpts()...); diff != "" {
				t.Errorf("unexpected pregeneration diff (-want +got): %s", diff)
			}

			for got.State == kmspb.CryptoKeyVersion_PENDING_GENERATION {
				time.Sleep(asyncPollInterval)

				got, err = client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
					Name: got.Name,
				})
				if err != nil {
					t.Fatal(err)
				}
			}

			want.State = kmspb.CryptoKeyVersion_ENABLED
			want.GenerateTime = timestamppb.Now()

			// Real KMS returns an attestation for HSM keys. Ignore it, because we
			// don't support attestations in the fake.
			opts := append(ProtoDiffOpts(), protocmp.IgnoreFields(
				new(kmspb.CryptoKeyVersion), protoreflect.Name("attestation")))

			if diff := cmp.Diff(want, got, opts...); diff != "" {
				t.Errorf("unexpected postgeneration diff (-want +got): %s", diff)
			}
		})
	}
}

func TestCreateCryptoKeyVersionMalformedParent(t *testing.T) {
	ctx := context.Background()
	_, err := client.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: "locations/foo",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}
