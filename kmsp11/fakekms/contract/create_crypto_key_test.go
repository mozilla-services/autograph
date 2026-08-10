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

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCreateCryptoKeyDefaults(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	got, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "encrypt",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	want := kmspb.CryptoKey{
		Name:       kr.Name + "/cryptoKeys/encrypt",
		CreateTime: timestamppb.Now(),
		Purpose:    kmspb.CryptoKey_ENCRYPT_DECRYPT,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
		},
		Primary: &kmspb.CryptoKeyVersion{
			Name:            kr.Name + "/cryptoKeys/encrypt/cryptoKeyVersions/1",
			CreateTime:      timestamppb.Now(),
			GenerateTime:    timestamppb.Now(),
			Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			State:           kmspb.CryptoKeyVersion_ENABLED,
		},
		DestroyScheduledDuration: &durationpb.Duration{Seconds: 2592000},
	}

	opts := append(ProtoDiffOpts(), protocmp.IgnoreUnknown())
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("unexpected diff (-want, +got): %s", diff)
	}
}

func TestCreateCryptoKeyAlgorithms(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	var cases = []struct {
		Name             string
		Purpose          kmspb.CryptoKey_CryptoKeyPurpose
		Algorithm        kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
		ProtectionLevel  kmspb.ProtectionLevel
		CryptoKeyBackend string
	}{
		{
			Name:            "ENCRYPT_DECRYPT_SOFTWARE",
			Purpose:         kmspb.CryptoKey_ENCRYPT_DECRYPT,
			Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		},
		{
			Name:             "ENCRYPT_DECRYPT_SINGLE_TENANT",
			Purpose:          kmspb.CryptoKey_ENCRYPT_DECRYPT,
			Algorithm:        kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			ProtectionLevel:  kmspb.ProtectionLevel_HSM_SINGLE_TENANT,
			CryptoKeyBackend: "projects/cloudkms-testing-hsm/locations/us-central1/singleTenantHsmInstances/staging-tmp-longrunning",
		},
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
			Name:             "SIGN_RSAPSS4096SHA512_SINGLE_TENANT",
			Purpose:          kmspb.CryptoKey_ASYMMETRIC_SIGN,
			Algorithm:        kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512,
			ProtectionLevel:  kmspb.ProtectionLevel_HSM_SINGLE_TENANT,
			CryptoKeyBackend: "projects/cloudkms-testing-hsm/locations/us-central1/singleTenantHsmInstances/staging-tmp-longrunning",
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
		{
			Name:             "ASYMM_DECRYPT_OAEP3072SHA256_SINGLE_TENANT",
			Purpose:          kmspb.CryptoKey_ASYMMETRIC_DECRYPT,
			Algorithm:        kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256,
			ProtectionLevel:  kmspb.ProtectionLevel_HSM_SINGLE_TENANT,
			CryptoKeyBackend: "projects/cloudkms-testing-hsm/locations/us-central1/singleTenantHsmInstances/staging-tmp-longrunning",
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			keyID := RandomID(t)
			got, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
				Parent:      kr.Name,
				CryptoKeyId: keyID,
				CryptoKey: &kmspb.CryptoKey{
					Purpose: c.Purpose,
					VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
						ProtectionLevel: c.ProtectionLevel,
						Algorithm:       c.Algorithm,
					},
					CryptoKeyBackend: c.CryptoKeyBackend,
				},
				SkipInitialVersionCreation: true,
			})
			if err != nil {
				t.Fatal(err)
			}

			want := &kmspb.CryptoKey{
				Name:       fmt.Sprintf("%s/cryptoKeys/%s", kr.Name, keyID),
				CreateTime: timestamppb.Now(),
				Purpose:    c.Purpose,
				VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
					ProtectionLevel: c.ProtectionLevel,
					Algorithm:       c.Algorithm,
				},
				CryptoKeyBackend:         c.CryptoKeyBackend,
				DestroyScheduledDuration: &durationpb.Duration{Seconds: 2592000},
			}
			opts := append(ProtoDiffOpts(), protocmp.IgnoreUnknown())
			if diff := cmp.Diff(want, got, opts...); diff != "" {
				t.Errorf("unexpected diff (-want +got): %s", diff)
			}
		})
	}
}

func TestCreateCryptoKeyMalformedParent(t *testing.T) {
	ctx := context.Background()

	_, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      "locations/foo",
		CryptoKeyId: "bar",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestCreateCryptoKeyMalformedID(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	_, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "&bar",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestCreateCryptoKeyDuplicateName(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "bar",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	}

	if _, err := client.CreateCryptoKey(ctx, req); err != nil {
		t.Fatal(err)
	}

	if _, err := client.CreateCryptoKey(ctx, req); status.Code(err) != codes.AlreadyExists {
		t.Errorf("err=%v, want code=%s", err, codes.AlreadyExists)
	}
}

func TestCreateCryptoKeyMissingAlgorithm(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	// ASYMMETRIC_SIGN and ASYMMETRIC_DECRYPT must have algorithm supplied
	purposes := []kmspb.CryptoKey_CryptoKeyPurpose{
		kmspb.CryptoKey_ASYMMETRIC_DECRYPT, kmspb.CryptoKey_ASYMMETRIC_SIGN,
	}

	for _, p := range purposes {
		_, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
			Parent:      kr.Name,
			CryptoKeyId: RandomID(t),
			CryptoKey: &kmspb.CryptoKey{
				Purpose: p,
			},
			SkipInitialVersionCreation: true,
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
		}
	}
}
