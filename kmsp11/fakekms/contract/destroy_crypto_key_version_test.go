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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDestroyEnabledCryptoKeyVersion(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	ckv := ck.Primary

	got, err := client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{
		Name: ckv.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	expectedDestroyTime := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Microsecond)

	ckv.State = kmspb.CryptoKeyVersion_DESTROY_SCHEDULED
	ckv.DestroyTime = timestamppb.New(expectedDestroyTime)

	if diff := cmp.Diff(ckv, got, ProtoDiffOpts()...); diff != "" {
		t.Errorf("ckv proto mismatch on destroy RPC (-want +got): %s", diff)
	}
}

func TestDestroyDisabledCryptoKeyVersion(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	// update state to disabled
	ck.Primary.State = kmspb.CryptoKeyVersion_DISABLED
	ckv, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ck.Primary,
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"state"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{
		Name: ckv.Name,
	})
	if err != nil {
		t.Fatal(err)
	}

	expectedDestroyTime := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Microsecond)

	ckv.State = kmspb.CryptoKeyVersion_DESTROY_SCHEDULED
	ckv.DestroyTime = timestamppb.New(expectedDestroyTime)

	if diff := cmp.Diff(ckv, got, ProtoDiffOpts()...); diff != "" {
		t.Errorf("ckv proto mismatch on destroy RPC (-want +got): %s", diff)
	}
}

func TestDestroyCryptoKeyVersionUnsupportedState(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	destroyReq := &kmspb.DestroyCryptoKeyVersionRequest{
		Name: ck.Primary.Name,
	}

	if _, err := client.DestroyCryptoKeyVersion(ctx, destroyReq); err != nil {
		t.Fatal(err)
	}

	_, err := client.DestroyCryptoKeyVersion(ctx, destroyReq)
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err=%v, want code=%s", err, codes.FailedPrecondition)
	}
}

func TestDestroyCryptoKeyVersionNotFound(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})

	_, err := client.DestroyCryptoKeyVersion(ctx, &kmspb.DestroyCryptoKeyVersionRequest{
		Name: ck.Name + "/cryptoKeyVersions/1",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}
