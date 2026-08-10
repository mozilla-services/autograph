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

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestUpdateCryptoKeyVersionDisableEnable(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})

	// ensure that enabled => disabled is permitted
	ck.Primary.State = kmspb.CryptoKeyVersion_DISABLED
	gotVersion, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ck.Primary,
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"state"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(ck.Primary, gotVersion, ProtoDiffOpts()...); diff != "" {
		t.Errorf("ckv proto mismatch on disable RPC (-want +got): %s", diff)
	}

	// ensure that `primary` in GetCryptoKey is updated too
	gotKey, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: ck.Name})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(ck, gotKey, ProtoDiffOpts()...); diff != "" {
		t.Errorf("ck proto mismatch after disable RPC (-want +got): %s", diff)
	}

	// ensure that disabled => enabled is permitted
	ck.Primary.State = kmspb.CryptoKeyVersion_ENABLED
	gotVersion, err = client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ck.Primary,
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"state"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(ck.Primary, gotVersion, ProtoDiffOpts()...); diff != "" {
		t.Errorf("ckv proto mismatch on enable RPC (-want +got): %s", diff)
	}
}

func TestUpdateCryptoKeyVersionNoFields(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	_, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestUpdateCryptoKeyVersionUnsupportedState(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	ckv.State = kmspb.CryptoKeyVersion_PENDING_IMPORT

	_, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"state"},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestUpdateCryptoKeyVersionUnsupportedField(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	ck := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent: kr.Name,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	ckv := client.CreateTestCKVAndWait(ctx, t, &kmspb.CreateCryptoKeyVersionRequest{
		Parent: ck.Name,
	})

	ckv.Name = "updated"

	_, err := client.UpdateCryptoKeyVersion(ctx, &kmspb.UpdateCryptoKeyVersionRequest{
		CryptoKeyVersion: ckv,
		UpdateMask: &fieldmaskpb.FieldMask{
			Paths: []string{"name"},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}
