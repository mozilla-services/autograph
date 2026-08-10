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
)

func TestGetCryptoKeyEqualsCreated(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	want := client.CreateTestCK(ctx, t, &kmspb.CreateCryptoKeyRequest{
		Parent:      kr.Name,
		CryptoKeyId: "foo",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
		SkipInitialVersionCreation: true,
	})

	got, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: want.Name,
	})
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(want, got, ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestGetCryptoKeyMalformedName(t *testing.T) {
	ctx := context.Background()

	_, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: "malformed name",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestGetCryptoKeyNotFound(t *testing.T) {
	ctx := context.Background()
	kr := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	_, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: kr.Name + "/cryptoKeys/foo",
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}
