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

	kms "cloud.google.com/go/kms/apiv1"
	"google.golang.org/protobuf/proto"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

// testClient is a key management client with additional helpers.
type testClient struct {
	*kms.KeyManagementClient
}

// CreateTestKR creates a KeyRing using the provided request.
func (c *testClient) CreateTestKR(ctx context.Context, t *testing.T, req *kmspb.CreateKeyRingRequest) *kmspb.KeyRing {
	t.Helper()

	r := &kmspb.CreateKeyRingRequest{
		KeyRingId: RandomID(t),
	}
	proto.Merge(r, req)

	kr, err := c.CreateKeyRing(ctx, r)
	if err != nil {
		t.Fatal(err)
	}

	return kr
}

// CreateTestCK creates a CryptoKey using the provided request.
func (c *testClient) CreateTestCK(ctx context.Context, t *testing.T, req *kmspb.CreateCryptoKeyRequest) *kmspb.CryptoKey {
	t.Helper()

	r := &kmspb.CreateCryptoKeyRequest{
		CryptoKeyId: RandomID(t),
	}
	proto.Merge(r, req)

	ck, err := c.CreateCryptoKey(ctx, r)
	if err != nil {
		t.Fatal(err)
	}

	return ck
}

// CreateTestCKVAndWait creates a CryptoKeyVersion with the provided request
// and waits for its state to be enabled before returning.
func (c *testClient) CreateTestCKVAndWait(ctx context.Context, t *testing.T, req *kmspb.CreateCryptoKeyVersionRequest) *kmspb.CryptoKeyVersion {
	t.Helper()

	ckv, err := c.CreateCryptoKeyVersion(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	for ckv.State == kmspb.CryptoKeyVersion_PENDING_GENERATION {
		time.Sleep(asyncPollInterval)
		ckv, err = c.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
			Name: ckv.Name,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	return ckv
}
