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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

func TestListKeyRingsSorted(t *testing.T) {
	ctx := context.Background()

	// In real KMS, we can't depend on beginning state being empty. We're
	// creating two key rings here just to make sure that two (or more) exist--
	// they may not be the first two that are returned in the list request.
	client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})
	client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	iter := client.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{Parent: location})

	r1, err := iter.Next()
	if err != nil {
		t.Fatalf("first call to iter.Next() resulted in error=%v, want nil", err)
	}

	r2, err := iter.Next()
	if err != nil {
		t.Fatalf("second call to iter.Next() resulted in error=%v, want nil", err)
	}

	if r1.Name > r2.Name {
		t.Errorf("r1.Name=%s > r2.Name=%s", r1.Name, r2.Name)
	}
}

func TestListKeyRingsMalformedParent(t *testing.T) {
	ctx := context.Background()

	iter := client.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{
		Parent: "locations/foo",
	})
	if _, err := iter.Next(); status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}
