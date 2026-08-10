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
)

func TestGetKeyRingEqualsCreated(t *testing.T) {
	ctx := context.Background()
	want := client.CreateTestKR(ctx, t, &kmspb.CreateKeyRingRequest{Parent: location})

	got, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: want.Name,
	})
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(want, got, ProtoDiffOpts()...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}
}

func TestGetKeyRingMalformedName(t *testing.T) {
	ctx := context.Background()

	_, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: "malformed name",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestGetKeyRingNotFound(t *testing.T) {
	ctx := context.Background()

	_, err := client.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{
		Name: fmt.Sprintf("%s/keyRings/%s", location, RandomID(t)),
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("err=%v, want code=%s", err, codes.NotFound)
	}
}
