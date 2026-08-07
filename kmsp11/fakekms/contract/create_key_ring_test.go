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
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCreateKeyRing(t *testing.T) {
	ctx := context.Background()
	keyRingID := RandomID(t)

	got, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: keyRingID,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := &kmspb.KeyRing{
		Name:       fmt.Sprintf("%s/keyRings/%s", location, keyRingID),
		CreateTime: timestamppb.Now(),
	}

	opts := append(ProtoDiffOpts(), protocmp.IgnoreUnknown())
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("unexpected diff (-want, +got): %s", diff)
	}
}

func TestCreateKeyRingMalformedParent(t *testing.T) {
	ctx := context.Background()

	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "locations/foo",
		KeyRingId: "bar",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestCreateKeyRingMalformedID(t *testing.T) {
	ctx := context.Background()

	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: "&bar",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestCreateKeyRingDuplicateName(t *testing.T) {
	ctx := context.Background()

	req := &kmspb.CreateKeyRingRequest{
		Parent:    location,
		KeyRingId: RandomID(t),
	}

	if _, err := client.CreateKeyRing(ctx, req); err != nil {
		t.Fatal(err)
	}

	if _, err := client.CreateKeyRing(ctx, req); status.Code(err) != codes.AlreadyExists {
		t.Errorf("err=%v, want code=%s", err, codes.AlreadyExists)
	}
}
