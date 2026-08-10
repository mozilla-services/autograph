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
	"bytes"
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

var ignoreDataAndDataCRC = protocmp.IgnoreFields(new(kmspb.GenerateRandomBytesResponse),
	protoreflect.Name("data"), protoreflect.Name("data_crc32c"))

func TestGenerateRandomBytes(t *testing.T) {
	ctx := context.Background()
	byteLength := 32

	got, err := client.GenerateRandomBytes(ctx, &kmspb.GenerateRandomBytesRequest{
		Location:        location,
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
		LengthBytes:     int32(byteLength),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Diff the proto, but ignore data and data_crc32c.
	// This causes the contract test to fail if new fields begin being
	// emitted by real KMS.
	want := &kmspb.GenerateRandomBytesResponse{}
	opts := append(ProtoDiffOpts(), ignoreDataAndDataCRC)
	if diff := cmp.Diff(want, got, opts...); diff != "" {
		t.Errorf("proto mismatch (-want +got): %s", diff)
	}

	if len(got.Data) != byteLength {
		t.Errorf("length mismatch: got %d, want %d", len(got.Data), byteLength)
	}
	if bytes.Equal(got.Data, make([]byte, byteLength)) {
		t.Error("got.Data is filled with zeroes")
	}

	verifyCRC32C(t, got.Data, got.DataCrc32C)
}

func TestGenerateRandomBytesMalformedLocation(t *testing.T) {
	ctx := context.Background()

	_, err := client.GenerateRandomBytes(ctx, &kmspb.GenerateRandomBytesRequest{
		Location:        "malformed location",
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
		LengthBytes:     32,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestGenerateRandomBytesUnsupportedProtectionLevel(t *testing.T) {
	ctx := context.Background()

	_, err := client.GenerateRandomBytes(ctx, &kmspb.GenerateRandomBytesRequest{
		Location:        location,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		LengthBytes:     32,
	})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("err=%v, want code=%s", err, codes.Unimplemented)
	}
}

func TestGenerateRandomBytesLengthTooShort(t *testing.T) {
	ctx := context.Background()

	_, err := client.GenerateRandomBytes(ctx, &kmspb.GenerateRandomBytesRequest{
		Location:        location,
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
		LengthBytes:     7,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}

func TestGenerateRandomBytesLengthTooLong(t *testing.T) {
	ctx := context.Background()

	_, err := client.GenerateRandomBytes(ctx, &kmspb.GenerateRandomBytesRequest{
		Location:        location,
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
		LengthBytes:     1025,
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err=%v, want code=%s", err, codes.InvalidArgument)
	}
}
