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

package fakekms

import (
	"context"
	"crypto/rand"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

// GenerateRandomBytes fakes a Cloud KMS API function.
func (f *fakeKMS) GenerateRandomBytes(ctx context.Context, req *kmspb.GenerateRandomBytesRequest) (*kmspb.GenerateRandomBytesResponse, error) {
	if _, err := parseLocationName(req.Location); err != nil {
		return nil, err
	}
	if req.LengthBytes < 8 || req.LengthBytes > 1024 {
		return nil, errInvalidArgument("Length must be between 8 and 1024 bytes")
	}
	if req.ProtectionLevel != kmspb.ProtectionLevel_HSM {
		return nil, errUnimplemented("Protection level %s is not supported",
			kmspb.ProtectionLevel_name[int32(req.ProtectionLevel)])
	}

	b := make([]byte, req.LengthBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return &kmspb.GenerateRandomBytesResponse{
		Data:       b,
		DataCrc32C: crc32c(b),
	}, nil
}
