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

package fakekms

import (
	"context"
	"sort"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateKeyRing fakes a Cloud KMS API function.
func (f *fakeKMS) CreateKeyRing(ctx context.Context, req *kmspb.CreateKeyRingRequest) (*kmspb.KeyRing, error) {
	if err := allowlist("parent", "key_ring_id").check(req); err != nil {
		return nil, err
	}

	parent, err := parseLocationName(req.Parent)
	if err != nil {
		return nil, err
	}
	if err := checkID(req.KeyRingId); err != nil {
		return nil, err
	}

	name := keyRingName{locationName: parent, KeyRingID: req.KeyRingId}
	if _, ok := f.keyRings[name]; ok {
		return nil, errAlreadyExists(name)
	}

	pb := &kmspb.KeyRing{
		Name:       name.String(),
		CreateTime: timestamppb.Now(),
	}
	f.keyRings[name] = &keyRing{
		pb:   pb,
		keys: make(map[cryptoKeyName]*cryptoKey),
	}
	return pb, nil
}

// GetKeyRing fakes a Cloud KMS API function.
func (f *fakeKMS) GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	if err := allowlist("name").check(req); err != nil {
		return nil, err
	}

	name, err := parseKeyRingName(req.Name)
	if err != nil {
		return nil, err
	}

	kr, ok := f.keyRings[name]
	if !ok {
		return nil, errNotFound(name)
	}
	return kr.pb, nil
}

// ListKeyRings fakes a Cloud KMS API function.
func (f *fakeKMS) ListKeyRings(ctx context.Context, req *kmspb.ListKeyRingsRequest) (*kmspb.ListKeyRingsResponse, error) {
	if err := allowlist("parent").check(req); err != nil {
		return nil, err
	}

	parent, err := parseLocationName(req.Parent)
	if err != nil {
		return nil, err
	}

	r := make([]*kmspb.KeyRing, 0, len(f.keyRings))
	for name, kr := range f.keyRings {
		if name.locationName == parent {
			r = append(r, kr.pb)
		}
	}

	if len(r) > maxPageSize {
		return nil, errMaxPageSize(len(r))
	}

	sort.Slice(r, func(i, j int) bool {
		return r[i].Name < r[j].Name
	})

	return &kmspb.ListKeyRingsResponse{
		KeyRings:  r,
		TotalSize: int32(len(r)),
	}, nil
}
