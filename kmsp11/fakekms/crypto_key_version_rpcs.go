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
	"strconv"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateCryptoKeyVersionVersion fakes a Cloud KMS API function.
func (f *fakeKMS) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := allowlist("parent").check(req); err != nil {
		return nil, err
	}

	ckName, err := parseCryptoKeyName(req.Parent)
	if err != nil {
		return nil, err
	}

	ck, err := f.cryptoKey(ckName)
	if err != nil {
		return nil, err
	}

	return f.createVersion(ck), nil
}

// createVersion adds a new version to the provided cryptoKey and returns its proto.
// Callers must already be holding f.mux (normally via the locking interceptor).
func (f *fakeKMS) createVersion(ck *cryptoKey) *kmspb.CryptoKeyVersion {
	ckName, _ := parseCryptoKeyName(ck.pb.Name)
	name := cryptoKeyVersionName{
		cryptoKeyName:      ckName,
		CryptoKeyVersionID: strconv.Itoa(len(ck.versions) + 1),
	}

	pb := &kmspb.CryptoKeyVersion{
		Name:            name.String(),
		CreateTime:      timestamppb.Now(),
		Algorithm:       ck.pb.VersionTemplate.Algorithm,
		ProtectionLevel: ck.pb.VersionTemplate.ProtectionLevel,
	}

	ckv := &cryptoKeyVersion{pb: pb}
	def, _ := algorithmDef(pb.Algorithm)

	if def.Asymmetric() {
		// async generation
		pb.State = kmspb.CryptoKeyVersion_PENDING_GENERATION
		go func() {
			k := def.KeyFactory.Generate() // no need to wait on the lock for this

			// Our lock interceptor ensures that f.mux is held whenever an RPC is in
			// flight. This goroutine won't be able to acquire f.mux until after the
			// CreateCryptoKeyVersion RPC completes. Since all RPCs acquire f.mux, we
			// can further guarantee that no other RPCs are in flight when this
			// routine proceeds.
			f.mux.Lock()
			defer f.mux.Unlock()

			ckv.keyMaterial = k
			pb.State = kmspb.CryptoKeyVersion_ENABLED
			pb.GenerateTime = timestamppb.Now()
		}()
	} else {
		// sync generation
		ckv.keyMaterial = def.KeyFactory.Generate()
		pb.GenerateTime = pb.CreateTime
		pb.State = kmspb.CryptoKeyVersion_ENABLED
	}

	ck.versions[name] = ckv
	return pb
}

// GetCryptoKeyVersion fakes a Cloud KMS API function.
func (f *fakeKMS) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := allowlist("name").check(req); err != nil {
		return nil, err
	}

	name, err := parseCryptoKeyVersionName(req.Name)
	if err != nil {
		return nil, err
	}

	ckv, err := f.cryptoKeyVersion(name)
	if err != nil {
		return nil, err
	}

	return ckv.pb, nil
}

// ListCryptoKeyVersions fakes a Cloud KMS API function.
func (f *fakeKMS) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	if err := allowlist("parent").check(req); err != nil {
		return nil, err
	}

	parent, err := parseCryptoKeyName(req.Parent)
	if err != nil {
		return nil, err
	}

	ck, err := f.cryptoKey(parent)
	if err != nil {
		return nil, err
	}

	r := make([]*kmspb.CryptoKeyVersion, 0, len(ck.versions))
	for _, ckv := range ck.versions {
		r = append(r, ckv.pb)
	}

	if len(r) > maxPageSize {
		return nil, errMaxPageSize(len(r))
	}

	sort.Slice(r, func(i, j int) bool {
		return r[i].Name < r[j].Name
	})

	return &kmspb.ListCryptoKeyVersionsResponse{
		CryptoKeyVersions: r,
		TotalSize:         int32(len(r)),
	}, nil
}

// UpdateCryptoKeyVersion fakes a Cloud KMS API function.
func (f *fakeKMS) UpdateCryptoKeyVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := allowlist("crypto_key_version", "update_mask").check(req); err != nil {
		return nil, err
	}

	if len(req.UpdateMask.GetPaths()) == 0 {
		return nil, errInvalidArgument("no fields selected for update")
	}

	name, err := parseCryptoKeyVersionName(req.CryptoKeyVersion.GetName())
	if err != nil {
		return nil, err
	}

	ckv, err := f.cryptoKeyVersion(name)
	if err != nil {
		return nil, err
	}

	for _, p := range req.UpdateMask.Paths {
		switch p {
		case "state":
			switch req.CryptoKeyVersion.State {
			case kmspb.CryptoKeyVersion_ENABLED, kmspb.CryptoKeyVersion_DISABLED:
				ckv.pb.State = req.CryptoKeyVersion.State
			default:
				return nil, errInvalidArgument("unsupported state in update call: %s",
					nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionState_name, int32(req.CryptoKeyVersion.State)))
			}
		default:
			return nil, errInvalidArgument("unsupported update path: %s", p)
		}
	}

	return ckv.pb, nil
}

// DestroyCryptoKeyVersion fakes a Cloud KMS API function.
func (f *fakeKMS) DestroyCryptoKeyVersion(ctx context.Context, req *kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if err := allowlist("name").check(req); err != nil {
		return nil, err
	}

	name, err := parseCryptoKeyVersionName(req.Name)
	if err != nil {
		return nil, err
	}

	ckv, err := f.cryptoKeyVersion(name)
	if err != nil {
		return nil, err
	}

	switch ckv.pb.State {
	case kmspb.CryptoKeyVersion_ENABLED, kmspb.CryptoKeyVersion_DISABLED:
		break
	default:
		return nil, errFailedPrecondition("state must be one of ENABLED or DISABLED in order to destroy")
	}

	// destroy_time is represented internally in KMS as int64 micros
	destroyTime := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Microsecond)

	ckv.pb.DestroyTime = timestamppb.New(destroyTime)
	ckv.pb.State = kmspb.CryptoKeyVersion_DESTROY_SCHEDULED
	return ckv.pb, nil
}
