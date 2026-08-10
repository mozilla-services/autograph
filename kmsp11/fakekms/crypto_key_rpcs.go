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
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateCryptoKey fakes a Cloud KMS API function.
func (f *fakeKMS) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if err := allowlist("parent", "crypto_key_id", "skip_initial_version_creation",
		"crypto_key.purpose", "crypto_key.version_template.algorithm",
		"crypto_key.version_template.protection_level",
		"crypto_key.crypto_key_backend").check(req); err != nil {
		return nil, err
	}

	krName, err := parseKeyRingName(req.Parent)
	if err != nil {
		return nil, err
	}
	if err := checkID(req.CryptoKeyId); err != nil {
		return nil, err
	}
	name := cryptoKeyName{keyRingName: krName, CryptoKeyID: req.CryptoKeyId}

	purpose := req.GetCryptoKey().GetPurpose()
	if purpose == kmspb.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED {
		return nil, errRequiredField("crypto_key.purpose")
	}

	alg := req.GetCryptoKey().GetVersionTemplate().GetAlgorithm()
	if alg == kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED {
		alg = kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION
	}
	if err := validateAlgorithm(alg, purpose); err != nil {
		return nil, err
	}

	protLevel := req.GetCryptoKey().GetVersionTemplate().GetProtectionLevel()
	if protLevel == kmspb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED {
		protLevel = kmspb.ProtectionLevel_SOFTWARE
	}
	if err := validateProtectionLevel(protLevel); err != nil {
		return nil, err
	}

	cryptoKeyBackend := req.GetCryptoKey().GetCryptoKeyBackend()
	if protLevel == kmspb.ProtectionLevel_HSM_SINGLE_TENANT &&
		cryptoKeyBackend == "" {
		return nil, errRequiredField("crypto_key.crypto_key_backend")
	}

	kr, ok := f.keyRings[krName]
	if !ok {
		return nil, errNotFound(krName)
	}
	if _, ok := kr.keys[name]; ok {
		return nil, errAlreadyExists(name)
	}

	pb := &kmspb.CryptoKey{
		Name:       name.String(),
		CreateTime: timestamppb.Now(),
		Purpose:    purpose,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			ProtectionLevel: protLevel,
			Algorithm:       alg,
		},
		CryptoKeyBackend:         cryptoKeyBackend,
		DestroyScheduledDuration: &durationpb.Duration{Seconds: 2592000},
	}

	ck := &cryptoKey{
		pb:       pb,
		versions: make(map[cryptoKeyVersionName]*cryptoKeyVersion),
	}

	if !req.SkipInitialVersionCreation {
		ckv := f.createVersion(ck)
		if purpose == kmspb.CryptoKey_ENCRYPT_DECRYPT {
			pb.Primary = ckv
		}
	}

	kr.keys[name] = ck
	return pb, nil
}

// GetCryptoKey fakes a Cloud KMS API function.
func (f *fakeKMS) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if err := allowlist("name").check(req); err != nil {
		return nil, err
	}

	name, err := parseCryptoKeyName(req.Name)
	if err != nil {
		return nil, err
	}

	ck, err := f.cryptoKey(name)
	if err != nil {
		return nil, err
	}

	return ck.pb, nil
}

// ListCryptoKeys fakes a Cloud KMS API function.
func (f *fakeKMS) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	if err := allowlist("parent").check(req); err != nil {
		return nil, err
	}

	parent, err := parseKeyRingName(req.Parent)
	if err != nil {
		return nil, err
	}

	kr, ok := f.keyRings[parent]
	if !ok {
		return nil, errNotFound(parent)
	}

	r := make([]*kmspb.CryptoKey, 0, len(kr.keys))
	for _, ck := range kr.keys {
		r = append(r, ck.pb)
	}

	if len(r) > maxPageSize {
		return nil, errMaxPageSize(len(r))
	}

	sort.Slice(r, func(i, j int) bool {
		return r[i].Name < r[j].Name
	})

	return &kmspb.ListCryptoKeysResponse{
		CryptoKeys: r,
		TotalSize:  int32(len(r)),
	}, nil
}

// UpdateCryptoKey fakes a Cloud KMS API function.
func (f *fakeKMS) UpdateCryptoKey(ctx context.Context, req *kmspb.UpdateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if err := allowlist("crypto_key", "update_mask").check(req); err != nil {
		return nil, err
	}

	if len(req.UpdateMask.GetPaths()) == 0 {
		return nil, errInvalidArgument("no fields selected for update")
	}

	name, err := parseCryptoKeyName(req.CryptoKey.Name)
	if err != nil {
		return nil, err
	}

	ck, err := f.cryptoKey(name)
	if err != nil {
		return nil, err
	}

	for _, p := range req.UpdateMask.Paths {
		switch p {
		case "version_template.algorithm":
			if err := validateAlgorithm(req.CryptoKey.VersionTemplate.Algorithm, ck.pb.Purpose); err != nil {
				return nil, err
			}
			ck.pb.VersionTemplate.Algorithm = req.CryptoKey.VersionTemplate.Algorithm
		default:
			return nil, errInvalidArgument("unsupported update path: %s", p)
		}
	}

	return ck.pb, nil
}
