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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"hash/crc32"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

func crc32c(data []byte) *wrapperspb.Int64Value {
	return wrapperspb.Int64(int64(crc32.Checksum(data, crc32cTable)))
}

// GetPublicKey fakes a Cloud KMS API function.
func (f *fakeKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) {
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

	if ckv.pb.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, errFailedPrecondition("key version %s is not enabled", name)
	}

	s, ok := ckv.keyMaterial.(crypto.Signer)
	if !ok {
		return nil, errFailedPrecondition("keys with algorithm %s do not contain a public key",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	derPub, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return nil, err
	}

	pemPub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPub,
	})

	return &kmspb.PublicKey{
		Name:            req.Name,
		Algorithm:       ckv.pb.Algorithm,
		Pem:             string(pemPub),
		PemCrc32C:       crc32c(pemPub),
		ProtectionLevel: ckv.pb.ProtectionLevel,
	}, nil
}

// AsymmetricDecrypt fakes a Cloud KMS API function.
func (f *fakeKMS) AsymmetricDecrypt(ctx context.Context, req *kmspb.AsymmetricDecryptRequest) (*kmspb.AsymmetricDecryptResponse, error) {
	if err := allowlist("name", "ciphertext", "ciphertext_crc32c").check(req); err != nil {
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

	if ckv.pb.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, errFailedPrecondition("key version %s is not enabled", name)
	}

	def, _ := algorithmDef(ckv.pb.Algorithm)
	if def.Purpose != kmspb.CryptoKey_ASYMMETRIC_DECRYPT {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for asymmetric decryption",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	if req.Ciphertext == nil {
		return nil, errInvalidArgument("ciphertext is empty")
	}

	if len(req.Ciphertext) > maxCiphertextSize {
		return nil, errInvalidArgument("len(ciphertext)=%d, want len(ciphertext)<=%d", len(req.Ciphertext), maxCiphertextSize)
	}

	ciphertextChecksum := crc32c(req.Ciphertext)
	if req.CiphertextCrc32C != nil && ciphertextChecksum.Value != req.CiphertextCrc32C.Value {
		return nil, errInvalidArgument("invalid ciphertext checksum")
	}

	pt, err := ckv.keyMaterial.(crypto.Decrypter).Decrypt(rand.Reader, req.Ciphertext, def.Opts)
	if err != nil {
		return nil, errInvalidArgument("decryption failed: %v", err)
	}

	return &kmspb.AsymmetricDecryptResponse{
		Plaintext:                pt,
		PlaintextCrc32C:          crc32c(pt),
		VerifiedCiphertextCrc32C: req.CiphertextCrc32C != nil,
		ProtectionLevel:          ckv.pb.ProtectionLevel,
	}, nil
}

// AsymmetricSign fakes a Cloud KMS API function.
func (f *fakeKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	if err := allowlist("name", "data", "data_crc32c", "digest.sha256", "digest.sha384", "digest.sha512", "digest_crc32c").check(req); err != nil {
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

	if ckv.pb.State != kmspb.CryptoKeyVersion_ENABLED {
		return nil, errFailedPrecondition("key version %s is not enabled", name)
	}

	def, _ := algorithmDef(ckv.pb.Algorithm)
	if def.Purpose != kmspb.CryptoKey_ASYMMETRIC_SIGN {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for signing",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	if req.DataCrc32C != nil && req.DigestCrc32C != nil {
		return nil, errInvalidArgument("only one of digest_crc32c or data_crc32c must be set")
	}

	opts := def.Opts.(crypto.SignerOpts)

	var data []byte
	switch {
	case req.Digest != nil && req.Data != nil:
		return nil, errInvalidArgument("only one of digest or data must be set")
	case req.Digest == nil && req.Data == nil:
		return nil, errInvalidArgument("at least one of digest or data must be set")
	case opts.HashFunc() == crypto.Hash(0): // algorithm doesn't support prehashed data
		if req.Data == nil {
			return nil, errInvalidArgument("data is empty")
		}
		dataChecksum := crc32c(req.Data)
		if req.DataCrc32C != nil && dataChecksum.Value != req.DataCrc32C.Value {
			return nil, errInvalidArgument("invalid data checksum")
		}
		data = req.Data
	case req.Data != nil:
		if req.Digest != nil {
			return nil, errInvalidArgument("digest should be empty")
		}
		// Validate checksum before computing the digest
		dataChecksum := crc32c(req.Data)
		if req.DataCrc32C != nil && dataChecksum.Value != req.DataCrc32C.Value {
			return nil, errInvalidArgument("invalid data checksum")
		}
		data = req.Data
		h := opts.HashFunc().New()
		h.Write(data)
		data = h.Sum(nil)
	case opts.HashFunc() == crypto.SHA256:
		data = req.Digest.GetSha256()
	case opts.HashFunc() == crypto.SHA384:
		data = req.Digest.GetSha384()
	case opts.HashFunc() == crypto.SHA512:
		data = req.Digest.GetSha512()
	default:
		return nil, errInternal("unsupported hash: %d", opts.HashFunc())
	}

	if opts.HashFunc() != crypto.Hash(0) && len(data) != opts.HashFunc().Size() {
		return nil, errInvalidArgument("len(digest)=%d, want %d", len(data), opts.HashFunc().Size())
	}

	dataChecksum := crc32c(data)
	if req.DigestCrc32C != nil && dataChecksum.Value != req.DigestCrc32C.Value {
		return nil, errInvalidArgument("invalid digest checksum")
	}

	sig, err := ckv.keyMaterial.(crypto.Signer).Sign(rand.Reader, data, opts)
	if err != nil {
		return nil, errInternal("signing failed: %v", err)
	}

	return &kmspb.AsymmetricSignResponse{
		Name:                 req.Name,
		Signature:            sig,
		SignatureCrc32C:      crc32c(sig),
		VerifiedDataCrc32C:   req.DataCrc32C != nil,
		VerifiedDigestCrc32C: req.DigestCrc32C != nil,
		ProtectionLevel:      ckv.pb.ProtectionLevel,
	}, nil
}
