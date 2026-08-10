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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"io"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

// maxPlaintextSize is the maximum plaintext size accepted by Cloud KMS.
const maxPlaintextSize = 64 * 1024

// maxCiphertextSize is the maximum ciphertext size accepted by Cloud KMS.
const maxCiphertextSize = 10 * maxPlaintextSize

// maxIvSize is the maximum initialization vector size accepted by Cloud KMS.
const maxIvSize = 16

// defaultTagLength is the authentication tag length used by Cloud KMS.
const defaultTagLength = 16

// RawEncrypt fakes a Cloud KMS API function.
func (f *fakeKMS) RawEncrypt(ctx context.Context, req *kmspb.RawEncryptRequest) (*kmspb.RawEncryptResponse, error) {
	if err := allowlist("name", "plaintext", "plaintext_crc32c", "additional_authenticated_data", "additional_authenticated_data_crc32c", "initialization_vector", "initialization_vector_crc32c").check(req); err != nil {
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
	if def.Purpose != kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for raw encryption",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	if req.Plaintext == nil {
		return nil, errInvalidArgument("plaintext is empty")
	}
	var plaintext []byte = req.Plaintext

	if len(plaintext) > maxPlaintextSize {
		return nil, errInvalidArgument("len(plaintext)=%d, want len(plaintext)<=%d", len(plaintext), maxPlaintextSize)
	}

	plaintextChecksum := crc32c(plaintext)
	if req.PlaintextCrc32C != nil && plaintextChecksum.Value != req.PlaintextCrc32C.Value {
		return nil, errInvalidArgument("invalid plaintext checksum")
	}

	var nonce []byte
	// Validate request fields.
	switch ckv.pb.Algorithm {
	case kmspb.CryptoKeyVersion_AES_128_GCM, kmspb.CryptoKeyVersion_AES_256_GCM:
		if req.InitializationVector != nil {
			return nil, errInvalidArgument("cannot specify iv when using AES-GCM")
		}
		nonce = make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, err
		}

		aadChecksum := crc32c(req.AdditionalAuthenticatedData)
		if req.AdditionalAuthenticatedData != nil &&
			req.AdditionalAuthenticatedDataCrc32C != nil &&
			aadChecksum.Value != req.AdditionalAuthenticatedDataCrc32C.Value {
			return nil, errInvalidArgument("invalid aad checksum")
		}
	case kmspb.CryptoKeyVersion_AES_128_CTR,
		kmspb.CryptoKeyVersion_AES_256_CTR,
		kmspb.CryptoKeyVersion_AES_128_CBC,
		kmspb.CryptoKeyVersion_AES_256_CBC:
		if req.AdditionalAuthenticatedData != nil {
			return nil, errInvalidArgument("cannot specify aad when using %s",
				nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
		}
		if req.InitializationVector != nil {
			if len(req.InitializationVector) > maxIvSize {
				return nil, errInvalidArgument("len(iv)=%d, want len(iv)<=%d", len(req.InitializationVector), maxIvSize)
			}
			nonce = req.InitializationVector
		} else {
			nonce = make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errInternal("unhandled algorithm")
	}

	var key []byte
	var ok bool
	if key, ok = ckv.keyMaterial.([]byte); !ok {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errInternal("AES cipher creation failed: %v", err)
	}

	var ciphertext []byte
	var tagLen int32
	switch ckv.pb.Algorithm {
	case kmspb.CryptoKeyVersion_AES_128_GCM, kmspb.CryptoKeyVersion_AES_256_GCM:
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errInternal("GCM cipher creation failed: %v", err)
		}
		ciphertext = aesgcm.Seal(nil, nonce, plaintext, req.AdditionalAuthenticatedData)
		tagLen = defaultTagLength
	case kmspb.CryptoKeyVersion_AES_128_CTR, kmspb.CryptoKeyVersion_AES_256_CTR:
		ciphertext = make([]byte, len(plaintext))
		aesctr := cipher.NewCTR(block, nonce)
		aesctr.XORKeyStream(ciphertext, plaintext)
	case kmspb.CryptoKeyVersion_AES_128_CBC, kmspb.CryptoKeyVersion_AES_256_CBC:
		if len(plaintext)%block.BlockSize() != 0 {
			return nil, errInvalidArgument("len(plaintext)=%d, want len(plaintext) mod %d == 0", len(plaintext), block.BlockSize())
		}
		ciphertext = make([]byte, len(plaintext))
		aescbc := cipher.NewCBCEncrypter(block, nonce)
		aescbc.CryptBlocks(ciphertext, plaintext)
	default:
		return nil, errInternal("unhandled algorithm")
	}

	return &kmspb.RawEncryptResponse{
		Name:                       req.Name,
		Ciphertext:                 ciphertext,
		CiphertextCrc32C:           crc32c(ciphertext),
		InitializationVector:       nonce,
		InitializationVectorCrc32C: crc32c(nonce),
		TagLength:                  tagLen,
		VerifiedPlaintextCrc32C:    req.PlaintextCrc32C != nil,
		VerifiedAdditionalAuthenticatedDataCrc32C: req.AdditionalAuthenticatedDataCrc32C != nil,
		VerifiedInitializationVectorCrc32C:        req.InitializationVectorCrc32C != nil,
		ProtectionLevel:                           ckv.pb.ProtectionLevel,
	}, nil
}

// RawDecrypt fakes a Cloud KMS API function.
func (f *fakeKMS) RawDecrypt(ctx context.Context, req *kmspb.RawDecryptRequest) (*kmspb.RawDecryptResponse, error) {
	if err := allowlist("name", "ciphertext", "ciphertext_crc32c", "additional_authenticated_data", "additional_authenticated_data_crc32c", "initialization_vector", "initialization_vector_crc32c").check(req); err != nil {
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
	if def.Purpose != kmspb.CryptoKey_RAW_ENCRYPT_DECRYPT {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for raw decryption",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	if req.Ciphertext == nil {
		return nil, errInvalidArgument("ciphertext is empty")
	}
	var ciphertext []byte = req.Ciphertext

	if len(ciphertext) > maxCiphertextSize {
		return nil, errInvalidArgument("len(ciphertext)=%d, want len(ciphertext)<=%d", len(ciphertext), maxCiphertextSize)
	}

	ciphertextChecksum := crc32c(ciphertext)
	if req.CiphertextCrc32C != nil && ciphertextChecksum.Value != req.CiphertextCrc32C.Value {
		return nil, errInvalidArgument("invalid ciphertext checksum")
	}

	if len(req.InitializationVector) > 16 {
		return nil, errInvalidArgument("len(initialization_vector)=%d, want len(initialization_vector)<=%d", len(req.InitializationVector), maxIvSize)
	}

	ivChecksum := crc32c(req.InitializationVector)
	if req.InitializationVector != nil && req.InitializationVectorCrc32C != nil && ivChecksum.Value != req.InitializationVectorCrc32C.Value {
		return nil, errInvalidArgument("invalid iv checksum")
	}

	if req.AdditionalAuthenticatedData != nil {
		switch ckv.pb.Algorithm {
		case kmspb.CryptoKeyVersion_AES_128_GCM, kmspb.CryptoKeyVersion_AES_256_GCM:
			break
		default:
			return nil, errInvalidArgument("cannot specify aad when using %s",
				nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
		}
	}

	aadChecksum := crc32c(req.AdditionalAuthenticatedData)
	if req.AdditionalAuthenticatedData != nil && req.AdditionalAuthenticatedDataCrc32C != nil && aadChecksum.Value != req.AdditionalAuthenticatedDataCrc32C.Value {
		return nil, errInvalidArgument("invalid aad checksum")
	}

	var key []byte
	var ok bool
	if key, ok = ckv.keyMaterial.([]byte); !ok {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errInternal("AES cipher creation failed: %v", err)
	}

	var plaintext []byte
	switch ckv.pb.Algorithm {
	case kmspb.CryptoKeyVersion_AES_128_GCM, kmspb.CryptoKeyVersion_AES_256_GCM:
		if len(ciphertext) < defaultTagLength {
			return nil, errInvalidArgument("len(ciphertext)=%d, want len(ciphertext) > %d", len(ciphertext), defaultTagLength)
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, errInternal("GCM cipher creation failed: %v", err)
		}
		plaintext, err = aesgcm.Open(nil, req.InitializationVector, ciphertext, req.AdditionalAuthenticatedData)
		if err != nil {
			return nil, errInternal("decryption failed: %v", err)
		}
	case kmspb.CryptoKeyVersion_AES_128_CTR, kmspb.CryptoKeyVersion_AES_256_CTR:
		plaintext = make([]byte, len(ciphertext))
		aesctr := cipher.NewCTR(block, req.InitializationVector)
		aesctr.XORKeyStream(plaintext, ciphertext)
	case kmspb.CryptoKeyVersion_AES_128_CBC, kmspb.CryptoKeyVersion_AES_256_CBC:
		plaintext = make([]byte, len(ciphertext))
		aescbc := cipher.NewCBCDecrypter(block, req.InitializationVector)
		aescbc.CryptBlocks(plaintext, ciphertext)
	default:
		return nil, errInternal("unhandled algorithm")
	}

	return &kmspb.RawDecryptResponse{
		Plaintext:                plaintext,
		PlaintextCrc32C:          crc32c(plaintext),
		VerifiedCiphertextCrc32C: req.CiphertextCrc32C != nil,
		VerifiedAdditionalAuthenticatedDataCrc32C: req.AdditionalAuthenticatedDataCrc32C != nil,
		VerifiedInitializationVectorCrc32C:        req.InitializationVectorCrc32C != nil,
		ProtectionLevel:                           ckv.pb.ProtectionLevel,
	}, nil
}

// MacSign fakes a Cloud KMS API function.
func (f *fakeKMS) MacSign(ctx context.Context, req *kmspb.MacSignRequest) (*kmspb.MacSignResponse, error) {
	if err := allowlist("name", "data", "data_crc32c").check(req); err != nil {
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
	if def.Purpose != kmspb.CryptoKey_MAC {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for MAC signing",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	hash := def.Opts.(crypto.Hash)

	if req.Data == nil {
		return nil, errInvalidArgument("data is empty")
	}
	var data []byte = req.Data

	if len(data) > 64*1024 {
		return nil, errInvalidArgument("len(data)=%d, want len(data)<=%d", len(data), 64*1024)
	}

	dataChecksum := crc32c(data)
	if req.DataCrc32C != nil && dataChecksum.Value != req.DataCrc32C.Value {
		return nil, errInvalidArgument("invalid data checksum")
	}

	var key []byte
	var ok bool
	if key, ok = ckv.keyMaterial.([]byte); !ok {
		return nil, err
	}

	mac := hmac.New(hash.New, key)
	_, err = mac.Write(data)
	if err != nil {
		return nil, errInternal("MAC signing failed: %v", err)
	}
	macTag := mac.Sum(nil)

	return &kmspb.MacSignResponse{
		Name:               req.Name,
		Mac:                macTag,
		MacCrc32C:          crc32c(macTag),
		VerifiedDataCrc32C: req.DataCrc32C != nil,
		ProtectionLevel:    ckv.pb.ProtectionLevel,
	}, nil
}

// MacVerify fakes a Cloud KMS API function.
func (f *fakeKMS) MacVerify(ctx context.Context, req *kmspb.MacVerifyRequest) (*kmspb.MacVerifyResponse, error) {
	if err := allowlist("name", "data", "data_crc32c", "mac", "mac_crc32c").check(req); err != nil {
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
	if def.Purpose != kmspb.CryptoKey_MAC {
		return nil, errFailedPrecondition("keys with algorithm %s may not be used for MAC verification",
			nameForValue(kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm_name, int32(ckv.pb.Algorithm)))
	}

	if req.Data == nil {
		return nil, errInvalidArgument("data is empty")
	}
	var data []byte = req.Data

	if len(data) > 64*1024 {
		return nil, errInvalidArgument("len(data)=%d, want len(data)<=%d", len(data), 64*1024)
	}

	dataChecksum := crc32c(data)
	if req.DataCrc32C != nil && dataChecksum.Value != req.DataCrc32C.Value {
		return nil, errInvalidArgument("invalid data checksum")
	}

	hash := def.Opts.(crypto.Hash)

	if req.Mac == nil {
		return nil, errInvalidArgument("mac is empty")
	}

	if len(req.Mac) != hash.Size() {
		return nil, errInvalidArgument("len(mac)=%d, want %d", len(req.Mac), hash.Size())
	}

	macChecksum := crc32c(req.Mac)
	if req.MacCrc32C != nil && macChecksum.Value != req.MacCrc32C.Value {
		return nil, errInvalidArgument("invalid mac checksum")
	}

	var key []byte
	var ok bool
	if key, ok = ckv.keyMaterial.([]byte); !ok {
		return nil, err
	}

	mac := hmac.New(hash.New, key)
	_, err = mac.Write(data)
	if err != nil {
		return nil, errInternal("MAC signing failed: %v", err)
	}
	macTag := mac.Sum(nil)

	return &kmspb.MacVerifyResponse{
		Name:                     req.Name,
		Success:                  hmac.Equal(req.Mac, macTag),
		VerifiedSuccessIntegrity: hmac.Equal(req.Mac, macTag),
		VerifiedDataCrc32C:       req.DataCrc32C != nil,
		VerifiedMacCrc32C:        req.MacCrc32C != nil,
		ProtectionLevel:          ckv.pb.ProtectionLevel,
	}, nil
}
