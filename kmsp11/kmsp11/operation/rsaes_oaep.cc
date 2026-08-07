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

#include "kmsp11/operation/rsaes_oaep.h"

#include "absl/cleanup/cleanup.h"
#include "common/status_macros.h"
#include "kmsp11/object.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {

namespace {

// An implementation of EncrypterInterface that encrypts RSAES-OAEP ciphertexts
// using BoringSSL.
class RsaOaepEncrypter : public EncrypterInterface {
 public:
  RsaOaepEncrypter(std::shared_ptr<Object> object,
                   bssl::UniquePtr<EVP_PKEY> key)
      : object_(object),
        key_(std::move(key)),
        ciphertext_(object->algorithm().key_bit_length / 8) {}

  // Encrypt returns a span whose underlying bytes are bound to the lifetime of
  // this encrypter.
  absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;

  virtual ~RsaOaepEncrypter() {}

 private:
  std::shared_ptr<Object> object_;
  bssl::UniquePtr<EVP_PKEY> key_;
  std::vector<uint8_t> ciphertext_;
};

absl::StatusOr<absl::Span<const uint8_t>> RsaOaepEncrypter::Encrypt(
    KmsClient* client, absl::Span<const uint8_t> plaintext) {
  ASSIGN_OR_RETURN(const EVP_MD* digest,
                   DigestForMechanism(*object_->algorithm().digest_mechanism));
  RETURN_IF_ERROR(EncryptRsaOaep(key_.get(), digest, plaintext,
                                 absl::MakeSpan(ciphertext_)));
  return absl::MakeConstSpan(ciphertext_);
}

// An implementation of DecrypterInterface that decrypts RSAES-OAEP ciphertexts
// using Cloud KMS.
class RsaOaepDecrypter : public DecrypterInterface {
 public:
  RsaOaepDecrypter(std::shared_ptr<Object> key) : key_(key) {}

  // Decrypt returns a span whose underlying bytes are bound to the lifetime of
  // this decrypter.
  absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;

  virtual ~RsaOaepDecrypter() {}

 private:
  std::shared_ptr<Object> key_;
  std::unique_ptr<std::string, ZeroDelete<std::string>> plaintext_;
};

absl::StatusOr<absl::Span<const uint8_t>> RsaOaepDecrypter::Decrypt(
    KmsClient* client, absl::Span<const uint8_t> ciphertext) {
  size_t expected_size = key_->algorithm().key_bit_length / 8;
  if (ciphertext.size() != expected_size) {
    return NewInvalidArgumentError(
        absl::StrFormat("ciphertext size mismatch (got %d, want %d)",
                        ciphertext.size(), expected_size),
        CKR_ENCRYPTED_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  kms_v1::AsymmetricDecryptRequest req;
  req.set_name(std::string(key_->kms_key_name()));
  req.set_ciphertext(ciphertext.data(), ciphertext.size());

  absl::StatusOr<kms_v1::AsymmetricDecryptResponse> resp =
      client->AsymmetricDecrypt(req);
  if (!resp.ok()) {
    switch (resp.status().code()) {
      case absl::StatusCode::kInvalidArgument:
        // A nice enhancement would be to consider if there is a clearer way for
        // KMS to specify that it's the ciphertext that's invalid (and not
        // something else).
        return NewInvalidArgumentError(resp.status().message(),
                                       CKR_ENCRYPTED_DATA_INVALID,
                                       SOURCE_LOCATION);
      default:
        return NewError(resp.status().code(), resp.status().message(),
                        CKR_DEVICE_ERROR, SOURCE_LOCATION);
    }
  }

  plaintext_.reset(resp->release_plaintext());
  return absl::MakeConstSpan(reinterpret_cast<uint8_t*>(plaintext_->data()),
                             plaintext_->size());
}

absl::Status ValidateRsaOaepParameters(Object* key, void* parameters,
                                       CK_ULONG parameters_size) {
  if (parameters_size != sizeof(CK_RSA_PKCS_OAEP_PARAMS)) {
    return InvalidMechanismParamError(
        "mechanism parameters must be of type CK_RSA_PKCS_OAEP_PARAMS",
        SOURCE_LOCATION);
  }
  CK_RSA_PKCS_OAEP_PARAMS* params =
      static_cast<CK_RSA_PKCS_OAEP_PARAMS*>(parameters);

  ASSIGN_OR_RETURN(const EVP_MD* digest,
                   DigestForMechanism(*key->algorithm().digest_mechanism));
  RETURN_IF_ERROR(EnsureHashMatches(params->hashAlg, digest));
  RETURN_IF_ERROR(EnsureMgf1HashMatches(params->mgf, digest));

  switch (params->source) {
    case 0:  // For compatibility. See b/217419373.
    case CKZ_DATA_SPECIFIED:
      break;
    default:
      return InvalidMechanismParamError(
          "source for OAEP must be 0 or CKZ_DATA_SPECIFIED", SOURCE_LOCATION);
  }
  if (params->pSourceData != nullptr || params->ulSourceDataLen != 0) {
    return InvalidMechanismParamError("OAEP labels are not supported",
                                      SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<std::unique_ptr<EncrypterInterface>> NewRsaOaepEncrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_RSA, CKO_PUBLIC_KEY,
                                        CKM_RSA_PKCS_OAEP, key.get()));
  RETURN_IF_ERROR(ValidateRsaOaepParameters(key.get(), mechanism->pParameter,
                                            mechanism->ulParameterLen));

  ASSIGN_OR_RETURN(std::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::make_unique<RsaOaepEncrypter>(key, std::move(parsed_key));
}

absl::StatusOr<std::unique_ptr<DecrypterInterface>> NewRsaOaepDecrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY,
                                        CKM_RSA_PKCS_OAEP, key.get()));
  RETURN_IF_ERROR(ValidateRsaOaepParameters(key.get(), mechanism->pParameter,
                                            mechanism->ulParameterLen));
  return std::make_unique<RsaOaepDecrypter>(key);
}

}  // namespace cloud_kms::kmsp11
