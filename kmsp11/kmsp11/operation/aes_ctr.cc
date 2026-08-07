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

#include "kmsp11/operation/aes_ctr.h"

#include "absl/cleanup/cleanup.h"
#include "common/status_macros.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/object.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

constexpr size_t kIvBytes = 16;
constexpr size_t kIvBits = kIvBytes * 8;
constexpr size_t kMaxPlaintextBytes = 64 * 1024;
constexpr size_t kMaxCiphertextBytes = kMaxPlaintextBytes + 16;

// An implementation of EncrypterInterface that generates AES-CTR ciphertexts
// using Cloud KMS.
class AesCtrEncrypter : public EncrypterInterface {
 public:
  AesCtrEncrypter(std::shared_ptr<Object> object, absl::Span<const uint8_t> iv)
      : object_(object), iv_(iv.begin(), iv.end()) {}

  absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;
  absl::Status EncryptUpdate(KmsClient* client,
                             absl::Span<const uint8_t> plaintext_part) override;
  absl::StatusOr<absl::Span<const uint8_t>> EncryptFinal(
      KmsClient* client) override;

  virtual ~AesCtrEncrypter() {}

 private:
  absl::StatusOr<absl::Span<const uint8_t>> EncryptInternal(
      KmsClient* client, absl::Span<const uint8_t> plaintext);

  std::shared_ptr<Object> object_;
  const std::vector<uint8_t> iv_;
  std::optional<std::vector<uint8_t, ZeroDeallocator<uint8_t>>>
      plaintext_;  // for multi-part only
  std::vector<uint8_t> ciphertext_;
};

absl::StatusOr<absl::Span<const uint8_t>> AesCtrEncrypter::Encrypt(
    KmsClient* client, absl::Span<const uint8_t> plaintext) {
  if (plaintext_) {
    return FailedPreconditionError(
        "Encrypt cannot be used to terminate a multi-part encryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }
  return EncryptInternal(client, plaintext);
}

absl::Status AesCtrEncrypter::EncryptUpdate(
    KmsClient* client, absl::Span<const uint8_t> plaintext_part) {
  if (!plaintext_) {
    plaintext_.emplace();
  }

  if (plaintext_part.size() + plaintext_->size() > kMaxPlaintextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("plaintext length (%u bytes) exceeds maximum "
                        "allowed (%u bytes)",
                        plaintext_part.size() + plaintext_->size(),
                        kMaxPlaintextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  plaintext_->reserve(plaintext_->size() + plaintext_part.size());
  plaintext_->insert(plaintext_->end(), plaintext_part.begin(),
                     plaintext_part.end());

  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> AesCtrEncrypter::EncryptFinal(
    KmsClient* client) {
  if (!plaintext_) {
    return FailedPreconditionError(
        "EncryptUpdate needs to be called prior to terminating a multi-part "
        "encryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }
  return EncryptInternal(client, *plaintext_);
}

absl::StatusOr<absl::Span<const uint8_t>> AesCtrEncrypter::EncryptInternal(
    KmsClient* client, absl::Span<const uint8_t> plaintext) {
  if (plaintext.size() > kMaxPlaintextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "plaintext length (%d bytes) exceeds maximum allowed %d",
            plaintext.size(), kMaxPlaintextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  kms_v1::RawEncryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_plaintext(std::string(reinterpret_cast<const char*>(plaintext.data()),
                                plaintext.size()));
  req.set_initialization_vector(
      std::string(reinterpret_cast<const char*>(iv_.data()), iv_.size()));

  ASSIGN_OR_RETURN(kms_v1::RawEncryptResponse resp, client->RawEncrypt(req));

  if (req.initialization_vector() != resp.initialization_vector()) {
    return NewInternalError(
        "the IV returned by the server does not match user-supplied IV",
        SOURCE_LOCATION);
  }

  ciphertext_.resize(resp.ciphertext().size());
  std::copy_n(resp.ciphertext().begin(), resp.ciphertext().size(),
              ciphertext_.begin());

  return ciphertext_;
}

// An implementation of DecrypterInterface that decrypts AES-CTR ciphertexts
// using Cloud KMS.
class AesCtrDecrypter : public DecrypterInterface {
 public:
  AesCtrDecrypter(std::shared_ptr<Object> object, absl::Span<const uint8_t> iv)
      : object_(object), iv_(iv.begin(), iv.end()) {}

  absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;
  absl::Status DecryptUpdate(
      KmsClient* client, absl::Span<const uint8_t> ciphertext_part) override;
  absl::StatusOr<absl::Span<const uint8_t>> DecryptFinal(
      KmsClient* client) override;

  virtual ~AesCtrDecrypter() {}

 private:
  absl::StatusOr<absl::Span<const uint8_t>> DecryptInternal(
      KmsClient* client, absl::Span<const uint8_t> ciphertext);

  std::shared_ptr<Object> object_;
  const std::vector<uint8_t> iv_;
  std::optional<std::vector<uint8_t>> ciphertext_;  // for multi-part
  std::unique_ptr<std::string, ZeroDelete<std::string>> plaintext_;
};

absl::StatusOr<absl::Span<const uint8_t>> AesCtrDecrypter::Decrypt(
    KmsClient* client, absl::Span<const uint8_t> ciphertext) {
  if (ciphertext.size() > kMaxCiphertextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "ciphertext length (%d bytes) exceeds maximum allowed %d",
            ciphertext.size(), kMaxCiphertextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }
  return DecryptInternal(client, ciphertext);
}

absl::Status AesCtrDecrypter::DecryptUpdate(
    KmsClient* client, absl::Span<const uint8_t> ciphertext_part) {
  if (!ciphertext_) {
    ciphertext_.emplace();
  }

  if (ciphertext_part.size() + ciphertext_->size() > kMaxCiphertextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("ciphertext length (%d bytes) exceeds maximum "
                        "allowed (%d bytes)",
                        ciphertext_part.size() + ciphertext_->size(),
                        kMaxCiphertextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  ciphertext_->reserve(ciphertext_->size() + ciphertext_part.size());
  ciphertext_->insert(ciphertext_->end(), ciphertext_part.begin(),
                      ciphertext_part.end());

  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> AesCtrDecrypter::DecryptFinal(
    KmsClient* client) {
  if (!ciphertext_) {
    return FailedPreconditionError(
        "DecryptUpdate needs to be called prior to terminating a multi-part "
        "decryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }
  return DecryptInternal(client, *ciphertext_);
}

absl::StatusOr<absl::Span<const uint8_t>> AesCtrDecrypter::DecryptInternal(
    KmsClient* client, absl::Span<const uint8_t> ciphertext) {
  kms_v1::RawDecryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_ciphertext(std::string(
      reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()));
  req.set_initialization_vector(
      std::string(reinterpret_cast<const char*>(iv_.data()), iv_.size()));
  ASSIGN_OR_RETURN(kms_v1::RawDecryptResponse resp, client->RawDecrypt(req));

  plaintext_.reset(resp.release_plaintext());
  return absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(plaintext_->data()), plaintext_->size());
}

absl::StatusOr<absl::Span<const uint8_t>> ExtractIv(void* parameters,
                                                    CK_ULONG parameters_size) {
  if (parameters_size != sizeof(CK_AES_CTR_PARAMS)) {
    return InvalidMechanismParamError(
        "mechanism parameters must be of type CK_AES_CTR_PARAMS",
        SOURCE_LOCATION);
  }

  CK_AES_CTR_PARAMS* params = reinterpret_cast<CK_AES_CTR_PARAMS*>(parameters);

  if (params->ulCounterBits != kIvBits) {
    return InvalidMechanismParamError(
        absl::StrFormat("invalid number of counter block bits: got %u; want %u",
                        params->ulCounterBits, kIvBits),
        SOURCE_LOCATION);
  }

  return params->cb;
}

}  // namespace

absl::StatusOr<std::unique_ptr<EncrypterInterface>> NewAesCtrEncrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY,
                                        mechanism->mechanism, key.get()));

  switch (mechanism->mechanism) {
    case CKM_AES_CTR: {
      ASSIGN_OR_RETURN(
          absl::Span<const uint8_t> iv,
          ExtractIv(mechanism->pParameter, mechanism->ulParameterLen));
      return std::make_unique<AesCtrEncrypter>(key, iv);
    }
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES-CTR encryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<DecrypterInterface>> NewAesCtrDecrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY,
                                        mechanism->mechanism, key.get()));

  switch (mechanism->mechanism) {
    case CKM_AES_CTR: {
      ASSIGN_OR_RETURN(
          absl::Span<const uint8_t> iv,
          ExtractIv(mechanism->pParameter, mechanism->ulParameterLen));
      return std::make_unique<AesCtrDecrypter>(key, iv);
    }
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES-CTR decryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

}  // namespace cloud_kms::kmsp11
