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

#include "kmsp11/operation/aes_cbc.h"

#include "absl/cleanup/cleanup.h"
#include "common/status_macros.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/object.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/padding.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

// Enum representing the padding mode used by the specified mechanism.
enum class PaddingMode { kNone, kPkcs7 };

constexpr size_t kIvBytes = 16;
constexpr size_t kBlockSize = 16;
constexpr size_t kMaxPlaintextBytes = 64 * 1024;
constexpr size_t kMaxCiphertextBytes = kMaxPlaintextBytes + 16;

// An implementation of EncrypterInterface that generates AES-CBC ciphertexts
// using Cloud KMS.
class AesCbcEncrypter : public EncrypterInterface {
 public:
  AesCbcEncrypter(std::shared_ptr<Object> object, absl::Span<uint8_t> iv,
                  PaddingMode padding)
      : object_(object), iv_(iv.begin(), iv.end()), padding_mode_(padding) {}

  absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;
  absl::Status EncryptUpdate(KmsClient* client,
                             absl::Span<const uint8_t> plaintext_part) override;
  absl::StatusOr<absl::Span<const uint8_t>> EncryptFinal(
      KmsClient* client) override;

  virtual ~AesCbcEncrypter() {}

 private:
  absl::StatusOr<absl::Span<const uint8_t>> EncryptInternal(
      KmsClient* client, absl::Span<const uint8_t> plaintext);

  std::shared_ptr<Object> object_;
  std::vector<uint8_t> iv_;
  PaddingMode padding_mode_;
  std::optional<std::vector<uint8_t, ZeroDeallocator<uint8_t>>>
      plaintext_;  // for multi-part
  std::vector<uint8_t> ciphertext_;
};

absl::StatusOr<absl::Span<const uint8_t>> AesCbcEncrypter::Encrypt(
    KmsClient* client, absl::Span<const uint8_t> plaintext) {
  if (plaintext_) {
    return FailedPreconditionError(
        "Encrypt cannot be used to terminate a multi-part encryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  if (plaintext.size() > kMaxPlaintextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "plaintext length (%d bytes) exceeds maximum allowed %d",
            plaintext.size(), kMaxPlaintextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  return EncryptInternal(client, plaintext);
}

absl::Status AesCbcEncrypter::EncryptUpdate(
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

absl::StatusOr<absl::Span<const uint8_t>> AesCbcEncrypter::EncryptFinal(
    KmsClient* client) {
  if (!plaintext_) {
    return FailedPreconditionError(
        "EncryptUpdate needs to be called prior to terminating a multi-part "
        "encryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  return EncryptInternal(client, *plaintext_);
}

absl::StatusOr<absl::Span<const uint8_t>> AesCbcEncrypter::EncryptInternal(
    KmsClient* client, absl::Span<const uint8_t> plaintext) {
  if (padding_mode_ == PaddingMode::kNone &&
      plaintext.size() % kBlockSize != 0) {
    return NewInvalidArgumentError(
        absl::StrFormat("plaintext length (%u bytes) should be a multiple of "
                        "the block size (%u bytes)",
                        plaintext.size(), kBlockSize),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  kms_v1::RawEncryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  std::vector<uint8_t> padded_plaintext;
  switch (padding_mode_) {
    case PaddingMode::kPkcs7:
      padded_plaintext = Pad(plaintext);
      req.set_plaintext(
          std::string(reinterpret_cast<const char*>(padded_plaintext.data()),
                      padded_plaintext.size()));
      break;
    case PaddingMode::kNone:
      req.set_plaintext(std::string(
          reinterpret_cast<const char*>(plaintext.data()), plaintext.size()));
      break;
    default:
      return NewInternalError("unsupported padding mode", SOURCE_LOCATION);
  }

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

// An implementation of DecrypterInterface that decrypts AES-CBC ciphertexts
// using Cloud KMS.
class AesCbcDecrypter : public DecrypterInterface {
 public:
  AesCbcDecrypter(std::shared_ptr<Object> object, absl::Span<uint8_t> iv,
                  PaddingMode padding)
      : object_(object), iv_(iv.begin(), iv.end()), padding_mode_(padding) {}

  absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;
  absl::Status DecryptUpdate(
      KmsClient* client, absl::Span<const uint8_t> ciphertext_part) override;
  absl::StatusOr<absl::Span<const uint8_t>> DecryptFinal(
      KmsClient* client) override;

  virtual ~AesCbcDecrypter() {}

 private:
  absl::StatusOr<absl::Span<const uint8_t>> DecryptInternal(
      KmsClient* client, absl::Span<const uint8_t> ciphertext);

  std::shared_ptr<Object> object_;
  std::vector<uint8_t> iv_;
  PaddingMode padding_mode_;
  std::optional<std::vector<uint8_t>> ciphertext_;  // for multi-part
  std::unique_ptr<std::string, ZeroDelete<std::string>> plaintext_;
};

absl::StatusOr<absl::Span<const uint8_t>> AesCbcDecrypter::Decrypt(
    KmsClient* client, absl::Span<const uint8_t> ciphertext) {
  if (ciphertext.size() > kMaxCiphertextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "ciphertext length (%u bytes) exceeds maximum allowed %u",
            ciphertext.size(), kMaxCiphertextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  return DecryptInternal(client, ciphertext);
}

absl::Status AesCbcDecrypter::DecryptUpdate(
    KmsClient* client, absl::Span<const uint8_t> ciphertext_part) {
  if (!ciphertext_) {
    ciphertext_.emplace();
  }

  if (ciphertext_part.size() + ciphertext_->size() > kMaxCiphertextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("ciphertext length (%u bytes) exceeds maximum "
                        "allowed (%u bytes)",
                        ciphertext_part.size() + ciphertext_->size(),
                        kMaxCiphertextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  ciphertext_->reserve(ciphertext_->size() + ciphertext_part.size());
  ciphertext_->insert(ciphertext_->end(), ciphertext_part.begin(),
                      ciphertext_part.end());

  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> AesCbcDecrypter::DecryptFinal(
    KmsClient* client) {
  if (!ciphertext_) {
    return FailedPreconditionError(
        "DecryptUpdate needs to be called prior to terminating a multi-part "
        "decryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  return DecryptInternal(client, *ciphertext_);
}

absl::StatusOr<absl::Span<const uint8_t>> AesCbcDecrypter::DecryptInternal(
    KmsClient* client, absl::Span<const uint8_t> ciphertext) {
  kms_v1::RawDecryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_ciphertext(std::string(
      reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()));
  req.set_initialization_vector(
      std::string(reinterpret_cast<const char*>(iv_.data()), iv_.size()));

  ASSIGN_OR_RETURN(kms_v1::RawDecryptResponse resp, client->RawDecrypt(req));

  plaintext_.reset(resp.release_plaintext());
  absl::Span<const uint8_t> full_plaintext(
      reinterpret_cast<const uint8_t*>(plaintext_->data()), plaintext_->size());

  switch (padding_mode_) {
    case PaddingMode::kNone:
      return full_plaintext;
    case PaddingMode::kPkcs7:
      return Unpad(full_plaintext);
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<EncrypterInterface>> NewAesCbcEncrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY,
                                        mechanism->mechanism, key.get()));
  if (!mechanism->pParameter || mechanism->ulParameterLen != kIvBytes) {
    return InvalidMechanismParamError(
        absl::StrFormat("the initialization vector must be %u bytes long",
                        kIvBytes),
        SOURCE_LOCATION);
  }

  CK_BYTE* iv;
  switch (mechanism->mechanism) {
    case CKM_AES_CBC:
      iv = reinterpret_cast<CK_BYTE*>(mechanism->pParameter);
      return std::make_unique<AesCbcEncrypter>(
          key, absl::MakeSpan(iv, mechanism->ulParameterLen),
          PaddingMode::kNone);
    case CKM_AES_CBC_PAD:
      iv = reinterpret_cast<CK_BYTE*>(mechanism->pParameter);
      return std::make_unique<AesCbcEncrypter>(
          key, absl::MakeSpan(iv, mechanism->ulParameterLen),
          PaddingMode::kPkcs7);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES-CBC encryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<DecrypterInterface>> NewAesCbcDecrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY,
                                        mechanism->mechanism, key.get()));
  if (!mechanism->pParameter || mechanism->ulParameterLen != kIvBytes) {
    return InvalidMechanismParamError(
        absl::StrFormat("the initialization vector must be %u bytes long",
                        kIvBytes),
        SOURCE_LOCATION);
  }

  CK_BYTE* iv = reinterpret_cast<CK_BYTE*>(mechanism->pParameter);
  switch (mechanism->mechanism) {
    case CKM_AES_CBC:
      return std::make_unique<AesCbcDecrypter>(
          key, absl::MakeSpan(iv, mechanism->ulParameterLen),
          PaddingMode::kNone);
    case CKM_AES_CBC_PAD:
      return std::make_unique<AesCbcDecrypter>(
          key, absl::MakeSpan(iv, mechanism->ulParameterLen),
          PaddingMode::kPkcs7);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES-CBC decryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

}  // namespace cloud_kms::kmsp11
