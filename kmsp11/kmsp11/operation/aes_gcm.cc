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

#include "kmsp11/operation/aes_gcm.h"

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

constexpr size_t kIvBytes = 12;
constexpr size_t kIvBits = kIvBytes * 8;
constexpr size_t kTagBits = 128;
constexpr size_t kMaxPlaintextBytes = 64 * 1024;
constexpr size_t kMaxCiphertextBytes = kMaxPlaintextBytes + 16;

// An implementation of EncrypterInterface that generates AES-GCM ciphertexts
// using Cloud KMS.
class AesGcmEncrypter : public EncrypterInterface {
 public:
  AesGcmEncrypter(std::shared_ptr<Object> object, absl::Span<const uint8_t> aad,
                  absl::Span<uint8_t> iv)
      : object_(object),
        iv_(iv),
        aad_(reinterpret_cast<const char*>(aad.data()), aad.size()) {}

  absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;
  absl::Status EncryptUpdate(KmsClient* client,
                             absl::Span<const uint8_t> plaintext_part) override;
  absl::StatusOr<absl::Span<const uint8_t>> EncryptFinal(
      KmsClient* client) override;

  virtual ~AesGcmEncrypter() {}

 private:
  absl::StatusOr<absl::Span<const uint8_t>> EncryptInternal(
      KmsClient* client, absl::Span<const uint8_t> plaintext);

  std::shared_ptr<Object> object_;
  absl::Span<uint8_t> iv_;
  std::string aad_;
  std::optional<std::vector<uint8_t, ZeroDeallocator<uint8_t>>>
      plaintext_;  // for multi-part only
  std::vector<uint8_t> ciphertext_;
};

absl::StatusOr<absl::Span<const uint8_t>> AesGcmEncrypter::Encrypt(
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

absl::Status AesGcmEncrypter::EncryptUpdate(
    KmsClient* client, absl::Span<const uint8_t> plaintext_part) {
  if (!plaintext_) {
    plaintext_.emplace();
  }

  if (plaintext_part.size() + plaintext_->size() > kMaxPlaintextBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("plaintext length (%d bytes) exceeds maximum "
                        "allowed (%d bytes)",
                        plaintext_part.size() + plaintext_->size(),
                        kMaxPlaintextBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  plaintext_->reserve(plaintext_->size() + plaintext_part.size());
  plaintext_->insert(plaintext_->end(), plaintext_part.begin(),
                     plaintext_part.end());

  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> AesGcmEncrypter::EncryptFinal(
    KmsClient* client) {
  if (!plaintext_) {
    return FailedPreconditionError(
        "EncryptUpdate needs to be called prior to terminating a multi-part "
        "encryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  return EncryptInternal(client, *plaintext_);
}

absl::StatusOr<absl::Span<const uint8_t>> AesGcmEncrypter::EncryptInternal(
    KmsClient* client, absl::Span<const uint8_t> plaintext) {
  kms_v1::RawEncryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_plaintext(std::string(reinterpret_cast<const char*>(plaintext.data()),
                                plaintext.size()));
  req.set_additional_authenticated_data(aad_);

  ASSIGN_OR_RETURN(kms_v1::RawEncryptResponse resp, client->RawEncrypt(req));

  std::copy_n(resp.initialization_vector().begin(),
              resp.initialization_vector().size(), iv_.begin());

  ciphertext_.resize(resp.ciphertext().size());
  std::copy_n(resp.ciphertext().begin(), resp.ciphertext().size(),
              ciphertext_.begin());

  return ciphertext_;
}

// An implementation of DecrypterInterface that decrypts AES-GCM ciphertexts
// using Cloud KMS.
class AesGcmDecrypter : public DecrypterInterface {
 public:
  AesGcmDecrypter(std::shared_ptr<Object> object, absl::Span<const uint8_t> iv,
                  absl::Span<const uint8_t> aad)
      : object_(object),
        iv_(iv.begin(), iv.end()),
        aad_(reinterpret_cast<const char*>(aad.data()), aad.size()) {}

  absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
      KmsClient* client, absl::Span<const uint8_t> ciphertext) override;
  absl::Status DecryptUpdate(
      KmsClient* client, absl::Span<const uint8_t> ciphertext_part) override;
  absl::StatusOr<absl::Span<const uint8_t>> DecryptFinal(
      KmsClient* client) override;

  virtual ~AesGcmDecrypter() {}

 private:
  absl::StatusOr<absl::Span<const uint8_t>> DecryptInternal(
      KmsClient* client, absl::Span<const uint8_t> ciphertext);

  std::shared_ptr<Object> object_;
  std::vector<uint8_t> iv_;
  std::string aad_;
  std::optional<std::vector<uint8_t>> ciphertext_;
  std::unique_ptr<std::string, ZeroDelete<std::string>> plaintext_;
};

absl::StatusOr<absl::Span<const uint8_t>> AesGcmDecrypter::Decrypt(
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

absl::Status AesGcmDecrypter::DecryptUpdate(
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

absl::StatusOr<absl::Span<const uint8_t>> AesGcmDecrypter::DecryptFinal(
    KmsClient* client) {
  if (!ciphertext_) {
    return FailedPreconditionError(
        "DecryptUpdate needs to be called prior to terminating a multi-part "
        "decryption operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  return DecryptInternal(client, *ciphertext_);
}

absl::StatusOr<absl::Span<const uint8_t>> AesGcmDecrypter::DecryptInternal(
    KmsClient* client, absl::Span<const uint8_t> ciphertext) {
  kms_v1::RawDecryptRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_ciphertext(std::string(
      reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size()));
  req.set_initialization_vector(reinterpret_cast<const char*>(iv_.data()),
                                iv_.size());
  req.set_additional_authenticated_data(aad_);

  ASSIGN_OR_RETURN(kms_v1::RawDecryptResponse resp, client->RawDecrypt(req));

  plaintext_.reset(resp.release_plaintext());
  return absl::MakeConstSpan(
      reinterpret_cast<const uint8_t*>(plaintext_->data()), plaintext_->size());
}

absl::StatusOr<CK_GCM_PARAMS> ExtractGcmParameters(void* parameters,
                                                   CK_ULONG parameters_size) {
  if (parameters_size != sizeof(CK_GCM_PARAMS)) {
    return InvalidMechanismParamError(
        "mechanism parameters must be of type CK_GCM_PARAMS", SOURCE_LOCATION);
  }

  CK_GCM_PARAMS params = *reinterpret_cast<CK_GCM_PARAMS*>(parameters);

  if (!params.pIv) {
    return InvalidMechanismParamError(
        "missing pIv param, which should point to a zero-initialized 12-byte "
        "buffer",
        SOURCE_LOCATION);
  }
  if (params.ulIvLen != kIvBytes || params.ulIvBits != kIvBits) {
    return InvalidMechanismParamError(
        absl::StrFormat("the only supported IV length is the default %u bytes",
                        kIvBytes),
        SOURCE_LOCATION);
  }
  if (params.ulAADLen != 0 && !params.pAAD) {
    return InvalidMechanismParamError(
        "AAD length specified but the AAD pointer is invalid", SOURCE_LOCATION);
  }
  if (params.ulTagBits != kTagBits) {
    return InvalidMechanismParamError(
        absl::StrFormat("the only supported tag length is the default %u bits",
                        kTagBits),
        SOURCE_LOCATION);
  }

  return params;
}

}  // namespace

absl::StatusOr<std::unique_ptr<EncrypterInterface>> NewAesGcmEncrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY,
                                        mechanism->mechanism, key.get()));

  switch (mechanism->mechanism) {
    case CKM_CLOUDKMS_AES_GCM: {
      ASSIGN_OR_RETURN(CK_GCM_PARAMS params,
                       ExtractGcmParameters(mechanism->pParameter,
                                            mechanism->ulParameterLen));
      // For encryption only, pIv should be zero-initialized.
      if (!IsZeroInitialized(absl::MakeConstSpan(params.pIv, params.ulIvLen))) {
        return InvalidMechanismParamError(
            absl::StrFormat("the pIv param should point to a zero-initialized "
                            "%u-byte buffer",
                            kIvBytes),
            SOURCE_LOCATION);
      }
      return std::make_unique<AesGcmEncrypter>(
          key, absl::MakeConstSpan(params.pAAD, params.ulAADLen),
          absl::MakeSpan(params.pIv, params.ulIvLen));
    }
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES-GCM encryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<DecrypterInterface>> NewAesGcmDecrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_AES, CKO_SECRET_KEY,
                                        mechanism->mechanism, key.get()));

  switch (mechanism->mechanism) {
    case CKM_CLOUDKMS_AES_GCM: {
      ASSIGN_OR_RETURN(CK_GCM_PARAMS params,
                       ExtractGcmParameters(mechanism->pParameter,
                                            mechanism->ulParameterLen));
      return std::make_unique<AesGcmDecrypter>(
          key, absl::MakeConstSpan(params.pIv, params.ulIvLen),
          absl::MakeConstSpan(params.pAAD, params.ulAADLen));
    }
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for AES-GCM decryption",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

}  // namespace cloud_kms::kmsp11
