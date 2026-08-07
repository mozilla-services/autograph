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

#include "kmsp11/operation/hmac.h"

#include <string_view>

#include "common/openssl.h"
#include "common/status_macros.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {
namespace {

constexpr size_t kMaxMacDataBytes = 64 * 1024;

// A SignerInterface implementation that makes HMAC signatures using Cloud KMS.
class HmacSigner : public SignerInterface {
 public:
  HmacSigner(std::shared_ptr<Object> object, size_t signature_length)
      : signature_length_(signature_length), object_(object) {}

  size_t signature_length() override { return signature_length_; };
  Object* object() override { return object_.get(); };

  absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> data,
                    absl::Span<uint8_t> signature) override;
  absl::Status SignUpdate(KmsClient* client,
                          absl::Span<const uint8_t> data) override;
  absl::Status SignFinal(KmsClient* client,
                         absl::Span<uint8_t> signature) override;

  virtual ~HmacSigner() {}

 private:
  absl::Status SignInternal(KmsClient* client, absl::Span<const uint8_t> data,
                            absl::Span<uint8_t> signature);

  const size_t signature_length_;
  std::shared_ptr<Object> object_;
  std::optional<std::vector<uint8_t>> buffer_;
};

absl::Status HmacSigner::Sign(KmsClient* client, absl::Span<const uint8_t> data,
                              absl::Span<uint8_t> signature) {
  if (buffer_) {
    return FailedPreconditionError(
        "Sign cannot be used to terminate a multi-part signing operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  if (data.size() > kMaxMacDataBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("data length (%d bytes) exceeds maximum allowed %d",
                        data.size(), kMaxMacDataBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat(
            "provided signature buffer has incorrect size (got %d, want %d)",
            signature.size(), signature_length()),
        SOURCE_LOCATION);
  }

  return SignInternal(client, data, signature);
}

absl::Status HmacSigner::SignUpdate(KmsClient* client,
                                            absl::Span<const uint8_t> data) {
  if (!buffer_) {
    buffer_.emplace();
  }

  if (data.size() + buffer_->size() > kMaxMacDataBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "data length (%d bytes) exceeds maximum allowed (%d bytes)",
            data.size() + buffer_->size(), kMaxMacDataBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  buffer_->reserve(buffer_->size() + data.size());
  buffer_->insert(buffer_->end(), data.begin(), data.end());

  return absl::OkStatus();
}

absl::Status HmacSigner::SignFinal(KmsClient* client,
                                   absl::Span<uint8_t> signature) {
  if (!buffer_) {
    return FailedPreconditionError(
        "SignUpdate needs to be called prior to terminating a multi-part "
        "signing operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  if (signature.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat(
            "provided signature buffer has incorrect size (got %d, want %d)",
            signature.size(), signature_length()),
        SOURCE_LOCATION);
  }

  return SignInternal(client, *buffer_, signature);
}

absl::Status HmacSigner::SignInternal(KmsClient* client,
                                      absl::Span<const uint8_t> data,
                                      absl::Span<uint8_t> signature) {
  kms_v1::MacSignRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_data(
      std::string(reinterpret_cast<const char*>(data.data()), data.size()));

  ASSIGN_OR_RETURN(kms_v1::MacSignResponse resp, client->MacSign(req));
  std::copy(resp.mac().begin(), resp.mac().end(), signature.begin());
  return absl::OkStatus();
}

// A VerifierInterface implementation that verifies HMAC signatures using Cloud
// KMS.
class HmacVerifier : public VerifierInterface {
 public:
  HmacVerifier(std::shared_ptr<Object> object, size_t signature_length)
      : object_(object), signature_length_(signature_length) {}

  size_t signature_length() { return signature_length_; };
  Object* object() override { return object_.get(); };

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> data,
                      absl::Span<const uint8_t> signature) override;
  absl::Status VerifyUpdate(KmsClient* client,
                            absl::Span<const uint8_t> data) override;
  absl::Status VerifyFinal(KmsClient* client,
                           absl::Span<const uint8_t> signature) override;

  virtual ~HmacVerifier() {}

 private:
  absl::Status VerifyInternal(KmsClient* client, absl::Span<const uint8_t> data,
                              absl::Span<const uint8_t> signature);

  std::shared_ptr<Object> object_;
  const size_t signature_length_;
  std::optional<std::vector<uint8_t>> buffer_;
};

absl::Status HmacVerifier::Verify(KmsClient* client,
                                  absl::Span<const uint8_t> data,
                                  absl::Span<const uint8_t> signature) {
  if (buffer_) {
    return FailedPreconditionError(
        "Verify cannot be used to terminate a multi-part verification "
        "operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  if (data.size() > kMaxMacDataBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("data length (%d bytes) exceeds maximum allowed %d",
                        data.size(), kMaxMacDataBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat(
            "provided signature has incorrect size (got %d, want %d)",
            signature.size(), signature_length()),
        SOURCE_LOCATION);
  }

  return VerifyInternal(client, data, signature);
}

absl::Status HmacVerifier::VerifyUpdate(KmsClient* client,
                                        absl::Span<const uint8_t> data) {
  if (!buffer_) {
    buffer_.emplace();
  }

  if (data.size() + buffer_->size() > kMaxMacDataBytes) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "data length (%d bytes) exceeds maximum allowed (%d bytes)",
            data.size() + buffer_->size(), kMaxMacDataBytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  buffer_->reserve(buffer_->size() + data.size());
  buffer_->insert(buffer_->end(), data.begin(), data.end());

  return absl::OkStatus();
}

absl::Status HmacVerifier::VerifyFinal(KmsClient* client,
                                       absl::Span<const uint8_t> signature) {
  if (!buffer_) {
    return FailedPreconditionError(
        "VerifyUpdate needs to be called prior to terminating a multi-part "
        "verification operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  if (signature.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat(
            "provided signature has incorrect size (got %d, want %d)",
            signature.size(), signature_length()),
        SOURCE_LOCATION);
  }

  return VerifyInternal(client, *buffer_, signature);
}

absl::Status HmacVerifier::VerifyInternal(KmsClient* client,
                                          absl::Span<const uint8_t> data,
                                          absl::Span<const uint8_t> signature) {
  kms_v1::MacVerifyRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_data(
      std::string(reinterpret_cast<const char*>(data.data()), data.size()));
  req.set_mac(std::string(reinterpret_cast<const char*>(signature.data()),
                          signature.size()));

  ASSIGN_OR_RETURN(kms_v1::MacVerifyResponse resp, client->MacVerify(req));
  if (!resp.success()) {
    return NewInvalidArgumentError("HMAC verification failed",
                                   CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }
  return absl::OkStatus();
}

absl::StatusOr<CK_KEY_TYPE> KeyTypeForMechanism(const CK_MECHANISM* mechanism) {
  switch (mechanism->mechanism) {
    case CKM_SHA_1_HMAC:
      return CKK_SHA_1_HMAC;
    case CKM_SHA224_HMAC:
      return CKK_SHA224_HMAC;
    case CKM_SHA256_HMAC:
      return CKK_SHA256_HMAC;
    case CKM_SHA384_HMAC:
      return CKK_SHA384_HMAC;
    case CKM_SHA512_HMAC:
      return CKK_SHA512_HMAC;
    default:
      return NewInternalError(
          absl::StrFormat("Cannot get CK_KEY_TYPE for mechanism %#x",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

}  // namespace

absl::StatusOr<std::unique_ptr<SignerInterface>> NewHmacSigner(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  ASSIGN_OR_RETURN(CK_KEY_TYPE key_type, KeyTypeForMechanism(mechanism));
  RETURN_IF_ERROR(CheckKeyPreconditions(key_type, CKO_SECRET_KEY,
                                        mechanism->mechanism, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  switch (mechanism->mechanism) {
    case CKM_SHA_1_HMAC:
      return std::make_unique<HmacSigner>(key, 20);
    case CKM_SHA224_HMAC:
      return std::make_unique<HmacSigner>(key, 28);
    case CKM_SHA256_HMAC:
      return std::make_unique<HmacSigner>(key, 32);
    case CKM_SHA384_HMAC:
      return std::make_unique<HmacSigner>(key, 48);
    case CKM_SHA512_HMAC:
      return std::make_unique<HmacSigner>(key, 64);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for HMAC signing",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<VerifierInterface>> NewHmacVerifier(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  ASSIGN_OR_RETURN(CK_KEY_TYPE key_type, KeyTypeForMechanism(mechanism));
  RETURN_IF_ERROR(CheckKeyPreconditions(key_type, CKO_SECRET_KEY,
                                        mechanism->mechanism, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  switch (mechanism->mechanism) {
    case CKM_SHA_1_HMAC:
      return std::make_unique<HmacVerifier>(key, 20);
    case CKM_SHA224_HMAC:
      return std::make_unique<HmacVerifier>(key, 28);
    case CKM_SHA256_HMAC:
      return std::make_unique<HmacVerifier>(key, 32);
    case CKM_SHA384_HMAC:
      return std::make_unique<HmacVerifier>(key, 48);
    case CKM_SHA512_HMAC:
      return std::make_unique<HmacVerifier>(key, 64);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for HMAC verification",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

}  // namespace cloud_kms::kmsp11
