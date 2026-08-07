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

#include "kmsp11/session.h"

#include <regex>

#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_join.h"
#include "common/kms_client.h"
#include "common/status_macros.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {
namespace {

absl::Status SessionReadOnlyError(const SourceLocation& source_location) {
  return NewError(absl::StatusCode::kFailedPrecondition, "session is read-only",
                  CKR_SESSION_READ_ONLY, source_location);
}

struct KeyGenerationParams {
  std::string label;
  AlgorithmDetails algorithm;
  std::optional<kms_v1::ProtectionLevel> protection_level;
  std::optional<std::string> crypto_key_backend;
};

absl::StatusOr<KeyGenerationParams> ExtractKeyGenerationParams(
    absl::Span<const CK_ATTRIBUTE> prv_template, bool allow_software_keys) {
  std::optional<std::string> label;
  std::optional<kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm> algorithm;
  std::optional<kms_v1::ProtectionLevel> protection_level;
  std::optional<std::string> crypto_key_backend;

  for (const CK_ATTRIBUTE& attr : prv_template) {
    switch (attr.type) {
      case CKA_LABEL:
        label =
            std::string(reinterpret_cast<char*>(attr.pValue), attr.ulValueLen);
        static std::regex* label_regexp = new std::regex("[a-zA-Z0-9_-]{1,63}");
        if (!std::regex_match(*label, *label_regexp)) {
          return NewInvalidArgumentError(
              "CKA_LABEL must be a valid Cloud KMS CryptoKey ID",
              CKR_ATTRIBUTE_VALUE_INVALID, SOURCE_LOCATION);
        }

        break;
      case CKA_KMS_ALGORITHM:
        if (attr.ulValueLen != sizeof(CK_ULONG)) {
          return NewInvalidArgumentError(
              absl::StrFormat("CKA_KMS_ALGORITHM value should be CK_ULONG "
                              "(size=%d, got=%d)",
                              sizeof(CK_ULONG), attr.ulValueLen),
              CKR_ATTRIBUTE_VALUE_INVALID, SOURCE_LOCATION);
        }
        algorithm = kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm(
            *static_cast<CK_ULONG*>(attr.pValue));
        break;
      case CKA_KMS_PROTECTION_LEVEL:
        if (attr.ulValueLen != sizeof(CK_ULONG)) {
          return NewInvalidArgumentError(
              absl::StrFormat(
                  "CKA_KMS_PROTECTION_LEVEL value should be CK_ULONG "
                  "(size=%d, got=%d)",
                  sizeof(CK_ULONG), attr.ulValueLen),
              CKR_ATTRIBUTE_VALUE_INVALID, SOURCE_LOCATION);
        }
        protection_level =
            kms_v1::ProtectionLevel(*static_cast<CK_ULONG*>(attr.pValue));
        if (protection_level != kms_v1::SOFTWARE &&
            protection_level != kms_v1::HSM &&
            protection_level != kms_v1::HSM_SINGLE_TENANT) {
          return NewInvalidArgumentError(
              absl::StrFormat("CKA_KMS_PROTECTION_LEVEL value should be "
                              "1(SOFTWARE), 2(HSM), or 5(HSM_SINGLE_TENANT)"
                              ", got=%d",
                              attr.ulValueLen),
              CKR_ATTRIBUTE_VALUE_INVALID, SOURCE_LOCATION);
        }
        if (protection_level == kms_v1::SOFTWARE && !allow_software_keys) {
          return NewInvalidArgumentError(
              "CKA_KMS_PROTECTION_LEVEL cannot be SOFTWARE because only keys "
              "with protection level = HSM are "
              "allowed. If you want to be able to create software keys, use "
              "allow_software_keys in the "
              "configuration.",
              CKR_ATTRIBUTE_VALUE_INVALID, SOURCE_LOCATION);
        }
        break;
      case CKA_KMS_CRYPTO_KEY_BACKEND:
        crypto_key_backend =
            std::string(reinterpret_cast<char*>(attr.pValue), attr.ulValueLen);
        break;
      default:
        return NewInvalidArgumentError(
            absl::StrFormat(
                "this token does not permit specifying attribute type %#x",
                attr.type),
            CKR_TEMPLATE_INCONSISTENT, SOURCE_LOCATION);
    }
  }

  if (!label.has_value()) {
    return NewInvalidArgumentError("CKA_LABEL must be specified for the key",
                                   CKR_TEMPLATE_INCOMPLETE, SOURCE_LOCATION);
  }
  if (!algorithm.has_value()) {
    return NewInvalidArgumentError(
        "CKA_KMS_ALGORITHM must be specified for the key",
        CKR_TEMPLATE_INCOMPLETE, SOURCE_LOCATION);
  }

  absl::StatusOr<AlgorithmDetails> algorithm_details = GetDetails(*algorithm);
  if (!algorithm_details.ok()) {
    return NewInvalidArgumentError(algorithm_details.status().message(),
                                   CKR_ATTRIBUTE_VALUE_INVALID,
                                   SOURCE_LOCATION);
  }

  if (protection_level.has_value() &&
      protection_level == kms_v1::HSM_SINGLE_TENANT &&
      !crypto_key_backend.has_value()) {
    return NewInvalidArgumentError(
        "CKA_KMS_CRYPTO_KEY_BACKEND must be specified with protection level "
        "HSM_SINGLE_TENANT",
        CKR_TEMPLATE_INCOMPLETE, SOURCE_LOCATION);
  }

  return KeyGenerationParams{*label, *algorithm_details, protection_level,
                             crypto_key_backend};
}

absl::StatusOr<kms_v1::CryptoKeyVersion> CreateNewVersionOfExistingKey(
    const KmsClient& client, const kms_v1::CryptoKey& crypto_key,
    const KeyGenerationParams& gen_params, bool allow_software_keys) {
  if (crypto_key.purpose() != gen_params.algorithm.purpose) {
    return NewError(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("key attribute mismatch when attempting to create "
                        "new version of existing key: "
                        "current purpose=%d, requested purpose=%d",
                        crypto_key.purpose(), gen_params.algorithm.purpose),
        CKR_ARGUMENTS_BAD, SOURCE_LOCATION);
  }

  if (crypto_key.version_template().algorithm() !=
      gen_params.algorithm.algorithm) {
    return NewError(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("key attribute mismatch when attempting to create "
                        "new version of existing key: "
                        "current algorithm=%d, requested algorithm=%d",
                        crypto_key.version_template().algorithm(),
                        gen_params.algorithm.algorithm),
        CKR_ARGUMENTS_BAD, SOURCE_LOCATION);
  }

  // Check that if the protection level is specified in the key generation
  // params, it matches the protection level of the crypto key.
  if (gen_params.protection_level.has_value() &&
      *gen_params.protection_level !=
          crypto_key.version_template().protection_level()) {
    return NewError(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("key attribute mismatch when attempting to create "
                        "new version of existing key: "
                        "current protection_level=%d, "
                        "requested protection_level=%d",
                        crypto_key.version_template().protection_level(),
                        *gen_params.protection_level),
        CKR_ARGUMENTS_BAD, SOURCE_LOCATION);
  }

  // Check the crypto key's protection level against the allowed protection
  // levels.
  absl::flat_hash_set<kms_v1::ProtectionLevel> allowed_protection_levels = {
      kms_v1::HSM, kms_v1::HSM_SINGLE_TENANT};
  if (allow_software_keys) allowed_protection_levels.insert(kms_v1::SOFTWARE);
  if (!allowed_protection_levels.contains(
          crypto_key.version_template().protection_level())) {
    return NewError(
        absl::StatusCode::kInvalidArgument,
        absl::StrFormat("key attribute mismatch when attempting to create "
                        "new version of existing key: "
                        "current protection_level=%d, "
                        "allowed protection_level=%s",
                        crypto_key.version_template().protection_level(),
                        absl::StrJoin(allowed_protection_levels, " or ")),
        CKR_ARGUMENTS_BAD, SOURCE_LOCATION);
  }

  kms_v1::CreateCryptoKeyVersionRequest req;
  req.set_parent(crypto_key.name());
  return client.CreateCryptoKeyVersionAndWait(req);
}

absl::StatusOr<CryptoKeyAndVersion> CreateKeyAndVersion(
    const KmsClient& client, std::string_view key_ring_name,
    const KeyGenerationParams& gen_params,
    bool experimental_create_multiple_versions, bool allow_software_keys) {
  if (experimental_create_multiple_versions) {
    kms_v1::GetCryptoKeyRequest req;
    req.set_name(absl::StrCat(key_ring_name, "/cryptoKeys/", gen_params.label));
    absl::StatusOr<kms_v1::CryptoKey> ck = client.GetCryptoKey(req);
    switch (ck.status().code()) {
      case absl::StatusCode::kOk: {
        ASSIGN_OR_RETURN(kms_v1::CryptoKeyVersion ckv,
                         CreateNewVersionOfExistingKey(client, *ck, gen_params,
                                                       allow_software_keys));
        return CryptoKeyAndVersion{*ck, ckv};
      }
      case absl::StatusCode::kNotFound:
        // The CryptoKey doesn't exist; continue on to create it.
        break;
      default:
        return ck.status();
    }
  }

  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(std::string(key_ring_name));
  req.set_crypto_key_id(gen_params.label);
  req.mutable_crypto_key()->set_purpose(gen_params.algorithm.purpose);
  req.mutable_crypto_key()->mutable_version_template()->set_algorithm(
      gen_params.algorithm.algorithm);
  // Unless otherwise specified in the key generation params, we generate keys
  // with protection level = HSM.
  if (gen_params.protection_level.has_value()) {
    req.mutable_crypto_key()->mutable_version_template()->set_protection_level(
        *gen_params.protection_level);
    if (*gen_params.protection_level == kms_v1::HSM_SINGLE_TENANT) {
      req.mutable_crypto_key()->set_crypto_key_backend(
          *gen_params.crypto_key_backend);
    }
  } else {
    req.mutable_crypto_key()->mutable_version_template()->set_protection_level(
        kms_v1::HSM);
  }

  absl::StatusOr<CryptoKeyAndVersion> key_and_version =
      client.CreateCryptoKeyAndWaitForFirstVersion(req);
  if (absl::IsAlreadyExists(key_and_version.status())) {
    if (experimental_create_multiple_versions) {
      // If we choose to make this experiment a full-fledged feature, we should
      // gracefully handle the case where the CryptoKey is created by another
      // (thread|process|caller) while this request is in flight.
      //
      // That recursive logic will be sort of ugly and complicated; just
      // returning CKR_DEVICE_ERROR/AlreadyExists here seems fine for the
      // purposes of the experiment.
      return key_and_version.status();
    }
    return NewError(
        absl::StatusCode::kAlreadyExists,
        absl::StrFormat("key with label %s already exists: %s",
                        gen_params.label, key_and_version.status().message()),
        CKR_ARGUMENTS_BAD, SOURCE_LOCATION);
  }
  return key_and_version;
}

}  // namespace

CK_SESSION_INFO Session::info() const {
  bool is_read_write = session_type_ == SessionType::kReadWrite;

  CK_STATE state;
  if (token_->is_logged_in()) {
    state = is_read_write ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
  } else {
    state = is_read_write ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
  }

  CK_FLAGS flags = CKF_SERIAL_SESSION;
  if (is_read_write) {
    flags |= CKF_RW_SESSION;
  }

  return CK_SESSION_INFO{
      token_->slot_id(),  // slotID
      state,              // state
      flags,              // flags
      0,                  // ulDeviceError
  };
}

void Session::ReleaseOperation() {
  absl::MutexLock l(&op_mutex_);
  op_ = std::nullopt;
}

absl::Status Session::FindObjectsInit(
    absl::Span<const CK_ATTRIBUTE> attributes) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  std::vector<CK_OBJECT_HANDLE> results =
      token_->FindObjects([&attributes](const Object& o) -> bool {
        for (const CK_ATTRIBUTE& attr : attributes) {
          if (!o.attributes().Contains(attr)) {
            return false;
          }
        }
        return true;
      });

  op_ = FindOp(results);
  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const CK_OBJECT_HANDLE>> Session::FindObjects(
    size_t max_count) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<FindOp>(*op_)) {
    return OperationNotInitializedError("find", SOURCE_LOCATION);
  }

  FindOp& op = std::get<FindOp>(*op_);
  return op.Next(max_count);
}

absl::Status Session::FindObjectsFinal() {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<FindOp>(*op_)) {
    return OperationNotInitializedError("find", SOURCE_LOCATION);
  }

  op_ = std::nullopt;
  return absl::OkStatus();
}

absl::Status Session::DecryptInit(std::shared_ptr<Object> key,
                                  CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewDecryptOp(key, mechanism));
  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> Session::Decrypt(
    absl::Span<const uint8_t> ciphertext) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<DecryptOp>(*op_)) {
    return OperationNotInitializedError("decrypt", SOURCE_LOCATION);
  }

  return std::get<DecryptOp>(*op_)->Decrypt(kms_client_, ciphertext);
}

absl::Status Session::DecryptUpdate(absl::Span<const uint8_t> ciphertext) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<DecryptOp>(*op_)) {
    return OperationNotInitializedError("decrypt", SOURCE_LOCATION);
  }

  return std::get<DecryptOp>(*op_)->DecryptUpdate(kms_client_, ciphertext);
}

absl::StatusOr<absl::Span<const uint8_t>> Session::DecryptFinal() {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<DecryptOp>(*op_)) {
    return OperationNotInitializedError("decrypt", SOURCE_LOCATION);
  }

  return std::get<DecryptOp>(*op_)->DecryptFinal(kms_client_);
}

absl::Status Session::EncryptInit(std::shared_ptr<Object> key,
                                  CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewEncryptOp(key, mechanism));
  return absl::OkStatus();
}

absl::StatusOr<absl::Span<const uint8_t>> Session::Encrypt(
    absl::Span<const uint8_t> plaintext) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<EncryptOp>(*op_)) {
    return OperationNotInitializedError("encrypt", SOURCE_LOCATION);
  }

  return std::get<EncryptOp>(*op_)->Encrypt(kms_client_, plaintext);
}

absl::Status Session::EncryptUpdate(absl::Span<const uint8_t> plaintext) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<EncryptOp>(*op_)) {
    return OperationNotInitializedError("encrypt", SOURCE_LOCATION);
  }

  return std::get<EncryptOp>(*op_)->EncryptUpdate(kms_client_, plaintext);
}
absl::StatusOr<absl::Span<const uint8_t>> Session::EncryptFinal() {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<EncryptOp>(*op_)) {
    return OperationNotInitializedError("encrypt", SOURCE_LOCATION);
  }

  return std::get<EncryptOp>(*op_)->EncryptFinal(kms_client_);
}

absl::Status Session::SignInit(std::shared_ptr<Object> key,
                               CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewSignOp(key, mechanism));
  return absl::OkStatus();
}

absl::Status Session::Sign(absl::Span<const uint8_t> digest,
                           absl::Span<uint8_t> signature) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<SignOp>(*op_)) {
    return OperationNotInitializedError("sign", SOURCE_LOCATION);
  }

  return std::get<SignOp>(*op_)->Sign(kms_client_, digest, signature);
}

absl::Status Session::SignUpdate(absl::Span<const uint8_t> data) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<SignOp>(*op_)) {
    return OperationNotInitializedError("sign", SOURCE_LOCATION);
  }

  return std::get<SignOp>(*op_)->SignUpdate(kms_client_, data);
}

absl::Status Session::SignFinal(absl::Span<uint8_t> signature) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<SignOp>(*op_)) {
    return OperationNotInitializedError("sign", SOURCE_LOCATION);
  }

  return std::get<SignOp>(*op_)->SignFinal(kms_client_, signature);
}

absl::StatusOr<size_t> Session::SignatureLength() {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<SignOp>(*op_)) {
    return OperationNotInitializedError("sign", SOURCE_LOCATION);
  }

  return std::get<SignOp>(*op_)->signature_length();
}

absl::Status Session::VerifyInit(std::shared_ptr<Object> key,
                                 CK_MECHANISM* mechanism) {
  absl::MutexLock l(&op_mutex_);

  if (op_.has_value()) {
    return OperationActiveError(SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(op_, NewVerifyOp(key, mechanism));
  return absl::OkStatus();
}

absl::Status Session::Verify(absl::Span<const uint8_t> digest,
                             absl::Span<const uint8_t> signature) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<VerifyOp>(*op_)) {
    return OperationNotInitializedError("verify", SOURCE_LOCATION);
  }

  return std::get<VerifyOp>(*op_)->Verify(kms_client_, digest, signature);
}

absl::Status Session::VerifyUpdate(absl::Span<const uint8_t> data) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<VerifyOp>(*op_)) {
    return OperationNotInitializedError("verify", SOURCE_LOCATION);
  }

  return std::get<VerifyOp>(*op_)->VerifyUpdate(kms_client_, data);
}

absl::Status Session::VerifyFinal(absl::Span<const uint8_t> signature) {
  absl::MutexLock l(&op_mutex_);

  if (!op_.has_value() || !std::holds_alternative<VerifyOp>(*op_)) {
    return OperationNotInitializedError("verify", SOURCE_LOCATION);
  }

  return std::get<VerifyOp>(*op_)->VerifyFinal(kms_client_, signature);
}

absl::StatusOr<AsymmetricHandleSet> Session::GenerateKeyPair(
    const CK_MECHANISM& mechanism,
    absl::Span<const CK_ATTRIBUTE> public_key_attrs,
    absl::Span<const CK_ATTRIBUTE> private_key_attrs,
    bool experimental_create_multiple_versions, bool allow_software_keys) {
  if (session_type_ == SessionType::kReadOnly) {
    return SessionReadOnlyError(SOURCE_LOCATION);
  }

  switch (mechanism.mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
    case CKM_EC_KEY_PAIR_GEN:
      break;
    default:
      return InvalidMechanismError(mechanism.mechanism, "GenerateKeyPair",
                                   SOURCE_LOCATION);
  }
  if (mechanism.pParameter || mechanism.ulParameterLen > 0) {
    return InvalidMechanismParamError(
        "key generation mechanisms do not take parameters", SOURCE_LOCATION);
  }

  if (!public_key_attrs.empty()) {
    return NewInvalidArgumentError(
        "this token does not accept public key attributes",
        CKR_TEMPLATE_INCONSISTENT, SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(
      KeyGenerationParams prv_gen_params,
      ExtractKeyGenerationParams(private_key_attrs, allow_software_keys));

  if (prv_gen_params.algorithm.key_gen_mechanism != mechanism.mechanism) {
    return NewInvalidArgumentError("algorithm mismatches keygen mechanism",
                                   CKR_TEMPLATE_INCONSISTENT, SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(
      CryptoKeyAndVersion key_and_version,
      CreateKeyAndVersion(*kms_client_, token_->key_ring_name(), prv_gen_params,
                          experimental_create_multiple_versions,
                          allow_software_keys));
  RETURN_IF_ERROR(token_->RefreshState(*kms_client_));

  AsymmetricHandleSet result;
  ASSIGN_OR_RETURN(result.public_key_handle,
                   token_->FindSingleObject([&](const Object& o) -> bool {
                     return o.kms_key_name() ==
                                key_and_version.crypto_key_version.name() &&
                            o.object_class() == CKO_PUBLIC_KEY;
                   }));
  ASSIGN_OR_RETURN(result.private_key_handle,
                   token_->FindSingleObject([&](const Object& o) -> bool {
                     return o.kms_key_name() ==
                                key_and_version.crypto_key_version.name() &&
                            o.object_class() == CKO_PRIVATE_KEY;
                   }));
  return result;
}

absl::StatusOr<CK_OBJECT_HANDLE> Session::GenerateKey(
    const CK_MECHANISM& mechanism,
    absl::Span<const CK_ATTRIBUTE> secret_key_attrs,
    bool experimental_create_multiple_versions, bool allow_software_keys) {
  if (session_type_ == SessionType::kReadOnly) {
    return SessionReadOnlyError(SOURCE_LOCATION);
  }

  switch (mechanism.mechanism) {
    case CKM_GENERIC_SECRET_KEY_GEN:
    case CKM_AES_KEY_GEN:
      break;
    default:
      return InvalidMechanismError(mechanism.mechanism, "GenerateKey",
                                   SOURCE_LOCATION);
  }
  if (mechanism.pParameter || mechanism.ulParameterLen > 0) {
    return InvalidMechanismParamError(
        "key generation mechanisms do not take parameters", SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(
      KeyGenerationParams gen_params,
      ExtractKeyGenerationParams(secret_key_attrs, allow_software_keys));

  if (gen_params.algorithm.key_gen_mechanism != mechanism.mechanism) {
    return NewInvalidArgumentError("algorithm mismatches keygen mechanism",
                                   CKR_TEMPLATE_INCONSISTENT, SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(
      CryptoKeyAndVersion key_and_version,
      CreateKeyAndVersion(*kms_client_, token_->key_ring_name(), gen_params,
                          experimental_create_multiple_versions,
                          allow_software_keys));
  RETURN_IF_ERROR(token_->RefreshState(*kms_client_));

  return token_->FindSingleObject([&](const Object& o) -> bool {
    return o.kms_key_name() == key_and_version.crypto_key_version.name() &&
           o.object_class() == CKO_SECRET_KEY;
  });
}

absl::Status Session::DestroyObject(std::shared_ptr<Object> key) {
  if (session_type_ == SessionType::kReadOnly) {
    return SessionReadOnlyError(SOURCE_LOCATION);
  }

  CK_BBOOL ck_true = CK_TRUE;
  if (!key->attributes().Contains(
          CK_ATTRIBUTE{CKA_DESTROYABLE, &ck_true, sizeof(ck_true)})) {
    return FailedPreconditionError("the selected object is not destroyable",
                                   CKR_ACTION_PROHIBITED, SOURCE_LOCATION);
  }

  kms_v1::DestroyCryptoKeyVersionRequest req;
  req.set_name(std::string(key->kms_key_name()));
  RETURN_IF_ERROR(kms_client_->DestroyCryptoKeyVersion(req));
  RETURN_IF_ERROR(token_->RefreshState(*kms_client_));
  return absl::OkStatus();
}

absl::Status Session::GenerateRandom(absl::Span<uint8_t> buffer) {
  if (buffer.size() < 8 || buffer.size() > 1024) {
    return NewError(
        absl::StatusCode::kInvalidArgument,
        "GenerateRandom buffer length must be between 8 and 1024 bytes",
        CKR_ARGUMENTS_BAD, SOURCE_LOCATION);
  }

  kms_v1::GenerateRandomBytesRequest req;
  req.set_protection_level(kms_v1::HSM);
  req.set_length_bytes(buffer.size());
  req.set_location(*ExtractLocationName(token_->key_ring_name()));

  ASSIGN_OR_RETURN(kms_v1::GenerateRandomBytesResponse resp,
                   kms_client_->GenerateRandomBytes(req));
  if (resp.data().size() != buffer.size()) {
    return NewInternalError(
        absl::StrFormat("requested %d bytes of data from KMS but received %d",
                        buffer.size(), resp.data().size()),
        SOURCE_LOCATION);
  }

  std::copy(resp.data().begin(), resp.data().end(), buffer.data());
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmsp11
