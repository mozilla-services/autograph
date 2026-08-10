/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSP11_SESSION_H_
#define KMSP11_SESSION_H_

#include "kmsp11/operation/operation.h"
#include "kmsp11/token.h"

namespace cloud_kms::kmsp11 {

enum class SessionType { kReadOnly, kReadWrite };

struct AsymmetricHandleSet {
  CK_OBJECT_HANDLE private_key_handle;
  CK_OBJECT_HANDLE public_key_handle;
};

// Session models a PKCS #11 Session and an optional ongoing operation.
//
// See go/kms-pkcs11-model
class Session {
 public:
  Session(Token* token, SessionType session_type, KmsClient* kms_client)
      : token_(token), session_type_(session_type), kms_client_(kms_client) {}

  Token* token() const { return token_; }
  CK_SESSION_INFO info() const;

  void ReleaseOperation();

  absl::Status FindObjectsInit(absl::Span<const CK_ATTRIBUTE> attributes);
  absl::StatusOr<absl::Span<const CK_OBJECT_HANDLE>> FindObjects(
      size_t max_count);
  absl::Status FindObjectsFinal();

  absl::Status DecryptInit(std::shared_ptr<Object> key,
                           CK_MECHANISM* mechanism);
  absl::StatusOr<absl::Span<const uint8_t>> Decrypt(
      absl::Span<const uint8_t> ciphertext);
  absl::Status DecryptUpdate(absl::Span<const uint8_t> ciphertext);
  absl::StatusOr<absl::Span<const uint8_t>> DecryptFinal();

  absl::Status EncryptInit(std::shared_ptr<Object> key,
                           CK_MECHANISM* mechanism);
  absl::StatusOr<absl::Span<const uint8_t>> Encrypt(
      absl::Span<const uint8_t> plaintext);
  absl::Status EncryptUpdate(absl::Span<const uint8_t> plaintext);
  absl::StatusOr<absl::Span<const uint8_t>> EncryptFinal();

  absl::Status SignInit(std::shared_ptr<Object> key, CK_MECHANISM* mechanism);
  absl::Status Sign(absl::Span<const uint8_t> digest,
                    absl::Span<uint8_t> signature);
  absl::Status SignUpdate(absl::Span<const uint8_t> data);
  absl::Status SignFinal(absl::Span<uint8_t> signature);
  absl::StatusOr<size_t> SignatureLength();

  absl::Status VerifyInit(std::shared_ptr<Object> key, CK_MECHANISM* mechanism);
  absl::Status Verify(absl::Span<const uint8_t> digest,
                      absl::Span<const uint8_t> signature);
  absl::Status VerifyUpdate(absl::Span<const uint8_t> data);
  absl::Status VerifyFinal(absl::Span<const uint8_t> signature);

  absl::StatusOr<AsymmetricHandleSet> GenerateKeyPair(
      const CK_MECHANISM& mechanism,
      absl::Span<const CK_ATTRIBUTE> public_key_attrs,
      absl::Span<const CK_ATTRIBUTE> private_key_attrs,
      bool experimental_create_multiple_versions = false,
      bool allow_software_keys = false);

  absl::StatusOr<CK_OBJECT_HANDLE> GenerateKey(
      const CK_MECHANISM& mechanism,
      absl::Span<const CK_ATTRIBUTE> secret_key_attrs,
      bool experimental_create_multiple_versions = false,
      bool allow_software_keys = false);

  absl::Status DestroyObject(std::shared_ptr<Object> object);

  absl::Status GenerateRandom(absl::Span<uint8_t> buffer);

 private:
  Token* token_;
  const SessionType session_type_;
  KmsClient* kms_client_;

  absl::Mutex op_mutex_;
  std::optional<Operation> op_ ABSL_GUARDED_BY(op_mutex_);
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_SESSION_H_
