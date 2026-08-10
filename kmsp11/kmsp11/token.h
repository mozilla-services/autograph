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

#ifndef KMSP11_TOKEN_H_
#define KMSP11_TOKEN_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "common/kms_client.h"
#include "kmsp11/config/config.pb.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/object.h"
#include "kmsp11/object_loader.h"
#include "kmsp11/object_store.h"

namespace cloud_kms::kmsp11 {

// Token models a PKCS #11 Token, and logically maps to a key ring in
// Cloud KMS.
//
// See go/kms-pkcs11-model
class Token {
 public:
  static absl::StatusOr<std::unique_ptr<Token>> New(
      CK_SLOT_ID slot_id, TokenConfig token_config, KmsClient* kms_client,
      bool generate_certs = false, bool allow_software_keys = false);

  CK_SLOT_ID slot_id() const { return slot_id_; }
  const CK_SLOT_INFO& slot_info() const { return slot_info_; }
  const CK_TOKEN_INFO& token_info() const { return token_info_; }
  std::string_view key_ring_name() const {
    return object_loader_->key_ring_name();
  }

  bool is_logged_in() const;
  absl::Status Login(CK_USER_TYPE user_type);
  absl::Status Logout();

  inline absl::StatusOr<std::shared_ptr<Object>> GetObject(
      CK_OBJECT_HANDLE object_handle) const {
    absl::ReaderMutexLock lock(&objects_mutex_);
    return objects_->GetObject(object_handle);
  }

  inline absl::StatusOr<std::shared_ptr<Object>> GetKey(
      CK_OBJECT_HANDLE handle) const {
    absl::ReaderMutexLock lock(&objects_mutex_);
    return objects_->GetKey(handle);
  }

  inline std::vector<CK_OBJECT_HANDLE> FindObjects(
      std::function<bool(const Object&)> predicate) const {
    absl::ReaderMutexLock lock(&objects_mutex_);
    return objects_->Find(predicate);
  }

  inline absl::StatusOr<CK_OBJECT_HANDLE> FindSingleObject(
      std::function<bool(const Object&)> predicate) const {
    absl::ReaderMutexLock lock(&objects_mutex_);
    return objects_->FindSingle(predicate);
  }

  absl::Status RefreshState(const KmsClient& client);

 private:
  Token(CK_SLOT_ID slot_id, CK_SLOT_INFO slot_info, CK_TOKEN_INFO token_info,
        std::unique_ptr<ObjectLoader> object_loader,
        std::unique_ptr<ObjectStore> objects)
      : slot_id_(slot_id),
        slot_info_(slot_info),
        token_info_(token_info),
        object_loader_(std::move(object_loader)),
        objects_(std::move(objects)),
        is_logged_in_(false) {}

  const CK_SLOT_ID slot_id_;
  const CK_SLOT_INFO slot_info_;
  const CK_TOKEN_INFO token_info_;

  std::unique_ptr<ObjectLoader> object_loader_;
  mutable absl::Mutex objects_mutex_;
  std::unique_ptr<ObjectStore> objects_ ABSL_GUARDED_BY(objects_mutex_);

  // All sessions with the same token have the same login state (rather than
  // login state being per-session, which seems like the more obvious choice.)
  // http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002343
  mutable absl::Mutex login_mutex_;
  bool is_logged_in_ ABSL_GUARDED_BY(login_mutex_);
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_TOKEN_H_
