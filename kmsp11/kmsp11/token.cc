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

#include "kmsp11/token.h"

#include <string_view>

#include "absl/container/flat_hash_set.h"
#include "absl/status/statusor.h"
#include "common/backoff.h"
#include "common/kms_client.h"
#include "common/status_macros.h"
#include "kmsp11/object_loader.h"
#include "kmsp11/object_store_state.pb.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

absl::StatusOr<CK_SLOT_INFO> NewSlotInfo() {
  CK_SLOT_INFO info = {
      {0},                // slotDescription (set with ' ' padding below)
      {0},                // manufacturerID (set with ' ' padding below)
      CKF_TOKEN_PRESENT,  // flags
      {0, 0},             // hardwareVersion
      {0, 0},             // firmwareVersion
  };
  RETURN_IF_ERROR(
      CryptokiStrCopy("A virtual slot mapped to a key ring in Google Cloud KMS",
                      info.slotDescription));
  RETURN_IF_ERROR(CryptokiStrCopy("Google", info.manufacturerID));
  return info;
}

absl::StatusOr<CK_TOKEN_INFO> NewTokenInfo(std::string_view token_label) {
  CK_TOKEN_INFO info = {
      {0},  // label (set with ' ' padding below)
      {0},  // manufacturerID (set with ' ' padding below)
      {0},  // model (set with ' ' padding below)
      {0},  // serialNumber (set below)
      CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_SO_PIN_LOCKED |
          CKF_RNG,                 // flags
      CK_EFFECTIVELY_INFINITE,     // ulMaxSessionCount
      CK_UNAVAILABLE_INFORMATION,  // ulSessionCount
      CK_EFFECTIVELY_INFINITE,     // ulMaxRwSessionCount
      CK_UNAVAILABLE_INFORMATION,  // ulRwSessionCount
      0,                           // ulMaxPinLen
      0,                           // ulMinPinLen
      CK_UNAVAILABLE_INFORMATION,  // ulTotalPublicMemory
      CK_UNAVAILABLE_INFORMATION,  // ulFreePublicMemory
      CK_UNAVAILABLE_INFORMATION,  // ulTotalPrivateMemory
      CK_UNAVAILABLE_INFORMATION,  // ulFreePrivateMemory
      {0, 0},                      // hardwareVersion
      {0, 0},                      // firmwareVersion
      {0}                          // utcTime (set below)
  };
  RETURN_IF_ERROR(CryptokiStrCopy(token_label, info.label));
  RETURN_IF_ERROR(CryptokiStrCopy("Google", info.manufacturerID));
  RETURN_IF_ERROR(CryptokiStrCopy("Cloud KMS Token", info.model));
  RETURN_IF_ERROR(CryptokiStrCopy("", info.serialNumber, '0'));
  RETURN_IF_ERROR(CryptokiStrCopy("", info.utcTime, '0'));
  return info;
}

}  // namespace

absl::StatusOr<std::unique_ptr<Token>> Token::New(CK_SLOT_ID slot_id,
                                                  TokenConfig token_config,
                                                  KmsClient* kms_client,
                                                  bool generate_certs,
                                                  bool allow_software_keys) {
  ASSIGN_OR_RETURN(CK_SLOT_INFO slot_info, NewSlotInfo());
  ASSIGN_OR_RETURN(CK_TOKEN_INFO token_info,
                   NewTokenInfo(token_config.label()));

  ASSIGN_OR_RETURN(
      std::unique_ptr<ObjectLoader> loader,
      ObjectLoader::New(token_config.key_ring(),
                        token_config.certs(), generate_certs, allow_software_keys));
  absl::StatusOr<ObjectStoreState> state_resp = loader->BuildState(*kms_client);

  // Exponential backoff to reduce errors at library initialization.
  constexpr absl::Duration kMinDelay = absl::Milliseconds(10);
  constexpr absl::Duration kMaxDelay = absl::Seconds(1);
  int retries = 0;
  while (retries < 10 &&
         (state_resp.status().code() == absl::StatusCode::kDeadlineExceeded ||
          state_resp.status().code() == absl::StatusCode::kUnavailable)) {
    absl::SleepFor(ComputeBackoff(kMinDelay, kMaxDelay, retries++));
    state_resp = loader->BuildState(*kms_client);
  }

  ASSIGN_OR_RETURN(ObjectStoreState state, state_resp);
  ASSIGN_OR_RETURN(std::unique_ptr<ObjectStore> store, ObjectStore::New(state));

  // using `new` to invoke a private constructor
  return std::unique_ptr<Token>(new Token(slot_id, slot_info, token_info,
                                          std::move(loader), std::move(store)));
}

bool Token::is_logged_in() const {
  absl::ReaderMutexLock l(&login_mutex_);
  return is_logged_in_;
}

absl::Status Token::Login(CK_USER_TYPE user) {
  switch (user) {
    case CKU_USER:
      break;
    case CKU_SO:
      return NewError(absl::StatusCode::kPermissionDenied,
                      "login as CKU_SO is not permitted", CKR_PIN_LOCKED,
                      SOURCE_LOCATION);
    case CKU_CONTEXT_SPECIFIC:
      // See description of CKA_ALWAYS_AUTHENTICATE at
      // http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc322855286
      return NewError(absl::StatusCode::kPermissionDenied,
                      "CKA_ALWAYS_AUTHENTICATE is not true on this token",
                      CKR_OPERATION_NOT_INITIALIZED, SOURCE_LOCATION);
    default:
      return NewInvalidArgumentError(
          absl::StrFormat("unknown user type: %#x", user),
          CKR_USER_TYPE_INVALID, SOURCE_LOCATION);
  }

  absl::WriterMutexLock l(&login_mutex_);
  if (is_logged_in_) {
    return FailedPreconditionError("user is already logged in",
                                   CKR_USER_ALREADY_LOGGED_IN, SOURCE_LOCATION);
  }
  is_logged_in_ = true;
  return absl::OkStatus();
}

absl::Status Token::Logout() {
  absl::WriterMutexLock l(&login_mutex_);
  if (!is_logged_in_) {
    return FailedPreconditionError("user is not logged in",
                                   CKR_USER_NOT_LOGGED_IN, SOURCE_LOCATION);
  }
  is_logged_in_ = false;
  return absl::OkStatus();
}

absl::Status Token::RefreshState(const KmsClient& client) {
  ASSIGN_OR_RETURN(ObjectStoreState state, object_loader_->BuildState(client));
  ASSIGN_OR_RETURN(std::unique_ptr<ObjectStore> store, ObjectStore::New(state));

  absl::WriterMutexLock lock(&objects_mutex_);
  objects_.swap(store);
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmsp11
