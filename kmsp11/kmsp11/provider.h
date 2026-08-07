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

#ifndef KMSP11_PROVIDER_H_
#define KMSP11_PROVIDER_H_

#include <thread>

#include "absl/status/statusor.h"
#include "absl/synchronization/notification.h"
#include "kmsp11/config/config.pb.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/mechanism.h"
#include "kmsp11/session.h"
#include "kmsp11/token.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/handle_map.h"

namespace cloud_kms::kmsp11 {

// Provider models a "run" of a Cryptoki library, from C_Initialize to
// C_Finalize.
//
// See go/kms-pkcs11-model
class Provider {
 public:
  static absl::StatusOr<std::unique_ptr<Provider>> New(LibraryConfig config);

  const LibraryConfig& library_config() const { return library_config_; }
  const CK_INFO& info() const { return info_; }
  const unsigned long token_count() const { return tokens_.size(); }
  KmsClient* kms_client() { return kms_client_.get(); }

  absl::StatusOr<Token*> TokenAt(CK_SLOT_ID slot_id);

  absl::StatusOr<CK_SESSION_HANDLE> OpenSession(CK_SLOT_ID slot_id,
                                                SessionType session_type);
  absl::StatusOr<std::shared_ptr<Session>> GetSession(
      CK_SESSION_HANDLE session_handle);
  absl::Status CloseSession(CK_SESSION_HANDLE session_handle);
  absl::Status CloseAllSessions(CK_SLOT_ID slot_id);

  // Returns a sorted list of the mechanism types supported in this library.
  absl::Span<const CK_MECHANISM_TYPE> Mechanisms();
  // Returns details about the provided mechanism type.
  absl::StatusOr<CK_MECHANISM_INFO> MechanismInfo(CK_MECHANISM_TYPE type);

 private:
  class Refresher {
   public:
    Refresher(Provider* provider, absl::Duration interval);
    virtual ~Refresher();

   private:
    absl::Notification shutdown_;
    std::thread thread_;
  };

  Provider(LibraryConfig library_config, CK_INFO info,
           std::vector<std::unique_ptr<Token>>&& tokens,
           std::unique_ptr<KmsClient> kms_client,
           absl::Duration refresh_interval)
      : library_config_(library_config),
        info_(info),
        tokens_(std::move(tokens)),
        sessions_(CKR_SESSION_HANDLE_INVALID),
        kms_client_(std::move(kms_client)) {
    if (refresh_interval > absl::ZeroDuration()) {
      refresher_.emplace(this, refresh_interval);
    }
    auto all_mechanisms = AllMechanisms();
    auto all_mac_mechanisms = AllMacMechanisms();
    auto all_raw_encryption_mechanisms = AllRawEncryptionMechanisms();
    std::vector<CK_MECHANISM_TYPE> types(all_mechanisms.size());
    for (const auto& [mechanism_type, mechanism] : all_mechanisms) {
      types.push_back(mechanism_type);
    }
    std::sort(types.begin(), types.end());
    mechanism_types_ = types;
  }

  const LibraryConfig library_config_;
  const CK_INFO info_;
  const std::vector<std::unique_ptr<Token>> tokens_;
  HandleMap<Session> sessions_;
  std::unique_ptr<KmsClient> kms_client_;
  std::optional<Refresher> refresher_;
  std::vector<CK_MECHANISM_TYPE> mechanism_types_;
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_PROVIDER_H_
