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

#ifndef KMSP11_OBJECT_LOADER_H_
#define KMSP11_OBJECT_LOADER_H_

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "common/kms_client.h"
#include "kmsp11/cert_authority.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/object_store_state.pb.h"

namespace cloud_kms::kmsp11 {

class ObjectLoader {
 public:
  static absl::StatusOr<std::unique_ptr<ObjectLoader>> New(
      std::string_view key_ring_name,
      absl::Span<const std::string* const> pem_user_certs, bool generate_certs,
      bool allow_software_keys = false);

  inline std::string_view key_ring_name() const { return key_ring_name_; }

  absl::StatusOr<ObjectStoreState> BuildState(const KmsClient& client);

 private:
  ObjectLoader(std::string_view key_ring_name,
               absl::flat_hash_map<std::string, std::string> user_certs,
               std::unique_ptr<CertAuthority> cert_authority,
               bool allow_software_keys)
      : key_ring_name_(key_ring_name),
        user_certs_(user_certs),
        cert_authority_(std::move(cert_authority)),
        allow_software_keys_(allow_software_keys) {}

  bool IsLoadable(const kms_v1::CryptoKey& key);
  bool IsLoadable(const kms_v1::CryptoKeyVersion& ckv);

  std::string key_ring_name_;
  // map from SPKI DER to user-provided certificate DER
  absl::flat_hash_map<std::string, std::string> user_certs_;
  std::unique_ptr<CertAuthority> cert_authority_;
  bool allow_software_keys_;

  class Cache {
   public:
    Key* Get(std::string_view ckv_name);
    Key* Store(const kms_v1::CryptoKeyVersion& ckv,
               std::string_view public_key_der,
               std::string_view certificate_der);
    Key* StoreSecretKey(const kms_v1::CryptoKeyVersion& ckv);
    void EvictUnused(const ObjectStoreState& state);

   private:
    CK_OBJECT_HANDLE NewHandle();

    absl::flat_hash_set<CK_OBJECT_HANDLE> allocated_handles_;
    absl::flat_hash_map<std::string, std::unique_ptr<Key>> keys_;
  };

  absl::Mutex cache_mutex_;
  Cache cache_ ABSL_GUARDED_BY(cache_mutex_);
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_OBJECT_LOADER_H_
