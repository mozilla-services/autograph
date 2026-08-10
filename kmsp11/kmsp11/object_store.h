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

#ifndef KMSP11_OBJECT_STORE_H_
#define KMSP11_OBJECT_STORE_H_

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/object.h"
#include "kmsp11/object_store_state.pb.h"

namespace cloud_kms::kmsp11 {

using ObjectStoreMap =
    absl::flat_hash_map<CK_OBJECT_HANDLE, std::shared_ptr<Object>>;

class ObjectStore {
 public:
  // Create a new ObjectStore with the provided state.
  static absl::StatusOr<std::unique_ptr<ObjectStore>> New(
      const ObjectStoreState& state);

  // GetObject retrieves the object with the provided handle, or returns
  // CKR_OBJECT_HANDLE_INVALID if the handle is not valid.
  absl::StatusOr<std::shared_ptr<Object>> GetObject(
      CK_OBJECT_HANDLE handle) const;

  // GetKey retrieves the key with the provided handle, or returns
  // CKR_KEY_HANDLE_INVALID if the handle is not valid or does not refer to a
  // key object.
  absl::StatusOr<std::shared_ptr<Object>> GetKey(CK_OBJECT_HANDLE handle) const;

  // Find retrieves a list of handles whose objects match the provided
  // predicate.
  std::vector<CK_OBJECT_HANDLE> Find(
      std::function<bool(const Object&)> predicate) const;

  // FindSingle retrieves the object that matches the provided predicate, or
  // NotFound if no such object exists, or PreconditionFailed if multiple
  // matching objects exist.
  absl::StatusOr<CK_OBJECT_HANDLE> FindSingle(
      std::function<bool(const Object&)> predicate) const;

 private:
  ObjectStore(ObjectStoreMap entries) : entries_(entries) {}

  const ObjectStoreMap entries_;
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_OBJECT_STORE_H_
