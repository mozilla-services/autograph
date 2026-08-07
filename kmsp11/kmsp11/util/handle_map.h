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

#ifndef KMSP11_UTIL_HANDLE_MAP_H_
#define KMSP11_UTIL_HANDLE_MAP_H_

#include "absl/container/flat_hash_map.h"
#include "absl/functional/function_ref.h"
#include "absl/status/statusor.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

// A HandleMap contains a set of items with assigned CK_ULONG handles.
// It is intended for use with the PKCS #11 Session and Object types, both
// of which are identified by a handle.
template <typename T>
class HandleMap {
 public:
  // Create a new map. The provided CK_RV will be used for Get and Remove
  // operations performed against an unknown handle.
  HandleMap(CK_RV not_found_rv) : not_found_rv_(not_found_rv) {}

  // Constructs a new T using the provided arguments, adds it to the map, and
  // returns its handle.
  template <typename... Args>
  inline CK_ULONG Add(Args&&... args) {
    absl::WriterMutexLock lock(&mutex_);

    // Generate a new handle by picking a random handle and ensuring that it is
    // not already in use. Repeat this process until we have a useable handle.
    CK_ULONG handle;
    do {
      handle = RandomHandle();
    } while (items_.contains(handle));

    items_.try_emplace(handle,
                       std::make_shared<T>(std::forward<Args>(args)...));
    return handle;
  }

  // Gets the map element with the provided handle, or returns NotFound if there
  // is no element with the provided handle.
  inline absl::StatusOr<std::shared_ptr<T>> Get(CK_ULONG handle) const {
    absl::ReaderMutexLock lock(&mutex_);

    auto it = items_.find(handle);
    if (it == items_.end()) {
      return HandleNotFoundError(handle, not_found_rv_, SOURCE_LOCATION);
    }

    return it->second;
  }

  // Removes the map element with the provided handle, or returns NotFound if
  // there is no element with the provided handle.
  inline absl::Status Remove(CK_ULONG handle) {
    absl::WriterMutexLock lock(&mutex_);

    auto it = items_.find(handle);
    if (it == items_.end()) {
      return HandleNotFoundError(handle, not_found_rv_, SOURCE_LOCATION);
    }

    items_.erase(it);
    return absl::OkStatus();
  }

  // Removes all map elements that match the provided predicate.
  inline void RemoveIf(absl::FunctionRef<bool(const T&)> predicate) {
    absl::WriterMutexLock lock(&mutex_);

    auto it = items_.begin();
    while (it != items_.end()) {
      if (predicate(*it->second)) {
        items_.erase(it++);
      } else {
        it++;
      }
    }
  }

 private:
  CK_RV not_found_rv_;
  mutable absl::Mutex mutex_;
  absl::flat_hash_map<CK_ULONG, std::shared_ptr<T>> items_
      ABSL_GUARDED_BY(mutex_);
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_HANDLE_MAP_H_
