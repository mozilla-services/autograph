/*
 * Copyright 2023 Google LLC
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

#ifndef KMSCNG_OBJECT_LOADER_H_
#define KMSCNG_OBJECT_LOADER_H_

#include "absl/status/statusor.h"
#include "kmscng/cng_headers.h"
#include "kmscng/config/config.pb.h"

namespace cloud_kms::kmscng {

struct HeapAllocatedKeyDetails {
  std::wstring key_name;
  std::wstring algorithm_identifier;
  uint32_t legacy_spec;
  uint32_t flags;

  std::unique_ptr<NCryptKeyName> NewNCryptKeyName() {
    return std::make_unique<NCryptKeyName>(
        NCryptKeyName{.pszName = key_name.data(),
                      .pszAlgid = algorithm_identifier.data(),
                      .dwLegacyKeySpec = legacy_spec,
                      .dwFlags = flags});
  }
};

struct EnumState {
  std::vector<HeapAllocatedKeyDetails> key_details;
  size_t current;
};

absl::StatusOr<std::vector<HeapAllocatedKeyDetails>> BuildCkvList(
    NCRYPT_PROV_HANDLE prov_handle, const ProviderConfig& config);

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_OBJECT_LOADER_H_
