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

#ifndef KMSP11_UTIL_GLOBAL_PROVIDER_H_
#define KMSP11_UTIL_GLOBAL_PROVIDER_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "kmsp11/provider.h"

namespace cloud_kms::kmsp11 {

// Sets the provided Provider as the global Provider for serving requests from
// this process. Returns InternalError/CKR_GENERAL_ERROR if provider is nullptr,
// or if a global provider is currently set.
absl::Status SetGlobalProvider(std::unique_ptr<Provider> provider);

// Gets a pointer to the global Provider instance, or nullptr if none is set.
Provider* GetGlobalProvider();

// Frees the global Provider instance. Returns InternalError/CKR_GENERAL_ERROR
// if no global provider instance exists.
absl::Status ReleaseGlobalProvider();

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_GLOBAL_PROVIDER_H_
