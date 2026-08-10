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

#ifndef KMSCNG_UTIL_STATUS_UTILS_H_
#define KMSCNG_UTIL_STATUS_UTILS_H_

// clang-format off
#include <windows.h>
#include <wincrypt.h>
// clang-format on

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "grpcpp/support/status.h"

namespace cloud_kms::kmscng {

// A catch-all default SECURITY_STATUS value to return in the event that no
// specific error is provided.
const SECURITY_STATUS kDefaultErrorStatus = NTE_FAIL;

// Set a SECURITY_STATUS that should be provided to the caller. This may not be
// set for an `ok` status, and ERROR_SUCCESS  may not be set as the return
// value. These requirements are CHECKed.
void SetErrorSs(absl::Status& status, SECURITY_STATUS ss);

// Get a SECURITY_STATUS suitable for returning to a caller. For an `ok` status,
// this is always ERROR_SUCCESS. For a non-OK status, this is the value that was
// set using SetErrorSt, or if no value was set, `kDefaultErrorCkRv`.
SECURITY_STATUS GetErrorSs(const absl::Status& status);

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_UTIL_STATUS_UTILS_H_
