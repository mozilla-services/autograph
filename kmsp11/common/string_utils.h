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

#ifndef COMMON_STRING_UTILS_H_
#define COMMON_STRING_UTILS_H_

#include <cstdint>
#include <string_view>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/types/span.h"

namespace cloud_kms {

// Reads the file from the provided filesystem path to a string. Returns
// FailedPrecondition on error; for example if the file does not exist, or there
// are insufficient permissions to read it.
absl::StatusOr<std::string> ReadFileToString(const std::string& file_path);

// Checks if the data buffer is zero-initialized.
bool IsZeroInitialized(absl::Span<const uint8_t> buffer);

// Checks that buffer only contains the specified value.
bool OnlyContainsValue(absl::Span<const uint8_t> buffer, uint8_t value);

}  // namespace cloud_kms

#endif  // COMMON_STRING_UTILS_H_
