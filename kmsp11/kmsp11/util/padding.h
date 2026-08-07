/*
 * Copyright 2022 Google LLC
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

#ifndef KMSP11_UTIL_PADDING_H_
#define KMSP11_UTIL_PADDING_H_

#include "absl/status/statusor.h"

namespace cloud_kms::kmsp11 {

// Add PKCS#7 padding.
// The block size is hardcoded to 16 bytes.
std::vector<uint8_t> Pad(absl::Span<const uint8_t> data);

// Removes PKCS#7 padding.
// The block size is hardcoded to 16 bytes.
absl::StatusOr<absl::Span<const uint8_t>> Unpad(absl::Span<const uint8_t> data);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_PADDING_H_
