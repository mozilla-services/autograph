// Copyright 2022 Google LLC
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

#include "kmsp11/util/padding.h"

#include "kmsp11/util/errors.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {

constexpr size_t kCipherBlockSize = 16;

std::vector<uint8_t> Pad(absl::Span<const uint8_t> data) {
  std::vector<uint8_t> padded_data;
  size_t padding_len = kCipherBlockSize - (data.size() % kCipherBlockSize);

  padded_data.reserve(data.size() + padding_len);
  padded_data.insert(padded_data.end(), data.begin(), data.end());
  padded_data.insert(padded_data.end(), padding_len,
                     static_cast<char>(padding_len));

  return padded_data;
}

absl::StatusOr<absl::Span<const uint8_t>> Unpad(
    absl::Span<const uint8_t> data) {
  // Check that the last char is a valid padding value.
  size_t padding_len = static_cast<size_t>(data.back());
  if (padding_len == 0 || padding_len > data.size() ||
      padding_len > kCipherBlockSize) {
    return NewInternalError("invalid plaintext padding", SOURCE_LOCATION);
  }

  if (!OnlyContainsValue(data.last(padding_len), data.back())) {
    return NewInternalError("invalid plaintext padding", SOURCE_LOCATION);
  }

  return data.first(data.size() - padding_len);
}

}  // namespace cloud_kms::kmsp11
