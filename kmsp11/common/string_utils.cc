// Copyright 2021 Google LLC
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

#include "common/string_utils.h"

#include <fstream>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"

namespace cloud_kms {

absl::StatusOr<std::string> ReadFileToString(const std::string& file_path) {
  std::ifstream in(file_path.c_str());
  if (in.fail()) {
    return absl::FailedPreconditionError(
        absl::StrCat("failed to read file ", file_path));
  }
  return std::string((std::istreambuf_iterator<char>(in)),
                     (std::istreambuf_iterator<char>()));
}

bool IsZeroInitialized(absl::Span<const uint8_t> buffer) {
  return OnlyContainsValue(buffer, '\0');
}

// Checks that buffer only contains the specified value.
bool OnlyContainsValue(absl::Span<const uint8_t> buffer, uint8_t value) {
  for (uint8_t v : buffer) {
    if (v != value) {
      return false;
    }
  }
  return true;
}

}  // namespace cloud_kms
