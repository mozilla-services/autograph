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

#include "kmsp11/util/string_utils.h"

#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

absl::Status CryptokiStrCopy(std::string_view src, absl::Span<uint8_t> dest,
                             char pad_char) {
  if (src.length() > dest.length()) {
    return NewError(
        absl::StatusCode::kOutOfRange,
        absl::StrFormat("\"%s\".length()=%d, want <= dest.length()=%d", src,
                        src.length(), dest.length()),
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }
  uint8_t* pos = std::copy(src.begin(), src.end(), dest.begin());
  std::fill(pos, dest.end(), pad_char);
  return absl::OkStatus();
}

std::string MarshalBigNum(const BIGNUM* value) {
  std::string s;
  s.resize(BN_num_bytes(value));
  BN_bn2bin(value, reinterpret_cast<uint8_t*>(s.data()));
  return s;
}

std::string MarshalBool(bool value) { return std::string(1, value); }

std::string MarshalDate(absl::Time value) {
  return absl::FormatTime("%E4Y%m%d", value, absl::UTCTimeZone());
}

std::string MarshalULong(unsigned long int value) {
  return std::string(reinterpret_cast<const char*>(&value),
                     sizeof(unsigned long int));
}

std::string MarshalULongList(absl::Span<const unsigned long int> value) {
  return std::string(reinterpret_cast<const char*>(value.data()),
                     value.size() * sizeof(unsigned long int));
}

absl::StatusOr<std::string> ExtractKeyId(std::string_view version_name) {
  std::vector<std::string> parts = absl::StrSplit(version_name, '/');
  if (parts.size() != 10 || parts[0] != "projects" || parts[2] != "locations" ||
      parts[4] != "keyRings" || parts[6] != "cryptoKeys" ||
      parts[8] != "cryptoKeyVersions") {
    return NewInternalError(
        absl::StrCat("invalid CryptoKeyVersion name: ", version_name),
        SOURCE_LOCATION);
  }
  return parts[7];
}

absl::StatusOr<std::string> ExtractLocationName(
    std::string_view key_ring_name) {
  std::vector<std::string> parts = absl::StrSplit(key_ring_name, '/');
  if (parts.size() != 6 || parts[0] != "projects" || parts[2] != "locations" ||
      parts[4] != "keyRings") {
    return NewInternalError(
        absl::StrCat("invalid KeyRing name: ", key_ring_name), SOURCE_LOCATION);
  }
  return absl::StrJoin(absl::Span<std::string>(parts.data(), 4), "/");
}

}  // namespace cloud_kms::kmsp11
