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

#include "kmsp11/attribute_map.h"

#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

void AttributeMap::Put(CK_ATTRIBUTE_TYPE type, std::string_view value) {
  attrs_[type] = std::string(value.data(), value.size());
}

void AttributeMap::PutSensitive(CK_ATTRIBUTE_TYPE type) {
  static constexpr SensitiveValue kSensitiveValue;
  attrs_[type] = kSensitiveValue;
}

bool AttributeMap::Contains(const CK_ATTRIBUTE& attribute) const {
  auto it = attrs_.find(attribute.type);
  if (it == attrs_.end()) {
    return false;
  }
  if (std::holds_alternative<SensitiveValue>(it->second)) {
    return false;
  }

  return std::get<std::string>(it->second) ==
         std::string_view(static_cast<char*>(attribute.pValue),
                          attribute.ulValueLen);
}

absl::StatusOr<std::string_view> AttributeMap::Value(
    CK_ATTRIBUTE_TYPE type) const {
  auto it = attrs_.find(type);
  if (it == attrs_.end()) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("attribute not found: %#x", type),
                    CKR_ATTRIBUTE_TYPE_INVALID, SOURCE_LOCATION);
  }
  if (std::holds_alternative<SensitiveValue>(it->second)) {
    return NewError(absl::StatusCode::kPermissionDenied,
                    absl::StrFormat("attribute value sensitive: %#x", type),
                    CKR_ATTRIBUTE_SENSITIVE, SOURCE_LOCATION);
  }
  const std::string& s = std::get<std::string>(it->second);
  return std::string_view(s);
}

}  // namespace cloud_kms::kmsp11
