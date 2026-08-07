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

#ifndef KMSP11_ATTRIBUTE_MAP_H_
#define KMSP11_ATTRIBUTE_MAP_H_

#include <variant>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "common/openssl.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {

// AttributeMap is a container for PKCS #11 attributes.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc235002350
class AttributeMap {
 public:
  void Put(CK_ATTRIBUTE_TYPE type, std::string_view value);
  void PutSensitive(CK_ATTRIBUTE_TYPE type);

  inline void PutBool(CK_ATTRIBUTE_TYPE type, bool value) {
    Put(type, MarshalBool(value));
  }

  inline void PutBigNum(CK_ATTRIBUTE_TYPE type, const BIGNUM* value) {
    Put(type, MarshalBigNum(value));
  }

  inline void PutDate(CK_ATTRIBUTE_TYPE type, absl::Time value) {
    Put(type, MarshalDate(value));
  }

  inline void PutULong(CK_ATTRIBUTE_TYPE type, CK_ULONG value) {
    Put(type, MarshalULong(value));
  }

  inline void PutULongList(CK_ATTRIBUTE_TYPE type,
                           absl::Span<const CK_ULONG> value) {
    Put(type, MarshalULongList(value));
  }

  bool Contains(const CK_ATTRIBUTE& attribute) const;
  absl::StatusOr<std::string_view> Value(CK_ATTRIBUTE_TYPE type) const;

 private:
  class SensitiveValue {};

  // See discussion of C_GetAttributeValue at
  // http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc235002350
  //
  // Any object may or may not contain an attribute. In our implementation,
  // attrs_ will contain an entry for the attribute type if the attribute is
  // present.
  //
  // If the attribute is present, its value may be empty, sensitive, or
  // populated:
  //  * Empty attributes have a value of the empty string.
  //  * Sensitive attributes have a value of type SensitiveValue. As an example,
  //    the value of CKA_PRIVATE_EXPONENT will be SensitiveValue for RSA private
  //    keys; the actual value is not available in this library.
  //  * Populated attributes have a std::string value that corresponds to the
  //    attribute's definition. For example, a CK_ULONG attribute will be
  //    modeled as a std::string of size sizeof(CK_ULONG).
  using AttributeValue = std::variant<std::string, SensitiveValue>;

  absl::flat_hash_map<CK_ATTRIBUTE_TYPE, AttributeValue> attrs_;
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_ATTRIBUTE_MAP_H_
