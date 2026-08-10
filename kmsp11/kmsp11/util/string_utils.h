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

#ifndef KMSP11_UTIL_STRING_UTILS_H_
#define KMSP11_UTIL_STRING_UTILS_H_

#include <cstdint>
#include <string_view>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "common/openssl.h"
#include "common/string_utils.h"

namespace cloud_kms::kmsp11 {

// Constructs a new string by reinterepting `data` as chars.
//
// C-style arrays of unsigned chars are used extensively in BoringSSL for binary
// data, and in Cryptoki for both text and binary data. In memory that we own,
// std::string is the preferred storage form for both text and binary data.
inline std::string StrFromBytes(absl::Span<const uint8_t> data) {
  return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

// Replaces all content at `dest` by first copying the contents of `src`
// and then filling any remaining bytes with `pad_char`. Returns OutOfRangeError
// if `src.length()` is greater than `dest.length()`.
//
// This is a Cryptoki convention for filling character data in info structs.
// CK_INFO.manufacturerID is an example of a field that is filled this way:
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc235002241
absl::Status CryptokiStrCopy(std::string_view src, absl::Span<uint8_t> dest,
                             char pad_char = ' ');

// Marshals an OpenSSL BIGNUM into the string format expected by Cryptoki.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Ref457115175
std::string MarshalBigNum(const BIGNUM* value);

// Marshals a boolean into the string format expected by Cryptoki. This is
// equivalent to a simple CK_CHAR conversion of 0x00 (false) or 0x01 (true).
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#CK_BYTE
std::string MarshalBool(bool value);

// Marshals a date into the string format expected by Cryptoki.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc323024069
std::string MarshalDate(absl::Time value);

// Marshals an unsigned long int into the string format expected by Cryptoki.
// Note that this is platform-dependent, and is equivalent to a simple char*
// conversion of a CK_ULONG.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc441755771
std::string MarshalULong(unsigned long int value);

// Marshals a span of unsigned long ints into the string format expected by
// Cryptoki. Note that this is platform-dependent, and is equivalent to a simple
// char* conversion of a CK_ULONG*.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc225305959
std::string MarshalULongList(absl::Span<const unsigned long int> value);

// Extracts the CryptoKey ID component from the provided CryptoKeyVersion name.
// For example, returns "baz" if provided an input of
// "projects/foo/locations/us/keyRings/bar/cryptoKeys/baz/cryptoKeyVersions/1".
absl::StatusOr<std::string> ExtractKeyId(std::string_view version_name);

// Extracts the Location name component from the provided KeyRing name.
// For example, returns "projects/foo/locations/us" if provided an input of
// "projects/foo/locations/us/keyRings/bar".
absl::StatusOr<std::string> ExtractLocationName(std::string_view key_ring_name);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_STRING_UTILS_H_
