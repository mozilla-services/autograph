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

#ifndef KMSCNG_UTIL_STRING_UTILS_H_
#define KMSCNG_UTIL_STRING_UTILS_H_

#include <string>

#include "kmscng/cng_headers.h"

namespace cloud_kms::kmscng {

std::string Uint32ToBytes(uint32_t value);

std::string ProvHandleToBytes(NCRYPT_PROV_HANDLE handle);

std::wstring StringToWide(const std::string& str);

// Converts the wide string to a regular string (UCS-2 or UTF-16 to UTF-8).
std::string WideToString(const std::wstring& wstr);

// Converts the wide string to bytes (i.e. exactly two bytes for every character
// without converting to UTF-8).
std::string WideToBytes(std::wstring_view data);

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_UTIL_STRING_UTILS_H_
