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

#include "kmscng/util/string_utils.h"

#include <codecvt>
#include <locale>

namespace cloud_kms::kmscng {

std::string Uint32ToBytes(uint32_t value) {
  return std::string(reinterpret_cast<char*>(&value), sizeof(uint32_t));
}

std::string ProvHandleToBytes(NCRYPT_PROV_HANDLE handle) {
  return std::string(reinterpret_cast<char*>(&handle),
                     sizeof(NCRYPT_PROV_HANDLE));
}

std::wstring StringToWide(const std::string& str) {
  std::wstring_convert<std::codecvt<wchar_t, char, std::mbstate_t>, wchar_t>
      converter;

  return converter.from_bytes(str);
}

std::string WideToString(const std::wstring& wstr) {
  std::wstring_convert<std::codecvt<wchar_t, char, std::mbstate_t>, wchar_t>
      converter;

  return converter.to_bytes(wstr);
}

std::string WideToBytes(std::wstring_view data) {
  return std::string(reinterpret_cast<const char*>(data.data()),
                     (data.size() + 1 /* null terminator*/) * sizeof(wchar_t));
}

}  // namespace cloud_kms::kmscng
