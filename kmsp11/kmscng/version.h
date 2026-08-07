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

#ifndef KMSCNG_VERSION_H_
#define KMSCNG_VERSION_H_

namespace cloud_kms::kmscng {

constexpr uint8_t kLibraryVersionMajor = 1;
constexpr uint8_t kLibraryVersionMinor = 3;

// https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers#ncrypt_version_property
constexpr uint32_t kLibraryVersionHex =
    (uint32_t(kLibraryVersionMajor) << 16) + kLibraryVersionMinor;

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_VERSION_H_
