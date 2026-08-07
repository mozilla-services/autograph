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

// A wrapper for CNG headers, for easier inclusion in other files.

#ifndef KMSCNG_CNG_HEADERS_H_
#define KMSCNG_CNG_HEADERS_H_

// clang-format off
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <bcrypt_provider.h>
#include <ncrypt.h>
#include <ncrypt_provider.h>
// clang-format on

#include <string_view>

// Take care of macro conflicts between wincrypt.h and BoringSSL.
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_ISSUER_AND_SERIAL
#undef PKCS7_SIGNER_INFO

namespace cloud_kms::kmscng {

constexpr std::wstring_view kProviderName = L"Google Cloud KMS Provider";
constexpr std::wstring_view kProviderDllName = L"kmscng.dll";
constexpr std::wstring_view kEndpointAddressProperty = L"KMSEndpointAddress";
constexpr std::wstring_view kChannelCredentialsProperty =
    L"KMSChannelCredentials";
constexpr std::wstring_view kUserProjectProperty = L"KMSUserProject";

constexpr char kEndpointAddressEnvVariable[] = "KMS_ENDPOINT_ADDRESS";
constexpr char kChannelCredentialsEnvVariable[] = "KMS_CHANNEL_CREDENTIALS";
constexpr char kUserProjectEnvVariable[] = "KMS_USER_PROJECT";

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_CNG_HEADERS_H_
