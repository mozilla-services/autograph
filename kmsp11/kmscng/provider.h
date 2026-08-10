// Copyright 2023 Google LLC
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

#ifndef KMSCNG_PROVIDER_H_
#define KMSCNG_PROVIDER_H_

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "common/kms_client.h"
#include "kmscng/cng_headers.h"

namespace cloud_kms::kmscng {

static constexpr std::array<NCryptAlgorithmName, 3> kAlgorithmNames{
    {{.pszName = const_cast<wchar_t*>(BCRYPT_ECDSA_P256_ALGORITHM),
      .dwClass = NCRYPT_SIGNATURE_INTERFACE,
      .dwAlgOperations = NCRYPT_SIGNATURE_OPERATION,
      .dwFlags = 0},
     {.pszName = const_cast<wchar_t*>(BCRYPT_ECDSA_P384_ALGORITHM),
      .dwClass = NCRYPT_SIGNATURE_INTERFACE,
      .dwAlgOperations = NCRYPT_SIGNATURE_OPERATION,
      .dwFlags = 0},
     {.pszName = const_cast<wchar_t*>(BCRYPT_RSA_ALGORITHM),
      .dwClass = NCRYPT_SIGNATURE_INTERFACE,
      .dwAlgOperations = NCRYPT_SIGNATURE_OPERATION,
      .dwFlags = 0}}};

class Provider {
 public:
  Provider();

  absl::StatusOr<std::string_view> GetProperty(std::wstring_view name);
  absl::Status SetProperty(std::wstring_view name, std::string_view value);

 private:
  absl::flat_hash_map<std::wstring, std::string> provider_info_;
};

// Initializes a new KmsClient while checking the provider properties for
// configuration options.
absl::StatusOr<std::unique_ptr<KmsClient>> NewKmsClient(
    NCRYPT_PROV_HANDLE prov_handle);

// Validates the input NCRYPT_PROV_HANDLE and returns a pointer to the Provider
// object if the handle is valid, an error otherwise.
absl::StatusOr<Provider*> ValidateProviderHandle(
    NCRYPT_PROV_HANDLE prov_handle);

}  // namespace cloud_kms::kmscng

#endif KMSCNG_PROVIDER_H_
