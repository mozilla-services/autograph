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

#include "kmscng/util/registration.h"

#include <iostream>

#include "absl/strings/str_format.h"
#include "kmscng/cng_headers.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

namespace cloud_kms::kmscng {

absl::Status RegisterProvider() {
  NTSTATUS status = 0;
  PWSTR algorithms[1] = {const_cast<wchar_t*>(NCRYPT_KEY_STORAGE_ALGORITHM)};

  CRYPT_INTERFACE_REG algorithm_class = {
      NCRYPT_KEY_STORAGE_INTERFACE,  // Ncrypt key storage interface
      CRYPT_LOCAL,                   // Scope: local system only
      1,                             // Algorithms count
      algorithms                     // Name(s) of the algorithm(s)
  };

  PCRYPT_INTERFACE_REG algorithm_classes[1] = {&algorithm_class};
  CRYPT_IMAGE_REG ksp_image = {
      const_cast<wchar_t*>(
          kProviderDllName.data()),  // File name of the KSP binary
      1,                 // Number of algorithm classes the binary supports
      algorithm_classes  // List of all algorithm classes available
  };

  CRYPT_PROVIDER_REG ksp_provider = {
      0,           // Aliases
      NULL,        // Names of aliases
      &ksp_image,  // Image that provides user-mode support
      NULL         // Image that provides kernel-mode support (*MUST* be NULL)
  };

  // Register our custom CNG provider
  status =
      BCryptRegisterProvider(kProviderName.data(),
                             CRYPT_OVERWRITE,  // overwrite an existing entry
                             &ksp_provider);
  if (!NT_SUCCESS(status)) {
    return absl::InternalError(absl::StrFormat(
        "BCryptRegisterProvider failed with error code 0x%08x\n", status));
  }

  // Add the algorithm name to the priority list of the key storage algorithm
  // class. (This makes it visible to BCryptResolveProviders.)
  status =
      BCryptAddContextFunction(CRYPT_LOCAL,  // Scope: local machine only
                               NULL,         // Application context: default
                               NCRYPT_KEY_STORAGE_INTERFACE,  // Algorithm class
                               NCRYPT_KEY_STORAGE_ALGORITHM,  // Algorithm name
                               CRYPT_PRIORITY_BOTTOM          // Lowest priority
      );
  if (!NT_SUCCESS(status)) {
    return absl::InternalError(absl::StrFormat(
        "BCryptAddContextFunction failed with error code 0x%08x\n", status));
  }

  // Identify our provider as an implementation of the key storage interface.
  status = BCryptAddContextFunctionProvider(
      CRYPT_LOCAL,                   // Scope: local machine only
      NULL,                          // Application context: default
      NCRYPT_KEY_STORAGE_INTERFACE,  // Algorithm class
      NCRYPT_KEY_STORAGE_ALGORITHM,  // Algorithm name
      kProviderName.data(),          // Provider name
      CRYPT_PRIORITY_BOTTOM          // Lowest priority
  );
  if (!NT_SUCCESS(status)) {
    return absl::InternalError(absl::StrFormat(
        "BCryptAddContextFunctionProvider failed with error code 0x%08x\n",
        status));
  }

  return absl::OkStatus();
}

absl::Status UnregisterProvider() {
  NTSTATUS status = 0;

  // Tell CNG that this provider no longer supports the algorithm.
  status = BCryptRemoveContextFunctionProvider(
      CRYPT_LOCAL,                   // Scope: local machine only
      NULL,                          // Application context: default
      NCRYPT_KEY_STORAGE_INTERFACE,  // Algorithm class
      NCRYPT_KEY_STORAGE_ALGORITHM,  // Algorithm name
      kProviderName.data()           // Provider name
  );
  if (!NT_SUCCESS(status)) {
    return absl::InternalError(absl::StrFormat(
        "BCryptRemoveContextFunctionProvider failed with error code 0x%08x\n",
        status));
  }

  // Drop the provider from the CNG priority list.
  status = BCryptRemoveContextFunction(
      CRYPT_LOCAL,                   // Scope: local machine only
      NULL,                          // Application context: default
      NCRYPT_KEY_STORAGE_INTERFACE,  // Algorithm class
      NCRYPT_KEY_STORAGE_ALGORITHM   // Algorithm name
  );
  if (!NT_SUCCESS(status)) {
    return absl::InternalError(absl::StrFormat(
        "BCryptRemoveContextFunction failed with error code 0x%08x\n", status));
  }

  // Unregister our custom CNG provider.
  status = BCryptUnregisterProvider(kProviderName.data());
  if (!NT_SUCCESS(status)) {
    return absl::InternalError(absl::StrFormat(
        "BCryptUnregisterProvider failed with error code 0x%08x\n", status));
  }

  return absl::OkStatus();
}

}  // namespace cloud_kms::kmscng
