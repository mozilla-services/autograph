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

#include "absl/status/status.h"
#include "kmscng/main/bridge.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/logging.h"

namespace cloud_kms::kmscng {

absl::Status CreatePersistedKey(__in NCRYPT_PROV_HANDLE hProvider,
                                __out NCRYPT_KEY_HANDLE* phKey,
                                __in LPCWSTR pszAlgId,
                                __in_opt LPCWSTR pszKeyName,
                                __in DWORD dwLegacyKeySpec,
                                __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** CreatePersistedKey invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status SetKeyProperty(__in NCRYPT_PROV_HANDLE hProvider,
                            __in NCRYPT_KEY_HANDLE hKey,
                            __in LPCWSTR pszProperty,
                            __in_bcount(cbInput) PBYTE pbInput,
                            __in DWORD cbInput, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** SetKeyProperty invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status FinalizeKey(__in NCRYPT_PROV_HANDLE hProvider,
                         __in NCRYPT_KEY_HANDLE hKey, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** FinalizeKey invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status DeleteKey(__in NCRYPT_PROV_HANDLE hProvider,
                       __inout NCRYPT_KEY_HANDLE hKey, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** DeleteKey invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status Encrypt(__in NCRYPT_PROV_HANDLE hProvider,
                     __in NCRYPT_KEY_HANDLE hKey,
                     __in_bcount(cbInput) PBYTE pbInput, __in DWORD cbInput,
                     __in VOID* pPaddingInfo,
                     __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
                     __in DWORD cbOutput, __out DWORD* pcbResult,
                     __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** Encrypt invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status Decrypt(__in NCRYPT_PROV_HANDLE hProvider,
                     __in NCRYPT_KEY_HANDLE hKey,
                     __in_bcount(cbInput) PBYTE pbInput, __in DWORD cbInput,
                     __in VOID* pPaddingInfo,
                     __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
                     __in DWORD cbOutput, __out DWORD* pcbResult,
                     __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** Decrypt invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status ImportKey(__in NCRYPT_PROV_HANDLE hProvider,
                       __in_opt NCRYPT_KEY_HANDLE hImportKey,
                       __in LPCWSTR pszBlobType,
                       __in_opt NCryptBufferDesc* pParameterList,
                       __out NCRYPT_KEY_HANDLE* phKey,
                       __in_bcount(cbData) PBYTE pbData, __in DWORD cbData,
                       __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** ImportKey invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status VerifySignature(__in NCRYPT_PROV_HANDLE hProvider,
                             __in NCRYPT_KEY_HANDLE hKey,
                             __in_opt VOID* pPaddingInfo,
                             __in_bcount(cbHashValue) PBYTE pbHashValue,
                             __in DWORD cbHashValue,
                             __in_bcount(cbSignature) PBYTE pbSignature,
                             __in DWORD cbSignature, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** VerifySignature invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status PromptUser(__in NCRYPT_PROV_HANDLE hProvider,
                        __in_opt NCRYPT_KEY_HANDLE hKey,
                        __in LPCWSTR pszOperation, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** PromptUser invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status NotifyChangeKey(__in NCRYPT_PROV_HANDLE hProvider,
                             __inout HANDLE* phEvent, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** NotifyChangeKey invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status SecretAgreement(__in NCRYPT_PROV_HANDLE hProvider,
                             __in NCRYPT_KEY_HANDLE hPrivKey,
                             __in NCRYPT_KEY_HANDLE hPubKey,
                             __out NCRYPT_SECRET_HANDLE* phAgreedSecret,
                             __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** SecretAgreement invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status DeriveKey(__in NCRYPT_PROV_HANDLE hProvider,
                       __in_opt NCRYPT_SECRET_HANDLE hSharedSecret,
                       __in LPCWSTR pwszKDF,
                       __in_opt NCryptBufferDesc* pParameterList,
                       __out_bcount_part_opt(cbDerivedKey, *pcbResult)
                           PUCHAR pbDerivedKey,
                       __in DWORD cbDerivedKey, __out DWORD* pcbResult,
                       __in ULONG dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** DeriveKey invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

absl::Status FreeSecret(__in NCRYPT_PROV_HANDLE hProvider,
                        __in NCRYPT_SECRET_HANDLE hSharedSecret) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "** unsupported ** FreeSecret invoked ** unsupported ** \n\n";
  return NewUnsupportedError(SOURCE_LOCATION);
}

}  // namespace cloud_kms::kmscng
