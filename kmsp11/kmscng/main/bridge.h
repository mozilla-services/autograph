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

#ifndef KMSCNG_MAIN_BRIDGE_H_
#define KMSCNG_MAIN_BRIDGE_H_

#include "absl/status/status.h"
#include "kmscng/cng_headers.h"

namespace cloud_kms::kmscng {

absl::Status OpenProvider(__out NCRYPT_PROV_HANDLE* phProvider,
                          __in LPCWSTR pszProviderName, __in DWORD dwFlags);

absl::Status FreeProvider(__in NCRYPT_PROV_HANDLE hProvider);

absl::Status OpenKey(__inout NCRYPT_PROV_HANDLE hProvider,
                     __out NCRYPT_KEY_HANDLE* phKey, __in LPCWSTR pszKeyName,
                     __in_opt DWORD dwLegacyKeySpec, __in DWORD dwFlags);

absl::Status CreatePersistedKey(__in NCRYPT_PROV_HANDLE hProvider,
                                __out NCRYPT_KEY_HANDLE* phKey,
                                __in LPCWSTR pszAlgId,
                                __in_opt LPCWSTR pszKeyName,
                                __in DWORD dwLegacyKeySpec, __in DWORD dwFlags);

absl::Status GetProviderProperty(__in NCRYPT_PROV_HANDLE hProvider,
                                 __in LPCWSTR pszProperty,
                                 __out_bcount_part_opt(cbOutput, *pcbResult)
                                     PBYTE pbOutput,
                                 __in DWORD cbOutput, __out DWORD* pcbResult,
                                 __in DWORD dwFlags);

absl::Status GetKeyProperty(__in NCRYPT_PROV_HANDLE hProvider,
                            __in NCRYPT_KEY_HANDLE hKey,
                            __in LPCWSTR pszProperty,
                            __out_bcount_part_opt(cbOutput, *pcbResult)
                                PBYTE pbOutput,
                            __in DWORD cbOutput, __out DWORD* pcbResult,
                            __in DWORD dwFlags);

absl::Status SetProviderProperty(__in NCRYPT_PROV_HANDLE hProvider,
                                 __in LPCWSTR pszProperty,
                                 __in_bcount(cbInput) PBYTE pbInput,
                                 __in DWORD cbInput, __in DWORD dwFlags);

absl::Status SetKeyProperty(__in NCRYPT_PROV_HANDLE hProvider,
                            __in NCRYPT_KEY_HANDLE hKey,
                            __in LPCWSTR pszProperty,
                            __in_bcount(cbInput) PBYTE pbInput,
                            __in DWORD cbInput, __in DWORD dwFlags);

absl::Status FinalizeKey(__in NCRYPT_PROV_HANDLE hProvider,
                         __in NCRYPT_KEY_HANDLE hKey, __in DWORD dwFlags);

absl::Status DeleteKey(__in NCRYPT_PROV_HANDLE hProvider,
                       __inout NCRYPT_KEY_HANDLE hKey, __in DWORD dwFlags);

absl::Status FreeKey(__in NCRYPT_PROV_HANDLE hProvider,
                     __in NCRYPT_KEY_HANDLE hKey);

absl::Status FreeBuffer(__deref PVOID pvInput);

absl::Status Encrypt(__in NCRYPT_PROV_HANDLE hProvider,
                     __in NCRYPT_KEY_HANDLE hKey,
                     __in_bcount(cbInput) PBYTE pbInput, __in DWORD cbInput,
                     __in VOID* pPaddingInfo,
                     __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
                     __in DWORD cbOutput, __out DWORD* pcbResult,
                     __in DWORD dwFlags);

absl::Status Decrypt(__in NCRYPT_PROV_HANDLE hProvider,
                     __in NCRYPT_KEY_HANDLE hKey,
                     __in_bcount(cbInput) PBYTE pbInput, __in DWORD cbInput,
                     __in VOID* pPaddingInfo,
                     __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
                     __in DWORD cbOutput, __out DWORD* pcbResult,
                     __in DWORD dwFlags);

absl::Status IsAlgSupported(__in NCRYPT_PROV_HANDLE hProvider,
                            __in LPCWSTR pszAlgId, __in DWORD dwFlags);

absl::Status EnumAlgorithms(__in NCRYPT_PROV_HANDLE hProvider,
                            __in DWORD dwAlgOperations,
                            __out DWORD* pdwAlgCount,
                            __deref_out_ecount(*pdwAlgCount)
                                NCryptAlgorithmName** ppAlgList,
                            __in DWORD dwFlags);

absl::Status EnumKeys(__in NCRYPT_PROV_HANDLE hProvider,
                      __in_opt LPCWSTR pszScope,
                      __deref_out NCryptKeyName** ppKeyName,
                      __inout PVOID* ppEnumState, __in DWORD dwFlags,
                      __in_opt std::string test_config_path = "");

absl::Status ImportKey(__in NCRYPT_PROV_HANDLE hProvider,
                       __in_opt NCRYPT_KEY_HANDLE hImportKey,
                       __in LPCWSTR pszBlobType,
                       __in_opt NCryptBufferDesc* pParameterList,
                       __out NCRYPT_KEY_HANDLE* phKey,
                       __in_bcount(cbData) PBYTE pbData, __in DWORD cbData,
                       __in DWORD dwFlags);

absl::Status ExportKey(
    __in NCRYPT_PROV_HANDLE hProvider, __in NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey, __in LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc* pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput, __out DWORD* pcbResult, __in DWORD dwFlags);

absl::Status SignHash(__in NCRYPT_PROV_HANDLE hProvider,
                      __in NCRYPT_KEY_HANDLE hKey, __in_opt VOID* pPaddingInfo,
                      __in_bcount(cbHashValue) PBYTE pbHashValue,
                      __in DWORD cbHashValue,
                      __out_bcount_part_opt(cbSignature, *pcbResult)
                          PBYTE pbSignature,
                      __in DWORD cbSignature, __out DWORD* pcbResult,
                      __in DWORD dwFlags);

absl::Status VerifySignature(__in NCRYPT_PROV_HANDLE hProvider,
                             __in NCRYPT_KEY_HANDLE hKey,
                             __in_opt VOID* pPaddingInfo,
                             __in_bcount(cbHashValue) PBYTE pbHashValue,
                             __in DWORD cbHashValue,
                             __in_bcount(cbSignature) PBYTE pbSignature,
                             __in DWORD cbSignature, __in DWORD dwFlags);

absl::Status PromptUser(__in NCRYPT_PROV_HANDLE hProvider,
                        __in_opt NCRYPT_KEY_HANDLE hKey,
                        __in LPCWSTR pszOperation, __in DWORD dwFlags);

absl::Status NotifyChangeKey(__in NCRYPT_PROV_HANDLE hProvider,
                             __inout HANDLE* phEvent, __in DWORD dwFlags);

absl::Status SecretAgreement(__in NCRYPT_PROV_HANDLE hProvider,
                             __in NCRYPT_KEY_HANDLE hPrivKey,
                             __in NCRYPT_KEY_HANDLE hPubKey,
                             __out NCRYPT_SECRET_HANDLE* phAgreedSecret,
                             __in DWORD dwFlags);

absl::Status DeriveKey(__in NCRYPT_PROV_HANDLE hProvider,
                       __in_opt NCRYPT_SECRET_HANDLE hSharedSecret,
                       __in LPCWSTR pwszKDF,
                       __in_opt NCryptBufferDesc* pParameterList,
                       __out_bcount_part_opt(cbDerivedKey, *pcbResult)
                           PUCHAR pbDerivedKey,
                       __in DWORD cbDerivedKey, __out DWORD* pcbResult,
                       __in ULONG dwFlags);

absl::Status FreeSecret(__in NCRYPT_PROV_HANDLE hProvider,
                        __in NCRYPT_SECRET_HANDLE hSharedSecret);

}  // namespace cloud_kms::kmscng

#endif KMSCNG_MAIN_BRIDGE_H_
