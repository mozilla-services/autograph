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
#include "kmscng/cng_headers.h"
#include "kmscng/main/bridge.h"
#include "kmscng/util/logging.h"
#include "kmscng/util/status_utils.h"

namespace cloud_kms::kmscng {

SECURITY_STATUS WINAPI OpenProviderFn(__out NCRYPT_PROV_HANDLE* phProvider,
                                      __in LPCWSTR pszProviderName,
                                      __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = OpenProvider(phProvider, pszProviderName, dwFlags);
  return LogAndResolve("OpenProviderFn", status);
}

SECURITY_STATUS WINAPI FreeProviderFn(__in NCRYPT_PROV_HANDLE hProvider) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = FreeProvider(hProvider);
  return LogAndResolve("FreeProviderFn", status);
}

SECURITY_STATUS WINAPI OpenKeyFn(__inout NCRYPT_PROV_HANDLE hProvider,
                                 __out NCRYPT_KEY_HANDLE* phKey,
                                 __in LPCWSTR pszKeyName,
                                 __in_opt DWORD dwLegacyKeySpec,
                                 __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      OpenKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, dwFlags);
  return LogAndResolve("OpenKeyFn", status);
}

SECURITY_STATUS WINAPI CreatePersistedKeyFn(__in NCRYPT_PROV_HANDLE hProvider,
                                            __out NCRYPT_KEY_HANDLE* phKey,
                                            __in LPCWSTR pszAlgId,
                                            __in_opt LPCWSTR pszKeyName,
                                            __in DWORD dwLegacyKeySpec,
                                            __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = CreatePersistedKey(
      hProvider, phKey, pszAlgId, pszKeyName, dwLegacyKeySpec, dwFlags);
  return LogAndResolve("CreatePersistedKeyFn", status);
}

SECURITY_STATUS WINAPI GetProviderPropertyFn(
    __in NCRYPT_PROV_HANDLE hProvider, __in LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput, __out DWORD* pcbResult, __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = GetProviderProperty(hProvider, pszProperty, pbOutput,
                                            cbOutput, pcbResult, dwFlags);
  return LogAndResolve("GetProviderPropertyFn", status);
}

SECURITY_STATUS WINAPI GetKeyPropertyFn(
    __in NCRYPT_PROV_HANDLE hProvider, __in NCRYPT_KEY_HANDLE hKey,
    __in LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput, __out DWORD* pcbResult, __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = GetKeyProperty(hProvider, hKey, pszProperty, pbOutput,
                                       cbOutput, pcbResult, dwFlags);
  return LogAndResolve("GetKeyPropertyFn", status);
}

SECURITY_STATUS WINAPI SetProviderPropertyFn(__in NCRYPT_PROV_HANDLE hProvider,
                                             __in LPCWSTR pszProperty,
                                             __in_bcount(cbInput) PBYTE pbInput,
                                             __in DWORD cbInput,
                                             __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      SetProviderProperty(hProvider, pszProperty, pbInput, cbInput, dwFlags);
  return LogAndResolve("SetProviderPropertyFn", status);
}

SECURITY_STATUS WINAPI SetKeyPropertyFn(__in NCRYPT_PROV_HANDLE hProvider,
                                        __in NCRYPT_KEY_HANDLE hKey,
                                        __in LPCWSTR pszProperty,
                                        __in_bcount(cbInput) PBYTE pbInput,
                                        __in DWORD cbInput,
                                        __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      SetKeyProperty(hProvider, hKey, pszProperty, pbInput, cbInput, dwFlags);
  return LogAndResolve("SetKeyPropertyFn", status);
}

SECURITY_STATUS WINAPI FinalizeKeyFn(__in NCRYPT_PROV_HANDLE hProvider,
                                     __in NCRYPT_KEY_HANDLE hKey,
                                     __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = FinalizeKey(hProvider, hKey, dwFlags);
  return LogAndResolve("FinalizeKeyFn", status);
}

SECURITY_STATUS WINAPI DeleteKeyFn(__in NCRYPT_PROV_HANDLE hProvider,
                                   __inout NCRYPT_KEY_HANDLE hKey,
                                   __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = DeleteKey(hProvider, hKey, dwFlags);
  return LogAndResolve("DeleteKeyFn", status);
}

SECURITY_STATUS WINAPI FreeKeyFn(__in NCRYPT_PROV_HANDLE hProvider,
                                 __in NCRYPT_KEY_HANDLE hKey) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = FreeKey(hProvider, hKey);
  return LogAndResolve("FreeKeyFn", status);
}

SECURITY_STATUS WINAPI FreeBufferFn(__deref PVOID pvInput) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = FreeBuffer(pvInput);
  return LogAndResolve("FreeBufferFn", status);
}

SECURITY_STATUS WINAPI EncryptFn(__in NCRYPT_PROV_HANDLE hProvider,
                                 __in NCRYPT_KEY_HANDLE hKey,
                                 __in_bcount(cbInput) PBYTE pbInput,
                                 __in DWORD cbInput, __in VOID* pPaddingInfo,
                                 __out_bcount_part_opt(cbOutput, *pcbResult)
                                     PBYTE pbOutput,
                                 __in DWORD cbOutput, __out DWORD* pcbResult,
                                 __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = Encrypt(hProvider, hKey, pbInput, cbInput, pPaddingInfo,
                                pbOutput, cbOutput, pcbResult, dwFlags);
  return LogAndResolve("EncryptFn", status);
}

SECURITY_STATUS WINAPI DecryptFn(__in NCRYPT_PROV_HANDLE hProvider,
                                 __in NCRYPT_KEY_HANDLE hKey,
                                 __in_bcount(cbInput) PBYTE pbInput,
                                 __in DWORD cbInput, __in VOID* pPaddingInfo,
                                 __out_bcount_part_opt(cbOutput, *pcbResult)
                                     PBYTE pbOutput,
                                 __in DWORD cbOutput, __out DWORD* pcbResult,
                                 __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = Decrypt(hProvider, hKey, pbInput, cbInput, pPaddingInfo,
                                pbOutput, cbOutput, pcbResult, dwFlags);
  return LogAndResolve("DecryptFn", status);
}

SECURITY_STATUS WINAPI IsAlgSupportedFn(__in NCRYPT_PROV_HANDLE hProvider,
                                        __in LPCWSTR pszAlgId,
                                        __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = IsAlgSupported(hProvider, pszAlgId, dwFlags);
  return LogAndResolve("IsAlgSupportedFn", status);
}

SECURITY_STATUS WINAPI EnumAlgorithmsFn(__in NCRYPT_PROV_HANDLE hProvider,
                                        __in DWORD dwAlgOperations,
                                        __out DWORD* pdwAlgCount,
                                        __deref_out_ecount(*pdwAlgCount)
                                            NCryptAlgorithmName** ppAlgList,
                                        __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = EnumAlgorithms(hProvider, dwAlgOperations, pdwAlgCount,
                                       ppAlgList, dwFlags);
  return LogAndResolve("EnumAlgorithmsFn", status);
}

SECURITY_STATUS WINAPI EnumKeysFn(__in NCRYPT_PROV_HANDLE hProvider,
                                  __in_opt LPCWSTR pszScope,
                                  __deref_out NCryptKeyName** ppKeyName,
                                  __inout PVOID* ppEnumState,
                                  __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      EnumKeys(hProvider, pszScope, ppKeyName, ppEnumState, dwFlags);
  return LogAndResolve("EnumKeysFn", status);
}

SECURITY_STATUS WINAPI ImportKeyFn(__in NCRYPT_PROV_HANDLE hProvider,
                                   __in_opt NCRYPT_KEY_HANDLE hImportKey,
                                   __in LPCWSTR pszBlobType,
                                   __in_opt NCryptBufferDesc* pParameterList,
                                   __out NCRYPT_KEY_HANDLE* phKey,
                                   __in_bcount(cbData) PBYTE pbData,
                                   __in DWORD cbData, __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      ImportKey(hProvider, hImportKey, pszBlobType, pParameterList, phKey,
                pbData, cbData, dwFlags);
  return LogAndResolve("ImportKeyFn", status);
}

SECURITY_STATUS WINAPI
ExportKeyFn(__in NCRYPT_PROV_HANDLE hProvider, __in NCRYPT_KEY_HANDLE hKey,
            __in_opt NCRYPT_KEY_HANDLE hExportKey, __in LPCWSTR pszBlobType,
            __in_opt NCryptBufferDesc* pParameterList,
            __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
            __in DWORD cbOutput, __out DWORD* pcbResult, __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      ExportKey(hProvider, hKey, hExportKey, pszBlobType, pParameterList,
                pbOutput, cbOutput, pcbResult, dwFlags);
  return LogAndResolve("ExportKeyFn", status);
}

SECURITY_STATUS WINAPI
SignHashFn(__in NCRYPT_PROV_HANDLE hProvider, __in NCRYPT_KEY_HANDLE hKey,
           __in_opt VOID* pPaddingInfo,
           __in_bcount(cbHashValue) PBYTE pbHashValue, __in DWORD cbHashValue,
           __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
           __in DWORD cbSignature, __out DWORD* pcbResult, __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      SignHash(hProvider, hKey, pPaddingInfo, pbHashValue, cbHashValue,
               pbSignature, cbSignature, pcbResult, dwFlags);
  return LogAndResolve("SignHashFn", status);
}

SECURITY_STATUS WINAPI VerifySignatureFn(
    __in NCRYPT_PROV_HANDLE hProvider, __in NCRYPT_KEY_HANDLE hKey,
    __in_opt VOID* pPaddingInfo, __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in DWORD cbHashValue, __in_bcount(cbSignature) PBYTE pbSignature,
    __in DWORD cbSignature, __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      VerifySignature(hProvider, hKey, pPaddingInfo, pbHashValue, cbHashValue,
                      pbSignature, cbSignature, dwFlags);
  return LogAndResolve("VerifySignatureFn", status);
}

SECURITY_STATUS WINAPI PromptUserFn(__in NCRYPT_PROV_HANDLE hProvider,
                                    __in_opt NCRYPT_KEY_HANDLE hKey,
                                    __in LPCWSTR pszOperation,
                                    __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = PromptUser(hProvider, hKey, pszOperation, dwFlags);
  return LogAndResolve("PromptUserFn", status);
}

SECURITY_STATUS WINAPI NotifyChangeKeyFn(__in NCRYPT_PROV_HANDLE hProvider,
                                         __inout HANDLE* phEvent,
                                         __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = NotifyChangeKey(hProvider, phEvent, dwFlags);
  return LogAndResolve("NotifyChangeKeyFn", status);
}

SECURITY_STATUS WINAPI SecretAgreementFn(
    __in NCRYPT_PROV_HANDLE hProvider, __in NCRYPT_KEY_HANDLE hPrivKey,
    __in NCRYPT_KEY_HANDLE hPubKey, __out NCRYPT_SECRET_HANDLE* phAgreedSecret,
    __in DWORD dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      SecretAgreement(hProvider, hPrivKey, hPubKey, phAgreedSecret, dwFlags);
  return LogAndResolve("SecretAgreementFn", status);
}

SECURITY_STATUS WINAPI DeriveKeyFn(
    __in NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_SECRET_HANDLE hSharedSecret, __in LPCWSTR pwszKDF,
    __in_opt NCryptBufferDesc* pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    __in DWORD cbDerivedKey, __out DWORD* pcbResult, __in ULONG dwFlags) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status =
      DeriveKey(hProvider, hSharedSecret, pwszKDF, pParameterList, pbDerivedKey,
                cbDerivedKey, pcbResult, dwFlags);
  return LogAndResolve("DeriveKeyFn", status);
}

SECURITY_STATUS WINAPI FreeSecretFn(__in NCRYPT_PROV_HANDLE hProvider,
                                    __in NCRYPT_SECRET_HANDLE hSharedSecret) {
  // TODO(b/270419822): Clean OpenSSL error stack.
  absl::Status status = FreeSecret(hProvider, hSharedSecret);
  return LogAndResolve("FreeSecretFn", status);
}

static NCRYPT_KEY_STORAGE_FUNCTION_TABLE kFunctionTable = {
    BCRYPT_MAKE_INTERFACE_VERSION(1, 0),
    OpenProviderFn,
    OpenKeyFn,
    CreatePersistedKeyFn,
    GetProviderPropertyFn,
    GetKeyPropertyFn,
    SetProviderPropertyFn,
    SetKeyPropertyFn,
    FinalizeKeyFn,
    DeleteKeyFn,
    FreeProviderFn,
    FreeKeyFn,
    FreeBufferFn,
    EncryptFn,
    DecryptFn,
    IsAlgSupportedFn,
    EnumAlgorithmsFn,
    EnumKeysFn,
    ImportKeyFn,
    ExportKeyFn,
    SignHashFn,
    VerifySignatureFn,
    PromptUserFn,
    NotifyChangeKeyFn,
    SecretAgreementFn,
    DeriveKeyFn,
    FreeSecretFn};

}  // namespace cloud_kms::kmscng

NTSTATUS WINAPI GetKeyStorageInterface(
    __in LPCWSTR pszProviderName,
    __out NCRYPT_KEY_STORAGE_FUNCTION_TABLE** ppFunctionTable,
    __in DWORD dwFlags) {
  if (!ppFunctionTable) {
    return NTE_INVALID_PARAMETER;
  }
  *ppFunctionTable = &cloud_kms::kmscng::kFunctionTable;
  return ERROR_SUCCESS;
}
