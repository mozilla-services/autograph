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

#include "kmscng/main/bridge.h"

#include <string_view>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "common/status_macros.h"
#include "kmscng/algorithm_details.h"
#include "kmscng/config/config.h"
#include "kmscng/config/config.pb.h"
#include "kmscng/object.h"
#include "kmscng/object_loader.h"
#include "kmscng/operation/sign_utils.h"
#include "kmscng/provider.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/logging.h"
#include "kmscng/util/status_utils.h"
#include "kmscng/util/string_utils.h"

namespace cloud_kms::kmscng {
namespace {

absl::Status ValidateFlags(uint32_t flags) {
  if (flags != 0 && flags != NCRYPT_SILENT_FLAG && flags != BCRYPT_PAD_PKCS1) {
    return NewInvalidArgumentError(
        absl::StrFormat("unsupported flag specified: %u", flags), NTE_BAD_FLAGS,
        SOURCE_LOCATION);
  }
  return absl::OkStatus();
}

}  // namespace

// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider
absl::Status OpenProvider(__out NCRYPT_PROV_HANDLE* phProvider,
                          __in LPCWSTR pszProviderName, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "OpenProvider invoked\n"
      << "Process id: " << GetCurrentProcessId()
      << "Provider name: " << WideToString(std::wstring(pszProviderName))
      << "\n"
      << "Flags: " << dwFlags << "\n\n";
  if (phProvider == nullptr) {
    return NewInvalidArgumentError("the provider handle cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  // Check that the user is actually trying to open our provider, and not a
  // default / different provider.
  if (!pszProviderName || std::wstring_view(pszProviderName) != kProviderName) {
    return NewInvalidArgumentError("unexpected provider name",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  RETURN_IF_ERROR(ValidateFlags(dwFlags));

  *phProvider = reinterpret_cast<NCRYPT_PROV_HANDLE>(new Provider());
  return absl::OkStatus();
}

// This function is called by NCryptFreeObject:
// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreeobject
absl::Status FreeProvider(__in NCRYPT_PROV_HANDLE hProvider) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "FreeProvider invoked\n"
      << "Provider: " << hProvider << "\n\n";
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(hProvider));
  delete prov;
  return absl::OkStatus();
}

// This function is called by NCryptGetProperty:
// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptgetproperty
absl::Status GetProviderProperty(__in NCRYPT_PROV_HANDLE hProvider,
                                 __in LPCWSTR pszProperty,
                                 __out_bcount_part_opt(cbOutput, *pcbResult)
                                     PBYTE pbOutput,
                                 __in DWORD cbOutput, __out DWORD* pcbResult,
                                 __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "GetProviderProperty invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Property name: " << WideToString(std::wstring(pszProperty)) << "\n"
      << "Output: " << uintptr_t(pbOutput) << "\n"
      << "Output size: " << cbOutput << "\n"
      << "Output result size: " << uintptr_t(pcbResult) << "\n"
      << "Flags: " << dwFlags << "\n\n";
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(hProvider));
  if (!pszProperty) {
    return NewInvalidArgumentError("pszProperty cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  if (!pcbResult) {
    return NewInvalidArgumentError("pcbResult cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  RETURN_IF_ERROR(ValidateFlags(dwFlags));

  ASSIGN_OR_RETURN(std::string_view property_value,
                   prov->GetProperty(pszProperty));
  *pcbResult = property_value.size();

  // Return size required to hold the property value if output buffer is null.
  if (!pbOutput) {
    return absl::OkStatus();
  }

  // Check provided buffer size to ensure the property value fits.
  if (cbOutput < property_value.size()) {
    return NewOutOfRangeError(
        absl::StrFormat("cbOutput size=%u not large enough to fit "
                        "property value of size %u",
                        cbOutput, property_value.size()),
        SOURCE_LOCATION);
  }

  property_value.copy(reinterpret_cast<char*>(pbOutput), property_value.size());
  return absl::OkStatus();
}

// This function is called by NCryptSetProperty:
// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsetproperty
absl::Status SetProviderProperty(__in NCRYPT_PROV_HANDLE hProvider,
                                 __in LPCWSTR pszProperty,
                                 __in_bcount(cbInput) PBYTE pbInput,
                                 __in DWORD cbInput, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "SetProviderProperty invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Property name: " << WideToString(std::wstring(pszProperty)) << "\n"
      << "Input: " << uintptr_t(pbInput) << "\n"
      << "Input size: " << cbInput << "\n"
      << "Flags: " << dwFlags << "\n\n";
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(hProvider));
  if (!pszProperty) {
    return NewInvalidArgumentError("pszProperty cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  if (!pbInput) {
    return NewInvalidArgumentError("pbInput cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  RETURN_IF_ERROR(ValidateFlags(dwFlags));

  return prov->SetProperty(
      pszProperty, std::string(reinterpret_cast<char*>(pbInput), cbInput));
}

// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenkey
absl::Status OpenKey(__inout NCRYPT_PROV_HANDLE hProvider,
                     __out NCRYPT_KEY_HANDLE* phKey, __in LPCWSTR pszKeyName,
                     __in_opt DWORD dwLegacyKeySpec, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "OpenKey invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Key name: " << WideToString(std::wstring(pszKeyName)) << "\n"
      << "LegacyKeySpec: " << dwLegacyKeySpec << "\n"
      << "Flags: " << dwFlags << "\n\n";
  if (hProvider == 0) {
    return NewInvalidArgumentError("The provider handle cannot be null",
                                   NTE_INVALID_HANDLE, SOURCE_LOCATION);
  }
  if (phKey == nullptr) {
    return NewInvalidArgumentError("the key handle cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  if (!pszKeyName) {
    return NewInvalidArgumentError("the key name cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  if (dwLegacyKeySpec != AT_KEYEXCHANGE && dwLegacyKeySpec != AT_SIGNATURE) {
    return NewInvalidArgumentError(
        absl::StrFormat("unsupported legacy key spec specified: %u",
                        dwLegacyKeySpec),
        NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  dwFlags = dwFlags & ~NCRYPT_SILENT_FLAG;
  dwFlags = dwFlags & ~NCRYPT_MACHINE_KEY_FLAG;
  if (dwFlags != 0) {
    return NewInvalidArgumentError(
        absl::StrFormat("unsupported flag specified: %u", dwFlags),
        NTE_BAD_FLAGS, SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(Object * object,
                   Object::New(hProvider, WideToString(pszKeyName)));
  *phKey = reinterpret_cast<NCRYPT_KEY_HANDLE>(object);
  return absl::OkStatus();
}

// This function is called by NCryptFreeObject:
// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreeobject
absl::Status FreeKey(__in NCRYPT_PROV_HANDLE hProvider,
                     __in NCRYPT_KEY_HANDLE hKey) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "FreeKey invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Key: " << hKey << "\n\n";
  ASSIGN_OR_RETURN(Object * obj, ValidateKeyHandle(hProvider, hKey));
  if (obj) {
    delete obj;
  }
  return absl::OkStatus();
}

// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptexportkey
absl::Status ExportKey(
    __in NCRYPT_PROV_HANDLE hProvider, __in NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey, __in LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc* pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in DWORD cbOutput, __out DWORD* pcbResult, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "ExportKey invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Key: " << hKey << "\n"
      << "Export Key: " << hExportKey << "\n"
      << "Blob type: " << WideToString(std::wstring(pszBlobType)) << "\n"
      << "Parameter list: " << uintptr_t(pParameterList) << "\n"
      << "Output: " << uintptr_t(pbOutput) << "\n"
      << "Output size: " << cbOutput << "\n"
      << "Output result size: " << uintptr_t(pcbResult) << "\n"
      << "Flags: " << dwFlags << "\n\n";
  ASSIGN_OR_RETURN(Object * object, ValidateKeyHandle(hProvider, hKey));
  if (hExportKey) {
    return NewInvalidArgumentError("hExportKey is not supported",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  constexpr std::wstring_view kEccPublicKeyType(BCRYPT_ECCPUBLIC_BLOB);
  constexpr std::wstring_view kRsaPublicKeyType(BCRYPT_RSAPUBLIC_BLOB);
  if (pszBlobType != kEccPublicKeyType && pszBlobType != kRsaPublicKeyType) {
    return NewInvalidArgumentError(
        absl::StrFormat("blob type not supported: %s",
                        WideToString(pszBlobType)),
        NTE_BAD_TYPE, SOURCE_LOCATION);
  }
  if (!pcbResult) {
    return NewInvalidArgumentError("pcbResult cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  RETURN_IF_ERROR(ValidateFlags(dwFlags));

  ASSIGN_OR_RETURN(std::vector<uint8_t> serialized_pub_key,
                   SerializePublicKey(object));
  *pcbResult = serialized_pub_key.size();

  // Return size required to hold the property value if output buffer is null.
  if (!pbOutput) {
    return absl::OkStatus();
  }

  // Check provided buffer size to ensure the property value fits.
  if (cbOutput < serialized_pub_key.size()) {
    return NewOutOfRangeError(
        absl::StrFormat("cbOutput size=%u not large enough to fit "
                        "property value of size %u",
                        cbOutput, serialized_pub_key.size()),
        SOURCE_LOCATION);
  }

  std::copy(serialized_pub_key.begin(), serialized_pub_key.end(), pbOutput);
  return absl::OkStatus();
}

// This function is called by NCryptGetProperty:
// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptgetproperty
absl::Status GetKeyProperty(__in NCRYPT_PROV_HANDLE hProvider,
                            __in NCRYPT_KEY_HANDLE hKey,
                            __in LPCWSTR pszProperty,
                            __out_bcount_part_opt(cbOutput, *pcbResult)
                                PBYTE pbOutput,
                            __in DWORD cbOutput, __out DWORD* pcbResult,
                            __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "GetKeyProperty invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Key: " << hKey << "\n"
      << "Property name: " << WideToString(std::wstring(pszProperty)) << "\n"
      << "Output: " << uintptr_t(pbOutput) << "\n"
      << "Output size: " << cbOutput << "\n"
      << "Output result size: " << uintptr_t(pcbResult) << "\n"
      << "Flags: " << dwFlags << "\n\n";
  ASSIGN_OR_RETURN(Object * object, ValidateKeyHandle(hProvider, hKey));
  if (!pszProperty) {
    return NewInvalidArgumentError("pszProperty cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  if (!pcbResult) {
    return NewInvalidArgumentError("pcbResult cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  RETURN_IF_ERROR(ValidateFlags(dwFlags));

  ASSIGN_OR_RETURN(std::string_view property_value,
                   object->GetProperty(pszProperty));
  *pcbResult = property_value.size();

  // Return size required to hold the property value if output buffer is null.
  if (!pbOutput) {
    return absl::OkStatus();
  }

  // Check provided buffer size to ensure the property value fits.
  if (cbOutput < property_value.size()) {
    return NewOutOfRangeError(
        absl::StrFormat("cbOutput size=%u not large enough to fit "
                        "property value of size %u",
                        cbOutput, property_value.size()),
        SOURCE_LOCATION);
  }

  property_value.copy(reinterpret_cast<char*>(pbOutput), property_value.size());
  return absl::OkStatus();
}

// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptenumkeys
absl::Status EnumKeys(__in NCRYPT_PROV_HANDLE hProvider,
                      __in_opt LPCWSTR pszScope,
                      __deref_out NCryptKeyName** ppKeyName,
                      __inout PVOID* ppEnumState, __in DWORD dwFlags,
                      __in_opt std::string test_config_path) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "EnumKeys invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Flags: " << dwFlags << "\n\n";
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(hProvider));
  if (pszScope) {
    return NewInvalidArgumentError("pszScope should be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  if (!ppKeyName) {
    return NewInvalidArgumentError("ppKeyName cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  dwFlags = dwFlags & ~NCRYPT_SILENT_FLAG;
  dwFlags = dwFlags & ~NCRYPT_MACHINE_KEY_FLAG;
  if (dwFlags != 0) {
    return NewInvalidArgumentError(
        absl::StrFormat("unsupported flag specified: %u", dwFlags),
        NTE_BAD_FLAGS, SOURCE_LOCATION);
  }

  EnumState* enum_state;
  ProviderConfig config;
  // Generate CKV list if this is the first call to EnumKeys.
  if (!*ppEnumState) {
    // If test_config_path exists, load config from there. This is only used
    // for internal testing.
    if (!test_config_path.empty()) {
      ASSIGN_OR_RETURN(config, LoadConfigFromFile(test_config_path));
    } else {
      // Load config from well-known system path.
      ASSIGN_OR_RETURN(config,
                       LoadConfigFromFile("C:\\Windows\\KMSCNG\\config.yaml"));
    }
    // Load CKV list from config file.
    ASSIGN_OR_RETURN(std::vector<HeapAllocatedKeyDetails> ckv_list,
                     BuildCkvList(hProvider, config));
    *ppEnumState = new EnumState{
        .key_details = ckv_list,
        .current = 0,
    };
    enum_state = reinterpret_cast<EnumState*>(*ppEnumState);
  } else {
    // Check ppEnumState value to make sure it's a valid vector index.
    enum_state = reinterpret_cast<EnumState*>(*ppEnumState);
    if (enum_state->current > enum_state->key_details.size()) {
      return NewInvalidArgumentError(
          absl::StrFormat("unrecognized ppEnumState value: %u",
                          enum_state->current),
          NTE_INVALID_PARAMETER, SOURCE_LOCATION);
    }
  }
  if (enum_state->current == enum_state->key_details.size()) {
    return NewInvalidArgumentError(
        absl::StrFormat("end of enumeration reached: %u", enum_state->current),
        NTE_NO_MORE_ITEMS, SOURCE_LOCATION);
  }
  *ppKeyName =
      enum_state->key_details[enum_state->current].NewNCryptKeyName().release();
  enum_state->current += 1;

  return absl::OkStatus();
}

// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsignhash
absl::Status SignHash(__in NCRYPT_PROV_HANDLE hProvider,
                      __in NCRYPT_KEY_HANDLE hKey, __in_opt VOID* pPaddingInfo,
                      __in_bcount(cbHashValue) PBYTE pbHashValue,
                      __in DWORD cbHashValue,
                      __out_bcount_part_opt(cbSignature, *pcbResult)
                          PBYTE pbSignature,
                      __in DWORD cbSignature, __out DWORD* pcbResult,
                      __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "SignHash invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Key: " << hKey << "\n"
      << "Padding info: " << uintptr_t(pPaddingInfo) << "\n"
      << "Hash value: " << uintptr_t(pbHashValue) << "\n"
      << "Hash value size: " << cbHashValue << "\n"
      << "Signature: " << uintptr_t(pbSignature) << "\n"
      << "Signature size: " << cbSignature << "\n"
      << "Signature result size: " << uintptr_t(pcbResult) << "\n"
      << "Flags: " << dwFlags << "\n\n";
  ASSIGN_OR_RETURN(Object * object, ValidateKeyHandle(hProvider, hKey));
  if (!pbHashValue) {
    return NewInvalidArgumentError("pbHashValue cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  if (!pcbResult) {
    return NewInvalidArgumentError("pcbResult cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  RETURN_IF_ERROR(ValidateFlags(dwFlags));

  // Check key properties against the expected AlgorithmDetails.
  RETURN_IF_ERROR(ValidateKeyPreconditions(object));

  ASSIGN_OR_RETURN(size_t signature_length, SignatureLength(object));
  *pcbResult = static_cast<uint32_t>(signature_length);

  // Return size required to hold the signature if output buffer is null.
  if (!pbSignature) {
    return absl::OkStatus();
  }

  // Check provided buffer size to ensure the property value fits.
  if (cbSignature < *pcbResult) {
    return NewOutOfRangeError(
        absl::StrFormat("cbSignature size=%u not large enough to fit "
                        "property value of size %u",
                        cbSignature, *pcbResult),
        SOURCE_LOCATION);
  }

  RETURN_IF_ERROR(
      SignDigest(object, absl::Span<const uint8_t>(pbHashValue, cbHashValue),
                 absl::Span<uint8_t>(pbSignature, cbSignature)));
  return absl::OkStatus();
}

// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptisalgsupported
absl::Status IsAlgSupported(__in NCRYPT_PROV_HANDLE hProvider,
                            __in LPCWSTR pszAlgId, __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "IsAlgSupported invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Alg Id: " << WideToString(std::wstring(pszAlgId)) << "\n"
      << "Flags: " << dwFlags << "\n\n";
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(hProvider));
  if (!pszAlgId) {
    return NewInvalidArgumentError("pszAlgId cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  RETURN_IF_ERROR(ValidateFlags(dwFlags));

  return IsSupportedAlgorithmIdentifier(pszAlgId);
}

// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptenumalgorithms
absl::Status EnumAlgorithms(__in NCRYPT_PROV_HANDLE hProvider,
                            __in DWORD dwAlgOperations,
                            __out DWORD* pdwAlgCount,
                            __deref_out_ecount(*pdwAlgCount)
                                NCryptAlgorithmName** ppAlgList,
                            __in DWORD dwFlags) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "EnumAlgorithms invoked\n"
      << "Provider: " << hProvider << "\n"
      << "Alg Operations: " << dwAlgOperations << "\n"
      << "Flags: " << dwFlags << "\n\n";
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(hProvider));
  dwAlgOperations = dwAlgOperations & ~NCRYPT_SIGNATURE_OPERATION;
  if (dwAlgOperations) {
    return NewInvalidArgumentError("invalid dwAlgOperations specified",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  if (!pdwAlgCount) {
    return NewInvalidArgumentError("pdwAlgCount cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  if (!ppAlgList) {
    return NewInvalidArgumentError("ppAlgList cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  RETURN_IF_ERROR(ValidateFlags(dwFlags));

  *ppAlgList = new NCryptAlgorithmName[kAlgorithmNames.size()];
  std::copy_n(kAlgorithmNames.data(), kAlgorithmNames.size(), *ppAlgList);
  *pdwAlgCount = kAlgorithmNames.size();

  return absl::OkStatus();
}

// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfreebuffer
absl::Status FreeBuffer(__deref PVOID pvInput) {
  LOG_IF(INFO, std::getenv(kVerboseLoggingEnvVariable))
      << "FreeBuffer invoked\n\n";
  if (!pvInput) {
    return NewInvalidArgumentError("pvInput cannot be null",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  delete pvInput;
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmscng
