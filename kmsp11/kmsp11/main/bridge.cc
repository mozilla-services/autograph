// Copyright 2021 Google LLC
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
#include "absl/types/optional.h"
#include "common/status_macros.h"
#include "glog/logging.h"
#include "kmsp11/config/config.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/fork_support.h"
#include "kmsp11/main/function_list.h"
#include "kmsp11/provider.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/global_provider.h"
#include "kmsp11/util/logging.h"
#include "kmsp11/util/status_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

constexpr CK_FUNCTION_LIST kFunctionList = NewFunctionList();

absl::StatusOr<Provider*> GetProvider() {
  Provider* provider = GetGlobalProvider();
  if (!provider) {
    return NotInitializedError(SOURCE_LOCATION);
  }
  return provider;
}

absl::StatusOr<Token*> GetToken(CK_SLOT_ID slot_id) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  return provider->TokenAt(slot_id);
}

absl::StatusOr<std::shared_ptr<Session>> GetSession(
    CK_SESSION_HANDLE session_handle) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  return provider->GetSession(session_handle);
}

}  // namespace

// Initialize the library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002322
absl::Status Initialize(CK_VOID_PTR pInitArgs) {
  auto* init_args = static_cast<CK_C_INITIALIZE_ARGS*>(pInitArgs);
  if (init_args) {
    if ((init_args->flags & CKF_OS_LOCKING_OK) != CKF_OS_LOCKING_OK &&
        (init_args->CreateMutex || init_args->DestroyMutex ||
         init_args->LockMutex || init_args->UnlockMutex)) {
      return NewInvalidArgumentError("library requires os locking",
                                     CKR_CANT_LOCK, SOURCE_LOCATION);
    }
    if ((init_args->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS) ==
        CKF_LIBRARY_CANT_CREATE_OS_THREADS) {
      return NewInvalidArgumentError("library requires thread creation",
                                     CKR_NEED_TO_CREATE_THREADS,
                                     SOURCE_LOCATION);
    }
  }

  LibraryConfig config;
  if (init_args && init_args->pReserved) {
    // This behavior isn't part of the spec, but there are numerous libraries
    // in the wild that allow specifying a config file in pInitArgs->pReserved.
    // There's also support for providing config this way in the OpenSSL engine:
    // https://github.com/OpenSC/libp11/blob/4084f83ee5ea51353facf151126b7d6d739d0784/src/eng_front.c#L62
    ASSIGN_OR_RETURN(
        config, LoadConfigFromFile(static_cast<char*>(init_args->pReserved)));
  } else {
    ASSIGN_OR_RETURN(config, LoadConfigFromEnvironment());
  }

  // Registering fork handlers is a one-time operation.
  if (!config.skip_fork_handlers()) {
    static const absl::Status kForkHandlersRegistered = RegisterForkHandlers();
    RETURN_IF_ERROR(kForkHandlersRegistered);
  }

  Provider* existing_provider = GetGlobalProvider();
  if (existing_provider) {
    return FailedPreconditionError("the library is already initialized",
                                   CKR_CRYPTOKI_ALREADY_INITIALIZED,
                                   SOURCE_LOCATION);
  }

  CHECK(kCryptoLibraryInitialized);
  if (config.require_fips_mode()) {
    absl::Status self_test_result = CheckFipsSelfTest();
    CHECK(self_test_result.ok()) << "FIPS tests failed: " << self_test_result;
  }

  // Provider::New emits info log messages (for example, noting that a CKV is
  // being skipped due to state DISABLED), so logging should be initialized
  // before it is invoked.
  RETURN_IF_ERROR(
      InitializeLogging(config.log_directory(), config.log_filename_suffix()));

  absl::StatusOr<std::unique_ptr<Provider>> new_provider =
      Provider::New(config);
  if (!new_provider.ok()) {
    ShutdownLogging();
    return new_provider.status();
  }

  return SetGlobalProvider(std::move(new_provider).value());
}

// Shut down the library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc383864872
absl::Status Finalize(CK_VOID_PTR pReserved) {
  RETURN_IF_ERROR(GetProvider());
  RETURN_IF_ERROR(ReleaseGlobalProvider());
  ShutdownLogging();
  return absl::OkStatus();
}

// Get basic information about the library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002324
absl::Status GetInfo(CK_INFO_PTR pInfo) {
  ASSIGN_OR_RETURN(const Provider* provider, GetProvider());
  if (!pInfo) {
    return NullArgumentError("pInfo", SOURCE_LOCATION);
  }

  *pInfo = provider->info();
  return absl::OkStatus();
}

// Get pointers to the functions exposed in this library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc319313512
absl::Status GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
  // Note that GetFunctionList is the only Cryptoki function that may be called
  // before the library is initialized.
  if (!ppFunctionList) {
    return NullArgumentError("ppFunctionList", SOURCE_LOCATION);
  }
  *ppFunctionList = const_cast<CK_FUNCTION_LIST*>(&kFunctionList);
  return absl::OkStatus();
}

// Get the list of slots in this library.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002327
// Note that tokenPresent is always ignored in our library, since we do not have
// removable tokens.
absl::Status GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                         CK_ULONG_PTR pulCount) {
  ASSIGN_OR_RETURN(const Provider* provider, GetProvider());
  if (!pulCount) {
    return NullArgumentError("pulCount", SOURCE_LOCATION);
  }

  if (!pSlotList) {
    *pulCount = provider->token_count();
    return absl::OkStatus();
  }

  if (*pulCount < provider->token_count()) {
    absl::Status result =
        OutOfRangeError(absl::StrFormat("*pulCount=%d but there are %d tokens",
                                        *pulCount, provider->token_count()),
                        SOURCE_LOCATION);
    *pulCount = provider->token_count();
    return result;
  }

  for (size_t i = 0; i < provider->token_count(); i++) {
    pSlotList[i] = i;
  }
  *pulCount = provider->token_count();
  return absl::OkStatus();
}

// Get information about a slot in the system.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002328
absl::Status GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo) {
  ASSIGN_OR_RETURN(const Token* token, GetToken(slotID));
  if (!pInfo) {
    return NullArgumentError("pInfo", SOURCE_LOCATION);
  }

  *pInfo = token->slot_info();
  return absl::OkStatus();
}

// Get information about a token in the system.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002329
absl::Status GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo) {
  ASSIGN_OR_RETURN(const Token* token, GetToken(slotID));
  if (!pInfo) {
    return NullArgumentError("pInfo", SOURCE_LOCATION);
  }

  *pInfo = token->token_info();
  return absl::OkStatus();
}

// Open a session between an application and a token in a particular slot.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002337
// Note that `pApplication` and `notify` are always ignored in our library,
// which does not support notifications.
absl::Status OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                         CK_VOID_PTR pApplication, CK_NOTIFY notify,
                         CK_SESSION_HANDLE_PTR phSession) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());

  if ((flags & CKF_SERIAL_SESSION) != CKF_SERIAL_SESSION) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "parallel sessions are not supported",
                    CKR_SESSION_PARALLEL_NOT_SUPPORTED, SOURCE_LOCATION);
  }
  if (!phSession) {
    return NullArgumentError("phSession", SOURCE_LOCATION);
  }

  SessionType session_type = (flags & CKF_RW_SESSION) == CKF_RW_SESSION
                                 ? SessionType::kReadWrite
                                 : SessionType::kReadOnly;
  ASSIGN_OR_RETURN(*phSession, provider->OpenSession(slotID, session_type));
  return absl::OkStatus();
}

// Close a session between an application and a token.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc383864884
absl::Status CloseSession(CK_SESSION_HANDLE hSession) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  return provider->CloseSession(hSession);
}

// Close all sessions between an application and a token.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002339
absl::Status CloseAllSessions(CK_SLOT_ID slotID) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  return provider->CloseAllSessions(slotID);
}

// Get information about a session.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002340
absl::Status GetSessionInfo(CK_SESSION_HANDLE hSession,
                            CK_SESSION_INFO_PTR pInfo) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session,
                   provider->GetSession(hSession));
  if (!pInfo) {
    return NullArgumentError("pInfo", SOURCE_LOCATION);
  }

  *pInfo = session->info();
  return absl::OkStatus();
}

// Log a user into a token.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002343
// Note that pPin and ulPinLen are always ignored in this library.
absl::Status Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                   CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session,
                   provider->GetSession(hSession));
  return session->token()->Login(userType);
}

// Log a user out from a token.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002344
absl::Status Logout(CK_SESSION_HANDLE hSession) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session,
                   provider->GetSession(hSession));
  return session->token()->Logout();
}

// Get a list of mechanisms supported in a token.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002331
absl::Status GetMechanismList(CK_SLOT_ID slotID,
                              CK_MECHANISM_TYPE_PTR pMechanismList,
                              CK_ULONG_PTR pulCount) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  RETURN_IF_ERROR(GetToken(slotID).status());  // ensure slotID is valid
  if (!pulCount) {
    return NullArgumentError("pulCount", SOURCE_LOCATION);
  }

  absl::Span<const CK_MECHANISM_TYPE> types = provider->Mechanisms();

  if (!pMechanismList) {
    *pulCount = types.size();
    return absl::OkStatus();
  }

  if (*pulCount < types.size()) {
    absl::Status result = OutOfRangeError(
        absl::StrFormat("*pulCount=%d but there are %d mechanisms", *pulCount,
                        types.size()),
        SOURCE_LOCATION);
    *pulCount = types.size();
    return result;
  }

  for (size_t i = 0; i < types.size(); i++) {
    pMechanismList[i] = types[i];
  }
  *pulCount = types.size();
  return absl::OkStatus();
}

// Get information about a mechanism supported in a token.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002332
absl::Status GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                              CK_MECHANISM_INFO_PTR pInfo) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  RETURN_IF_ERROR(GetToken(slotID).status());  // ensure slotID is valid
  if (!pInfo) {
    return NullArgumentError("pInfo", SOURCE_LOCATION);
  }
  ASSIGN_OR_RETURN(*pInfo, provider->MechanismInfo(type));
  return absl::OkStatus();
}

// Get the values of the supplied attributes for the given object.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002350
absl::Status GetAttributeValue(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject,
                               CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  ASSIGN_OR_RETURN(std::shared_ptr<Object> object,
                   session->token()->GetObject(hObject));
  if (!pTemplate) {
    return NullArgumentError("pTemplate", SOURCE_LOCATION);
  }

  absl::Status result = absl::OkStatus();
  for (CK_ATTRIBUTE& attr : absl::MakeSpan(pTemplate, ulCount)) {
    absl::StatusOr<std::string_view> value =
        object->attributes().Value(attr.type);

    // C_GetAttributeValue cases 1 and 2
    if (!value.ok()) {
      result = value.status();
      attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
      continue;
    }

    // C_GetAttributeValue case 3
    if (!attr.pValue) {
      attr.ulValueLen = value->size();
      continue;
    }

    // C_GetAttributeValue case 4
    if (attr.ulValueLen >= value->size()) {
      std::copy(value->begin(), value->end(), static_cast<char*>(attr.pValue));
      attr.ulValueLen = value->size();
      continue;
    }

    // C_GetAttributeValue case 5
    attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
    result = OutOfRangeError(
        absl::StrFormat(
            "attribute %#X is of length %d, received buffer of length %d",
            attr.type, value->size(), attr.ulValueLen),
        SOURCE_LOCATION);
  }

  return result;
}

// Begin an object browsing operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002352
absl::Status FindObjectsInit(CK_SESSION_HANDLE hSession,
                             CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));

  if (ulCount > 0 && !pTemplate) {
    return NullArgumentError("pTemplate", SOURCE_LOCATION);
  }

  return session->FindObjectsInit(absl::MakeConstSpan(pTemplate, ulCount));
}

// Continue an object browsing operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002353
absl::Status FindObjects(CK_SESSION_HANDLE hSession,
                         CK_OBJECT_HANDLE_PTR phObject,
                         CK_ULONG ulMaxObjectCount,
                         CK_ULONG_PTR pulObjectCount) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));

  if (!phObject) {
    return NullArgumentError("phObject", SOURCE_LOCATION);
  }
  if (!pulObjectCount) {
    return NullArgumentError("pulObjectCount", SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(absl::Span<const CK_OBJECT_HANDLE> handles,
                   session->FindObjects(ulMaxObjectCount));

  std::copy(handles.begin(), handles.end(), phObject);
  *pulObjectCount = handles.size();
  return absl::OkStatus();
}

// End an object browsing operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002354
absl::Status FindObjectsFinal(CK_SESSION_HANDLE hSession) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  return session->FindObjectsFinal();
}

// Begin a decrypt operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002361
absl::Status DecryptInit(CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  ASSIGN_OR_RETURN(std::shared_ptr<Object> key, session->token()->GetKey(hKey));

  if (!pMechanism) {
    return NullArgumentError("pMechanism", SOURCE_LOCATION);
  }
  return session->DecryptInit(key, pMechanism);
}

// Complete a decrypt operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002362
absl::Status Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                     CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
                     CK_ULONG_PTR pulDataLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pEncryptedData) {
    session->ReleaseOperation();
    return NullArgumentError("pEncryptedData", SOURCE_LOCATION);
  }
  if (!pulDataLen) {
    session->ReleaseOperation();
    return NullArgumentError("pulDataLen", SOURCE_LOCATION);
  }

  absl::StatusOr<absl::Span<const uint8_t>> plaintext =
      session->Decrypt(absl::MakeConstSpan(pEncryptedData, ulEncryptedDataLen));
  if (!plaintext.ok()) {
    session->ReleaseOperation();
    return plaintext.status();
  }

  if (!pData) {
    *pulDataLen = plaintext->size();
    return absl::OkStatus();
  }

  if (*pulDataLen < plaintext->size()) {
    absl::Status result = OutOfRangeError(
        absl::StrFormat(
            "plaintext of length %d cannot fit in buffer of length %d",
            plaintext->size(), *pulDataLen),
        SOURCE_LOCATION);
    *pulDataLen = plaintext->size();
    return result;
  }

  std::copy(plaintext->begin(), plaintext->end(), pData);
  *pulDataLen = plaintext->size();

  session->ReleaseOperation();
  return absl::OkStatus();
}

// Continue a multi-part encrypt operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc385057935
absl::Status DecryptUpdate(CK_SESSION_HANDLE hSession,
                           CK_BYTE_PTR pEncryptedPart,
                           CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                           CK_ULONG_PTR pulPartLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pEncryptedPart) {
    session->ReleaseOperation();
    return NullArgumentError("pEncryptedPart", SOURCE_LOCATION);
  }
  if (!pulPartLen) {
    session->ReleaseOperation();
    return NullArgumentError("pulPartLen", SOURCE_LOCATION);
  }

  absl::Status result = session->DecryptUpdate(
      absl::MakeConstSpan(pEncryptedPart, ulEncryptedPartLen));

  if (!result.ok()) {
    session->ReleaseOperation();
  }

  // The library does not return partial decrypted plaintext, so we set the
  // partial output length to 0.
  *pulPartLen = 0;

  return result;
}

// Complete a multi-part encrypt operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc323024136
absl::Status DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                          CK_ULONG_PTR pulLastPartLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pulLastPartLen) {
    session->ReleaseOperation();
    return NullArgumentError("pulLastPartLen", SOURCE_LOCATION);
  }

  absl::StatusOr<absl::Span<const uint8_t>> plaintext = session->DecryptFinal();
  if (!plaintext.ok()) {
    session->ReleaseOperation();
    return plaintext.status();
  }

  if (!pLastPart) {
    *pulLastPartLen = plaintext->size();
    return absl::OkStatus();
  }

  if (*pulLastPartLen < plaintext->size()) {
    absl::Status result = OutOfRangeError(
        absl::StrFormat(
            "plaintext of length %d cannot fit in buffer of length %d",
            plaintext->size(), *pulLastPartLen),
        SOURCE_LOCATION);
    *pulLastPartLen = plaintext->size();
    return result;
  }

  std::copy(plaintext->begin(), plaintext->end(), pLastPart);
  *pulLastPartLen = plaintext->size();

  session->ReleaseOperation();
  return absl::OkStatus();
}

// Begin an encrypt operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002356
absl::Status EncryptInit(CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  ASSIGN_OR_RETURN(std::shared_ptr<Object> key, session->token()->GetKey(hKey));

  if (!pMechanism) {
    return NullArgumentError("pMechanism", SOURCE_LOCATION);
  }
  return session->EncryptInit(key, pMechanism);
}

// Complete an encrypt operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002357
absl::Status Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                     CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
                     CK_ULONG_PTR pulEncryptedDataLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pData) {
    session->ReleaseOperation();
    return NullArgumentError("pData", SOURCE_LOCATION);
  }
  if (!pulEncryptedDataLen) {
    session->ReleaseOperation();
    return NullArgumentError("pulEncryptedDataLen", SOURCE_LOCATION);
  }

  absl::StatusOr<absl::Span<const uint8_t>> ciphertext =
      session->Encrypt(absl::MakeConstSpan(pData, ulDataLen));
  if (!ciphertext.ok()) {
    session->ReleaseOperation();
    return ciphertext.status();
  }

  if (!pEncryptedData) {
    *pulEncryptedDataLen = ciphertext->size();
    return absl::OkStatus();
  }

  if (*pulEncryptedDataLen < ciphertext->size()) {
    absl::Status result = OutOfRangeError(
        absl::StrFormat(
            "ciphertext of length %d cannot fit in buffer of length %d",
            ciphertext->size(), *pulEncryptedDataLen),
        SOURCE_LOCATION);
    *pulEncryptedDataLen = ciphertext->size();
    return result;
  }

  std::copy(ciphertext->begin(), ciphertext->end(), pEncryptedData);
  *pulEncryptedDataLen = ciphertext->size();

  session->ReleaseOperation();
  return absl::OkStatus();
}

// Continue a multi-part encrypt operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc323024131
absl::Status EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                           CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                           CK_ULONG_PTR pulEncryptedPartLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pPart) {
    session->ReleaseOperation();
    return NullArgumentError("pPart", SOURCE_LOCATION);
  }
  if (!pulEncryptedPartLen) {
    session->ReleaseOperation();
    return NullArgumentError("pulEncryptedPartLen", SOURCE_LOCATION);
  }

  absl::Status result =
      session->EncryptUpdate(absl::MakeConstSpan(pPart, ulPartLen));

  if (!result.ok()) {
    session->ReleaseOperation();
  }

  // The library does not return partial encrypted ciphertext, so we set the
  // partial output length to 0.
  *pulEncryptedPartLen = 0;

  return result;
}

// Complete a multi-part encrypt operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc323024132
absl::Status EncryptFinal(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pLastEncryptedPart,
                          CK_ULONG_PTR pulLastEncryptedPartLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pulLastEncryptedPartLen) {
    session->ReleaseOperation();
    return NullArgumentError("pulLastEncryptedPartLen", SOURCE_LOCATION);
  }

  absl::StatusOr<absl::Span<const uint8_t>> ciphertext =
      session->EncryptFinal();
  if (!ciphertext.ok()) {
    session->ReleaseOperation();
    return ciphertext.status();
  }

  if (!pLastEncryptedPart) {
    *pulLastEncryptedPartLen = ciphertext->size();
    return absl::OkStatus();
  }

  if (*pulLastEncryptedPartLen < ciphertext->size()) {
    absl::Status result = OutOfRangeError(
        absl::StrFormat(
            "ciphertext of length %d cannot fit in buffer of length %d",
            ciphertext->size(), *pulLastEncryptedPartLen),
        SOURCE_LOCATION);
    *pulLastEncryptedPartLen = ciphertext->size();
    return result;
  }

  std::copy(ciphertext->begin(), ciphertext->end(), pLastEncryptedPart);
  *pulLastEncryptedPartLen = ciphertext->size();

  session->ReleaseOperation();
  return absl::OkStatus();
}

// Begin a single-part or multi-part sign operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002372
absl::Status SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                      CK_OBJECT_HANDLE hKey) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  ASSIGN_OR_RETURN(std::shared_ptr<Object> key, session->token()->GetKey(hKey));

  if (!pMechanism) {
    return NullArgumentError("pMechanism", SOURCE_LOCATION);
  }
  return session->SignInit(key, pMechanism);
}

// Complete a single-part sign operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002373
absl::Status Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                  CK_ULONG_PTR pulSignatureLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pData) {
    session->ReleaseOperation();
    return NullArgumentError("pData", SOURCE_LOCATION);
  }
  if (!pulSignatureLen) {
    session->ReleaseOperation();
    return NullArgumentError("pulSignatureLen", SOURCE_LOCATION);
  }

  absl::StatusOr<size_t> sig_length = session->SignatureLength();
  if (!sig_length.ok()) {
    session->ReleaseOperation();
    return sig_length.status();
  }

  if (!pSignature) {
    *pulSignatureLen = *sig_length;
    return absl::OkStatus();
  }

  if (*pulSignatureLen < *sig_length) {
    absl::Status result = OutOfRangeError(
        absl::StrFormat(
            "signature of length %d cannot fit in buffer of length %d",
            *sig_length, *pulSignatureLen),
        SOURCE_LOCATION);
    *pulSignatureLen = *sig_length;
    return result;
  }

  absl::Status result = session->Sign(absl::MakeConstSpan(pData, ulDataLen),
                                      absl::MakeSpan(pSignature, *sig_length));
  session->ReleaseOperation();
  if (result.ok()) {
    *pulSignatureLen = *sig_length;
  }
  return result;
}

// Continue a multi-part sign operation.
// https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc323024145
absl::Status SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                        CK_ULONG ulPartLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pPart) {
    session->ReleaseOperation();
    return NullArgumentError("pData", SOURCE_LOCATION);
  }

  absl::Status result =
      session->SignUpdate(absl::MakeConstSpan(pPart, ulPartLen));

  if (!result.ok()) {
    session->ReleaseOperation();
  }
  return result;
}

// Complete a multi-part sign operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc323024146
absl::Status SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                       CK_ULONG_PTR pulSignatureLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pulSignatureLen) {
    session->ReleaseOperation();
    return NullArgumentError("pulSignatureLen", SOURCE_LOCATION);
  }

  absl::StatusOr<size_t> sig_length = session->SignatureLength();
  if (!sig_length.ok()) {
    session->ReleaseOperation();
    return sig_length.status();
  }

  if (!pSignature) {
    *pulSignatureLen = *sig_length;
    return absl::OkStatus();
  }

  if (*pulSignatureLen < *sig_length) {
    absl::Status result = OutOfRangeError(
        absl::StrFormat(
            "signature of length %d cannot fit in buffer of length %d",
            *sig_length, *pulSignatureLen),
        SOURCE_LOCATION);
    *pulSignatureLen = *sig_length;
    return result;
  }

  absl::Status result =
      session->SignFinal(absl::MakeSpan(pSignature, *sig_length));
  session->ReleaseOperation();
  if (result.ok()) {
    *pulSignatureLen = *sig_length;
  }
  return result;
}

// Begin a single-part or multi-part verify operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002379
absl::Status VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  ASSIGN_OR_RETURN(std::shared_ptr<Object> key, session->token()->GetKey(hKey));

  if (!pMechanism) {
    return NullArgumentError("pMechanism", SOURCE_LOCATION);
  }
  return session->VerifyInit(key, pMechanism);
}

// Complete a single-part verify operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc235002380
absl::Status Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                    CK_ULONG ulSignatureLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pData) {
    session->ReleaseOperation();
    return NullArgumentError("pData", SOURCE_LOCATION);
  }
  if (!pSignature) {
    session->ReleaseOperation();
    return NullArgumentError("pSignature", SOURCE_LOCATION);
  }

  absl::Status result =
      session->Verify(absl::MakeConstSpan(pData, ulDataLen),
                      absl::MakeConstSpan(pSignature, ulSignatureLen));
  session->ReleaseOperation();
  return result;
}

// Continue a multi-part verify operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc323024151
absl::Status VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                          CK_ULONG ulPartLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pPart) {
    session->ReleaseOperation();
    return NullArgumentError("pData", SOURCE_LOCATION);
  }

  absl::Status result =
      session->VerifyUpdate(absl::MakeConstSpan(pPart, ulPartLen));

  if (!result.ok()) {
    session->ReleaseOperation();
  }
  return result;
}

// Complete a multi-part verify operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Toc323024152
absl::Status VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                         CK_ULONG ulSignatureLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pSignature) {
    session->ReleaseOperation();
    return NullArgumentError("pSignature", SOURCE_LOCATION);
  }

  absl::Status result =
      session->VerifyFinal(absl::MakeConstSpan(pSignature, ulSignatureLen));
  session->ReleaseOperation();
  return result;
}

// Generate a new secret key.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323024156
absl::Status GenerateKey(CK_SESSION_HANDLE hSession,
                         CK_MECHANISM_PTR pMechanism,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                         CK_OBJECT_HANDLE_PTR phKey) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));

  if (!pMechanism) {
    return NullArgumentError("pMechanism", SOURCE_LOCATION);
  }
  if (!phKey) {
    return NullArgumentError("phKey", SOURCE_LOCATION);
  }

  absl::Span<const CK_ATTRIBUTE> attributes;
  if (ulCount > 0) {
    if (!pTemplate) {
      return NullArgumentError("pTemplate", SOURCE_LOCATION);
    }
    attributes = absl::MakeConstSpan(pTemplate, ulCount);
  }

  ASSIGN_OR_RETURN(
      CK_OBJECT_HANDLE handle,
      session->GenerateKey(
          *pMechanism, attributes,
          provider->library_config().experimental_create_multiple_versions(),
          provider->library_config().allow_software_keys()));

  *phKey = handle;
  return absl::OkStatus();
}

// Generate a new asymmetric key pair.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc323024157
absl::Status GenerateKeyPair(
    CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey) {
  ASSIGN_OR_RETURN(Provider * provider, GetProvider());
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));

  if (!pMechanism) {
    return NullArgumentError("pMechanism", SOURCE_LOCATION);
  }
  if (!phPublicKey) {
    return NullArgumentError("phPublicKey", SOURCE_LOCATION);
  }
  if (!phPrivateKey) {
    return NullArgumentError("phPrivateKey", SOURCE_LOCATION);
  }

  absl::Span<const CK_ATTRIBUTE> pub_attributes;
  if (ulPublicKeyAttributeCount > 0) {
    if (!pPublicKeyTemplate) {
      return NullArgumentError("pPublicKeyTemplate", SOURCE_LOCATION);
    }
    pub_attributes =
        absl::MakeConstSpan(pPublicKeyTemplate, ulPublicKeyAttributeCount);
  }

  absl::Span<const CK_ATTRIBUTE> prv_attributes;
  if (ulPrivateKeyAttributeCount > 0) {
    if (!pPrivateKeyTemplate) {
      return NullArgumentError("pPrivateKeyTemplate", SOURCE_LOCATION);
    }
    prv_attributes =
        absl::MakeConstSpan(pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
  }

  ASSIGN_OR_RETURN(
      AsymmetricHandleSet handles,
      session->GenerateKeyPair(
          *pMechanism, pub_attributes, prv_attributes,
          provider->library_config().experimental_create_multiple_versions(),
          provider->library_config().allow_software_keys()));

  *phPublicKey = handles.public_key_handle;
  *phPrivateKey = handles.private_key_handle;
  return absl::OkStatus();
}

absl::Status DestroyObject(CK_SESSION_HANDLE hSession,
                           CK_OBJECT_HANDLE hObject) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  ASSIGN_OR_RETURN(std::shared_ptr<Object> object,
                   session->token()->GetObject(hObject));
  return session->DestroyObject(object);
}

// Retrieve HSM randomness.
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024163
absl::Status GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
                            CK_ULONG ulRandomLen) {
  ASSIGN_OR_RETURN(std::shared_ptr<Session> session, GetSession(hSession));
  if (!pRandomData) {
    return NullArgumentError("pRandomData", SOURCE_LOCATION);
  }
  return session->GenerateRandom(absl::MakeSpan(pRandomData, ulRandomLen));
}

}  // namespace cloud_kms::kmsp11
