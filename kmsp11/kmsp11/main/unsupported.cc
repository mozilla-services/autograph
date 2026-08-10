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

// This file contains stubs for PKCS #11 functions that are not implemented in
// our library.

#include "absl/status/status.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

absl::Status InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
                       CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
                     CK_ULONG ulPinLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
                    CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin,
                    CK_ULONG ulNewLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status GetOperationState(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pOperationState,
                               CK_ULONG_PTR pulOperationStateLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status SetOperationState(CK_SESSION_HANDLE hSession,
                               CK_BYTE_PTR pOperationState,
                               CK_ULONG ulOperationStateLen,
                               CK_OBJECT_HANDLE hEncryptionKey,
                               CK_OBJECT_HANDLE hAuthenticationKey) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status CreateObject(CK_SESSION_HANDLE hSession,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                          CK_OBJECT_HANDLE_PTR phObject) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                        CK_OBJECT_HANDLE_PTR phNewObject) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                           CK_ULONG_PTR pulSize) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status SetAttributeValue(CK_SESSION_HANDLE hSession,
                               CK_OBJECT_HANDLE hObject,
                               CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status DigestInit(CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                    CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
                    CK_ULONG_PTR pulDigestLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                          CK_ULONG ulPartLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                         CK_ULONG_PTR pulDigestLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status SignRecoverInit(CK_SESSION_HANDLE hSession,
                             CK_MECHANISM_PTR pMechanism,
                             CK_OBJECT_HANDLE hKey) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                         CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                         CK_ULONG_PTR pulSignatureLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                               CK_MECHANISM_PTR pMechanism,
                               CK_OBJECT_HANDLE hKey) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                           CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
                           CK_ULONG_PTR pulDataLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                                 CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                                 CK_ULONG_PTR pulEncryptedPartLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                                 CK_BYTE_PTR pEncryptedPart,
                                 CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                                 CK_ULONG_PTR pulPartLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                               CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                               CK_ULONG_PTR pulEncryptedPartLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                                 CK_BYTE_PTR pEncryptedPart,
                                 CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                                 CK_ULONG_PTR pulPartLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                     CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                       CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                       CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                       CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                       CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                       CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                        CK_ULONG ulSeedLen) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status GetFunctionStatus(CK_SESSION_HANDLE hSession) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status CancelFunction(CK_SESSION_HANDLE hSession) {
  return UnsupportedError(SOURCE_LOCATION);
}

absl::Status WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
                              CK_VOID_PTR pReserved) {
  return UnsupportedError(SOURCE_LOCATION);
}

}  // namespace cloud_kms::kmsp11
