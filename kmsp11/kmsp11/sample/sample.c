/*
 * Copyright 2021 Google LLC
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

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

// Begin: Loading the OASIS PKCS#11 headers.
// Several macros must be defined before loading pkcs11.h.
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"
// End: Loading the OASIS PKCS#11 headers.

// run_sample is a sample function that demonstrates loading the library
// dynamically and using the loaded library to locate a key and create a
// digital signature. It returns 0 on success, and a non-zero value on failure.
int run_sample(const char* library_path, const char* config_file_path,
               const char* ec_p256_signing_key_id) {
  // Dynamically load the PKCS#11 shared library.
  // Note that there should be no corresponding dlclose call. Our library does
  // not support being dynamically unloaded.
  void* library = dlopen(library_path, RTLD_LAZY | RTLD_NODELETE);
  if (!library) {
    fprintf(stderr, "error loading libkmsp11.so");
    return 1;
  }

  // Dynamically load the function list table from the loaded library.
  CK_C_GetFunctionList get_function_list =
      (CK_C_GetFunctionList)dlsym(library, "C_GetFunctionList");
  if (!get_function_list) {
    fprintf(stderr, "error locating C_GetFunctionList in the loaded library");
    return 1;
  }

  // Load the function list into 'f'.
  CK_FUNCTION_LIST* f;
  CK_RV rv = get_function_list(&f);
  if (rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_GetFunctionList", rv);
    return 1;
  }

  // Initialize the library.
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;
  init_args.pReserved = (char*)config_file_path;
  rv = f->C_Initialize(&init_args);
  if (rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_Initialize", rv);
    return 1;
  }

  // Open a session handle.
  CK_SESSION_HANDLE sess;
  rv = f->C_OpenSession(/*slotID=*/0, /*flags=*/CKF_SERIAL_SESSION,
                        /*pApplication=*/0, /*Notify=*/0, &sess);
  if (rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_OpenSession", rv);
    goto library_cleanup;
  }

  // Begin searching for our signing key.
  CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
  CK_ATTRIBUTE template[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_LABEL, (CK_UTF8CHAR*)ec_p256_signing_key_id,
       strlen(ec_p256_signing_key_id)},
  };
  rv = f->C_FindObjectsInit(sess, template, 2);
  if (rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_FindObjectsInit", rv);
    goto session_cleanup;
  }

  // Retrieve the handle to the signing key.
  CK_OBJECT_HANDLE private_key;
  CK_ULONG found_count;
  rv = f->C_FindObjects(sess, &private_key, 1, &found_count);
  if (rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_FindObjects", rv);
    goto session_cleanup;
  }
  if (found_count != 1) {
    fprintf(stderr, "found_count=%ld after calling C_FindObjects", found_count);
    goto session_cleanup;
  }

  // End the search.
  rv = f->C_FindObjectsFinal(sess);
  if (rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_FindObjectsFinal", rv);
    goto session_cleanup;
  }

  // Initialize our signing operation.
  CK_MECHANISM mech = {CKM_ECDSA, 0, 0};
  rv = f->C_SignInit(sess, &mech, private_key);
  if (rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_SignInit", rv);
    goto session_cleanup;
  }

  // Prepare to call 'Sign'.

  // When calling Sign, `data` should be filled with the SHA-256 digest of the
  // data to be signed over.
  CK_BYTE data[32] = {0};
  // An output buffer to hold the computed signature.
  CK_BYTE signature[64] = {0};

  // Call 'Sign'.
  CK_ULONG signature_length = sizeof(signature);
  rv = f->C_Sign(sess, data, sizeof(data), signature, &signature_length);
  if (rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_Sign", rv);
    goto session_cleanup;
  }
  if (signature_length != sizeof(signature)) {
    fprintf(stderr,
            "unexpected signature length = %ld (want %ld) after calling C_Sign",
            signature_length, sizeof(signature));
    goto session_cleanup;
  }

  printf("computed signature: ");
  for (size_t i = 0; i < sizeof(signature); i++) {
    printf("%X", signature[i]);
  }
  printf("\n");

  CK_RV cleanup_rv;

session_cleanup:
  cleanup_rv = f->C_CloseSession(sess);
  if (cleanup_rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_CloseSession", rv);
    if (rv == CKR_OK) {
      rv = cleanup_rv;
    }
  }

library_cleanup:
  cleanup_rv = f->C_Finalize(0);
  if (cleanup_rv != CKR_OK) {
    fprintf(stderr, "CK_RV=%lX calling C_Finalize", rv);
    if (rv == CKR_OK) {
      rv = cleanup_rv;
    }
  }

  return rv;
}
