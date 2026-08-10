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

#ifndef KMSP11_KMSP11_H_
#define KMSP11_KMSP11_H_

#ifdef __cplusplus
extern "C" {
#endif

// A marker for a PKCS #11 attribute or flag defined by Google.
// (Note that 0x80000000UL is CKA_VENDOR_DEFINED).
#define CKA_GOOGLE_DEFINED (0x80000000UL | 0x1E100UL)

// An attribute that indicates the backing CryptoKeyVersionAlgorithm in Cloud
// KMS.
#define CKA_KMS_ALGORITHM (CKA_GOOGLE_DEFINED | 0x01UL)

// ECDSA on the NIST P-256 curve with a SHA256 digest.
#define KMS_ALGORITHM_EC_SIGN_P256_SHA256 12UL
// ECDSA on the NIST P-384 curve with a SHA384 digest.
#define KMS_ALGORITHM_EC_SIGN_P384_SHA384 13UL

// RSAES-OAEP with a 2048 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_DECRYPT_OAEP_2048_SHA256 8UL
// RSAES-OAEP with a 3072 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_DECRYPT_OAEP_3072_SHA256 9UL
// RSAES-OAEP with a 4096 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_DECRYPT_OAEP_4096_SHA256 10UL
// RSAES-OAEP with a 4096 bit key and a SHA512 digest.
#define KMS_ALGORITHM_RSA_DECRYPT_OAEP_4096_SHA512 17UL

// RSASSA-PKCS1-v1_5 with a 2048 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PKCS1_2048_SHA256 5UL
// RSASSA-PKCS1-v1_5 with a 3072 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PKCS1_3072_SHA256 6UL
// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PKCS1_4096_SHA256 7UL
// RSASSA-PKCS1-v1_5 with a 4096 bit key and a SHA512 digest.
#define KMS_ALGORITHM_RSA_SIGN_PKCS1_4096_SHA512 16UL

// RSASSA-PSS with a 2048 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PSS_2048_SHA256 2UL
// RSASSA-PSS with a 3072 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PSS_3072_SHA256 3UL
// RSASSA-PSS with a 4096 bit key and a SHA256 digest.
#define KMS_ALGORITHM_RSA_SIGN_PSS_4096_SHA256 4UL
// RSASSA-PSS with a 4096 bit key and a SHA512 digest.
#define KMS_ALGORITHM_RSA_SIGN_PSS_4096_SHA512 15UL

// RSASSA-PKCS1-v1_5 signing without encoding, with a 2048 bit key.
#define KMS_ALGORITHM_RSA_SIGN_RAW_PKCS1_2048 28UL
// RSASSA-PKCS1-v1_5 signing without encoding, with a 3072 bit key.
#define KMS_ALGORITHM_RSA_SIGN_RAW_PKCS1_3072 29UL
// RSASSA-PKCS1-v1_5 signing without encoding, with a 4096 bit key.
#define KMS_ALGORITHM_RSA_SIGN_RAW_PKCS1_4096 30UL

// HMAC-SHA256 signing with a 256 bit key.
#define KMS_ALGORITHM_HMAC_SHA256 32UL
// HMAC-SHA1 signing with a 160 bit key.
#define KMS_ALGORITHM_HMAC_SHA1 33UL
// HMAC-SHA384 signing with a 384 bit key.
#define KMS_ALGORITHM_HMAC_SHA384 34UL
// HMAC-SHA512 signing with a 512 bit key.
#define KMS_ALGORITHM_HMAC_SHA512 35UL
// HMAC-SHA224 signing with a 224 bit key.
#define KMS_ALGORITHM_HMAC_SHA224 36UL

// AES+GCM (Galois Counter Mode) with a 128 bit key.
#define KMS_ALGORITHM_AES_128_GCM 41UL
// AES+GCM (Galois Counter Mode) with a 256 bit key.
#define KMS_ALGORITHM_AES_256_GCM 19UL
// AES+CBC (Cipher Block Chaining Mode) with a 128 bit key.
#define KMS_ALGORITHM_AES_128_CBC 42UL
// AES+CBC (Cipher Block Chaining Mode) with a 256 bit key.
#define KMS_ALGORITHM_AES_256_CBC 43UL
// AES+CTR (Counter Mode) with a 128 bit key.
#define KMS_ALGORITHM_AES_128_CTR 44UL
// AES+CTR (Counter Mode) with a 256 bit key.
#define KMS_ALGORITHM_AES_256_CTR 45UL

// An attribute that indicates the backing ProtectionLevel in Cloud
// KMS.
#define CKA_KMS_PROTECTION_LEVEL (CKA_GOOGLE_DEFINED | 0x02UL)

// Software protection level.
#define KMS_PROTECTION_LEVEL_SOFTWARE 1UL
// Hardware protection level.
#define KMS_PROTECTION_LEVEL_HARDWARE 2UL
// Single tenant hardware protection level.
#define KMS_PROTECTION_LEVEL_HSM_SINGLE_TENANT 5UL

// An attribute that indicates the crypto key backend of an existing
// single tenant instance for key creation under the HSM_SINGLE_TENANT
// protection level.
#define CKA_KMS_CRYPTO_KEY_BACKEND (CKA_GOOGLE_DEFINED | 0x03UL)

// A marker for a PKCS #11 mechanism defined by Google.
// (Note that 0x80000000UL is CKM_VENDOR_DEFINED).
#define CKM_GOOGLE_DEFINED (0x80000000UL | 0x1E100UL)

// CKM_AES_GCM-based custom mechanism, with the following restrictions:
// - users cannot specify custom initialization vector (IV) data
// - users must use an IV that Cloud KMS generates
// - the IV (12 bytes) provided by Cloud KMS is written into the memory
//   pointed to by the pIV field of the CK_GCM_PARAMS struct provided by the
//   user.
//   NOTE: this is done at C_Encrypt time, so the memory pointed to by the pIV
//   field should not be freed between C_EncryptInit and C_Encrypt..
#define CKM_CLOUDKMS_AES_GCM (CKM_GOOGLE_DEFINED | 0x01UL)

#ifdef __cplusplus
}
#endif

#endif  // KMSP11_KMSP11_H_
