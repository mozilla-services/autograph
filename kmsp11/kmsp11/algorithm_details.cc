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

#include "kmsp11/algorithm_details.h"

#include "absl/container/btree_set.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

struct AlgorithmCmp {
  using is_transparent = void;
  bool operator()(const AlgorithmDetails& a, const AlgorithmDetails& b) const {
    return a.algorithm < b.algorithm;
  }
  bool operator()(const AlgorithmDetails& a,
                  kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm b) const {
    return a.algorithm < b;
  }
  bool operator()(kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm a,
                  const AlgorithmDetails& b) const {
    return a < b.algorithm;
  }
};

static const auto* const kAlgorithmDetails = new absl::btree_set<
    AlgorithmDetails, AlgorithmCmp>{
    // EC_SIGN_*
    {
        kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,             // purpose
        {CKM_ECDSA, CKM_ECDSA_SHA256},                  // allowed_mechanisms
        CKK_EC,                                         // key_type
        256,                                            // key_bit_length
        CKM_EC_KEY_PAIR_GEN,                            // key_gen_mechanism
        CKM_SHA256,                                     // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,             // purpose
        {CKM_ECDSA, CKM_ECDSA_SHA384},                  // allowed_mechanisms
        CKK_EC,                                         // key_type
        384,                                            // key_bit_length
        CKM_EC_KEY_PAIR_GEN,                            // key_gen_mechanism
        CKM_SHA384,                                     // digest_mechanism
    },

    // RSA_DECRYPT_OAEP_*
    {
        kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,                   // purpose
        {CKM_RSA_PKCS_OAEP},        // allowed_mechanisms
        CKK_RSA,                    // key_type
        2048,                       // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
        CKM_SHA256,                 // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_3072_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,                   // purpose
        {CKM_RSA_PKCS_OAEP},        // allowed_mechanisms
        CKK_RSA,                    // key_type
        3072,                       // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
        CKM_SHA256,                 // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,                   // purpose
        {CKM_RSA_PKCS_OAEP},        // allowed_mechanisms
        CKK_RSA,                    // key_type
        4096,                       // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
        CKM_SHA256,                 // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA512,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,                   // purpose
        {CKM_RSA_PKCS_OAEP},        // allowed_mechanisms
        CKK_RSA,                    // key_type
        4096,                       // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
        CKM_SHA512,                 // digest_mechanism
    },

    // RSA_SIGN_PKCS1_*
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
        {CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS},  // allowed_mechanisms
        CKK_RSA,                              // key_type
        2048,                                 // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,            // key_gen_mechanism
        CKM_SHA256,                           // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
        {CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS},  // allowed_mechanisms
        CKK_RSA,                              // key_type
        3072,                                 // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,            // key_gen_mechanism
        CKM_SHA256,                           // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
        {CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS},  // allowed_mechanisms
        CKK_RSA,                              // key_type
        4096,                                 // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,            // key_gen_mechanism
        CKM_SHA256,                           // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
        {CKM_RSA_PKCS, CKM_SHA512_RSA_PKCS},  // allowed_mechanisms
        CKK_RSA,                              // key_type
        4096,                                 // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,            // key_gen_mechanism
        CKM_SHA512,                           // digest_mechanism
    },

    // RSA_SIGN_PSS_*
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                  // purpose
        {CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS},  // allowed_mechanisms
        CKK_RSA,                                      // key_type
        2048,                                         // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,                    // key_gen_mechanism
        CKM_SHA256,                                   // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                  // purpose
        {CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS},  // allowed_mechanisms
        CKK_RSA,                                      // key_type
        3072,                                         // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,                    // key_gen_mechanism
        CKM_SHA256,                                   // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                  // purpose
        {CKM_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS},  // allowed_mechanisms
        CKK_RSA,                                      // key_type
        4096,                                         // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,                    // key_gen_mechanism
        CKM_SHA256,                                   // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                  // purpose
        {CKM_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS},  // allowed_mechanisms
        CKK_RSA,                                      // key_type
        4096,                                         // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,                    // key_gen_mechanism
        CKM_SHA512,                                   // digest_mechanism
    },

    // RSA_SIGN_RAW_PKCS1_*
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                 // purpose
        {CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS,
         CKM_SHA512_RSA_PKCS},      // allowed_mechanisms
        CKK_RSA,                    // key_type
        2048,                       // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
        std::nullopt,               // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_3072,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                 // purpose
        {CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS,
         CKM_SHA512_RSA_PKCS},      // allowed_mechanisms
        CKK_RSA,                    // key_type
        3072,                       // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
        std::nullopt,               // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_4096,  // algorithm
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,                 // purpose
        {CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS,
         CKM_SHA512_RSA_PKCS},      // allowed_mechanisms
        CKK_RSA,                    // key_type
        4096,                       // key_bit_length
        CKM_RSA_PKCS_KEY_PAIR_GEN,  // key_gen_mechanism
        std::nullopt,               // digest_mechanism
    },
    // HMAC_*
    {
        kms_v1::CryptoKeyVersion::HMAC_SHA1,  // algorithm
        kms_v1::CryptoKey::MAC,               // purpose
        {CKM_SHA_1_HMAC},                     // allowed_mechanisms
        CKK_SHA_1_HMAC,                       // key_type
        160,                                  // key_bit_length
        CKM_GENERIC_SECRET_KEY_GEN,           // key_gen_mechanism
        std::nullopt,                         // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::HMAC_SHA224,  // algorithm
        kms_v1::CryptoKey::MAC,                 // purpose
        {CKM_SHA224_HMAC},                      // allowed_mechanisms
        CKK_SHA224_HMAC,                        // key_type
        224,                                    // key_bit_length
        CKM_GENERIC_SECRET_KEY_GEN,             // key_gen_mechanism
        std::nullopt,                           // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::HMAC_SHA256,  // algorithm
        kms_v1::CryptoKey::MAC,                 // purpose
        {CKM_SHA256_HMAC},                      // allowed_mechanisms
        CKK_SHA256_HMAC,                        // key_type
        256,                                    // key_bit_length
        CKM_GENERIC_SECRET_KEY_GEN,             // key_gen_mechanism
        std::nullopt,                           // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::HMAC_SHA384,  // algorithm
        kms_v1::CryptoKey::MAC,                 // purpose
        {CKM_SHA384_HMAC},                      // allowed_mechanisms
        CKK_SHA384_HMAC,                        // key_type
        384,                                    // key_bit_length
        CKM_GENERIC_SECRET_KEY_GEN,             // key_gen_mechanism
        std::nullopt,                           // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::HMAC_SHA512,  // algorithm
        kms_v1::CryptoKey::MAC,                 // purpose
        {CKM_SHA512_HMAC},                      // allowed_mechanisms
        CKK_SHA512_HMAC,                        // key_type
        512,                                    // key_bit_length
        CKM_GENERIC_SECRET_KEY_GEN,             // key_gen_mechanism
        std::nullopt,                           // digest_mechanism
    },
    // AES_*
    {
        kms_v1::CryptoKeyVersion::AES_128_GCM,   // algorithm
        kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,  // purpose
        {CKM_CLOUDKMS_AES_GCM},                  // allowed_mechanisms
        CKK_AES,                                 // key_type
        128,                                     // key_bit_length
        CKM_AES_KEY_GEN,                         // key_gen_mechanism
        std::nullopt,                            // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::AES_256_GCM,   // algorithm
        kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,  // purpose
        {CKM_CLOUDKMS_AES_GCM},                  // allowed_mechanisms
        CKK_AES,                                 // key_type
        256,                                     // key_bit_length
        CKM_AES_KEY_GEN,                         // key_gen_mechanism
        std::nullopt,                            // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::AES_128_CTR,   // algorithm
        kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,  // purpose
        {CKM_AES_CTR},                           // allowed_mechanisms
        CKK_AES,                                 // key_type
        128,                                     // key_bit_length
        CKM_AES_KEY_GEN,                         // key_gen_mechanism
        std::nullopt,                            // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::AES_256_CTR,   // algorithm
        kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,  // purpose
        {CKM_AES_CTR},                           // allowed_mechanisms
        CKK_AES,                                 // key_type
        256,                                     // key_bit_length
        CKM_AES_KEY_GEN,                         // key_gen_mechanism
        std::nullopt,                            // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::AES_128_CBC,   // algorithm
        kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,  // purpose
        {CKM_AES_CBC, CKM_AES_CBC_PAD},          // allowed_mechanisms
        CKK_AES,                                 // key_type
        128,                                     // key_bit_length
        CKM_AES_KEY_GEN,                         // key_gen_mechanism
        std::nullopt,                            // digest_mechanism
    },
    {
        kms_v1::CryptoKeyVersion::AES_256_CBC,   // algorithm
        kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT,  // purpose
        {CKM_AES_CBC, CKM_AES_CBC_PAD},          // allowed_mechanisms
        CKK_AES,                                 // key_type
        256,                                     // key_bit_length
        CKM_AES_KEY_GEN,                         // key_gen_mechanism
        std::nullopt,                            // digest_mechanism
    },
};

absl::StatusOr<AlgorithmDetails> GetDetails(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  auto it = kAlgorithmDetails->find(algorithm);
  if (it == kAlgorithmDetails->end()) {
    return NewInternalError(
        absl::StrFormat("algorithm not found: %d", algorithm), SOURCE_LOCATION);
  }
  return *it;
}

}  // namespace cloud_kms::kmsp11
