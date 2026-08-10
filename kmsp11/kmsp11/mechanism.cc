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

#include "kmsp11/mechanism.h"

#include "absl/container/flat_hash_map.h"
#include "kmsp11/kmsp11.h"

namespace cloud_kms::kmsp11 {
namespace {

constexpr CK_FLAGS kEcFlags =
    CKF_EC_F_P | CKF_EC_NAMEDCURVE | CKF_EC_UNCOMPRESS;

}  // namespace

const absl::flat_hash_map<CK_MECHANISM_TYPE, const CK_MECHANISM_INFO>&
AllMechanisms() {
  static const absl::flat_hash_map<CK_MECHANISM_TYPE, const CK_MECHANISM_INFO>
      kMechanisms = {
          // min/max key size of ECDSA mechanisms should be in bits, per
          // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894664.
          {
              CKM_ECDSA,
              {
                  256,                              // ulMinKeySize
                  384,                              // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY | kEcFlags  // flags
              },

          },
          {
              CKM_ECDSA_SHA256,
              {
                  256,                              // ulMinKeySize
                  256,                              // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY | kEcFlags  // flags
              },
          },
          {
              CKM_ECDSA_SHA384,
              {
                  384,                              // ulMinKeySize
                  384,                              // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY | kEcFlags  // flags
              },
          },
          {
              CKM_EC_KEY_PAIR_GEN,
              {
                  256,                                       // ulMinKeySize
                  384,                                       // ulMaxKeySize
                  CKF_HW | CKF_GENERATE_KEY_PAIR | kEcFlags  // flags
              },
          },
          // min/max key size of PKCS #1 RSA mechanisms should be in bits, per
          // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894633.
          {
              CKM_RSA_PKCS_KEY_PAIR_GEN,
              {
                  2048,                           // ulMinKeySize
                  4096,                           // ulMaxKeySize
                  CKF_HW | CKF_GENERATE_KEY_PAIR  // flags
              },
          },
          {
              CKM_RSA_PKCS,
              {
                  2048,                  // ulMinKeySize
                  4096,                  // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },

          },
          {
              CKM_SHA256_RSA_PKCS,
              {
                  2048,                  // ulMinKeySize
                  4096,                  // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },
          },
          {
              CKM_SHA512_RSA_PKCS,
              {
                  2048,                  // ulMinKeySize
                  4096,                  // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },

          },
          // min/max key size of PKCS #1 RSA OAEP mechanisms should be in bits,
          // per
          // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894637.
          {
              CKM_RSA_PKCS_OAEP,
              {
                  2048,                      // ulMinKeySize
                  4096,                      // ulMaxKeySize
                  CKF_DECRYPT | CKF_ENCRYPT  // flags
              },
          },
          // min/max key size of PKCS #1 RSA PSS mechanisms should be in bits,
          // per
          // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894639.
          {
              CKM_RSA_PKCS_PSS,
              {
                  2048,                  // ulMinKeySize
                  4096,                  // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },
          },
          {
              CKM_SHA256_RSA_PKCS_PSS,
              {
                  2048,                  // ulMinKeySize
                  4096,                  // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },
          },
          {
              CKM_SHA512_RSA_PKCS_PSS,
              {
                  4096,                  // ulMinKeySize
                  4096,                  // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },
          },
          // min/max key size should be in bits, per
          // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894692
          {
              CKM_GENERIC_SECRET_KEY_GEN,
              {
                  160,                   // ulMinKeySize
                  256,                   // ulMaxKeySize
                  CKF_HW | CKF_GENERATE  // flags
              },
          },
          // min/max key size should be in bytes, per
          // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061300.
          {
              CKM_SHA_1_HMAC,
              {
                  20,                    // ulMinKeySize
                  20,                    // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },
          },
          {
              CKM_SHA224_HMAC,
              {
                  28,                    // ulMinKeySize
                  28,                    // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },
          },
          {
              CKM_SHA256_HMAC,
              {
                  32,                    // ulMinKeySize
                  32,                    // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },
          },
          {
              CKM_SHA384_HMAC,
              {
                  48,                    // ulMinKeySize
                  48,                    // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },
          },
          {
              CKM_SHA512_HMAC,
              {
                  48,                    // ulMinKeySize
                  48,                    // ulMaxKeySize
                  CKF_SIGN | CKF_VERIFY  // flags
              },
          },
          // min/max key size should be in bytes, per
          // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894697
          {
              CKM_AES_KEY_GEN,
              {
                  16,                        // ulMinKeySize
                  32,                        // ulMaxKeySize
                  CKF_DECRYPT | CKF_ENCRYPT  // flags
              },
          },
          {
              CKM_CLOUDKMS_AES_GCM,
              {
                  16,                        // ulMinKeySize
                  32,                        // ulMaxKeySize
                  CKF_DECRYPT | CKF_ENCRYPT  // flags
              },
          },
          {
              CKM_AES_CTR,
              {
                  16,                        // ulMinKeySize
                  32,                        // ulMaxKeySize
                  CKF_DECRYPT | CKF_ENCRYPT  // flags
              },
          },
          {
              CKM_AES_CBC,
              {
                  16,                        // ulMinKeySize
                  32,                        // ulMaxKeySize
                  CKF_DECRYPT | CKF_ENCRYPT  // flags
              },
          },
          {
              CKM_AES_CBC_PAD,
              {
                  16,                        // ulMinKeySize
                  32,                        // ulMaxKeySize
                  CKF_DECRYPT | CKF_ENCRYPT  // flags
              },
          },
      };

  return kMechanisms;
}

const absl::flat_hash_set<CK_MECHANISM_TYPE>& AllMacMechanisms() {
  // These mechanisms are only supported if the experimental_allow_mac_keys
  // config flag is set.
  static const absl::flat_hash_set<CK_MECHANISM_TYPE> kMacMechanisms = {
      CKM_SHA_1_HMAC, CKM_SHA224_HMAC, CKM_SHA256_HMAC,
      CKM_SHA384_HMAC, CKM_SHA512_HMAC,
  };
  return kMacMechanisms;
}

const absl::flat_hash_set<CK_MECHANISM_TYPE>& AllRawEncryptionMechanisms() {
  // These mechanisms are only supported if the
  // experimental_allow_raw_encryption_keys config flag is set.
  static const absl::flat_hash_set<CK_MECHANISM_TYPE> kRawEncryptionMechanisms =
      {CKM_CLOUDKMS_AES_GCM, CKM_AES_CTR, CKM_AES_CBC, CKM_AES_CBC_PAD};
  return kRawEncryptionMechanisms;
}

}  // namespace cloud_kms::kmsp11
