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

#include "kmscng/algorithm_details.h"

#include "absl/container/btree_set.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_format.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/string_utils.h"

namespace cloud_kms::kmscng {

absl::flat_hash_set<std::wstring> algorithm_identifiers = {
    {BCRYPT_ECDSA_P256_ALGORITHM},
    {BCRYPT_ECDSA_P384_ALGORITHM},
    {BCRYPT_RSA_ALGORITHM},
};

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

static const auto* const kAlgorithmDetails =
    new absl::btree_set<AlgorithmDetails, AlgorithmCmp>{
        // EC_SIGN_*
        {
            kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,  // algorithm
            kms_v1::CryptoKey::ASYMMETRIC_SIGN,             // purpose
            NCRYPT_ECDSA_ALGORITHM_GROUP,                   // algorithm_group
            BCRYPT_ECDSA_P256_ALGORITHM,  // algorithm_property
            NCRYPT_ALLOW_SIGNING_FLAG,    // key_usage
        },
        {
            kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384,  // algorithm
            kms_v1::CryptoKey::ASYMMETRIC_SIGN,             // purpose
            NCRYPT_ECDSA_ALGORITHM_GROUP,                   // algorithm_group
            BCRYPT_ECDSA_P384_ALGORITHM,  // algorithm_property
            NCRYPT_ALLOW_SIGNING_FLAG,    // key_usage
        },
        {
            kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,  // algorithm
            kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
            NCRYPT_RSA_ALGORITHM_GROUP,  // algorithm_group
            BCRYPT_RSA_ALGORITHM,        // algorithm_property
            NCRYPT_ALLOW_SIGNING_FLAG,   // key_usage
        },
        {
            kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256,  // algorithm
            kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
            NCRYPT_RSA_ALGORITHM_GROUP,  // algorithm_group
            BCRYPT_RSA_ALGORITHM,        // algorithm_property
            NCRYPT_ALLOW_SIGNING_FLAG,   // key_usage
        },
        {
            kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256,  // algorithm
            kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
            NCRYPT_RSA_ALGORITHM_GROUP,  // algorithm_group
            BCRYPT_RSA_ALGORITHM,        // algorithm_property
            NCRYPT_ALLOW_SIGNING_FLAG,   // key_usage
        },
        {
            kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512,  // algorithm
            kms_v1::CryptoKey::ASYMMETRIC_SIGN,                    // purpose
            NCRYPT_RSA_ALGORITHM_GROUP,  // algorithm_group
            BCRYPT_RSA_ALGORITHM,        // algorithm_property
            NCRYPT_ALLOW_SIGNING_FLAG,   // key_usage
        },
    };

absl::StatusOr<AlgorithmDetails> GetDetails(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  auto it = kAlgorithmDetails->find(algorithm);
  if (it == kAlgorithmDetails->end()) {
    return NewError(absl::StatusCode::kInternal,
                    absl::StrFormat("algorithm not found: %d", algorithm),
                    NTE_NOT_SUPPORTED, SOURCE_LOCATION);
  }
  return *it;
}

absl::Status IsSupportedAlgorithmIdentifier(std::wstring_view algorithm) {
  if (!algorithm_identifiers.contains(algorithm)) {
    return NewError(absl::StatusCode::kUnimplemented,
                    absl::StrFormat("unsupported algorithm: %s",
                                    WideToString(algorithm.data())),
                    NTE_NOT_SUPPORTED, SOURCE_LOCATION);
  }
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmscng
