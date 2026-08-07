/*
 * Copyright 2023 Google LLC
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

#ifndef KMSCNG_OPERATION_SIGN_UTILS_H_
#define KMSCNG_OPERATION_SIGN_UTILS_H_

#include <string_view>

#include "absl/status/status.h"
#include "absl/types/span.h"
#include "kmscng/object.h"
#include "kmscng/util/string_utils.h"

namespace cloud_kms::kmscng {

// Validates that the KMS algorithm is supported by the provider.
absl::Status IsValidSigningAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Returns the right digest type for the provided KMS algorithm.
absl::StatusOr<const EVP_MD*> DigestForAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Returns the right curve ID for the provided KMS algorithm.
absl::StatusOr<int> CurveIdForAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Returns the right magic ID for the provided KMS algorithm.
absl::StatusOr<uint32_t> MagicIdForAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Checks the object properties against the expected properties defined in the
// relevant AlgorithmDetails struct.
absl::Status ValidateKeyPreconditions(Object* object);

// Serializes the public key in a BCRYPT_ECCPUBLIC_BLOB format:
// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob#remarks
absl::StatusOr<std::vector<uint8_t>> SerializePublicKey(Object* object);

// Returns the expected signature length based on the key type.
absl::StatusOr<size_t> SignatureLength(Object* object);

// Signs the precomputed `digest` using Cloud KMS, and copies it into the
// provided `signature` buffer.
absl::Status SignDigest(Object* object, absl::Span<const uint8_t> digest,
                        absl::Span<uint8_t> signature);

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_OPERATION_SIGN_UTILS_H_
