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

#ifndef KMSP11_TEST_RESOURCE_HELPERS_H_
#define KMSP11_TEST_RESOURCE_HELPERS_H_

#include <string_view>

#include "absl/time/time.h"
#include "common/kms_v1.h"
#include "common/openssl.h"
#include "common/test/resource_helpers.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "kmsp11/object.h"

namespace cloud_kms::kmsp11 {

// Returns a mock KeyPair with the provided algorithm and public key.
absl::StatusOr<KeyPair> NewMockKeyPair(
    google::cloud::kms::v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm
        algorithm,
    std::string_view public_key_runfile);

// Returns a mock Object with the provided algorithm.
absl::StatusOr<Object> NewMockSecretKey(
    google::cloud::kms::v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm
        algorithm);

// Retrieves the public key associated with the private key and parses it in
// EVP_PKEY format.
absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> GetEVPPublicKey(
    fakekms::Server* fake_server, kms_v1::CryptoKeyVersion ckv);

// Returns the object handle for the private key associated with the specified
// crypto key version.
absl::StatusOr<CK_OBJECT_HANDLE> GetPrivateKeyObjectHandle(
    CK_SESSION_HANDLE session, kms_v1::CryptoKeyVersion ckv);

// Returns the object handle for the public key associated with the specified
// crypto key version.
absl::StatusOr<CK_OBJECT_HANDLE> GetPublicKeyObjectHandle(
    CK_SESSION_HANDLE session, kms_v1::CryptoKeyVersion ckv);

// Returns the object handle for the secret key associated with the specified
// crypto key version.
absl::StatusOr<CK_OBJECT_HANDLE> GetSecretKeyObjectHandle(
    CK_SESSION_HANDLE session, kms_v1::CryptoKeyVersion ckv);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_TEST_RESOURCE_HELPERS_H_
