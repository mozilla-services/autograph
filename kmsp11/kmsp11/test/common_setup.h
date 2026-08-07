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

#ifndef KMSP11_TEST_COMMON_RESOURCES_H_
#define KMSP11_TEST_COMMON_RESOURCES_H_

#include "fakekms/cpp/fakekms.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {

// Creates a configuration file for one keyring/token for testing and
// initializes the keyring in fake kms.
std::string CreateConfigFileWithOneKeyring(fakekms::Server* fake_server);

// Version of CreateConfigFileWithOneKeyring that returns the initialized
// keyring.
std::string CreateConfigFileWithOneKeyring(fakekms::Server* fake_server,
                                           kms_v1::KeyRing* kr);

// Initializes an HSM CryptoKey in the specified keyring for the required
// purpose and algorithm; initializes a version for this CryptoKey; and returns
// the version.
kms_v1::CryptoKeyVersion InitializeCryptoKeyAndKeyVersion(
    fakekms::Server* fake_server, kms_v1::KeyRing kr,
    kms_v1::CryptoKey::CryptoKeyPurpose purpose,
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Initialize the CK_C_INITIALIZE_ARGS from a configuration file.
CK_C_INITIALIZE_ARGS InitArgs(const char* config_file);

// Initializes a KMS KeyRing. Creates a configuration file with this keyring as
// a token and initializes bridge with this configuration file. Returns the
// configuration file.
absl::StatusOr<std::string> InitializeBridgeForOneKmsKeyRing(
    fakekms::Server* fake_server);

// Initializes a KMS KeyRing, a key in this KeyRing, and a crypto key version
// with the specified algorithm. Creates a configuration file with this keyring as
// a token and initializes bridge with this configuration file. Returns the
// configuration file.
absl::StatusOr<std::string> InitializeBridgeForOneKmsKey(
    fakekms::Server* fake_server, kms_v1::CryptoKey::CryptoKeyPurpose purpose,
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Version of InitializeBridgeForOneKmsKey that also returns the initialized crypto
// key version.
absl::StatusOr<std::string> InitializeBridgeForOneKmsKey(
    fakekms::Server* fake_server, kms_v1::CryptoKey::CryptoKeyPurpose purpose,
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    kms_v1::CryptoKeyVersion* ckv);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_TEST_COMMON_RESOURCES_H_
