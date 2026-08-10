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

#include "common/test/test_status_macros.h"
#include "kmscng/test/matchers.h"

namespace cloud_kms::kmscng {
namespace {

using ::testing::ElementsAre;

TEST(GetAlgorithmDetailsTest, AlgorithmEc) {
  ASSERT_OK_AND_ASSIGN(
      AlgorithmDetails details,
      GetDetails(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));

  EXPECT_EQ(details.algorithm, kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  EXPECT_EQ(details.purpose, kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  EXPECT_THAT(details.algorithm_group, NCRYPT_ECDSA_ALGORITHM_GROUP);
  EXPECT_EQ(details.algorithm_property, BCRYPT_ECDSA_P256_ALGORITHM);
  EXPECT_EQ(details.key_usage, NCRYPT_ALLOW_SIGNING_FLAG);
}

TEST(GetAlgorithmDetailsTest, AlgorithmRsa) {
  ASSERT_OK_AND_ASSIGN(
      AlgorithmDetails details,
      GetDetails(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256));

  EXPECT_EQ(details.algorithm,
            kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256);
  EXPECT_EQ(details.purpose, kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  EXPECT_THAT(details.algorithm_group, NCRYPT_RSA_ALGORITHM_GROUP);
  EXPECT_EQ(details.algorithm_property, BCRYPT_RSA_ALGORITHM);
  EXPECT_EQ(details.key_usage, NCRYPT_ALLOW_SIGNING_FLAG);
}

TEST(GetAlgorithmDetailsTest, AlgorithmNotFound) {
  absl::StatusOr<AlgorithmDetails> details =
      GetDetails(kms_v1::CryptoKeyVersion::EXTERNAL_SYMMETRIC_ENCRYPTION);
  EXPECT_FALSE(details.ok());
  EXPECT_THAT(details.status(), StatusIs(absl::StatusCode::kInternal));
  EXPECT_THAT(details.status(), StatusSsIs(NTE_NOT_SUPPORTED));
}

TEST(IsSupportedAlgorithmIdentifierTest, Success) {
  EXPECT_OK(IsSupportedAlgorithmIdentifier(BCRYPT_ECDSA_P256_ALGORITHM));
}

TEST(IsSupportedAlgorithmIdentifierTest, AlgorithmNotFound) {
  EXPECT_THAT(IsSupportedAlgorithmIdentifier(BCRYPT_MD5_ALGORITHM),
              StatusSsIs(NTE_NOT_SUPPORTED));
}

}  // namespace
}  // namespace cloud_kms::kmscng
