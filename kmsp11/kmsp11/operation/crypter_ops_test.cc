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

#include "kmsp11/operation/crypter_ops.h"

#include "common/test/runfiles.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/object.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

TEST(DecryptOpTest, ValidMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_RSA_PKCS_OAEP_PARAMS params{
      CKM_SHA256,          // hashAlg
      CKG_MGF1_SHA256,     // mgf
      CKZ_DATA_SPECIFIED,  // source
      nullptr,             // pSourceData
      0,                   // ulSourceDataLen
  };

  CK_MECHANISM mechanism{
      CKM_RSA_PKCS_OAEP,  // mechanism
      &params,            // pParameter
      sizeof(params),     // ulParameterLen
  };

  EXPECT_OK(NewDecryptOp(key, &mechanism));
}

TEST(DecryptOpTest, InvalidMechanismFailure) {
  CK_MECHANISM mech = {CKM_AES_ECB};
  EXPECT_THAT(NewDecryptOp(nullptr, &mech), StatusRvIs(CKR_MECHANISM_INVALID));
}

TEST(EncryptOpTest, ValidMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_RSA_PKCS_OAEP_PARAMS params{
      CKM_SHA256,          // hashAlg
      CKG_MGF1_SHA256,     // mgf
      CKZ_DATA_SPECIFIED,  // source
      nullptr,             // pSourceData
      0,                   // ulSourceDataLen
  };

  CK_MECHANISM mechanism{
      CKM_RSA_PKCS_OAEP,  // mechanism
      &params,            // pParameter
      sizeof(params),     // ulParameterLen
  };

  EXPECT_OK(NewEncryptOp(key, &mechanism));
}

TEST(EncryptOpTest, InvalidMechanismFailure) {
  CK_MECHANISM mech = {CKM_AES_ECB};
  EXPECT_THAT(NewEncryptOp(nullptr, &mech), StatusRvIs(CKR_MECHANISM_INVALID));
}

TEST(SignOpTest, ValidMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_MECHANISM mechanism{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(NewSignOp(key, &mechanism));
}

TEST(SignOpTest, ValidDigestingMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  CK_MECHANISM mechanism{CKM_ECDSA_SHA256, nullptr, 0};
  EXPECT_OK(NewSignOp(key, &mechanism));
}

TEST(SignOpTest, InvalidMechanismFailure) {
  CK_MECHANISM mech = {CKM_SHA512_256_HMAC};
  EXPECT_THAT(NewSignOp(nullptr, &mech), StatusRvIs(CKR_MECHANISM_INVALID));
}

TEST(VerifyOpTest, ValidMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_MECHANISM mechanism{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(NewVerifyOp(key, &mechanism));
}

TEST(VerifyOpTest, ValidDigestingMechanismSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.public_key);

  CK_MECHANISM mechanism{CKM_ECDSA_SHA256, nullptr, 0};
  EXPECT_OK(NewVerifyOp(key, &mechanism));
}

TEST(VerifyOpTest, InvalidMechanismFailure) {
  CK_MECHANISM mech = {CKM_SHA512_256_HMAC};
  EXPECT_THAT(NewVerifyOp(nullptr, &mech), StatusRvIs(CKR_MECHANISM_INVALID));
}

}  // namespace
}  // namespace cloud_kms::kmsp11
