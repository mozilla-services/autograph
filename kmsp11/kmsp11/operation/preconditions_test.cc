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

#include "kmsp11/operation/preconditions.h"

#include "common/test/runfiles.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmsp11/object.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

absl::StatusOr<KeyPair> NewMockKeyPair(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    std::string_view public_key_runfile) {
  kms_v1::CryptoKeyVersion ckv;
  ckv.set_name(
      "projects/foo/locations/bar/keyRings/baz/cryptoKeys/qux/"
      "cryptoKeyVersions/1");
  ckv.set_algorithm(algorithm);
  ckv.set_state(kms_v1::CryptoKeyVersion::ENABLED);

  ASSIGN_OR_RETURN(std::string pub_pem, LoadTestRunfile(public_key_runfile));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> pub,
                   ParseX509PublicKeyPem(pub_pem));
  return Object::NewKeyPair(ckv, pub.get());
}

TEST(PreconditionsTest, PreconditionsMatchSuccess) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));

  EXPECT_OK(CheckKeyPreconditions(CKK_EC, CKO_PRIVATE_KEY, CKM_ECDSA,
                                  &kp.private_key));
}

TEST(PreconditionsTest, PreconditionsMismatchKeyType) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  EXPECT_THAT(CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY, CKM_RSA_PKCS,
                                    &kp.private_key),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(PreconditionsTest, PreconditionsMismatchKeyClass) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp, NewMockKeyPair(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                                 "ec_p256_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  EXPECT_THAT(
      CheckKeyPreconditions(CKK_EC, CKO_PUBLIC_KEY, CKM_ECDSA, &kp.private_key),
      StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

TEST(PreconditionsTest, PreconditionsMismatchKeyMechanism) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  EXPECT_THAT(CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY, CKM_RSA_PKCS,
                                    &kp.private_key),
              StatusRvIs(CKR_KEY_FUNCTION_NOT_PERMITTED));
}

TEST(PreconditionsTest, PreconditionsMismatchKeyTypePriority) {
  ASSERT_OK_AND_ASSIGN(
      KeyPair kp,
      NewMockKeyPair(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,
                     "rsa_2048_public.pem"));
  std::shared_ptr<Object> key = std::make_shared<Object>(kp.private_key);

  // Both key_type and object_class are wrong, but key_type should take priority
  // per the P11 spec
  EXPECT_THAT(
      CheckKeyPreconditions(CKK_EC, CKO_PUBLIC_KEY, CKM_ECDSA, &kp.private_key),
      StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

}  // namespace
}  // namespace cloud_kms::kmsp11