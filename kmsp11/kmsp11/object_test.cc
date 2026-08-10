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

#include "kmsp11/object.h"

#include "common/status_macros.h"
#include "common/test/runfiles.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmsp11/cert_authority.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::Field;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::SizeIs;

kms_v1::CryptoKeyVersion NewTestCkv() {
  kms_v1::CryptoKeyVersion v;
  v.set_name(
      "projects/foo/locations/global/keyRings/bar/cryptoKeys/baz/"
      "cryptoKeyVersions/1");
  v.set_algorithm(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  return v;
}

absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> GetTestP256Key() {
  ASSIGN_OR_RETURN(std::string test_key, LoadTestRunfile("ec_p256_public.pem"));
  return ParseX509PublicKeyPem(test_key);
}

absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> GetTestRsa2048Key() {
  ASSIGN_OR_RETURN(std::string test_key,
                   LoadTestRunfile("rsa_2048_public.pem"));
  return ParseX509PublicKeyPem(test_key);
}

TEST(NewKeyPairTest, KmsKeyNameMatches) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  EXPECT_EQ(key_pair.public_key.kms_key_name(), ckv.name());
  EXPECT_EQ(key_pair.private_key.kms_key_name(), ckv.name());
}

TEST(NewKeyPairTest, ObjectClassMatches) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  EXPECT_EQ(key_pair.public_key.object_class(), CKO_PUBLIC_KEY);
  EXPECT_EQ(key_pair.private_key.object_class(), CKO_PRIVATE_KEY);
}

TEST(NewKeyPairTest, PrivateKeyIsDestroyable) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  EXPECT_THAT(key_pair.private_key.attributes().Value(CKA_DESTROYABLE),
              IsOkAndHolds("\x01"));
}

TEST(NewKeyPairTest, PublicKeyIsNotDestroyable) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  EXPECT_THAT(key_pair.public_key.attributes().Value(CKA_DESTROYABLE),
              IsOkAndHolds(std::string("\x00", 1)));
}

TEST(NewKeyPairTest, AlgorithmMatches) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  std::vector<AlgorithmDetails> algs = {key_pair.public_key.algorithm(),
                                        key_pair.private_key.algorithm()};
  EXPECT_THAT(
      algs,
      Each(AllOf(
          Field("algorithm", &AlgorithmDetails::algorithm, ckv.algorithm()),
          Field("key_bit_length", &AlgorithmDetails::key_bit_length, 256),
          Field("key_type", &AlgorithmDetails::key_type, CKK_EC))));
}

TEST(NewKeyPairTest, LabelMatches) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));

  EXPECT_THAT(key_pair.public_key.attributes().Value(CKA_LABEL),
              IsOkAndHolds("baz"));
  EXPECT_THAT(key_pair.private_key.attributes().Value(CKA_LABEL),
              IsOkAndHolds("baz"));
}

TEST(NewKeyPairTest, PublicKeyAttributes) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));
  const AttributeMap& attrs = key_pair.public_key.attributes();

  // check a handful of the attributes to make sure they're consistent
  EXPECT_THAT(attrs.Value(CKA_CLASS),
              IsOkAndHolds(MarshalULong(CKO_PUBLIC_KEY)));
  EXPECT_THAT(attrs.Value(CKA_KMS_ALGORITHM),
              IsOkAndHolds(
                  MarshalULong(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256)));
  EXPECT_THAT(attrs.Value(CKA_TOKEN), IsOkAndHolds(MarshalBool(true)));
  EXPECT_THAT(attrs.Value(CKA_PRIVATE), IsOkAndHolds(MarshalBool(false)));
  EXPECT_THAT(attrs.Value(CKA_DERIVE), IsOkAndHolds(MarshalBool(false)));
  EXPECT_THAT(attrs.Value(CKA_VERIFY), IsOkAndHolds(MarshalBool(true)));
  EXPECT_THAT(attrs.Value(CKA_ENCRYPT), IsOkAndHolds(MarshalBool(false)));

  // check a couple of attributes that shouldn't be set
  EXPECT_THAT(attrs.Value(CKA_SIGN), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
  EXPECT_THAT(attrs.Value(CKA_ISSUER), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
}

TEST(NewKeyPairTest, PrivateKeyAttributes) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));
  const AttributeMap& attrs = key_pair.private_key.attributes();

  // check a handful of the attributes to make sure they're consistent
  EXPECT_THAT(attrs.Value(CKA_CLASS),
              IsOkAndHolds(MarshalULong(CKO_PRIVATE_KEY)));
  EXPECT_THAT(attrs.Value(CKA_KMS_ALGORITHM),
              IsOkAndHolds(
                  MarshalULong(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256)));
  EXPECT_THAT(attrs.Value(CKA_SUBJECT), IsOkAndHolds(""));
  EXPECT_THAT(attrs.Value(CKA_MODIFIABLE), IsOkAndHolds(MarshalBool(false)));
  EXPECT_THAT(attrs.Value(CKA_DERIVE), IsOkAndHolds(MarshalBool(false)));
  EXPECT_THAT(attrs.Value(CKA_SIGN), IsOkAndHolds(MarshalBool(true)));
  EXPECT_THAT(attrs.Value(CKA_DECRYPT), IsOkAndHolds(MarshalBool(false)));

  // check a couple of attributes that shouldn't be set
  EXPECT_THAT(attrs.Value(CKA_VERIFY), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
  EXPECT_THAT(attrs.Value(CKA_COLOR), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
}

TEST(NewKeyPairTest, EcKeyAttributes) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());
  BSSL_CONST EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pub.get());

  ASSERT_OK_AND_ASSIGN(std::string params, MarshalEcParametersDer(ec_key));
  ASSERT_OK_AND_ASSIGN(std::string point,
                       MarshalEcPointToAsn1OctetStringDer(ec_key));

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));
  const AttributeMap& pub_attrs = key_pair.public_key.attributes();
  const AttributeMap& prv_attrs = key_pair.private_key.attributes();

  EXPECT_THAT(pub_attrs.Value(CKA_EC_PARAMS), IsOkAndHolds(params));
  EXPECT_THAT(pub_attrs.Value(CKA_EC_POINT), IsOkAndHolds(point));
  EXPECT_THAT(pub_attrs.Value(CKA_VALUE),
              StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));

  EXPECT_THAT(prv_attrs.Value(CKA_EC_PARAMS), IsOkAndHolds(params));
  EXPECT_THAT(prv_attrs.Value(CKA_EC_POINT), IsOkAndHolds(point));
  EXPECT_THAT(prv_attrs.Value(CKA_VALUE), StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
}

TEST(NewKeyPairTest, RsaKeyAttributes) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ckv.set_algorithm(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256);

  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestRsa2048Key());
  const RSA* rsa_key = EVP_PKEY_get0_RSA(pub.get());
  const BIGNUM *n, *e;
  RSA_get0_key(rsa_key, &n, &e, /*d=*/nullptr);

  ASSERT_OK_AND_ASSIGN(KeyPair key_pair, Object::NewKeyPair(ckv, pub.get()));
  const AttributeMap& pub_attrs = key_pair.public_key.attributes();
  const AttributeMap& prv_attrs = key_pair.private_key.attributes();

  EXPECT_THAT(pub_attrs.Value(CKA_MODULUS_BITS),
              IsOkAndHolds(MarshalULong(2048)));
  EXPECT_THAT(pub_attrs.Value(CKA_MODULUS), IsOkAndHolds(MarshalBigNum(n)));
  EXPECT_THAT(pub_attrs.Value(CKA_PUBLIC_EXPONENT),
              IsOkAndHolds(MarshalBigNum(e)));
  EXPECT_THAT(pub_attrs.Value(CKA_PRIVATE_EXPONENT),
              StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));

  EXPECT_THAT(prv_attrs.Value(CKA_MODULUS_BITS),
              IsOkAndHolds(MarshalULong(2048)));
  EXPECT_THAT(prv_attrs.Value(CKA_PUBLIC_EXPONENT),
              IsOkAndHolds(MarshalBigNum(e)));
  EXPECT_THAT(prv_attrs.Value(CKA_PRIVATE_EXPONENT),
              StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
  EXPECT_THAT(prv_attrs.Value(CKA_PRIME_2),
              StatusRvIs(CKR_ATTRIBUTE_SENSITIVE));
}

TEST(NewCertificateTest, CertificateAttributes) {
  kms_v1::CryptoKeyVersion ckv = NewTestCkv();
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub, GetTestP256Key());
  ASSERT_OK_AND_ASSIGN(std::string key_der, MarshalX509PublicKeyDer(pub.get()));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<CertAuthority> authority,
                       CertAuthority::New());
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<X509> x509,
                       authority->GenerateCert(ckv, pub.get()));
  ASSERT_OK_AND_ASSIGN(Object cert, Object::NewCertificate(ckv, x509.get()));

  const AttributeMap& attrs = cert.attributes();

  EXPECT_THAT(attrs.Value(CKA_CLASS),
              IsOkAndHolds(MarshalULong(CKO_CERTIFICATE)));
  EXPECT_THAT(attrs.Value(CKA_KMS_ALGORITHM),
              IsOkAndHolds(MarshalULong(KMS_ALGORITHM_EC_SIGN_P256_SHA256)));
  EXPECT_THAT(attrs.Value(CKA_CERTIFICATE_TYPE),
              IsOkAndHolds(MarshalULong(CKC_X_509)));
  EXPECT_THAT(attrs.Value(CKA_TRUSTED), IsOkAndHolds(MarshalBool(false)));
  EXPECT_THAT(attrs.Value(CKA_CERTIFICATE_CATEGORY),
              IsOkAndHolds(MarshalULong(CK_CERTIFICATE_CATEGORY_UNSPECIFIED)));
  EXPECT_THAT(attrs.Value(CKA_CHECK_VALUE), IsOkAndHolds(SizeIs(3)));
  EXPECT_THAT(attrs.Value(CKA_START_DATE), IsOkAndHolds(Not(IsEmpty())));
  EXPECT_THAT(attrs.Value(CKA_END_DATE), IsOkAndHolds(HasSubstr("99991231")));
  EXPECT_THAT(attrs.Value(CKA_PUBLIC_KEY_INFO), IsOkAndHolds(key_der));

  EXPECT_THAT(attrs.Value(CKA_SUBJECT), IsOkAndHolds(HasSubstr("baz")));
  EXPECT_THAT(attrs.Value(CKA_ID), IsOkAndHolds(ckv.name()));
  EXPECT_THAT(attrs.Value(CKA_ISSUER),
              IsOkAndHolds(HasSubstr("cloud-kms-pkcs11")));
  EXPECT_THAT(attrs.Value(CKA_SERIAL_NUMBER), IsOkAndHolds(Not(IsEmpty())));
  EXPECT_THAT(attrs.Value(CKA_URL), IsOkAndHolds(IsEmpty()));
  EXPECT_THAT(attrs.Value(CKA_HASH_OF_SUBJECT_PUBLIC_KEY),
              IsOkAndHolds(IsEmpty()));
  EXPECT_THAT(attrs.Value(CKA_HASH_OF_ISSUER_PUBLIC_KEY),
              IsOkAndHolds(IsEmpty()));
  EXPECT_THAT(attrs.Value(CKA_JAVA_MIDP_SECURITY_DOMAIN),
              IsOkAndHolds(MarshalULong(CK_SECURITY_DOMAIN_UNSPECIFIED)));

  // check a couple of attributes that shouldn't be set
  EXPECT_THAT(attrs.Value(CKA_VERIFY), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
  EXPECT_THAT(attrs.Value(CKA_COLOR), StatusRvIs(CKR_ATTRIBUTE_TYPE_INVALID));
}

}  // namespace
}  // namespace cloud_kms::kmsp11
