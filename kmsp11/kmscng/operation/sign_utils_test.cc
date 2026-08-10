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

#include "kmscng/operation/sign_utils.h"

#include "common/kms_client.h"
#include "common/test/resource_helpers.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmscng/cng_headers.h"
#include "kmscng/object.h"
#include "kmscng/provider.h"
#include "kmscng/test/matchers.h"
#include "kmscng/util/string_utils.h"

namespace cloud_kms::kmscng {
namespace {

using ::testing::HasSubstr;

class ValidAlgorithmSignUtilsTest
    : public testing::Test,
      public testing::WithParamInterface<
          kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm> {};

const std::array kSupportedAlgorithms = {
    kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
    kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384,
    kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256,
    kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256,
    kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256,
    kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512
};

INSTANTIATE_TEST_SUITE_P(TestValidAlgorithms, ValidAlgorithmSignUtilsTest,
                         testing::ValuesIn(kSupportedAlgorithms));

TEST_P(ValidAlgorithmSignUtilsTest, IsValidSigningAlgorithmSuccess) {
  EXPECT_OK(
      IsValidSigningAlgorithm(kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384));
}

TEST(IsValidSigningAlgorithmTest, InvalidAlgoritmhm) {
  EXPECT_THAT(IsValidSigningAlgorithm(
                  kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA1),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("invalid asymmetric signing algorithm")));
}

TEST_P(ValidAlgorithmSignUtilsTest, DigestForAlgorithmSuccess) {
  EXPECT_OK(DigestForAlgorithm(kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384));
}

TEST(DigestForAlgorithmTest, InvalidAlgoritmhm) {
  EXPECT_THAT(
      DigestForAlgorithm(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA1),
      StatusIs(absl::StatusCode::kInternal,
               HasSubstr("cannot get digest type")));
}

TEST(CurveIdForAlgorithmTest, EcdsaSuccess) {
  EXPECT_OK(CurveIdForAlgorithm(kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384));
}

TEST(CurveIdForAlgorithmTest, InvalidAlgoritmhm) {
  EXPECT_THAT(
      CurveIdForAlgorithm(kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("cannot get curve")));
}

TEST_P(ValidAlgorithmSignUtilsTest, MagicIdForAlgorithmSuccess) {
  EXPECT_OK(MagicIdForAlgorithm(kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384));
}

TEST(MagicIdForAlgorithmTest, InvalidAlgoritmhm) {
  EXPECT_THAT(
      MagicIdForAlgorithm(kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA1),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("cannot get magic")));
}

class SignUtilsTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());
    auto client = fake_server_->NewClient();

    kms_v1::KeyRing kr;
    kr = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr);

    kms_v1::CryptoKey ec_ck;
    ec_ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
    ec_ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
    ec_ck.mutable_version_template()->set_protection_level(
        kms_v1::ProtectionLevel::HSM);

    ec_ck = CreateCryptoKeyOrDie(client.get(), kr.name(), "ec_ck", ec_ck, true);

    kms_v1::CryptoKeyVersion ec_ckv;
    ec_ckv = CreateCryptoKeyVersionOrDie(client.get(), ec_ck.name(), ec_ckv);
    ec_ckv = WaitForEnablement(client.get(), ec_ckv);

    kms_v1::CryptoKey rsa_ck;
    rsa_ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
    rsa_ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256);
    rsa_ck.mutable_version_template()->set_protection_level(
        kms_v1::ProtectionLevel::HSM);

    rsa_ck =
        CreateCryptoKeyOrDie(client.get(), kr.name(), "rsa_ck", rsa_ck, true);

    kms_v1::CryptoKeyVersion rsa_ckv;
    rsa_ckv = CreateCryptoKeyVersionOrDie(client.get(), rsa_ck.name(), rsa_ckv);
    rsa_ckv = WaitForEnablement(client.get(), rsa_ckv);

    Provider provider;
    // Set custom properties to hit fake KMS.
    EXPECT_OK(provider.SetProperty(kEndpointAddressProperty,
                                   fake_server_->listen_addr()));
    EXPECT_OK(provider.SetProperty(kChannelCredentialsProperty, "insecure"));

    ASSERT_OK_AND_ASSIGN(
        ec_object_, Object::New(reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider),
                                ec_ckv.name()));
    ASSERT_OK_AND_ASSIGN(
        rsa_object_,
        Object::New(reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider),
                    rsa_ckv.name()));
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  Object* ec_object_;
  Object* rsa_object_;
};

TEST_F(SignUtilsTest, ValidateEcKeyPreconditionsSuccess) {
  EXPECT_OK(ValidateKeyPreconditions(ec_object_));
}

TEST_F(SignUtilsTest, ValidateRsaKeyPreconditionsSuccess) {
  EXPECT_OK(ValidateKeyPreconditions(rsa_object_));
}

TEST_F(SignUtilsTest, SerializePublicEcKeySuccess) {
  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> output,
                       SerializePublicKey(ec_object_));
  BCRYPT_ECCKEY_BLOB* header =
      reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(output.data());
  EXPECT_EQ(header->dwMagic, BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
  EXPECT_EQ(header->cbKey, 32);
}

TEST_F(SignUtilsTest, SerializePublicRsaKeySuccess) {
  ASSERT_OK_AND_ASSIGN(std::vector<uint8_t> output,
                       SerializePublicKey(rsa_object_));
  BCRYPT_RSAKEY_BLOB* header =
      reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(output.data());
  EXPECT_EQ(header->Magic, BCRYPT_RSAPUBLIC_MAGIC);
  EXPECT_EQ(header->BitLength, 4096);
}

TEST_F(SignUtilsTest, ExpectedSignatureLengthSuccess) {
  // Expected EC_SIGN_P256_SHA256 signature length == 64.
  EXPECT_THAT(SignatureLength(ec_object_), IsOkAndHolds(64));
}

TEST_F(SignUtilsTest, SignDigestSuccess) {
  std::vector<uint8_t> digest(32, '\1');
  std::vector<uint8_t> signature(64, '\0');
  EXPECT_OK(SignDigest(ec_object_, absl::MakeSpan(digest),
                       absl::MakeSpan(signature)));
}

TEST_F(SignUtilsTest, SignDigestInvalidDigestSize) {
  std::vector<uint8_t> digest(33, '\1');
  std::vector<uint8_t> signature(64, '\0');
  EXPECT_THAT(
      SignDigest(ec_object_, absl::MakeSpan(digest), absl::MakeSpan(signature)),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("digest has incorrect size")));
}

TEST_F(SignUtilsTest, SignDigestInvalidSignatureSize) {
  std::vector<uint8_t> digest(32, '\1');
  std::vector<uint8_t> signature(65, '\0');
  EXPECT_THAT(
      SignDigest(ec_object_, absl::MakeSpan(digest), absl::MakeSpan(signature)),
      StatusIs(absl::StatusCode::kInternal,
               HasSubstr("signature buffer has incorrect size")));
}

}  // namespace
}  // namespace cloud_kms::kmscng
