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

#include "kmsp11/provider.h"

#include "common/test/proto_parser.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::Contains;
using ::testing::Eq;
using ::testing::Field;
using ::testing::Le;

class ProviderTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());

    auto client = fake_server_->NewClient();
    kms_v1::KeyRing kr1;
    kr1 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr1);
    kms_v1::KeyRing kr2;
    kr2 = CreateKeyRingOrDie(client.get(), kTestLocation, RandomId(), kr2);

    LibraryConfig config = ParseTestProto(
        absl::StrFormat(R"(
      tokens {
        key_ring: "%s"
        label: "foo"
      }
      tokens {
        key_ring: "%s"
        label: "bar"
      }
      kms_endpoint: "%s",
      use_insecure_grpc_channel_credentials: true,
    )",
                        kr1.name(), kr2.name(), fake_server_->listen_addr()));

    ASSERT_OK_AND_ASSIGN(provider_, Provider::New(config));
    info_ = provider_->info();
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  std::unique_ptr<Provider> provider_;
  CK_INFO info_;
};

TEST_F(ProviderTest, InfoCryptokiVersionIsSet) {
  EXPECT_THAT(
      info_.cryptokiVersion,
      AllOf(Field("major", &CK_VERSION::major, Eq(CRYPTOKI_VERSION_MAJOR)),
            Field("minor", &CK_VERSION::minor, Eq(CRYPTOKI_VERSION_MINOR))));
}

TEST_F(ProviderTest, InfoManufacturerIdIsSet) {
  EXPECT_EQ(StrFromBytes(info_.manufacturerID),
            // Note the space-padding to get to 32 characters
            "Google                          ");
}

TEST_F(ProviderTest, InfoFlagsIsZero) { EXPECT_THAT(info_.flags, Eq(0)); }

TEST_F(ProviderTest, LibraryDescriptionIsSet) {
  EXPECT_THAT(StrFromBytes(info_.libraryDescription),
              // Note the space-padding to get to 32 characters
              "Cryptoki Library for Cloud KMS  ");
}

TEST_F(ProviderTest, InfoLibraryVersionIsSet) {
  EXPECT_THAT(info_.libraryVersion,
              AllOf(Field("major", &CK_VERSION::major, Le(10)),
                    Field("minor", &CK_VERSION::minor, Le(100))));
}

TEST_F(ProviderTest, ConfiguredTokens) {
  EXPECT_EQ(provider_->token_count(), 2);

  ASSERT_OK_AND_ASSIGN(const Token* token0, provider_->TokenAt(0));
  EXPECT_THAT(StrFromBytes(token0->token_info().label),
              MatchesStdRegex("foo[ ]+"));

  ASSERT_OK_AND_ASSIGN(const Token* token1, provider_->TokenAt(1));
  EXPECT_THAT(StrFromBytes(token1->token_info().label),
              MatchesStdRegex("bar[ ]+"));
}

TEST_F(ProviderTest, SupportedMechanisms) {
  EXPECT_THAT(provider_->Mechanisms(),
              // Check a subset of the permitted mechanisms, to avoid having
              // this test be a change detector.
              AllOf(Contains(CKM_RSA_PKCS_KEY_PAIR_GEN),
                    Contains(CKM_RSA_PKCS_PSS), Contains(CKM_ECDSA)));
}

TEST_F(ProviderTest, DecryptFlag) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       provider_->MechanismInfo(CKM_RSA_PKCS_OAEP));
  EXPECT_EQ(info.flags & CKF_DECRYPT, CKF_DECRYPT);
}

TEST_F(ProviderTest, EncryptFlag) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       provider_->MechanismInfo(CKM_RSA_PKCS_OAEP));
  EXPECT_EQ(info.flags & CKF_ENCRYPT, CKF_ENCRYPT);
}

TEST_F(ProviderTest, SignFlag) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       provider_->MechanismInfo(CKM_RSA_PKCS_PSS));
  EXPECT_EQ(info.flags & CKF_SIGN, CKF_SIGN);
}

TEST_F(ProviderTest, VerifyFlag) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       provider_->MechanismInfo(CKM_RSA_PKCS));
  EXPECT_EQ(info.flags & CKF_VERIFY, CKF_VERIFY);
}

TEST_F(ProviderTest, RsaMin2048) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       provider_->MechanismInfo(CKM_RSA_PKCS_OAEP));
  EXPECT_EQ(info.ulMinKeySize, 2048);
}

TEST_F(ProviderTest, RsaMax4096) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       provider_->MechanismInfo(CKM_RSA_PKCS));
  EXPECT_EQ(info.ulMaxKeySize, 4096);
}

TEST_F(ProviderTest, EcMax384) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       provider_->MechanismInfo(CKM_ECDSA));
  EXPECT_EQ(info.ulMaxKeySize, 384);
}

TEST_F(ProviderTest, EcFlags) {
  ASSERT_OK_AND_ASSIGN(CK_MECHANISM_INFO info,
                       provider_->MechanismInfo(CKM_ECDSA));
  EXPECT_EQ(info.flags & CKF_EC_F_P, CKF_EC_F_P);
  EXPECT_EQ(info.flags & CKF_EC_NAMEDCURVE, CKF_EC_NAMEDCURVE);
  EXPECT_EQ(info.flags & CKF_EC_UNCOMPRESS, CKF_EC_UNCOMPRESS);
}

TEST_F(ProviderTest, UnsupportedMechanism) {
  EXPECT_THAT(provider_->MechanismInfo(CKM_SHA512_256_HMAC),
              AllOf(StatusIs(absl::StatusCode::kNotFound),
                    StatusRvIs(CKR_MECHANISM_INVALID)));
}

}  // namespace
}  // namespace cloud_kms::kmsp11
