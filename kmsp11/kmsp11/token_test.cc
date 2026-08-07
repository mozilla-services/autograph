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

#include "kmsp11/token.h"

#include "common/kms_client.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::Eq;
using ::testing::Field;
using ::testing::IsEmpty;
using ::testing::Le;
using ::testing::Pointee;
using ::testing::Property;

class TokenTest : public testing::Test {
 protected:
  inline void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());

    auto fake_client = fake_server_->NewClient();
    key_ring_ = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(),
                                   key_ring_);

    config_.set_key_ring(key_ring_.name());
    client_ = std::make_unique<KmsClient>(KmsClient::Options{
        .endpoint_address = fake_server_->listen_addr(),
        .rpc_timeout = absl::Seconds(1),
    });
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  kms_v1::KeyRing key_ring_;
  TokenConfig config_;
  std::unique_ptr<KmsClient> client_;
};

TEST_F(TokenTest, SlotInfoSlotDescriptionIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get(), false));

  EXPECT_EQ(StrFromBytes(token->slot_info().slotDescription),
            // Note the space-padding to get to 64 characters
            "A virtual slot mapped to a key ring in Google Cloud KMS         ");
}

TEST_F(TokenTest, SlotInfoManufacturerIdIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  EXPECT_EQ(StrFromBytes(token->slot_info().manufacturerID),
            // Note the space-padding to get to 32 characters
            "Google                          ");
}

TEST_F(TokenTest, SlotInfoFlagsAreSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(token->slot_info().flags, CKF_TOKEN_PRESENT);
}

TEST_F(TokenTest, SlotInfoHardwareVersionIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->slot_info().hardwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, SlotInfoFirmwareVersionIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->slot_info().firmwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, TokenInfoLabelDefaultUnset) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().label), std::string(32, ' '));
}

TEST_F(TokenTest, TokenInfoLabelExplicitValue) {
  config_.set_label("foo bar");
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().label),
            // Note the space-padding to get to 32 characters
            "foo bar                         ");
}

TEST_F(TokenTest, TokenInfoManufacturerIdIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().manufacturerID),
            // Note the space-padding to get to 32 characters
            "Google                          ");
}

TEST_F(TokenTest, TokenInfoModelIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().model),
            // Note the space-padding to get to 16 characters
            "Cloud KMS Token ");
}

TEST_F(TokenTest, SerialNumberIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_EQ(StrFromBytes(token->token_info().serialNumber), "0000000000000000");
}

TEST_F(TokenTest, FlagValues) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.flags & CKF_WRITE_PROTECTED, 0);
  EXPECT_EQ(info.flags & CKF_USER_PIN_INITIALIZED, CKF_USER_PIN_INITIALIZED);
  EXPECT_EQ(info.flags & CKF_TOKEN_INITIALIZED, CKF_TOKEN_INITIALIZED);
  EXPECT_EQ(info.flags & CKF_SO_PIN_LOCKED, CKF_SO_PIN_LOCKED);
}

TEST_F(TokenTest, MaxSessionCountsAreEffectivelyInfinite) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.ulMaxSessionCount, CK_EFFECTIVELY_INFINITE);
  EXPECT_EQ(info.ulMaxRwSessionCount, CK_EFFECTIVELY_INFINITE);
}

TEST_F(TokenTest, SessionCountsUnavailable) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.ulSessionCount, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(info.ulRwSessionCount, CK_UNAVAILABLE_INFORMATION);
}

TEST_F(TokenTest, PinLengthMinAndMaxIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.ulMaxPinLen, 0);
  EXPECT_EQ(info.ulMinPinLen, 0);
}

TEST_F(TokenTest, MemoryStatsUnavailable) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(info.ulTotalPublicMemory, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(info.ulFreePublicMemory, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(info.ulTotalPrivateMemory, CK_UNAVAILABLE_INFORMATION);
  EXPECT_EQ(info.ulFreePrivateMemory, CK_UNAVAILABLE_INFORMATION);
}

TEST_F(TokenTest, TokenInfoHardwareVersionIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_THAT(info.hardwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, TokenInfoFirmwareVersionIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();
  EXPECT_THAT(info.firmwareVersion,
              AllOf(Field("major", &CK_VERSION::major, 0),
                    Field("minor", &CK_VERSION::minor, 0)));
}

TEST_F(TokenTest, UtcTimeIsSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  const CK_TOKEN_INFO& info = token->token_info();

  EXPECT_EQ(StrFromBytes(info.utcTime), "0000000000000000");
}

TEST_F(TokenTest, LoginAsUserSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_OK(token->Login(CKU_USER));
  EXPECT_TRUE(token->is_logged_in());
}

TEST_F(TokenTest, LoginAsUserFailsOnRelogin) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_OK(token->Login(CKU_USER));
  EXPECT_THAT(token->Login(CKU_USER), StatusRvIs(CKR_USER_ALREADY_LOGGED_IN));
}

TEST_F(TokenTest, LoginAsSOFails) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->Login(CKU_SO), StatusRvIs(CKR_PIN_LOCKED));
}

TEST_F(TokenTest, LoginAsContextSpecificFails) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->Login(CKU_CONTEXT_SPECIFIC),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(TokenTest, LoginLogoutSucceeds) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_OK(token->Login(CKU_USER));
  EXPECT_TRUE(token->is_logged_in());
  EXPECT_OK(token->Logout());
  EXPECT_FALSE(token->is_logged_in());
}

TEST_F(TokenTest, LogoutWithoutLoginFails) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->Logout(), StatusRvIs(CKR_USER_NOT_LOGGED_IN));
}

TEST_F(TokenTest, FindObjectsPublicBeforePrivate) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  std::vector<CK_ULONG> handles =
      token->FindObjects([](const Object& o) -> bool { return true; });
  EXPECT_EQ(handles.size(), 2);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
  EXPECT_THAT(
      token->GetObject(handles[1]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv.name()),
          Property("object_class", &Object::object_class, CKO_PRIVATE_KEY)))));
}

TEST_F(TokenTest, FindObjectsKeyNamesSorted) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(kms_client.get(), ckv1);

  kms_v1::CryptoKeyVersion ckv2;
  ckv2 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv2);
  ckv2 = WaitForEnablement(kms_client.get(), ckv2);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  std::vector<CK_ULONG> handles =
      token->FindObjects([](const Object& o) -> bool {
        return o.object_class() == CKO_PUBLIC_KEY;
      });
  EXPECT_EQ(handles.size(), 2);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv1.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
  EXPECT_THAT(
      token->GetObject(handles[1]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv2.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
}

TEST_F(TokenTest, ObjectsEmptyHandleSet) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->FindObjects([](const Object& o) -> bool { return true; }),
              IsEmpty());
}

TEST_F(TokenTest, ObjectsUnknownHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->GetObject(1), StatusRvIs(CKR_OBJECT_HANDLE_INVALID));
}

TEST_F(TokenTest, EncryptDecryptKeyUnavailable) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "k", ck, false);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->FindObjects([](const Object& o) -> bool { return true; }),
              IsEmpty());
}

TEST_F(TokenTest, SoftwareKeyUnavailableWhenSoftwareKeysDisallowed) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::SOFTWARE);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "k", ck, false);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  EXPECT_THAT(token->FindObjects([](const Object& o) -> bool { return true; }),
              IsEmpty());
}

TEST_F(TokenTest, SoftwareKeyAvailableWhenSoftwareKeysAllowed) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::SOFTWARE);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);
  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /* generate_certs = */ false,
                 /* allow_software_keys =*/true));

  std::vector<CK_ULONG> handles =
      token->FindObjects([](const Object& o) -> bool {
        return o.object_class() == CKO_PUBLIC_KEY;
      });
  EXPECT_EQ(handles.size(), 1);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
}

TEST_F(TokenTest, SingleTenantKeyAvailable) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM_SINGLE_TENANT);
  ck.set_crypto_key_backend("test");
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);
  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /* generate_certs = */ false,
                 /* allow_software_keys =*/ false));

  std::vector<CK_ULONG> handles =
      token->FindObjects([](const Object& o) -> bool {
        return o.object_class() == CKO_PUBLIC_KEY;
      });
  EXPECT_EQ(handles.size(), 1);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
}

TEST_F(TokenTest, DisabledKeyUnavailable) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(kms_client.get(), ckv1);

  kms_v1::CryptoKeyVersion ckv2;
  ckv2 = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv2);
  ckv2 = WaitForEnablement(kms_client.get(), ckv2);

  // Disable ckv1
  ckv1.set_state(kms_v1::CryptoKeyVersion_CryptoKeyVersionState_DISABLED);
  google::protobuf::FieldMask update_mask;
  update_mask.add_paths("state");
  ckv1 = UpdateCryptoKeyVersionOrDie(kms_client.get(), ckv1, update_mask);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  std::vector<CK_ULONG> handles =
      token->FindObjects([](const Object& o) -> bool { return true; });
  EXPECT_EQ(handles.size(), 2);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv2.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));
  EXPECT_THAT(
      token->GetObject(handles[1]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv2.name()),
          Property("object_class", &Object::object_class, CKO_PRIVATE_KEY)))));
}

TEST_F(TokenTest, DisabledKeyUnavailableAfterRefresh) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));

  std::vector<CK_ULONG> handles;

  // On initial load, we should see both handles.
  handles = token->FindObjects([](const Object& o) -> bool { return true; });
  EXPECT_EQ(handles.size(), 2);

  // Disable ckv
  ckv.set_state(kms_v1::CryptoKeyVersion::DISABLED);
  google::protobuf::FieldMask update_mask;
  update_mask.add_paths("state");
  ckv = UpdateCryptoKeyVersionOrDie(kms_client.get(), ckv, update_mask);

  EXPECT_OK(token->RefreshState(*client_));

  // After refresh, there should be no objects.
  handles = token->FindObjects([](const Object& o) -> bool { return true; });
  EXPECT_EQ(handles.size(), 0);
}

TEST_F(TokenTest, CertGeneratedWhenConfigIsSet) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get(), true));

  std::vector<CK_ULONG> handles =
      token->FindObjects([](const Object& o) -> bool {
        return o.object_class() == CKO_CERTIFICATE;
      });
  EXPECT_EQ(handles.size(), 1);

  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv.name()),
          Property("object_class", &Object::object_class, CKO_CERTIFICATE)))));
}

TEST_F(TokenTest, CertNotGeneratedWhenConfigIsUnset) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get(), false));

  EXPECT_THAT(token->FindObjects([](const Object& o) -> bool {
    return o.object_class() == CKO_CERTIFICATE;
  }),
              IsEmpty());
}

}  // namespace
}  // namespace cloud_kms::kmsp11
