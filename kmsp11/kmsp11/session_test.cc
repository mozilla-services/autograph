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

#include "kmsp11/session.h"

#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::ElementsAreArray;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Pointee;
using ::testing::Property;
using ::testing::SizeIs;

class SessionTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());

    auto fake_client = fake_server_->NewClient();
    key_ring_ = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(),
                                   key_ring_);

    config_.set_key_ring(key_ring_.name());
    client_ = std::make_unique<KmsClient>(KmsClient::Options{
        .endpoint_address = fake_server_->listen_addr(),
        .rpc_timeout = absl::Seconds(5),
    });
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  kms_v1::KeyRing key_ring_;
  TokenConfig config_;
  std::unique_ptr<KmsClient> client_;
};

TEST_F(SessionTest, InfoContainsSlotId) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_EQ(s.info().slotID, 0);
}

TEST_F(SessionTest, ReadOnlySession) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_EQ(s.info().state, CKS_RO_PUBLIC_SESSION);
  EXPECT_EQ(s.info().flags & CKF_RW_SESSION, 0);
}

TEST_F(SessionTest, ReadWriteSession) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  EXPECT_EQ(s.info().state, CKS_RW_PUBLIC_SESSION);
  EXPECT_EQ(s.info().flags & CKF_RW_SESSION, CKF_RW_SESSION);
}

TEST_F(SessionTest, SessionFlagsSerial) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_EQ(s.info().flags & CKF_SERIAL_SESSION, CKF_SERIAL_SESSION);
}

TEST_F(SessionTest, SessionErrorIsZero) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_EQ(s.info().ulDeviceError, 0);
}

TEST_F(SessionTest, NewSessionInheritsLoginState) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  EXPECT_OK(token->Login(CKU_USER));

  Session s(token.get(), SessionType::kReadOnly, client_.get());
  EXPECT_EQ(s.info().state, CKS_RO_USER_FUNCTIONS);
}

TEST_F(SessionTest, ReadOnlyStateUpdatedAfterLoginAndLogout) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_EQ(s.info().state, CKS_RO_PUBLIC_SESSION);
  EXPECT_EQ(s.info().flags & CKF_RW_SESSION, 0);

  EXPECT_OK(token->Login(CKU_USER));
  EXPECT_EQ(s.info().state, CKS_RO_USER_FUNCTIONS);
  EXPECT_EQ(s.info().flags & CKF_RW_SESSION, 0);

  EXPECT_OK(token->Logout());
  EXPECT_EQ(s.info().state, CKS_RO_PUBLIC_SESSION);
  EXPECT_EQ(s.info().flags & CKF_RW_SESSION, 0);
}

TEST_F(SessionTest, ReadWriteStateUpdatedAfterLoginAndLogout) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  EXPECT_EQ(s.info().state, CKS_RW_PUBLIC_SESSION);
  EXPECT_EQ(s.info().flags & CKF_RW_SESSION, CKF_RW_SESSION);

  EXPECT_OK(token->Login(CKU_USER));
  EXPECT_EQ(s.info().state, CKS_RW_USER_FUNCTIONS);
  EXPECT_EQ(s.info().flags & CKF_RW_SESSION, CKF_RW_SESSION);

  EXPECT_OK(token->Logout());
  EXPECT_EQ(s.info().state, CKS_RW_PUBLIC_SESSION);
  EXPECT_EQ(s.info().flags & CKF_RW_SESSION, CKF_RW_SESSION);
}

TEST_F(SessionTest, FindEmptyTokenSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_OK(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()));
  EXPECT_THAT(s.FindObjects(1), IsOkAndHolds(IsEmpty()));
  EXPECT_OK(s.FindObjectsFinal());
}

TEST_F(SessionTest, FindAllSinglePage) {
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
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_OK(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()));
  ASSERT_OK_AND_ASSIGN(absl::Span<const CK_OBJECT_HANDLE> handles,
                       s.FindObjects(5));
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

  EXPECT_OK(s.FindObjectsFinal());
}

TEST_F(SessionTest, FindIgnoreResults) {
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
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_OK(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()));
  EXPECT_OK(s.FindObjectsFinal());
}

TEST_F(SessionTest, FindPublicKeysMultiPage) {
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
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  CK_OBJECT_CLASS want_class = CKO_PUBLIC_KEY;
  std::vector<CK_ATTRIBUTE> attr_template = {
      {CKA_CLASS, &want_class, sizeof(want_class)},
  };

  EXPECT_OK(s.FindObjectsInit(attr_template));

  ASSERT_OK_AND_ASSIGN(absl::Span<const CK_OBJECT_HANDLE> handles,
                       s.FindObjects(1));
  EXPECT_EQ(handles.size(), 1);
  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv1.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));

  ASSERT_OK_AND_ASSIGN(handles, s.FindObjects(1));
  EXPECT_EQ(handles.size(), 1);
  EXPECT_THAT(
      token->GetObject(handles[0]),
      IsOkAndHolds(Pointee(AllOf(
          Property("kms_key_name", &Object::kms_key_name, ckv2.name()),
          Property("object_class", &Object::object_class, CKO_PUBLIC_KEY)))));

  ASSERT_OK_AND_ASSIGN(handles, s.FindObjects(1));
  EXPECT_EQ(handles.size(), 0);

  EXPECT_OK(s.FindObjectsFinal());
}

TEST_F(SessionTest, FindInitAlreadyActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_OK(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()));

  EXPECT_THAT(s.FindObjectsInit(std::vector<CK_ATTRIBUTE>()),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(SessionTest, FindNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_THAT(s.FindObjects(1), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, FindFinalNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_THAT(s.FindObjectsFinal(), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, Decrypt) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  kms_v1::PublicKey pub_proto = GetPublicKeyOrDie(kms_client.get(), ckv);
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pub_proto.pem()));

  std::vector<uint8_t> plaintext = {0x00, 0x01, 0xFE, 0xFF};
  uint8_t ciphertext[256];
  EXPECT_OK(EncryptRsaOaep(pub.get(), EVP_sha256(), plaintext,
                           absl::MakeSpan(ciphertext)));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(s.DecryptInit(object, &mech));
  EXPECT_THAT(s.Decrypt(ciphertext), IsOkAndHolds(plaintext));
}

TEST_F(SessionTest, DecryptInitAlreadyActive) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(s.DecryptInit(object, &mech))
  EXPECT_THAT(s.DecryptInit(object, &mech), StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(SessionTest, DecryptNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t ciphertext[32];
  EXPECT_THAT(s.Decrypt(ciphertext), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, DecryptUpdateNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t data[32];
  EXPECT_THAT(s.DecryptUpdate(data), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, DecryptFinalNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_THAT(s.DecryptFinal(), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, DecryptFinalWithoutUpdateFails) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::AES_256_GCM);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_SECRET_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> key,
                       s.token()->GetObject(handles[0]));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(s.DecryptInit(key, &mech));
  EXPECT_THAT(s.DecryptFinal(), StatusRvIs(CKR_FUNCTION_FAILED));
}

TEST_F(SessionTest, Encrypt) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PUBLIC_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(s.EncryptInit(object, &mech));

  std::vector<uint8_t> plaintext = {0x00, 0x01, 0x02, 0x03};
  EXPECT_THAT(s.Encrypt(plaintext), IsOkAndHolds(SizeIs(256)));
}

TEST_F(SessionTest, EncryptInitAlreadyActive) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PUBLIC_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA256, CKG_MGF1_SHA256,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(s.EncryptInit(object, &mech));
  EXPECT_THAT(s.EncryptInit(object, &mech), StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(SessionTest, EncryptNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t plaintext[256];
  EXPECT_THAT(s.Encrypt(plaintext), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, EncryptUpdateNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t data[32];
  EXPECT_THAT(s.EncryptUpdate(data), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, EncryptFinalNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_THAT(s.EncryptFinal(), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, EncryptFinalWithoutUpdateFails) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::AES_256_GCM);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_SECRET_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> key,
                       s.token()->GetObject(handles[0]));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(s.EncryptInit(key, &mech));
  EXPECT_THAT(s.EncryptFinal(), StatusRvIs(CKR_FUNCTION_FAILED));
}

TEST_F(SessionTest, Sign) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  kms_v1::PublicKey pub_proto = GetPublicKeyOrDie(kms_client.get(), ckv);
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pub_proto.pem()));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};

  uint8_t digest[32], signature[64];
  EXPECT_OK(s.SignInit(object, &mech));
  EXPECT_OK(s.Sign(digest, absl::MakeSpan(signature)));

  EXPECT_OK(EcdsaVerifyP1363(EVP_PKEY_get0_EC_KEY(pub.get()), EVP_sha256(),
                             digest, signature));
}

TEST_F(SessionTest, SignInitAlreadyActive) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};

  EXPECT_OK(s.SignInit(object, &mech))
  EXPECT_THAT(s.SignInit(object, &mech), StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(SessionTest, SignatureLength) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};

  EXPECT_OK(s.SignInit(object, &mech));
  EXPECT_THAT(s.SignatureLength(), IsOkAndHolds(64));
}

TEST_F(SessionTest, SignatureLengthNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_THAT(s.SignatureLength(), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, SignNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t digest[32], signature[64];
  EXPECT_THAT(s.Sign(digest, absl::MakeSpan(signature)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, SignVerify) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> prv,
                       s.token()->GetObject(handles[0]));

  handles = s.token()->FindObjects([&](const Object& o) -> bool {
    return o.kms_key_name() == ckv.name() && o.object_class() == CKO_PUBLIC_KEY;
  });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> pub,
                       s.token()->GetObject(handles[0]));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};

  uint8_t digest[32], signature[64];
  EXPECT_OK(s.SignInit(prv, &mech));
  EXPECT_OK(s.Sign(digest, absl::MakeSpan(signature)));
  s.ReleaseOperation();

  EXPECT_OK(s.VerifyInit(pub, &mech));
  EXPECT_OK(s.Verify(digest, signature));
}

TEST_F(SessionTest, SignUpdateNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t data[32];
  EXPECT_THAT(s.SignUpdate(data), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, SignFinalNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t signature[64];
  EXPECT_THAT(s.SignFinal(absl::MakeSpan(signature)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, SignFinalWithoutUpdateFails) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> prv,
                       s.token()->GetObject(handles[0]));

  handles = s.token()->FindObjects([&](const Object& o) -> bool {
    return o.kms_key_name() == ckv.name() && o.object_class() == CKO_PUBLIC_KEY;
  });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> pub,
                       s.token()->GetObject(handles[0]));

  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};

  uint8_t signature[64];
  EXPECT_OK(s.SignInit(prv, &mech));
  EXPECT_THAT(s.SignFinal(absl::MakeSpan(signature)),
              StatusRvIs(CKR_FUNCTION_FAILED));
}

TEST_F(SessionTest, SignMultiPartSuccess) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> prv,
                       s.token()->GetObject(handles[0]));

  handles = s.token()->FindObjects([&](const Object& o) -> bool {
    return o.kms_key_name() == ckv.name() && o.object_class() == CKO_PUBLIC_KEY;
  });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> pub,
                       s.token()->GetObject(handles[0]));

  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};

  uint8_t data[32], signature[64];
  EXPECT_OK(s.SignInit(prv, &mech));
  EXPECT_OK(s.SignUpdate(data));
  EXPECT_OK(s.SignFinal(absl::MakeSpan(signature)));
}

TEST_F(SessionTest, VerifyInitAlreadyActive) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PUBLIC_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> object,
                       s.token()->GetObject(handles[0]));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};

  EXPECT_OK(s.VerifyInit(object, &mech));
  EXPECT_THAT(s.VerifyInit(object, &mech), StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_F(SessionTest, VerifyNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t digest[32], signature[64];
  EXPECT_THAT(s.Verify(digest, signature),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, VerifyUpdateNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t data[32];
  EXPECT_THAT(s.VerifyUpdate(data), StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, VerifyFinalNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  uint8_t signature[64];
  EXPECT_THAT(s.VerifyFinal(absl::MakeSpan(signature)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_F(SessionTest, VerifyFinalWithoutUpdateFails) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> prv,
                       s.token()->GetObject(handles[0]));

  handles = s.token()->FindObjects([&](const Object& o) -> bool {
    return o.kms_key_name() == ckv.name() && o.object_class() == CKO_PUBLIC_KEY;
  });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> pub,
                       s.token()->GetObject(handles[0]));

  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};

  uint8_t signature[64];
  EXPECT_OK(s.VerifyInit(pub, &mech));
  EXPECT_THAT(s.VerifyFinal(absl::MakeSpan(signature)),
              StatusRvIs(CKR_FUNCTION_FAILED));
}

TEST_F(SessionTest, SignVerifyMultiPartSuccess) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<CK_OBJECT_HANDLE> handles =
      s.token()->FindObjects([&](const Object& o) -> bool {
        return o.kms_key_name() == ckv.name() &&
               o.object_class() == CKO_PRIVATE_KEY;
      });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> prv,
                       s.token()->GetObject(handles[0]));

  handles = s.token()->FindObjects([&](const Object& o) -> bool {
    return o.kms_key_name() == ckv.name() && o.object_class() == CKO_PUBLIC_KEY;
  });
  EXPECT_EQ(handles.size(), 1);
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> pub,
                       s.token()->GetObject(handles[0]));

  CK_MECHANISM mech{CKM_ECDSA_SHA256, nullptr, 0};

  uint8_t data[32], signature[64];
  EXPECT_OK(s.SignInit(prv, &mech));
  EXPECT_OK(s.SignUpdate(data));
  EXPECT_OK(s.SignFinal(absl::MakeSpan(signature)));

  s.ReleaseOperation();

  EXPECT_OK(s.VerifyInit(pub, &mech));
  EXPECT_OK(s.VerifyUpdate(data));
  EXPECT_OK(s.VerifyFinal(absl::MakeSpan(signature)));
}

TEST_F(SessionTest, GenerateRandomSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<uint8_t> zero(32, '\0');
  std::vector<uint8_t> rand(zero);
  EXPECT_OK(s.GenerateRandom(absl::MakeSpan(rand)));
  EXPECT_THAT(rand, Not(ElementsAreArray(zero)));
}

TEST_F(SessionTest, GenerateRandomSuccessMinBufferSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<uint8_t> zero(8, '\0');
  std::vector<uint8_t> rand(zero);
  EXPECT_OK(s.GenerateRandom(absl::MakeSpan(rand)));
  EXPECT_THAT(rand, Not(ElementsAreArray(zero)));
}

TEST_F(SessionTest, GenerateRandomSuccessMaxBufferSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<uint8_t> zero(1024, '\0');
  std::vector<uint8_t> rand(zero);
  EXPECT_OK(s.GenerateRandom(absl::MakeSpan(rand)));
  EXPECT_THAT(rand, Not(ElementsAreArray(zero)));
}

TEST_F(SessionTest, GenerateRandomFailureUndersizedBuffer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<uint8_t> rand(7);
  EXPECT_THAT(s.GenerateRandom(absl::MakeSpan(rand)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_ARGUMENTS_BAD)));
}

TEST_F(SessionTest, GenerateRandomFailureOversizedBuffer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  std::vector<uint8_t> rand(1025);
  EXPECT_THAT(s.GenerateRandom(absl::MakeSpan(rand)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_ARGUMENTS_BAD)));
}

class GenerateKeyPairTest : public SessionTest {};

TEST_F(GenerateKeyPairTest, ReadOnlySessionReturnsFailedPrecondition) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_THAT(s.GenerateKeyPair(CK_MECHANISM{}, {}, {}),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_SESSION_READ_ONLY)));
}

TEST_F(GenerateKeyPairTest, InvalidMechanismReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());
  CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};

  EXPECT_THAT(s.GenerateKeyPair(mech, {}, {}),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_MECHANISM_INVALID)));
}

TEST_F(GenerateKeyPairTest, MechanismParameterReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  char dummy[128];
  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, dummy, sizeof(dummy)};

  EXPECT_THAT(s.GenerateKeyPair(mech, {}, {}),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_MECHANISM_PARAM_INVALID)));
}

TEST_F(GenerateKeyPairTest, PublicKeyTemplateReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  CK_KEY_TYPE key_type_value = CKK_RSA;
  CK_ATTRIBUTE pub_template[] = {
      {CKA_KEY_TYPE, &key_type_value, sizeof(key_type_value)},
  };

  EXPECT_THAT(
      s.GenerateKeyPair(mech, pub_template, {}),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("token does not accept public key attributes")),
            StatusRvIs(CKR_TEMPLATE_INCONSISTENT)));
}

TEST_F(GenerateKeyPairTest,
       PrivateKeyTemplateWithUnsupportedAttributeReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  CK_OBJECT_CLASS object_class = CKO_PRIVATE_KEY;
  CK_ULONG kms_algorithm = KMS_ALGORITHM_RSA_SIGN_PKCS1_2048_SHA256;
  std::string label = "my-great-key";
  CK_ATTRIBUTE prv_template[] = {
      {CKA_CLASS, &object_class, sizeof(object_class)},
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(
      s.GenerateKeyPair(mech, {}, prv_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("token does not permit specifying attribute")),
            StatusRvIs(CKR_TEMPLATE_INCONSISTENT)));
}

TEST_F(GenerateKeyPairTest,
       PrivateKeyTemplateMissingAlgorithmReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ATTRIBUTE prv_template[] = {
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(s.GenerateKeyPair(mech, {}, prv_template),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("CKA_KMS_ALGORITHM must be specified")),
                    StatusRvIs(CKR_TEMPLATE_INCOMPLETE)));
}

TEST_F(GenerateKeyPairTest,
       PrivateKeyTemplateInvalidAlgorithmValueSizeReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_BYTE bad_algorithm_datatype = 1;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &bad_algorithm_datatype,
       sizeof(bad_algorithm_datatype)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(
      s.GenerateKeyPair(mech, {}, prv_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("CKA_KMS_ALGORITHM value should be CK_ULONG")),
            StatusRvIs(CKR_ATTRIBUTE_VALUE_INVALID)));
}

TEST_F(GenerateKeyPairTest,
       PrivateKeyTemplateMissingLabelReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_RSA_SIGN_PKCS1_2048_SHA256;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
  };

  EXPECT_THAT(s.GenerateKeyPair(mech, {}, prv_template),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("CKA_LABEL must be specified")),
                    StatusRvIs(CKR_TEMPLATE_INCOMPLETE)));
}

TEST_F(GenerateKeyPairTest,
       PrivateKeyTemplateBadLabelValueReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "$invalid-label!";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(
      s.GenerateKeyPair(mech, {}, prv_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("LABEL must be a valid Cloud KMS CryptoKey ID")),
            StatusRvIs(CKR_ATTRIBUTE_VALUE_INVALID)));
}

TEST_F(
    GenerateKeyPairTest,
    PrivateKeyTemplateInvalidProtectionLevelValueSizeReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  CK_BYTE bad_protection_level_datatype = 1;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_KMS_PROTECTION_LEVEL, &bad_protection_level_datatype,
       sizeof(bad_protection_level_datatype)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(
      s.GenerateKeyPair(mech, {}, prv_template),
      AllOf(StatusIs(
                absl::StatusCode::kInvalidArgument,
                HasSubstr("CKA_KMS_PROTECTION_LEVEL value should be CK_ULONG")),
            StatusRvIs(CKR_ATTRIBUTE_VALUE_INVALID)));
}

TEST_F(GenerateKeyPairTest,
       PrivateKeyTemplateInvalidProtectionLevelReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  CK_ULONG bad_protection_level = 1560;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_KMS_PROTECTION_LEVEL, &bad_protection_level,
       sizeof(bad_protection_level)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(s.GenerateKeyPair(mech, {}, prv_template),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("CKA_KMS_PROTECTION_LEVEL value should "
                                       "be 1(SOFTWARE), 2(HSM), or "
                                       "5(HSM_SINGLE_TENANT)")),
                    StatusRvIs(CKR_ATTRIBUTE_VALUE_INVALID)));
}

TEST_F(
    GenerateKeyPairTest,
    PrivateKeyTemplateSoftwareProtectionLevelReturnsInvalidArgumentWhenSoftwareKeysDisallowed) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  CK_ULONG protection_level = KMS_PROTECTION_LEVEL_SOFTWARE;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_KMS_PROTECTION_LEVEL, &protection_level, sizeof(protection_level)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(
      s.GenerateKeyPair(mech, {}, prv_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("CKA_KMS_PROTECTION_LEVEL cannot be SOFTWARE")),
            StatusRvIs(CKR_ATTRIBUTE_VALUE_INVALID)));
}

TEST_F(GenerateKeyPairTest,
       PrivateKeyTemplateBadAlgorithmValueReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = 1337;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(s.GenerateKeyPair(mech, {}, prv_template),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("algorithm not found")),
                    StatusRvIs(CKR_ATTRIBUTE_VALUE_INVALID)));
}

TEST_F(GenerateKeyPairTest,
       MismatchedAlgorithmAndMechanismReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(
      s.GenerateKeyPair(mech, {}, prv_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("algorithm mismatches keygen mechanism")),
            StatusRvIs(CKR_TEMPLATE_INCONSISTENT)));
}

TEST_F(GenerateKeyPairTest,
       MissingCryptoKeyBackendWhenSingleTenantReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  CK_ULONG protection_level = KMS_PROTECTION_LEVEL_HSM_SINGLE_TENANT;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
      {CKA_KMS_PROTECTION_LEVEL, &protection_level, sizeof(protection_level)},
  };

  EXPECT_THAT(
      s.GenerateKeyPair(mech, {}, prv_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("CKA_KMS_CRYPTO_KEY_BACKEND must be "
                               "specified with protection level "
                               "HSM_SINGLE_TENANT")),
            StatusRvIs(CKR_TEMPLATE_INCOMPLETE)));
}

TEST_F(GenerateKeyPairTest, DuplicateLabelReturnsAlreadyExistsDefaultConfig) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck =
      CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck, true);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_RSA_SIGN_PSS_2048_SHA256;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(s.GenerateKeyPair(mech, {}, prv_template),
              AllOf(StatusIs(absl::StatusCode::kAlreadyExists),
                    StatusRvIs(CKR_ARGUMENTS_BAD)));
}

TEST_F(GenerateKeyPairTest,
       Version2CanBeCreatedWithExperimentalCreateMultipleVersionsForHSMKeys) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck,
                            false);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P384_SHA384;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_OK(s.GenerateKeyPair(mech, {}, prv_template, true));
  EXPECT_THAT(token->FindObjects([&](const Object& o) {
    return absl::StartsWith(o.kms_key_name(), ck.name());
  }),
              SizeIs(4)  // Two keypairs, each with public and private.
  );
}

TEST_F(
    GenerateKeyPairTest,
    Version2CanBeCreatedWithExperimentalCreateMultipleVersionsForSoftwareKeys) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::SOFTWARE);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck,
                            false);

  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /*generate_certs = */ false,
                 /*allow_software_keys = */ true));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P384_SHA384;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_OK(s.GenerateKeyPair(mech, {}, prv_template, true, true));
  EXPECT_THAT(token->FindObjects([&](const Object& o) {
    return absl::StartsWith(o.kms_key_name(), ck.name());
  }),
              SizeIs(4)  // Two keypairs, each with public and private.
  );
}

TEST_F(
    GenerateKeyPairTest,
    Version2CanBeCreatedWithExperimentalCreateMultipleVersionsForSingleTenantKeys) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM_SINGLE_TENANT);
  ck.set_crypto_key_backend("test");
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck,
                            false);

  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /*generate_certs = */ false,
                 /*allow_software_keys = */ false));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P384_SHA384;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_OK(s.GenerateKeyPair(mech, {}, prv_template, true, false));
  EXPECT_THAT(token->FindObjects([&](const Object& o) {
    return absl::StartsWith(o.kms_key_name(), ck.name());
  }),
              SizeIs(4)  // Two keypairs, each with public and private.
  );
}

TEST_F(GenerateKeyPairTest, GeneratedHsmKeyPairIsImmediatelyAvailable) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  ASSERT_OK_AND_ASSIGN(AsymmetricHandleSet handles,
                       s.GenerateKeyPair(mech, {}, prv_template, true));

  EXPECT_OK(token->GetObject(handles.public_key_handle));
  EXPECT_OK(token->GetObject(handles.private_key_handle));
}

TEST_F(GenerateKeyPairTest, GeneratedSoftwareKeyPairIsImmediatelyAvailable) {
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /*generate_certs = */ false,
                 /*allow_software_keys = */ true));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  CK_ULONG protection_level = KMS_PROTECTION_LEVEL_SOFTWARE;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
      {CKA_KMS_PROTECTION_LEVEL, &protection_level, sizeof(protection_level)}
  };

  ASSERT_OK_AND_ASSIGN(AsymmetricHandleSet handles,
                       s.GenerateKeyPair(mech, {}, prv_template, true, true));

  EXPECT_OK(token->GetObject(handles.public_key_handle));
  EXPECT_OK(token->GetObject(handles.private_key_handle));
}

TEST_F(GenerateKeyPairTest,
       GeneratedSingleTenantKeyPairIsImmediatelyAvailable) {
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /*generate_certs = */ false,
                 /*allow_software_keys = */ false));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  CK_ULONG protection_level = KMS_PROTECTION_LEVEL_HSM_SINGLE_TENANT;
  std::string crypto_key_backend = "test";
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
      {CKA_KMS_PROTECTION_LEVEL, &protection_level, sizeof(protection_level)},
      {CKA_KMS_CRYPTO_KEY_BACKEND, crypto_key_backend.data(),
       crypto_key_backend.size()}};

  ASSERT_OK_AND_ASSIGN(AsymmetricHandleSet handles,
                       s.GenerateKeyPair(mech, {}, prv_template, true, false));

  EXPECT_OK(token->GetObject(handles.public_key_handle));
  EXPECT_OK(token->GetObject(handles.private_key_handle));
}

TEST_F(GenerateKeyPairTest,
       ExperimentalCreateMultipleVersionsFailsOnAttributeMismatch) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck =
      CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck, true);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_RSA_SIGN_PSS_2048_SHA256;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(s.GenerateKeyPair(mech, {}, prv_template, true),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key attribute mismatch")));
}

TEST_F(
    GenerateKeyPairTest,
    ExperimentalCreateMultipleVersionsFailsOnGenParamsAndCryptoKeyProtectionLevelMismatch) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::SOFTWARE);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck,
                            false);

  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /*generate_certs = */ false,
                 /*allow_software_keys = */ true));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_EC_KEY_PAIR_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P384_SHA384;
  CK_ULONG protection_level = KMS_PROTECTION_LEVEL_HARDWARE;
  CK_ATTRIBUTE prv_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
      {CKA_KMS_PROTECTION_LEVEL, &protection_level, sizeof(protection_level)}
  };


  EXPECT_THAT(s.GenerateKeyPair(mech, {}, prv_template, true),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key attribute mismatch")));
}

class GenerateKeyTest : public SessionTest {};

TEST_F(GenerateKeyTest, ReadOnlySessionReturnsFailedPrecondition) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_THAT(s.GenerateKey(CK_MECHANISM{}, {}),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_SESSION_READ_ONLY)));
}

TEST_F(GenerateKeyTest, InvalidMechanismReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());
  CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};

  EXPECT_THAT(s.GenerateKey(mech, {}),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_MECHANISM_INVALID)));
}

TEST_F(GenerateKeyTest, MechanismParameterReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  char dummy[128];
  CK_MECHANISM mech = {CKM_AES_KEY_GEN, dummy, sizeof(dummy)};

  EXPECT_THAT(s.GenerateKey(mech, {}),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_MECHANISM_PARAM_INVALID)));
}

TEST_F(GenerateKeyTest, KeyTemplateMissingAlgorithmReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ATTRIBUTE key_template[] = {
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(s.GenerateKey(mech, key_template),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("CKA_KMS_ALGORITHM must be specified")),
                    StatusRvIs(CKR_TEMPLATE_INCOMPLETE)));
}

TEST_F(GenerateKeyTest,
       KeyTemplateInvalidAlgorithmValueSizeReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_BYTE bad_algorithm_datatype = 1;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &bad_algorithm_datatype,
       sizeof(bad_algorithm_datatype)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(
      s.GenerateKey(mech, key_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("CKA_KMS_ALGORITHM value should be CK_ULONG")),
            StatusRvIs(CKR_ATTRIBUTE_VALUE_INVALID)));
}

TEST_F(GenerateKeyTest, KeyTemplateMissingLabelReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_AES_256_GCM;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
  };

  EXPECT_THAT(s.GenerateKey(mech, key_template),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("CKA_LABEL must be specified")),
                    StatusRvIs(CKR_TEMPLATE_INCOMPLETE)));
}

TEST_F(GenerateKeyTest, KeyTemplateBadLabelValueReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  std::string label = "$invalid-label!";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_AES_256_GCM;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(
      s.GenerateKey(mech, key_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("LABEL must be a valid Cloud KMS CryptoKey ID")),
            StatusRvIs(CKR_ATTRIBUTE_VALUE_INVALID)));
}

TEST_F(GenerateKeyTest, KeyTemplateBadAlgorithmValueReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = 1337;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(s.GenerateKey(mech, key_template),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                             HasSubstr("algorithm not found")),
                    StatusRvIs(CKR_ATTRIBUTE_VALUE_INVALID)));
}

TEST_F(GenerateKeyTest, MismatchedAlgorithmAndMechanismReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_GENERIC_SECRET_KEY_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_AES_256_GCM;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(
      s.GenerateKey(mech, key_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("algorithm mismatches keygen mechanism")),
            StatusRvIs(CKR_TEMPLATE_INCONSISTENT)));
}

TEST_F(GenerateKeyTest,
       MissingCryptoKeyBackendWhenSingleTenantReturnsInvalidArgument) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_AES_256_GCM;
  CK_ULONG protection_level = KMS_PROTECTION_LEVEL_HSM_SINGLE_TENANT;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
      {CKA_KMS_PROTECTION_LEVEL, &protection_level, sizeof(protection_level)},
  };

  EXPECT_THAT(
      s.GenerateKey(mech, key_template),
      AllOf(StatusIs(absl::StatusCode::kInvalidArgument,
                     HasSubstr("CKA_KMS_CRYPTO_KEY_BACKEND must be "
                               "specified with protection level "
                               "HSM_SINGLE_TENANT")),
            StatusRvIs(CKR_TEMPLATE_INCOMPLETE)));
}

TEST_F(GenerateKeyTest, DuplicateLabelReturnsAlreadyExistsDefaultConfig) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::AES_256_GCM);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck =
      CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck, true);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_AES_256_GCM;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_THAT(s.GenerateKey(mech, key_template),
              AllOf(StatusIs(absl::StatusCode::kAlreadyExists),
                    StatusRvIs(CKR_ARGUMENTS_BAD)));
}

TEST_F(GenerateKeyTest,
       Version2CanBeCreatedWithExperimentalCreateMultipleVersionsForHSMKeys) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::AES_256_GCM);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck,
                            false);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_AES_256_GCM;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_OK(s.GenerateKey(mech, key_template, true));
  EXPECT_THAT(token->FindObjects([&](const Object& o) {
    return absl::StartsWith(o.kms_key_name(), ck.name());
  }),
              SizeIs(2)  // Two secret keys.
  );
}

TEST_F(GenerateKeyTest,
       Version2CanBeCreatedWithExperimentalCreateMultipleVersionsForSoftwareKeys) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::AES_256_GCM);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::SOFTWARE);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck,
                            false);

  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /*generate_certs = */ false,
                 /*allow_software_keys = */ true));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_AES_256_GCM;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_OK(s.GenerateKey(mech, key_template, true, true));
  EXPECT_THAT(token->FindObjects([&](const Object& o) {
    return absl::StartsWith(o.kms_key_name(), ck.name());
  }),
              SizeIs(2)  // Two secret keys.
  );
}

TEST_F(GenerateKeyTest,
       Version2CanBeCreatedWithExperimentalCreateMultipleVersionsForSingleTenantKeys) {
  std::string label = "my-great-key";

  auto kms_client = fake_server_->NewClient();
  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::AES_256_GCM);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM_SINGLE_TENANT);
  ck.set_crypto_key_backend("test");
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), label, ck,
                            false);

  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /*generate_certs = */ false,
                 /*allow_software_keys = */ false));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_AES_KEY_GEN, nullptr, 0};
  CK_ULONG kms_algorithm = KMS_ALGORITHM_AES_256_GCM;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  EXPECT_OK(s.GenerateKey(mech, key_template, true, false));
  EXPECT_THAT(token->FindObjects([&](const Object& o) {
    return absl::StartsWith(o.kms_key_name(), ck.name());
  }),
              SizeIs(2)  // Two secret keys.
  );
}

TEST_F(GenerateKeyTest, GeneratedHsmKeyIsImmediatelyAvailable) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_GENERIC_SECRET_KEY_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_HMAC_SHA256;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE handle,
                       s.GenerateKey(mech, key_template, true));

  EXPECT_OK(token->GetObject(handle));
}

TEST_F(GenerateKeyTest, GeneratedSoftwareKeyIsImmediatelyAvailable) {
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /*generate_certs = */ false,
                 /*allow_software_keys = */ true));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_GENERIC_SECRET_KEY_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_HMAC_SHA256;
  CK_ULONG protection_level = KMS_PROTECTION_LEVEL_HARDWARE;
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
      {CKA_KMS_PROTECTION_LEVEL, &protection_level, sizeof(protection_level)}
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE handle,
                       s.GenerateKey(mech, key_template, true, true));

  EXPECT_OK(token->GetObject(handle));
}

TEST_F(GenerateKeyTest, GeneratedSingleTenantKeyIsImmediatelyAvailable) {
  ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<Token> token,
      Token::New(0, config_, client_.get(), /*generate_certs = */ false,
                 /*allow_software_keys = */ false));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  CK_MECHANISM mech = {CKM_GENERIC_SECRET_KEY_GEN, nullptr, 0};
  std::string label = "my-great-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_HMAC_SHA256;
  CK_ULONG protection_level = KMS_PROTECTION_LEVEL_HSM_SINGLE_TENANT;
  std::string crypto_key_backend = "test";
  CK_ATTRIBUTE key_template[] = {
      {CKA_KMS_ALGORITHM, &kms_algorithm, sizeof(kms_algorithm)},
      {CKA_LABEL, label.data(), label.size()},
      {CKA_KMS_PROTECTION_LEVEL, &protection_level, sizeof(protection_level)},
      {CKA_KMS_CRYPTO_KEY_BACKEND, crypto_key_backend.data(),
       crypto_key_backend.size()}
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE handle,
                       s.GenerateKey(mech, key_template, true, false));

  EXPECT_OK(token->GetObject(handle));
}

class DestroyObjectTest : public SessionTest {};

TEST_F(DestroyObjectTest, ReadOnlySessionReturnsFailedPrecondition) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadOnly, client_.get());

  EXPECT_THAT(s.DestroyObject(nullptr),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_SESSION_READ_ONLY)));
}

TEST_F(DestroyObjectTest, DestroyPublicKeyReturnsActionProhibited) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE pub_handle,
                       token->FindSingleObject([&](const Object& o) {
                         return o.kms_key_name() == ckv.name() &&
                                o.object_class() == CKO_PUBLIC_KEY;
                       }));
  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> public_key,
                       token->GetObject(pub_handle));

  EXPECT_THAT(s.DestroyObject(public_key),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_ACTION_PROHIBITED)));
}

TEST_F(DestroyObjectTest, DestroyedKeyPairIsImmediatelyAbsent) {
  auto kms_client = fake_server_->NewClient();

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck.mutable_version_template()->set_protection_level(
      kms_v1::ProtectionLevel::HSM);
  ck = CreateCryptoKeyOrDie(kms_client.get(), key_ring_.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(kms_client.get(), ck.name(), ckv);
  ckv = WaitForEnablement(kms_client.get(), ckv);

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<Token> token,
                       Token::New(0, config_, client_.get()));
  Session s(token.get(), SessionType::kReadWrite, client_.get());

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE prv_handle,
                       token->FindSingleObject([&](const Object& o) {
                         return o.kms_key_name() == ckv.name() &&
                                o.object_class() == CKO_PRIVATE_KEY;
                       }));
  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE pub_handle,
                       token->FindSingleObject([&](const Object& o) {
                         return o.kms_key_name() == ckv.name() &&
                                o.object_class() == CKO_PUBLIC_KEY;
                       }));

  ASSERT_OK_AND_ASSIGN(std::shared_ptr<Object> private_key,
                       token->GetObject(prv_handle));

  EXPECT_OK(s.DestroyObject(private_key));

  EXPECT_THAT(token->GetObject(prv_handle),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(token->GetObject(pub_handle),
              StatusIs(absl::StatusCode::kNotFound));
}

}  // namespace
}  // namespace cloud_kms::kmsp11
