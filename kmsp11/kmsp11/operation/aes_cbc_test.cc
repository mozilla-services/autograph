// Copyright 2022 Google LLC
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

#include "kmsp11/operation/aes_cbc.h"

#include "common/kms_client.h"
#include "common/test/runfiles.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/object.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/padding.h"

namespace cloud_kms::kmsp11 {
namespace {

CK_MECHANISM NewAesCbcMechanism(CK_BYTE* iv) {
  return CK_MECHANISM{
      CKM_AES_CBC,  // mechanism
      iv,           // pParameter
      16,           // ulParameterLen
  };
}

CK_MECHANISM NewAesCbcPaddingMechanism(CK_BYTE* iv) {
  return CK_MECHANISM{
      CKM_AES_CBC_PAD,  // mechanism
      iv,               // pParameter
      16,               // ulParameterLen
  };
}

TEST(NewAesCbcEncrypterTest, Success) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::AES_256_CBC));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(16, '\1');
  CK_MECHANISM mechanism = NewAesCbcMechanism(iv.data());

  EXPECT_OK(NewAesCbcEncrypter(key, &mechanism));
}

TEST(NewAesCbcEncrypterTest, FailureWrongKeyType) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::HMAC_SHA1));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(16, '\1');
  CK_MECHANISM mechanism = NewAesCbcMechanism(iv.data());

  EXPECT_THAT(NewAesCbcEncrypter(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(NewAesCbcEncrypterTest, FailureWrongIvLengthSupplied) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::AES_256_CBC));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(16, '\1');
  CK_MECHANISM mechanism = NewAesCbcMechanism(iv.data());
  mechanism.ulParameterLen = 12;

  EXPECT_THAT(NewAesCbcEncrypter(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewAesCbcDecrypterTest, FailureWrongKeyType) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::HMAC_SHA1));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(16, '\1');
  CK_MECHANISM mechanism = NewAesCbcMechanism(iv.data());

  EXPECT_THAT(NewAesCbcDecrypter(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(NewAesCbcDecrypterTest, FailureWrongIvLengthSupplied) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::AES_256_CBC));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(16, '\1');
  CK_MECHANISM mechanism = NewAesCbcMechanism(iv.data());
  mechanism.ulParameterLen = 12;

  EXPECT_THAT(NewAesCbcDecrypter(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

class AesCbcTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());
    client_ = std::make_unique<KmsClient>(KmsClient::Options{
        .endpoint_address = fake_server_->listen_addr(),
        .rpc_timeout = absl::Seconds(1),
        .error_decorator =
            [](absl::Status& status) { SetErrorRv(status, CKR_DEVICE_ERROR); },
    });

    auto fake_client = fake_server_->NewClient();

    kms_v1::KeyRing kr;
    kr = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(), kr);

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::AES_128_CBC);
    ck = CreateCryptoKeyOrDie(fake_client.get(), kr.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(fake_client.get(), ckv);

    kms_key_name_ = ckv.name();

    ASSERT_OK_AND_ASSIGN(Object key, Object::NewSecretKey(ckv));
    prv_ = std::make_shared<Object>(key);

    std::vector<uint8_t> iv(16, '\1');
    CK_MECHANISM mechanism = NewAesCbcMechanism(iv.data());

    // NOTE: the iv will go out of scope once SetUp() is complete.
    // You should not use `encrypter_` and `decrypter_` for custom mechanism
    // tests that rely on the memory being available at C_Encrypt{Final}-time.
    // See kmsp11.h for more info about `CKM_CLOUDKMS_AES_CBC_PAD`.
    // Most tests below use `CKM_AES_CBC`, which does not have the same memory
    // management requirements and copies the input IV during C_EncryptInit.
    ASSERT_OK_AND_ASSIGN(encrypter_, NewAesCbcEncrypter(prv_, &mechanism));
    ASSERT_OK_AND_ASSIGN(decrypter_, NewAesCbcDecrypter(prv_, &mechanism));

    // This is safe to access after C_EncryptInit, to check expectations.
    iv_ = std::vector<uint8_t>(16, '\1');
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  std::unique_ptr<KmsClient> client_;
  std::string kms_key_name_;
  std::shared_ptr<Object> prv_;
  std::vector<uint8_t> iv_;
  std::unique_ptr<EncrypterInterface> encrypter_;
  std::unique_ptr<DecrypterInterface> decrypter_;
};

TEST_F(AesCbcTest, EncryptSuccess) {
  std::string plaintext = "Here is my data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> ciphertext,
                       encrypter_->Encrypt(client_.get(), plaintext_bytes));
  EXPECT_NE(plaintext_bytes, ciphertext);

  kms_v1::RawEncryptRequest req;
  req.set_name(kms_key_name_);
  req.set_plaintext(plaintext);
  req.set_initialization_vector(reinterpret_cast<const char*>(iv_.data()),
                                iv_.size());
  ASSERT_OK_AND_ASSIGN(kms_v1::RawEncryptResponse resp,
                       client_->RawEncrypt(req));

  std::vector<uint8_t> resp_bytes(resp.ciphertext().begin(),
                                  resp.ciphertext().end());
  EXPECT_EQ(resp_bytes, ciphertext);
  EXPECT_EQ(resp_bytes.size(), ciphertext.size());
}

TEST_F(AesCbcTest, EncryptFailureBadPlaintextSize) {
  uint8_t plaintext[65537];
  EXPECT_THAT(encrypter_->Encrypt(client_.get(), plaintext),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesCbcTest, EncryptUpdateFailurePartLengthOversize) {
  EXPECT_THAT(
      encrypter_->EncryptUpdate(client_.get(), std::vector<uint8_t>(65537)),
      StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesCbcTest, EncryptUpdateFailurePartLengthSumOversize) {
  EXPECT_OK(
      encrypter_->EncryptUpdate(client_.get(), std::vector<uint8_t>(65535)));
  EXPECT_THAT(encrypter_->EncryptUpdate(client_.get(), std::vector<uint8_t>(2)),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesCbcTest, EncryptFailureKeyDisabled) {
  kms_v1::CryptoKeyVersion ckv;
  ckv.set_name(kms_key_name_);
  ckv.set_state(kms_v1::CryptoKeyVersion::DISABLED);

  google::protobuf::FieldMask update_mask;
  update_mask.add_paths("state");

  UpdateCryptoKeyVersionOrDie(fake_server_->NewClient().get(), ckv,
                              update_mask);

  uint8_t plaintext[256];
  EXPECT_THAT(encrypter_->Encrypt(client_.get(), plaintext),
              StatusRvIs(CKR_DEVICE_ERROR));
}

TEST_F(AesCbcTest, EncryptServerGeneratedIvSuccess) {
  std::string plaintext = "Here is my data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
  std::vector<uint8_t> initial_iv(16, '\0');

  // Use local AesCtrEncrypter, since the custom mechanism expects the IV memory
  // to still be accessible during C_Encrypt.
  CK_MECHANISM mechanism = NewAesCbcPaddingMechanism(iv_.data());
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<EncrypterInterface> encrypter,
                       NewAesCbcEncrypter(prv_, &mechanism));

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> ciphertext,
                       encrypter->Encrypt(client_.get(), plaintext_bytes));
  EXPECT_NE(plaintext_bytes, ciphertext);

  kms_v1::RawEncryptRequest req;
  req.set_name(kms_key_name_);
  std::vector<uint8_t> padded_plaintext = Pad(plaintext_bytes);
  req.set_plaintext(reinterpret_cast<const char*>(padded_plaintext.data()),
                    padded_plaintext.size());
  req.set_initialization_vector(reinterpret_cast<const char*>(iv_.data()),
                                iv_.size());
  ASSERT_OK_AND_ASSIGN(kms_v1::RawEncryptResponse resp,
                       client_->RawEncrypt(req));

  std::vector<uint8_t> resp_bytes(resp.ciphertext().begin(),
                                  resp.ciphertext().end());

  EXPECT_NE(iv_, initial_iv);
  EXPECT_EQ(resp_bytes, ciphertext);
  EXPECT_EQ(resp_bytes.size(), ciphertext.size());
}

TEST_F(AesCbcTest, EncryptDecryptSuccess) {
  std::string plaintext = "Here is my data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> ciphertext,
                       encrypter_->Encrypt(client_.get(), plaintext_bytes));
  EXPECT_NE(plaintext_bytes, ciphertext);

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> recovered_plaintext,
                       decrypter_->Decrypt(client_.get(), ciphertext));

  EXPECT_EQ(recovered_plaintext, plaintext_bytes);
}

TEST_F(AesCbcTest, EncryptDecryptMultiPartSuccess) {
  std::string plaintext = "Here is my data.";
  std::string plaintext_part1 = "Here is ";
  std::string plaintext_part2 = "my data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
  std::vector<uint8_t> plaintext_bytes_part1(plaintext_part1.begin(),
                                             plaintext_part1.end());
  std::vector<uint8_t> plaintext_bytes_part2(plaintext_part2.begin(),
                                             plaintext_part2.end());

  ASSERT_OK(encrypter_->EncryptUpdate(client_.get(), plaintext_bytes_part1));
  ASSERT_OK(encrypter_->EncryptUpdate(client_.get(), plaintext_bytes_part2));
  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> ciphertext,
                       encrypter_->EncryptFinal(client_.get()));

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> recovered_plaintext,
                       decrypter_->Decrypt(client_.get(), ciphertext));

  EXPECT_EQ(recovered_plaintext, plaintext_bytes);
}

TEST_F(AesCbcTest, EncryptFakeKmsDecryptLibrarySuccess) {
  std::string plaintext = "Here is my data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());

  kms_v1::RawEncryptRequest req;
  req.set_name(kms_key_name_);
  req.set_plaintext(plaintext);
  req.set_initialization_vector(reinterpret_cast<const char*>(iv_.data()),
                                iv_.size());
  ASSERT_OK_AND_ASSIGN(kms_v1::RawEncryptResponse resp,
                       client_->RawEncrypt(req));

  std::vector<uint8_t> ciphertext(resp.ciphertext().begin(),
                                  resp.ciphertext().end());

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> recovered_plaintext,
                       decrypter_->Decrypt(client_.get(), ciphertext));

  EXPECT_EQ(recovered_plaintext, plaintext_bytes);
}

TEST_F(AesCbcTest, EncryptLibraryDecryptFakeKmsSuccess) {
  std::string plaintext = "Here is my data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> ciphertext,
                       encrypter_->Encrypt(client_.get(), plaintext_bytes));

  kms_v1::RawDecryptRequest req;
  req.set_name(kms_key_name_);
  req.set_ciphertext(reinterpret_cast<const char*>(ciphertext.data()),
                     ciphertext.size());
  req.set_initialization_vector(reinterpret_cast<const char*>(iv_.data()),
                                iv_.size());
  ASSERT_OK_AND_ASSIGN(kms_v1::RawDecryptResponse resp,
                       client_->RawDecrypt(req));

  EXPECT_EQ(resp.plaintext(), plaintext);
}

TEST_F(AesCbcTest, DecryptFailureBadCiphertextSize) {
  uint8_t ciphertext[65536 + 16 + 1];
  EXPECT_THAT(decrypter_->Decrypt(client_.get(), ciphertext),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesCbcTest, DecryptUpdateFailurePartLengthOversize) {
  EXPECT_THAT(decrypter_->DecryptUpdate(client_.get(),
                                        std::vector<uint8_t>(65536 + 16 + 1)),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesCbcTest, DecryptUpdateFailurePartLengthSumOversize) {
  EXPECT_OK(decrypter_->DecryptUpdate(client_.get(),
                                      std::vector<uint8_t>(65536 + 16)));
  EXPECT_THAT(decrypter_->DecryptUpdate(client_.get(), std::vector<uint8_t>(1)),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesCbcTest, DecryptFailureKeyDisabled) {
  kms_v1::CryptoKeyVersion ckv;
  ckv.set_name(kms_key_name_);
  ckv.set_state(kms_v1::CryptoKeyVersion::DISABLED);

  google::protobuf::FieldMask update_mask;
  update_mask.add_paths("state");

  UpdateCryptoKeyVersionOrDie(fake_server_->NewClient().get(), ckv,
                              update_mask);

  uint8_t ciphertext[256];
  EXPECT_THAT(decrypter_->Decrypt(client_.get(), ciphertext),
              StatusRvIs(CKR_DEVICE_ERROR));
}

}  // namespace
}  // namespace cloud_kms::kmsp11
