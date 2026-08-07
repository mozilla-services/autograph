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

#include "kmsp11/operation/aes_gcm.h"

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

namespace cloud_kms::kmsp11 {
namespace {

CK_GCM_PARAMS NewGcmParams(std::vector<uint8_t>* iv,
                           std::vector<uint8_t>* aad) {
  return CK_GCM_PARAMS{
      iv->data(),                                   // pIv
      12,                                           // ulIvLen
      96,                                           // ulIvBits
      aad->data(),                                  // pAAD
      static_cast<unsigned long int>(aad->size()),  // ulAADLen
      128,                                          // ulTagBits
  };
}

CK_MECHANISM NewAesGcmMechanism(CK_GCM_PARAMS* params) {
  return CK_MECHANISM{
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      params,                // pParameter
      sizeof(*params),       // ulParameterLen
  };
}

TEST(NewAesGcmEncrypterTest, Success) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::AES_256_GCM));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = NewGcmParams(&iv, &aad);
  CK_MECHANISM mechanism = NewAesGcmMechanism(&params);

  EXPECT_OK(NewAesGcmEncrypter(key, &mechanism));
}

TEST(NewAesGcmEncrypterTest, FailureWrongKeyType) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::HMAC_SHA1));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = NewGcmParams(&iv, &aad);
  CK_MECHANISM mechanism = NewAesGcmMechanism(&params);

  EXPECT_THAT(NewAesGcmEncrypter(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(NewAesGcmEncrypterTest, FailureNoParameters) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::AES_256_GCM));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  CK_MECHANISM mechanism = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      nullptr,               // pParameter
      0,                     // ulParameterLen
  };

  EXPECT_THAT(NewAesGcmEncrypter(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewAesGcmEncrypterTest, FailureWrongIvLengthSupplied) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::AES_256_GCM));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = NewGcmParams(&iv, &aad);
  params.ulIvLen = 10;
  CK_MECHANISM mechanism = NewAesGcmMechanism(&params);

  EXPECT_THAT(NewAesGcmEncrypter(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewAesGcmEncrypterTest, FailureIvSupplied) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::AES_256_GCM));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(12, '\1');  // non-zero IV
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = NewGcmParams(&iv, &aad);
  CK_MECHANISM mechanism = NewAesGcmMechanism(&params);

  EXPECT_THAT(NewAesGcmEncrypter(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewAesGcmDecrypterTest, FailureWrongKeyType) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::HMAC_SHA1));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = NewGcmParams(&iv, &aad);
  CK_MECHANISM mechanism = NewAesGcmMechanism(&params);

  EXPECT_THAT(NewAesGcmDecrypter(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

TEST(NewAesGcmDecrypterTest, FailureNoParameters) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::AES_256_GCM));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  CK_MECHANISM mechanism = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      nullptr,               // pParameter
      0,                     // ulParameterLen
  };

  EXPECT_THAT(NewAesGcmDecrypter(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewAesGcmDecrypterTest, FailureWrongIvLengthSupplied) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::AES_256_GCM));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  std::vector<uint8_t> iv(10);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = NewGcmParams(&iv, &aad);
  params.ulIvLen = 10;
  CK_MECHANISM mechanism = NewAesGcmMechanism(&params);

  EXPECT_THAT(NewAesGcmDecrypter(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

class AesGcmTest : public testing::Test {
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
        kms_v1::CryptoKeyVersion::AES_256_GCM);
    ck = CreateCryptoKeyOrDie(fake_client.get(), kr.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(fake_client.get(), ckv);

    kms_key_name_ = ckv.name();

    ASSERT_OK_AND_ASSIGN(Object key, Object::NewSecretKey(ckv));
    prv_ = std::make_shared<Object>(key);

    iv_ = std::vector<uint8_t>(12);
    aad_ = "Here is some aad.";
    std::vector<uint8_t> aad_bytes(aad_.begin(), aad_.end());
    CK_GCM_PARAMS params = NewGcmParams(&iv_, &aad_bytes);
    CK_MECHANISM mechanism = NewAesGcmMechanism(&params);

    ASSERT_OK_AND_ASSIGN(encrypter_, NewAesGcmEncrypter(prv_, &mechanism));
    ASSERT_OK_AND_ASSIGN(decrypter_, NewAesGcmDecrypter(prv_, &mechanism));
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  std::unique_ptr<KmsClient> client_;
  std::string kms_key_name_;
  std::shared_ptr<Object> prv_;
  std::vector<uint8_t> iv_;
  std::string aad_;
  std::unique_ptr<EncrypterInterface> encrypter_;
  std::unique_ptr<DecrypterInterface> decrypter_;
};

TEST_F(AesGcmTest, EncryptSuccess) {
  std::string plaintext = "Here is some data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
  std::vector<uint8_t> empty_iv(iv_.begin(), iv_.end());

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> ciphertext,
                       encrypter_->Encrypt(client_.get(), plaintext_bytes));
  EXPECT_NE(plaintext_bytes, ciphertext);

  kms_v1::RawEncryptRequest req;
  req.set_name(kms_key_name_);
  req.set_plaintext(plaintext);
  req.set_additional_authenticated_data(aad_);
  ASSERT_OK_AND_ASSIGN(kms_v1::RawEncryptResponse resp,
                       client_->RawEncrypt(req));

  std::vector<uint8_t> resp_bytes(resp.ciphertext().begin(),
                                  resp.ciphertext().end());
  EXPECT_NE(resp_bytes, ciphertext);
  EXPECT_NE(iv_, empty_iv);
  EXPECT_EQ(resp_bytes.size(), ciphertext.size());
}

TEST_F(AesGcmTest, EncryptFailurePlaintextOversize) {
  uint8_t plaintext[65537];
  EXPECT_THAT(encrypter_->Encrypt(client_.get(), plaintext),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesGcmTest, EncryptFailurePlaintextPartOversize) {
  uint8_t plaintext[65537];
  EXPECT_THAT(encrypter_->EncryptUpdate(client_.get(), plaintext),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesGcmTest, EncryptFailurePlaintextPartSumOversize) {
  uint8_t plaintext1[65535], plaintext2[2];
  EXPECT_OK(encrypter_->EncryptUpdate(client_.get(), plaintext1));
  EXPECT_THAT(encrypter_->EncryptUpdate(client_.get(), plaintext2),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesGcmTest, EncryptFailureKeyDisabled) {
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

TEST_F(AesGcmTest, EncryptDecryptSuccess) {
  std::string plaintext = "Here is some data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
  std::vector<uint8_t> aad_bytes(aad_.begin(), aad_.end());

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> ciphertext,
                       encrypter_->Encrypt(client_.get(), plaintext_bytes));
  EXPECT_NE(plaintext_bytes, ciphertext);

  CK_GCM_PARAMS params = NewGcmParams(&iv_, &aad_bytes);
  CK_MECHANISM mechanism = NewAesGcmMechanism(&params);
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<DecrypterInterface> decrypter,
                       NewAesGcmDecrypter(prv_, &mechanism));
  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> recovered_plaintext,
                       decrypter->Decrypt(client_.get(), ciphertext));

  EXPECT_EQ(recovered_plaintext, plaintext_bytes);
}

TEST_F(AesGcmTest, EncryptDecryptMultiPartSuccess) {
  std::string plaintext = "Here is some data.";
  std::string plaintext_part1 = "Here is ";
  std::string plaintext_part2 = "some data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
  std::vector<uint8_t> plaintext_bytes_part1(plaintext_part1.begin(),
                                             plaintext_part1.end());
  std::vector<uint8_t> plaintext_bytes_part2(plaintext_part2.begin(),
                                             plaintext_part2.end());
  std::vector<uint8_t> aad_bytes(aad_.begin(), aad_.end());

  ASSERT_OK(encrypter_->EncryptUpdate(client_.get(), plaintext_bytes_part1));
  ASSERT_OK(encrypter_->EncryptUpdate(client_.get(), plaintext_bytes_part2));
  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> ciphertext,
                       encrypter_->EncryptFinal(client_.get()));

  CK_GCM_PARAMS params = NewGcmParams(&iv_, &aad_bytes);
  CK_MECHANISM mechanism = NewAesGcmMechanism(&params);
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<DecrypterInterface> decrypter,
                       NewAesGcmDecrypter(prv_, &mechanism));
  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> recovered_plaintext,
                       decrypter->Decrypt(client_.get(), ciphertext));

  EXPECT_EQ(recovered_plaintext, plaintext_bytes);
}

TEST_F(AesGcmTest, EncryptFakeKmsDecryptLibrarySuccess) {
  std::string plaintext = "Here is some data.";
  std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
  std::string aad = "Here is some aad.";
  std::vector<uint8_t> aad_bytes(aad.begin(), aad.end());

  kms_v1::RawEncryptRequest req;
  req.set_name(kms_key_name_);
  req.set_plaintext(plaintext);
  req.set_additional_authenticated_data(aad);
  ASSERT_OK_AND_ASSIGN(kms_v1::RawEncryptResponse resp,
                       client_->RawEncrypt(req));

  std::vector<uint8_t> iv(resp.initialization_vector().begin(),
                          resp.initialization_vector().end());
  CK_GCM_PARAMS params = NewGcmParams(&iv, &aad_bytes);
  CK_MECHANISM mechanism = NewAesGcmMechanism(&params);
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<DecrypterInterface> decrypter,
                       NewAesGcmDecrypter(prv_, &mechanism));

  std::vector<uint8_t> ciphertext(resp.ciphertext().begin(),
                                  resp.ciphertext().end());

  ASSERT_OK_AND_ASSIGN(absl::Span<const uint8_t> recovered_plaintext,
                       decrypter->Decrypt(client_.get(), ciphertext));

  EXPECT_EQ(recovered_plaintext, plaintext_bytes);
}

TEST_F(AesGcmTest, DecryptFailureCiphertextOversize) {
  uint8_t ciphertext[65536 + 16 + 1];
  EXPECT_THAT(decrypter_->Decrypt(client_.get(), ciphertext),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesGcmTest, DecryptFailureCiphertextPartOversize) {
  uint8_t ciphertext[65536 + 16 + 1];
  EXPECT_THAT(decrypter_->DecryptUpdate(client_.get(), ciphertext),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesGcmTest, DecryptFailureCiphertextPartSumOversize) {
  uint8_t ciphertext1[65536 + 16], ciphertext2[1];
  EXPECT_OK(decrypter_->DecryptUpdate(client_.get(), ciphertext1));
  EXPECT_THAT(decrypter_->DecryptUpdate(client_.get(), ciphertext2),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_F(AesGcmTest, DecryptFailureKeyDisabled) {
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
