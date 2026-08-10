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

#include "kmsp11/operation/hmac.h"

#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "kmsp11/object.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;

TEST(NewSignerTest, AnySuppliedParamIsInvalid) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::HMAC_SHA256));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  char buf[1];
  CK_MECHANISM mechanism{CKM_SHA256_HMAC, buf, sizeof(buf)};
  EXPECT_THAT(NewHmacSigner(key, &mechanism),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST(NewSignerTest, KeyTypeInconsistentWhenSha1KeyIsSupplied) {
  ASSERT_OK_AND_ASSIGN(Object prv,
                       NewMockSecretKey(kms_v1::CryptoKeyVersion::HMAC_SHA1));
  std::shared_ptr<Object> key = std::make_shared<Object>(prv);

  CK_MECHANISM mechanism{CKM_SHA256_HMAC, nullptr, 0};
  EXPECT_THAT(NewHmacSigner(key, &mechanism),
              StatusRvIs(CKR_KEY_TYPE_INCONSISTENT));
}

class HmacTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());
    client_ = std::make_unique<KmsClient>(KmsClient::Options{
        .endpoint_address = fake_server_->listen_addr(),
        .rpc_timeout = absl::Seconds(1),
    });

    auto fake_client = fake_server_->NewClient();

    kms_v1::KeyRing kr;
    kr = CreateKeyRingOrDie(fake_client.get(), kTestLocation, RandomId(), kr);

    kms_v1::CryptoKey ck;
    ck.set_purpose(kms_v1::CryptoKey::MAC);
    ck.mutable_version_template()->set_algorithm(
        kms_v1::CryptoKeyVersion::HMAC_SHA256);
    ck = CreateCryptoKeyOrDie(fake_client.get(), kr.name(), "ck", ck, true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(fake_client.get(), ck.name(), ckv);
    ckv = WaitForEnablement(fake_client.get(), ckv);

    kms_key_name_ = ckv.name();

    ASSERT_OK_AND_ASSIGN(Object key, Object::NewSecretKey(ckv));
    prv_ = std::make_shared<Object>(key);
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  std::unique_ptr<KmsClient> client_;
  std::string kms_key_name_;
  std::shared_ptr<Object> prv_;
};

TEST_F(HmacTest, SignSuccess) {
  std::string data = "Here is some data.";
  std::vector<uint8_t> data_bytes(data.begin(), data.end());

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), data_bytes, absl::MakeSpan(sig)));

  kms_v1::MacSignRequest req;
  req.set_name(kms_key_name_);
  req.set_data(data);
  ASSERT_OK_AND_ASSIGN(kms_v1::MacSignResponse resp, client_->MacSign(req));

  std::vector<uint8_t> resp_bytes(resp.mac().begin(), resp.mac().end());
  EXPECT_EQ(resp_bytes, sig);
}

TEST_F(HmacTest, SignDataLengthOversize) {
  uint8_t data[65537], sig[32];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(HmacTest, SignDataPartLengthOversize) {
  uint8_t data[65537];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));

  EXPECT_THAT(signer->SignUpdate(client_.get(), data),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(HmacTest, SignDataPartSumLengthOversize) {
  uint8_t data1[65535], data2[2];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));

  EXPECT_OK(signer->SignUpdate(client_.get(), data1));
  EXPECT_THAT(signer->SignUpdate(client_.get(), data2),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(HmacTest, SignSignatureLengthOversize) {
  uint8_t data[65536], sig[33];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));

  EXPECT_THAT(signer->Sign(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInternal),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST_F(HmacTest, SignMultiPartSuccess) {
  std::string data = "Here is some data.";
  std::string data_part1 = "Here is ";
  std::string data_part2 = "some data.";
  std::vector<uint8_t> data_part1_bytes(data_part1.begin(), data_part1.end());
  std::vector<uint8_t> data_part2_bytes(data_part2.begin(), data_part2.end());

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->SignUpdate(client_.get(), data_part1_bytes));
  EXPECT_OK(signer->SignUpdate(client_.get(), data_part2_bytes));
  EXPECT_OK(signer->SignFinal(client_.get(), absl::MakeSpan(sig)));

  kms_v1::MacSignRequest req;
  req.set_name(kms_key_name_);
  req.set_data(data);
  ASSERT_OK_AND_ASSIGN(kms_v1::MacSignResponse resp, client_->MacSign(req));

  std::vector<uint8_t> resp_bytes(resp.mac().begin(), resp.mac().end());
  EXPECT_EQ(resp_bytes, sig);
}

TEST_F(HmacTest, SignFinalWithoutUpdateFails) {
  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());

  EXPECT_THAT(signer->SignFinal(client_.get(), absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(HmacTest, SignSinglePartAfterUpdateFails) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->SignUpdate(client_.get(), data));

  EXPECT_THAT(signer->Sign(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(HmacTest, SignVerifySuccess) {
  std::string data = "Here is some data.";
  std::vector<uint8_t> data_bytes(data.begin(), data.end());

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->Sign(client_.get(), data_bytes, absl::MakeSpan(sig)));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       NewHmacVerifier(prv_, &mech));
  EXPECT_OK(verifier->Verify(client_.get(), data_bytes, absl::MakeSpan(sig)));
}

TEST_F(HmacTest, VerifyDataLengthOversize) {
  uint8_t data[65537], sig[32];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       NewHmacVerifier(prv_, &mech));

  EXPECT_THAT(verifier->Verify(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(HmacTest, VerifyDataPartLengthOversize) {
  uint8_t data[65537];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       NewHmacVerifier(prv_, &mech));

  EXPECT_THAT(verifier->VerifyUpdate(client_.get(), data),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(HmacTest, VerifyDataPartSumLengthOversize) {
  uint8_t data1[65535], data2[2];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       NewHmacVerifier(prv_, &mech));

  EXPECT_OK(verifier->VerifyUpdate(client_.get(), data1));
  EXPECT_THAT(verifier->VerifyUpdate(client_.get(), data2),
              AllOf(StatusIs(absl::StatusCode::kInvalidArgument),
                    StatusRvIs(CKR_DATA_LEN_RANGE)));
}

TEST_F(HmacTest, VerifySignatureLengthOversize) {
  uint8_t data[65536], sig[33];

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       NewHmacVerifier(prv_, &mech));

  EXPECT_THAT(verifier->Verify(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kInternal),
                    StatusRvIs(CKR_GENERAL_ERROR)));
}

TEST_F(HmacTest, SignVerifyMultiPartSuccess) {
  std::string data = "Here is some data.";
  std::string data_part1 = "Here is ";
  std::string data_part2 = "some data.";
  std::vector<uint8_t> data_part1_bytes(data_part1.begin(), data_part1.end());
  std::vector<uint8_t> data_part2_bytes(data_part2.begin(), data_part2.end());

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<SignerInterface> signer,
                       NewHmacSigner(prv_, &mech));
  std::vector<uint8_t> sig(signer->signature_length());
  EXPECT_OK(signer->SignUpdate(client_.get(), data_part1_bytes));
  EXPECT_OK(signer->SignUpdate(client_.get(), data_part2_bytes));
  EXPECT_OK(signer->SignFinal(client_.get(), absl::MakeSpan(sig)));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       NewHmacVerifier(prv_, &mech));
  EXPECT_OK(verifier->VerifyUpdate(client_.get(), data_part1_bytes));
  EXPECT_OK(verifier->VerifyUpdate(client_.get(), data_part2_bytes));
  EXPECT_OK(verifier->VerifyFinal(client_.get(), absl::MakeSpan(sig)));
}

TEST_F(HmacTest, VerifyFinalWithoutUpdateFails) {
  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       NewHmacVerifier(prv_, &mech));
  std::vector<uint8_t> sig(32);

  EXPECT_THAT(verifier->VerifyFinal(client_.get(), absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_F(HmacTest, VerifySinglePartAfterUpdateFails) {
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};

  CK_MECHANISM mech{CKM_SHA256_HMAC, nullptr, 0};
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<VerifierInterface> verifier,
                       NewHmacVerifier(prv_, &mech));
  std::vector<uint8_t> sig(32);
  EXPECT_OK(verifier->VerifyUpdate(client_.get(), data));

  EXPECT_THAT(verifier->Verify(client_.get(), data, absl::MakeSpan(sig)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

}  // namespace
}  // namespace cloud_kms::kmsp11
