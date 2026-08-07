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

#include "common/kms_client.h"

#include "absl/time/time.h"
#include "common/openssl.h"
#include "common/test/matchers.h"
#include "common/test/resource_helpers.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "fakekms/cpp/fault_helpers.h"
#include "gmock/gmock.h"
#include "kms_client.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms {
namespace {

using ::testing::SizeIs;

// TODO(b/270419822): Clean up these using statements once crypto_utils has
// been moved to common.
using ::cloud_kms::kmsp11::EcdsaSigAsn1ToP1363;
using ::cloud_kms::kmsp11::EcdsaVerifyP1363;
using ::cloud_kms::kmsp11::EncryptRsaOaep;
using ::cloud_kms::kmsp11::ParseX509PublicKeyPem;

std::unique_ptr<KmsClient> NewClient(
    std::string_view listen_addr,
    absl::Duration rpc_timeout = absl::Milliseconds(500)) {
  return std::make_unique<KmsClient>(KmsClient::Options{
      .endpoint_address = std::string(listen_addr), .rpc_timeout = rpc_timeout});
}

TEST(KmsClientTest, ListCryptoKeysSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck1;
  ck1.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck1 = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck1", ck1, true);

  kms_v1::CryptoKey ck2;
  ck2.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck2.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck2 = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck2", ck2, true);

  kms_v1::ListCryptoKeysRequest list_req;
  list_req.set_parent(kr.name());
  CryptoKeysRange range = client->ListCryptoKeys(list_req);

  CryptoKeysRange::iterator it = range.begin();
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey rck1, *it);
  EXPECT_THAT(rck1, EqualsProto(ck1));

  it++;
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey rck2, *it);
  EXPECT_THAT(rck2, EqualsProto(ck2));

  it++;
  EXPECT_EQ(it, range.end());
}

TEST(KmsClientTest, ListCryptoKeysFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::ListCryptoKeysRequest list_req;
  list_req.set_parent("foo");
  CryptoKeysRange range = client->ListCryptoKeys(list_req);

  CryptoKeysRange::iterator it = range.begin();
  EXPECT_THAT(*it, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, ListCryptoKeyVersionsSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv1;
  ckv1 = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv1);
  ckv1 = WaitForEnablement(client->kms_stub(), ckv1);

  kms_v1::CryptoKeyVersion ckv2;
  ckv2 = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv2);
  ckv2 = WaitForEnablement(client->kms_stub(), ckv2);

  kms_v1::ListCryptoKeyVersionsRequest list_req;
  list_req.set_parent(ck.name());
  CryptoKeyVersionsRange range = client->ListCryptoKeyVersions(list_req);

  CryptoKeyVersionsRange::iterator it = range.begin();
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKeyVersion rckv1, *it);
  EXPECT_THAT(rckv1, EqualsProto(ckv1));

  it++;
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKeyVersion rckv2, *it);
  EXPECT_THAT(rckv2, EqualsProto(ckv2));

  it++;
  EXPECT_EQ(it, range.end());
}

TEST(KmsClientTest, ListCryptoKeyVersionsFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::ListCryptoKeyVersionsRequest list_req;
  list_req.set_parent("foo");
  CryptoKeyVersionsRange range = client->ListCryptoKeyVersions(list_req);

  CryptoKeyVersionsRange::iterator it = range.begin();
  EXPECT_THAT(*it, StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, GetPublicKeySuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ckv = WaitForEnablement(client->kms_stub(), ckv);

  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name(ckv.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::PublicKey pk, client->GetPublicKey(pub_req));

  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pk.pem()));
  EXPECT_TRUE(EVP_PKEY_get0_EC_KEY(pub.get()));
}

TEST(KmsClientTest, GetPublicKeyFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name("foo");
  EXPECT_THAT(client->GetPublicKey(pub_req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, AsymmetricDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ckv = WaitForEnablement(client->kms_stub(), ckv);

  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name(ckv.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::PublicKey pk, client->GetPublicKey(pub_req));

  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pk.pem()));

  std::string plaintext_str = "Here is a sample plaintext";
  absl::Span<const uint8_t> plaintext(
      reinterpret_cast<const uint8_t*>(plaintext_str.data()),
      plaintext_str.size());

  uint8_t ct_data[256];
  absl::Span<uint8_t> ciphertext = absl::MakeSpan(ct_data);

  EXPECT_OK(EncryptRsaOaep(pub.get(), EVP_sha256(), plaintext, ciphertext));

  kms_v1::AsymmetricDecryptRequest decrypt_req;
  decrypt_req.set_name(ckv.name());
  decrypt_req.set_ciphertext(ciphertext.data(), ciphertext.size());

  ASSERT_OK_AND_ASSIGN(kms_v1::AsymmetricDecryptResponse decrypt_resp,
                       client->AsymmetricDecrypt(decrypt_req));
  EXPECT_EQ(decrypt_resp.plaintext(), plaintext_str);
}

TEST(KmsClientTest, AsymmetricDecryptFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::AsymmetricDecryptRequest req;
  req.set_name("foo");
  EXPECT_THAT(client->AsymmetricDecrypt(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, AsymmetricSignSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ckv = WaitForEnablement(client->kms_stub(), ckv);

  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name(ckv.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::PublicKey pk, client->GetPublicKey(pub_req));

  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub,
                       ParseX509PublicKeyPem(pk.pem()));

  std::string data = "Here is some data to authenticate";
  uint8_t digest[32];
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), digest);

  kms_v1::AsymmetricSignRequest sign_req;
  sign_req.set_name(ckv.name());
  sign_req.mutable_digest()->set_sha256(digest, sizeof(digest));

  ASSERT_OK_AND_ASSIGN(kms_v1::AsymmetricSignResponse sign_resp,
                       client->AsymmetricSign(sign_req));

  EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pub.get());
  ASSERT_OK_AND_ASSIGN(
      std::vector<uint8_t> p1363_sig,
      EcdsaSigAsn1ToP1363(sign_resp.signature(), EC_KEY_get0_group(ec_key)));

  EXPECT_OK(EcdsaVerifyP1363(ec_key, EVP_sha256(), digest, p1363_sig));
}

TEST(KmsClientTest, AsymmetricSignFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::AsymmetricSignRequest req;
  req.set_name("foo");
  req.set_data("bar");
  EXPECT_THAT(client->AsymmetricSign(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, MacSignVerifySuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::MAC);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::HMAC_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ckv = WaitForEnablement(client->kms_stub(), ckv);

  std::string data = "Here is some data to authenticate";

  kms_v1::MacSignRequest sign_req;
  sign_req.set_name(ckv.name());
  sign_req.set_data(data);

  ASSERT_OK_AND_ASSIGN(kms_v1::MacSignResponse sign_resp,
                       client->MacSign(sign_req));

  kms_v1::MacVerifyRequest verify_req;
  verify_req.set_name(ckv.name());
  verify_req.set_data(data);
  verify_req.set_mac(sign_resp.mac());

  ASSERT_OK_AND_ASSIGN(kms_v1::MacVerifyResponse verify_resp,
                       client->MacVerify(verify_req));
  EXPECT_TRUE(verify_resp.success());
}

TEST(KmsClientTest, MacSignFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::MacSignRequest req;
  req.set_name("foo");
  EXPECT_THAT(client->MacSign(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, MacVerifyFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::MacVerifyRequest req;
  req.set_name("foo");
  EXPECT_THAT(client->MacVerify(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, RawEncryptDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::AES_256_GCM);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ckv = WaitForEnablement(client->kms_stub(), ckv);

  std::string data = "Here is some data to encrypt";

  kms_v1::RawEncryptRequest encrypt_req;
  encrypt_req.set_name(ckv.name());
  encrypt_req.set_plaintext(data);
  encrypt_req.set_additional_authenticated_data("");

  ASSERT_OK_AND_ASSIGN(kms_v1::RawEncryptResponse encrypt_resp,
                       client->RawEncrypt(encrypt_req));

  kms_v1::RawDecryptRequest decrypt_req;
  decrypt_req.set_name(ckv.name());
  decrypt_req.set_ciphertext(encrypt_resp.ciphertext());
  decrypt_req.set_additional_authenticated_data("");
  decrypt_req.set_initialization_vector(encrypt_resp.initialization_vector());

  ASSERT_OK_AND_ASSIGN(kms_v1::RawDecryptResponse decrypt_resp,
                       client->RawDecrypt(decrypt_req));
  EXPECT_EQ(decrypt_resp.plaintext(), data);
}

TEST(KmsClientTest, RawEncryptFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::RawEncryptRequest req;
  req.set_name("foo");
  EXPECT_THAT(client->RawEncrypt(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, RawDecryptFailureInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::RawDecryptRequest req;
  req.set_name("foo");
  EXPECT_THAT(client->RawDecrypt(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, RawEncryptFailureCustomIvAesGcm) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::AES_256_GCM);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ckv = WaitForEnablement(client->kms_stub(), ckv);

  std::string data = "Here is some data to encrypt";

  kms_v1::RawEncryptRequest encrypt_req;
  encrypt_req.set_name(ckv.name());
  encrypt_req.set_plaintext(data);
  encrypt_req.set_additional_authenticated_data("");
  encrypt_req.set_initialization_vector("my_custom_iv_123");

  EXPECT_THAT(client->RawEncrypt(encrypt_req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, CreateCryptoKeyCreatesCryptoKey) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(kr.name());
  req.set_crypto_key_id("ck");
  req.mutable_crypto_key()->set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);

  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey created, client->CreateCryptoKey(req));

  EXPECT_THAT(
      GetCryptoKeyOrDie(client->kms_stub(), kr.name() + "/cryptoKeys/ck"),
      EqualsProto(created));
}

TEST(KmsClientTest, CreateCryptoKeyFailsOnExistingName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(kr.name());
  req.set_crypto_key_id("ck");
  req.mutable_crypto_key()->set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);

  EXPECT_THAT(client->CreateCryptoKey(req),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(KmsClientTest, CreateCryptoKeyInvalidArgumentOnInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(kr.name());
  req.set_crypto_key_id("@123!");
  req.mutable_crypto_key()->set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);

  EXPECT_THAT(client->CreateCryptoKey(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest,
     CreateCryptoKeyAndFirstVersionCreatesCryptoKeyAndFirstVersion) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(kr.name());
  req.set_crypto_key_id("ck");
  req.mutable_crypto_key()->set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);

  ASSERT_OK_AND_ASSIGN(CryptoKeyAndVersion created,
                       client->CreateCryptoKeyAndWaitForFirstVersion(req));

  EXPECT_THAT(
      GetCryptoKeyOrDie(client->kms_stub(), kr.name() + "/cryptoKeys/ck"),
      EqualsProto(created.crypto_key));
  EXPECT_THAT(
      GetCryptoKeyVersionOrDie(
          client->kms_stub(), kr.name() + "/cryptoKeys/ck/cryptoKeyVersions/1"),
      EqualsProto(created.crypto_key_version));
}

TEST(KmsClientTest, CreateCryptoKeyAndFirstVersionFailsOnExistingName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(kr.name());
  req.set_crypto_key_id("ck");
  req.mutable_crypto_key()->set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);

  EXPECT_THAT(client->CreateCryptoKeyAndWaitForFirstVersion(req),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(KmsClientTest,
     CreateCryptoKeyAndFirstVersionInvalidArgumentOnInvalidName) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(kr.name());
  req.set_crypto_key_id("@123!");
  req.mutable_crypto_key()->set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);

  EXPECT_THAT(client->CreateCryptoKeyAndWaitForFirstVersion(req),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KmsClientTest, CreateCryptoKeyAndFirstVersionTimesOutAtDeadline) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client =
      NewClient(fake->listen_addr(), absl::Milliseconds(150));

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(kr.name());
  req.set_crypto_key_id("ck");
  req.mutable_crypto_key()->set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  req.mutable_crypto_key()->mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  AddDelayOrDie(*fake, absl::Milliseconds(200), "GetCryptoKeyVersion");

  // CreateCryptoKeyAndWaitForFirstVersion causes a CreateCryptoKey followed by
  // one or more GetCryptoKeyVersions. If GetCKV has a 200ms delay, and we have
  // set a 150ms deadline, then the deadline will always be exceeded.
  EXPECT_THAT(client->CreateCryptoKeyAndWaitForFirstVersion(req),
              StatusIs(absl::StatusCode::kDeadlineExceeded));
}

TEST(KmsClientTest, DestroyCryptoKeyVersionSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client->kms_stub(), ck.name(), ckv);
  ASSERT_EQ(ckv.state(), kms_v1::CryptoKeyVersion::ENABLED);

  kms_v1::DestroyCryptoKeyVersionRequest destroy_req;
  destroy_req.set_name(ckv.name());
  ASSERT_OK_AND_ASSIGN(ckv, client->DestroyCryptoKeyVersion(destroy_req));

  EXPECT_EQ(ckv.state(), kms_v1::CryptoKeyVersion::DESTROY_SCHEDULED);
}

TEST(KmsClientTest, CreateCryptoKeyVersionAndWaitOutputMatchesStub) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client =
      NewClient(fake->listen_addr(), absl::Seconds(2));

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), RandomId(), ck,
                            false);

  kms_v1::CreateCryptoKeyVersionRequest req;
  req.set_parent(ck.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKeyVersion ckv2,
                       client->CreateCryptoKeyVersionAndWait(req));

  std::string expected_name = absl::StrCat(ck.name(), "/cryptoKeyVersions/2");
  EXPECT_THAT(GetCryptoKeyVersionOrDie(client->kms_stub(), expected_name),
              EqualsProto(ckv2));
}

TEST(KmsClientTest, CreateCryptoKeyVersionAndWaitTimesOutAtDeadline) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client =
      NewClient(fake->listen_addr(), absl::Milliseconds(150));

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), RandomId(), ck,
                            false);

  kms_v1::CreateCryptoKeyVersionRequest req;
  req.set_parent(ck.name());

  AddDelayOrDie(*fake, absl::Milliseconds(200), "GetCryptoKeyVersion");

  // CreateCryptoKeyVersionAndWait causes a CreateCryptoKey followed by one or
  // more GetCryptoKeyVersions. If GetCKV has a 200ms delay, and we have set a
  // 150ms deadline, then the deadline will always be exceeded.
  EXPECT_THAT(client->CreateCryptoKeyVersionAndWait(req),
              StatusIs(absl::StatusCode::kDeadlineExceeded));
}

TEST(KmsClientTest, CreateCryptoKeyVersionWaitsForEnablement) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client =
      NewClient(fake->listen_addr(), absl::Seconds(2));

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  ck.mutable_version_template()->set_algorithm(
      kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), RandomId(), ck,
                            false);

  kms_v1::CreateCryptoKeyVersionRequest req;
  req.set_parent(ck.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKeyVersion ckv2,
                       client->CreateCryptoKeyVersionAndWait(req));

  EXPECT_EQ(ckv2.state(), kms_v1::CryptoKeyVersion::ENABLED);
}

TEST(KmsClientTest, GetCryptoKeySuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), RandomId(), ck,
                            false);

  kms_v1::GetCryptoKeyRequest req;
  req.set_name(ck.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey got_ck, client->GetCryptoKey(req));

  EXPECT_THAT(got_ck, EqualsProto(ck));
}

TEST(KmsClientTest, GetCryptoKeyVersionSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck =
      CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), RandomId(), ck, true);

  kms_v1::CreateCryptoKeyVersionRequest req;
  req.set_parent(ck.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKeyVersion ckv,
                       client->CreateCryptoKeyVersionAndWait(req));

  kms_v1::GetCryptoKeyVersionRequest req_ckv;
  req_ckv.set_name(ckv.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKeyVersion got_ckv,
                       client->GetCryptoKeyVersion(req_ckv));

  EXPECT_THAT(got_ckv, EqualsProto(ckv));
}

TEST(KmsClientTest, ClientRetriesTransparentlyOnUnavailable) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), RandomId(), ck,
                            false);

  AddErrorOrDie(*fake, absl::UnavailableError("not available"));

  kms_v1::GetCryptoKeyRequest req;
  req.set_name(ck.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey got_ck, client->GetCryptoKey(req));

  // Expecting OK status because our retry policy should retry on UNAVAILABLE.
  EXPECT_THAT(got_ck, EqualsProto(ck));
}

TEST(KmsClientTest, ClientRetriesTransparentlyOnServerDeadlineExceeded) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::KeyRing kr;
  kr = CreateKeyRingOrDie(client->kms_stub(), kTestLocation, RandomId(), kr);

  kms_v1::CryptoKey ck;
  ck.set_purpose(kms_v1::CryptoKey::ENCRYPT_DECRYPT);
  ck = CreateCryptoKeyOrDie(client->kms_stub(), kr.name(), RandomId(), ck,
                            false);

  AddErrorOrDie(*fake, absl::DeadlineExceededError("deadline exceeded"));

  kms_v1::GetCryptoKeyRequest req;
  req.set_name(ck.name());
  ASSERT_OK_AND_ASSIGN(kms_v1::CryptoKey got_ck, client->GetCryptoKey(req));

  // Expecting OK status because our retry policy should retry on
  // DEADLINE_EXCEEDED.
  EXPECT_THAT(got_ck, EqualsProto(ck));
}

TEST(KmsClientTest, GenerateRandomBytesSuccess) {
  constexpr size_t kByteLength = 64;

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake,
                       fakekms::Server::New());
  std::unique_ptr<KmsClient> client = NewClient(fake->listen_addr());

  kms_v1::GenerateRandomBytesRequest req;
  req.set_location(std::string(kTestLocation));
  req.set_protection_level(kms_v1::HSM);
  req.set_length_bytes(kByteLength);

  ASSERT_OK_AND_ASSIGN(kms_v1::GenerateRandomBytesResponse resp,
                       client->GenerateRandomBytes(req));
  EXPECT_THAT(resp.data(), SizeIs(kByteLength));
}

}  // namespace
}  // namespace cloud_kms
