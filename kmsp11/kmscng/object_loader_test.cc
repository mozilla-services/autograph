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

#include "kmscng/object_loader.h"

#include "common/kms_client.h"
#include "common/test/proto_parser.h"
#include "common/test/resource_helpers.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmscng/cng_headers.h"
#include "kmscng/provider.h"
#include "kmscng/test/matchers.h"
#include "kmscng/util/string_utils.h"

namespace cloud_kms::kmscng {
namespace {

class BuildCkvListTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());

    kms_stub_ = fake_server_->NewClient();
    key_ring_ = CreateKeyRingOrDie(kms_stub_.get(), kTestLocation, RandomId(),
                                   key_ring_);
    client_ = std::make_unique<KmsClient>(
        KmsClient::Options{.endpoint_address = fake_server_->listen_addr(),
                           .rpc_timeout = absl::Seconds(1)});

    // Provider provider;
    prov_handle_ = reinterpret_cast<NCRYPT_PROV_HANDLE>(&prov_);
    // Set custom properties to hit fake KMS.
    EXPECT_OK(prov_.SetProperty(kEndpointAddressProperty,
                                fake_server_->listen_addr()));
    EXPECT_OK(prov_.SetProperty(kChannelCredentialsProperty, "insecure"));
  }

  kms_v1::CryptoKeyVersion AddKeyAndInitialVersion(
      std::string_view key_id, kms_v1::CryptoKey::CryptoKeyPurpose purpose,
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
      kms_v1::ProtectionLevel protection_level = kms_v1::HSM) {
    kms_v1::CryptoKey ck;
    ck.set_purpose(purpose);
    ck.mutable_version_template()->set_algorithm(algorithm);
    ck.mutable_version_template()->set_protection_level(protection_level);
    ck = CreateCryptoKeyOrDie(kms_stub_.get(), key_ring_.name(), key_id, ck,
                              true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(kms_stub_.get(), ck.name(), ckv);
    return WaitForEnablement(kms_stub_.get(), ckv);
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  std::unique_ptr<kms_v1::KeyManagementService::Stub> kms_stub_;
  kms_v1::KeyRing key_ring_;
  std::unique_ptr<KmsClient> client_;
  Provider prov_;
  NCRYPT_PROV_HANDLE prov_handle_;
};

TEST_F(BuildCkvListTest, EmptyConfigReturnsEmptyList) {
  ProviderConfig config;

  ASSERT_OK_AND_ASSIGN(std::vector<HeapAllocatedKeyDetails> ckv_list,
                       BuildCkvList(prov_handle_, config));

  EXPECT_EQ(ckv_list.size(), 0);
}

TEST_F(BuildCkvListTest, OutputContainsVersion) {
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ProviderConfig config = ParseTestProto(
      absl::StrFormat(R"pb(
                        resources { crypto_key_version: "%s" })pb",
                      ckv.name()));

  ASSERT_OK_AND_ASSIGN(std::vector<HeapAllocatedKeyDetails> ckv_list,
                       BuildCkvList(prov_handle_, config));

  EXPECT_EQ(ckv_list.size(), 1);
  EXPECT_EQ(ckv_list[0].key_name, StringToWide(ckv.name()));
  EXPECT_EQ(ckv_list[0].algorithm_identifier, BCRYPT_ECDSA_P256_ALGORITHM);
  EXPECT_EQ(ckv_list[0].legacy_spec, AT_SIGNATURE);
  EXPECT_EQ(ckv_list[0].flags, NCRYPT_MACHINE_KEY_FLAG);
}

TEST_F(BuildCkvListTest, OutputContainsMultipleVersions) {
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ProviderConfig config =
      ParseTestProto(absl::StrFormat(R"pb(
                                       resources { crypto_key_version: "%s" }
                                       resources { crypto_key_version: "%s" }
                                     )pb",
                                     ckv.name(), ckv.name()));

  ASSERT_OK_AND_ASSIGN(std::vector<HeapAllocatedKeyDetails> ckv_list,
                       BuildCkvList(prov_handle_, config));

  EXPECT_EQ(ckv_list.size(), 2);
  EXPECT_EQ(ckv_list[0].key_name, StringToWide(ckv.name()));
  EXPECT_EQ(ckv_list[1].key_name, StringToWide(ckv.name()));
}

TEST_F(BuildCkvListTest, KeyWithSoftwareProtectionLevelIsOmitted) {
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                              kms_v1::ProtectionLevel::SOFTWARE);
  ProviderConfig config = ParseTestProto(
      absl::StrFormat(R"pb(
                        resources { crypto_key_version: "%s" })pb",
                      ckv.name()));

  ASSERT_OK_AND_ASSIGN(std::vector<HeapAllocatedKeyDetails> ckv_list,
                       BuildCkvList(prov_handle_, config));
  EXPECT_EQ(ckv_list.size(), 0);
}

TEST_F(BuildCkvListTest, VersionWithStateDisabledIsOmitted) {
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ckv.set_state(kms_v1::CryptoKeyVersion::DISABLED);
  google::protobuf::FieldMask update_mask;
  update_mask.add_paths("state");
  ckv = UpdateCryptoKeyVersionOrDie(kms_stub_.get(), ckv, update_mask);

  ProviderConfig config = ParseTestProto(
      absl::StrFormat(R"pb(
                        resources { crypto_key_version: "%s" })pb",
                      ckv.name()));
  ASSERT_OK_AND_ASSIGN(std::vector<HeapAllocatedKeyDetails> ckv_list,
                       BuildCkvList(prov_handle_, config));
  EXPECT_EQ(ckv_list.size(), 0);
}

TEST_F(BuildCkvListTest, VersionWithAlgorithmP224IsOmitted) {
  kms_v1::CryptoKeyVersion ckv = AddKeyAndInitialVersion(
      "ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm(
          /* EC_SIGN_P224_SHA256 */ 11));
  ProviderConfig config = ParseTestProto(
      absl::StrFormat(R"pb(
                        resources { crypto_key_version: "%s" })pb",
                      ckv.name()));

  ASSERT_OK_AND_ASSIGN(std::vector<HeapAllocatedKeyDetails> ckv_list,
                       BuildCkvList(prov_handle_, config));
  EXPECT_EQ(ckv_list.size(), 0);
}

}  // namespace
}  // namespace cloud_kms::kmscng
