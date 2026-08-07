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

#include <string_view>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_format.h"
#include "common/kms_v1.h"
#include "common/test/resource_helpers.h"
#include "common/test/test_platform.h"
#include "common/test/test_status_macros.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "grpc++/grpc++.h"
#include "gtest/gtest.h"
#include "kmscng/cng_headers.h"
#include "kmscng/provider.h"
#include "kmscng/util/registration.h"
#include "kmscng/util/string_utils.h"

#define ASSERT_SUCCESS(arg) ASSERT_EQ(arg, 0)
#define EXPECT_SUCCESS(arg) EXPECT_EQ(arg, 0)

ABSL_FLAG(std::string, kms_endpoint, "",
          "Required. The Cloud KMS gRPC endpoint to invoke. For example, "
          "'cloudkms.googleapis.com:443'.");
ABSL_FLAG(std::string, user_project, "",
          "Optional. The user project to use for per-request billing and "
          "global quotas (user project override). Empty means no override.");
ABSL_FLAG(std::string, location_name, "",
          "Required. The project and location to create resources in. For "
          "example, 'projects/foo/locations/global'.");
ABSL_FLAG(std::string, key_ring_id_prefix, "kr",
          "Optional. A prefix to add to generated key rings.");

namespace cloud_kms::kmscng {
namespace {

using ::testing::IsNull;
using ::testing::Not;

class EndToEndTest : public testing::Test {
 public:
  EndToEndTest()
      : kms_endpoint_(absl::GetFlag(FLAGS_kms_endpoint)),
        user_project_(absl::GetFlag(FLAGS_user_project)),
        location_name_(absl::GetFlag(FLAGS_location_name)),
        key_ring_id_(RandomId(absl::GetFlag(FLAGS_key_ring_id_prefix))) {}

  absl::StatusOr<kms_v1::CryptoKeyVersion> CreateTestCryptoKeyVersion(
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

 protected:
  static void SetUpTestSuite() { ASSERT_OK(RegisterProvider()); }
  static void TearDownTestSuite() { ASSERT_OK(UnregisterProvider()); }

  const std::string kms_endpoint_;
  const std::string user_project_;
  const std::string location_name_;
  const std::string key_ring_id_;
};

absl::StatusOr<kms_v1::CryptoKeyVersion>
EndToEndTest::CreateTestCryptoKeyVersion(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  auto kms_stub = kms_v1::KeyManagementService::NewStub(
      grpc::CreateChannel(kms_endpoint_, grpc::GoogleDefaultCredentials()));

  grpc::ClientContext ctx1;
  ctx1.AddMetadata("x-goog-request-params",
                   absl::StrCat("parent=", location_name_));
  if (!user_project_.empty()) {
    ctx1.AddMetadata("x-goog-user-project", user_project_);
  }

  kms_v1::CreateKeyRingRequest req_kr;
  req_kr.set_parent(location_name_);
  req_kr.set_key_ring_id(key_ring_id_);

  kms_v1::KeyRing kr;
  RETURN_IF_ERROR(kms_stub->CreateKeyRing(&ctx1, req_kr, &kr));

  // If we eventually add support for key creation and additional algorithms in
  // the CNG provider, we can move CKV creation within the tests and do it
  // through the provider.

  kms_v1::CryptoKey crypto_key;
  crypto_key.set_purpose(kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  crypto_key.mutable_version_template()->set_protection_level(kms_v1::HSM);
  crypto_key.mutable_version_template()->set_algorithm(algorithm);
  kms_v1::CreateCryptoKeyRequest req_ck;
  req_ck.set_parent(kr.name());
  req_ck.set_crypto_key_id("ck");
  *req_ck.mutable_crypto_key() = crypto_key;
  req_ck.set_skip_initial_version_creation(true);

  kms_v1::CryptoKey ck;
  grpc::ClientContext ctx2;
  ctx2.AddMetadata("x-goog-request-params", absl::StrCat("parent=", kr.name()));
  if (!user_project_.empty()) {
    ctx2.AddMetadata("x-goog-user-project", user_project_);
  }

  CHECK_OK(kms_stub->CreateCryptoKey(&ctx2, req_ck, &ck));

  kms_v1::CryptoKeyVersion crypto_key_version;
  kms_v1::CreateCryptoKeyVersionRequest req_ckv;
  req_ckv.set_parent(ck.name());
  *req_ckv.mutable_crypto_key_version() = crypto_key_version;

  kms_v1::CryptoKeyVersion ckv;
  grpc::ClientContext ctx3;
  ctx3.AddMetadata("x-goog-request-params", absl::StrCat("parent=", ck.name()));
  if (!user_project_.empty()) {
    ctx3.AddMetadata("x-goog-user-project", user_project_);
  }

  CHECK_OK(kms_stub->CreateCryptoKeyVersion(&ctx3, req_ckv, &ckv));

  grpc::ClientContext ctx4;
  ctx4.AddMetadata("x-goog-request-params", absl::StrCat("parent=", ck.name()));
  if (!user_project_.empty()) {
    ctx4.AddMetadata("x-goog-user-project", user_project_);
  }
  for (int i = 0; i++; i < 300) {
    absl::SleepFor(absl::Seconds(1));
    kms_v1::GetCryptoKeyVersionRequest req_get;
    req_get.set_name(ckv.name());
    CHECK_OK(kms_stub->GetCryptoKeyVersion(&ctx4, req_get, &ckv));

    if (ckv.state() == kms_v1::CryptoKeyVersion::ENABLED) {
      break;
    }
  }
  return ckv;
}

TEST_F(EndToEndTest, TestEcdsaP256SignSuccess) {
  ASSERT_OK_AND_ASSIGN(const kms_v1::CryptoKeyVersion ckv,
                       CreateTestCryptoKeyVersion(
                           kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256));

  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_SUCCESS(
      NCryptOpenStorageProvider(&provider_handle, kProviderName.data(), 0));

  // Set custom property to hit the right KMS endpoint.
  ASSERT_SUCCESS(NCryptSetProperty(
      provider_handle, kEndpointAddressProperty.data(),
      reinterpret_cast<uint8_t*>(const_cast<char*>(kms_endpoint_.data())),
      kms_endpoint_.size(), 0));

  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_SUCCESS(NCryptOpenKey(provider_handle, &key_handle,
                               StringToWide(ckv.name()).data(), AT_SIGNATURE,
                               0));

  std::vector<uint8_t> digest(32, '\1');
  std::vector<uint8_t> signature(64, '\0');
  std::vector<uint8_t> empty_sig = signature;
  DWORD output_size = 0;
  NTSTATUS status =
      NCryptSignHash(key_handle, nullptr, digest.data(), digest.size(),
                     signature.data(), signature.size(), &output_size, 0);
  EXPECT_SUCCESS(status) << absl::StrFormat(
      "NCryptSignHash failed with error code 0x%08x\n", status);
  EXPECT_EQ(output_size, signature.size());
  EXPECT_NE(signature, empty_sig);

  EXPECT_SUCCESS(NCryptFreeObject(key_handle));
  EXPECT_SUCCESS(NCryptFreeObject(provider_handle));
}

TEST_F(EndToEndTest, TestRsa2048SignSuccess) {
  ASSERT_OK_AND_ASSIGN(
      const kms_v1::CryptoKeyVersion ckv,
      CreateTestCryptoKeyVersion(
          kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256));

  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_SUCCESS(
      NCryptOpenStorageProvider(&provider_handle, kProviderName.data(), 0));

  // Set custom property to hit the right KMS endpoint.
  ASSERT_SUCCESS(NCryptSetProperty(
      provider_handle, kEndpointAddressProperty.data(),
      reinterpret_cast<uint8_t*>(const_cast<char*>(kms_endpoint_.data())),
      kms_endpoint_.size(), 0));

  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_SUCCESS(NCryptOpenKey(provider_handle, &key_handle,
                               StringToWide(ckv.name()).data(), AT_SIGNATURE,
                               0));

  std::vector<uint8_t> digest(32, '\1');
  std::vector<uint8_t> signature(256, '\0');
  std::vector<uint8_t> empty_sig = signature;
  DWORD output_size = 0;
  NTSTATUS status =
      NCryptSignHash(key_handle, nullptr, digest.data(), digest.size(),
                     signature.data(), signature.size(), &output_size, 0);
  EXPECT_SUCCESS(status) << absl::StrFormat(
      "NCryptSignHash failed with error code 0x%08x\n", status);
  EXPECT_EQ(output_size, signature.size());
  EXPECT_NE(signature, empty_sig);

  EXPECT_SUCCESS(NCryptFreeObject(key_handle));
  EXPECT_SUCCESS(NCryptFreeObject(provider_handle));
}

}  // namespace
}  // namespace cloud_kms::kmscng
