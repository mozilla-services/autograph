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

#include <fstream>
#include <string_view>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_format.h"
#include "common/kms_v1.h"
#include "common/openssl.h"
#include "common/test/test_platform.h"
#include "common/test/test_status_macros.h"
#include "glog/logging.h"
#include "gmock/gmock.h"
#include "grpc++/grpc++.h"
#include "gtest/gtest.h"
#include "kmsp11/cryptoki.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/test/resource_helpers.h"

ABSL_FLAG(std::string, library_path, "",
          "Required. The path to the PKCS #11 library binary to be loaded. For "
          "example, '/path/to/libkmsp11.so'.");
ABSL_FLAG(std::string, kms_endpoint, "",
          "Required. The Cloud KMS gRPC endpoint to invoke. For example, "
          "'cloudkms.googleapis.com:443'.");
ABSL_FLAG(std::string, location_name, "",
          "Required. The project and location to create resources in. For "
          "example, 'projects/foo/locations/global'.");
ABSL_FLAG(std::string, key_ring_id_prefix, "kr",
          "Optional. A prefix to add to generated key rings.");
ABSL_FLAG(std::string, user_project, "",
          "Optional. The user project to use for per-request billing and "
          "global quotas (user project override). Empty means no override.");
ABSL_FLAG(std::string, rpc_feature_flags, "",
          "Optional. Cloud KMS feature flags to include with RPC requests. "
          "Empty means no feature flags.");

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::IsNull;
using ::testing::Not;

class EndToEndTest : public testing::Test {
 public:
  EndToEndTest()
      : library_path_(absl::GetFlag(FLAGS_library_path)),
        kms_endpoint_(absl::GetFlag(FLAGS_kms_endpoint)),
        location_name_(absl::GetFlag(FLAGS_location_name)),
        key_ring_id_(RandomId(absl::GetFlag(FLAGS_key_ring_id_prefix))),
        user_project_(absl::GetFlag(FLAGS_user_project)),
        rpc_feature_flags_(absl::GetFlag(FLAGS_rpc_feature_flags)),
        config_filename_(std::tmpnam(nullptr)) {}

  void SetUp() override;
  void TearDown() override;

 protected:
  CK_FUNCTION_LIST* f_;

 private:
  absl::StatusOr<kms_v1::KeyRing> CreateTestKeyRing();

  const std::string library_path_;
  const std::string kms_endpoint_;
  const std::string location_name_;
  const std::string key_ring_id_;
  const std::string user_project_;
  const std::string rpc_feature_flags_;
  const std::string config_filename_;
};

void EndToEndTest::SetUp() {
  ASSERT_OK_AND_ASSIGN(const kms_v1::KeyRing key_ring, CreateTestKeyRing());

  // Write a library configuration file.
  std::ofstream(config_filename_) << absl::StrFormat(
      R"(---
kms_endpoint: "%s"
user_project_override: "%s"
tokens:
  - key_ring: "%s"
)",
      kms_endpoint_, user_project_, key_ring.name());
  if (!rpc_feature_flags_.empty()) {
    std::ofstream(config_filename_) << "experimental_rpc_feature_flags: \""
                                    << rpc_feature_flags_ << "\"" << std::endl;
  }

  SetEnvVariable("KMS_PKCS11_CONFIG", config_filename_);

  // Dynamically load the PKCS#11 shared library.
  // Note that there should be no corresponding dlclose call, since our
  // library does not support being dynamically unloaded.
  ASSERT_OK_AND_ASSIGN(
      void* untyped_get_fn_list,
      LoadLibrarySymbol(library_path_.c_str(), "C_GetFunctionList"));
  CK_C_GetFunctionList get_fn_list =
      reinterpret_cast<CK_C_GetFunctionList>(untyped_get_fn_list);

  // Load the function list into 'f_'.
  ASSERT_EQ(get_fn_list(&f_), CKR_OK);
}

void EndToEndTest::TearDown() {
  ClearEnvVariable("KMS_PKCS11_CONFIG");
  std::remove(config_filename_.c_str());
}

absl::StatusOr<kms_v1::KeyRing> EndToEndTest::CreateTestKeyRing() {
  auto kms_stub = kms_v1::KeyManagementService::NewStub(
      grpc::CreateChannel(kms_endpoint_, grpc::GoogleDefaultCredentials()));

  grpc::ClientContext ctx;
  ctx.AddMetadata("x-goog-request-params",
                  absl::StrCat("parent=", location_name_));
  if (!user_project_.empty()) {
    ctx.AddMetadata("x-goog-user-project", user_project_);
  }

  kms_v1::CreateKeyRingRequest req;
  req.set_parent(location_name_);
  req.set_key_ring_id(key_ring_id_);

  kms_v1::KeyRing kr;
  RETURN_IF_ERROR(kms_stub->CreateKeyRing(&ctx, req, &kr));
  return kr;
}

TEST_F(EndToEndTest, TestEcdsaSignVerify) {
  // Initialize the library and create a new read-write session on the
  // first/only token.
  ASSERT_EQ(f_->C_Initialize(nullptr), CKR_OK);
  CK_SESSION_HANDLE session_handle;
  ASSERT_EQ(f_->C_OpenSession(
                /*slotID=*/0, /*flags=*/CKF_RW_SESSION | CKF_SERIAL_SESSION,
                /*pApplication=*/nullptr, /*Notify=*/nullptr, &session_handle),
            CKR_OK);

  // Create a keypair for ECDSA signing.
  CK_MECHANISM key_gen_mechanism = {.mechanism = CKM_EC_KEY_PAIR_GEN,
                                    .pParameter = nullptr,
                                    .ulParameterLen = 0};
  std::string key_label = "p256-signing-key";
  CK_ULONG kms_algorithm = KMS_ALGORITHM_EC_SIGN_P256_SHA256;
  std::vector<CK_ATTRIBUTE> attrs = {
      CK_ATTRIBUTE{.type = CKA_LABEL,
                   .pValue = key_label.data(),
                   .ulValueLen = uint32_t(key_label.size())},
      CK_ATTRIBUTE{.type = CKA_KMS_ALGORITHM,
                   .pValue = &kms_algorithm,
                   .ulValueLen = sizeof(kms_algorithm)},
  };
  CK_OBJECT_HANDLE public_key, private_key;
  ASSERT_EQ(f_->C_GenerateKeyPair(
                /*hSession=*/session_handle, /*pMechanism=*/&key_gen_mechanism,
                /*pPublicKeyTemplate=*/nullptr, /*ulPublicKeyAttributeCount=*/0,
                /*pPrivateKeyTemplate=*/attrs.data(),
                /*ulPrivateKeyAttributeCount=*/attrs.size(),
                /*phPublicKey=*/&public_key, /*phPrivateKey=*/&private_key),
            CKR_OK);

  // Create a signature over an arbitrary 32-byte digest.
  std::vector<uint8_t> digest(32);
  RAND_bytes(digest.data(), digest.size());
  CK_MECHANISM sign_verify_mechanism = {
      .mechanism = CKM_ECDSA, .pParameter = nullptr, .ulParameterLen = 0};
  ASSERT_EQ(f_->C_SignInit(/*hSession=*/session_handle,
                           /*pMechanism=*/&sign_verify_mechanism,
                           /*hKey=*/private_key),
            CKR_OK);
  std::vector<uint8_t> signature(64);
  CK_ULONG signature_length = signature.size();
  ASSERT_EQ(f_->C_Sign(/*hSession=*/session_handle, /*pData=*/digest.data(),
                       /*ulDataLen=*/digest.size(),
                       /*pSignature=*/signature.data(),
                       /*pulSignatureLen=*/&signature_length),
            CKR_OK);
  ASSERT_GT(signature_length, 0);

  // Verify the signature over the digest (a local operation).
  ASSERT_EQ(f_->C_VerifyInit(/*hSession=*/session_handle,
                             /*pMechanism=*/&sign_verify_mechanism,
                             /*hKey=*/public_key),
            CKR_OK);
  EXPECT_EQ(f_->C_Verify(/*hSession=*/session_handle, /*pData=*/digest.data(),
                         /*ulDataLen=*/digest.size(),
                         /*pSignature=*/signature.data(),
                         /*ulSignatureLen=*/signature_length),
            CKR_OK);
}

}  // namespace
}  // namespace cloud_kms::kmsp11
