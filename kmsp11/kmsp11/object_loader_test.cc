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

#include "kmsp11/object_loader.h"

#include "common/test/runfiles.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::ElementsAre;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Property;
using ::testing::internal::CaptureStderr;
using ::testing::internal::GetCapturedStderr;

class BuildStateTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(fake_server_, fakekms::Server::New());

    kms_stub_ = fake_server_->NewClient();
    key_ring_ = CreateKeyRingOrDie(kms_stub_.get(), kTestLocation, RandomId(),
                                   key_ring_);
    client_ = std::make_unique<KmsClient>(
        KmsClient::Options{.endpoint_address = fake_server_->listen_addr(),
                           .rpc_timeout = absl::Seconds(1)});
  }

  kms_v1::CryptoKeyVersion AddKeyAndInitialVersion(
      std::string_view key_name, kms_v1::CryptoKey::CryptoKeyPurpose purpose,
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
      kms_v1::ProtectionLevel protection_level = kms_v1::HSM,
      std::string_view crypto_key_backend = "") {
    kms_v1::CryptoKey ck;
    ck.set_purpose(purpose);
    ck.mutable_version_template()->set_algorithm(algorithm);
    ck.mutable_version_template()->set_protection_level(protection_level);
    if (crypto_key_backend != "") {
      ck.set_crypto_key_backend(crypto_key_backend);
    }
    ck = CreateCryptoKeyOrDie(kms_stub_.get(), key_ring_.name(), key_name, ck,
                              true);

    kms_v1::CryptoKeyVersion ckv;
    ckv = CreateCryptoKeyVersionOrDie(kms_stub_.get(), ck.name(), ckv);
    return WaitForEnablement(kms_stub_.get(), ckv);
  }

  absl::StatusOr<std::string> GenerateCertPemForCkv(
      const kms_v1::CryptoKeyVersion& ckv) {
    kms_v1::PublicKey public_key_proto =
        GetPublicKeyOrDie(kms_stub_.get(), ckv);
    ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> public_key,
                     ParseX509PublicKeyPem(public_key_proto.pem()));
    ASSIGN_OR_RETURN(std::unique_ptr<CertAuthority> authority,
                     CertAuthority::New());
    ASSIGN_OR_RETURN(bssl::UniquePtr<X509> cert,
                     authority->GenerateCert(ckv, public_key.get()));
    bssl::UniquePtr<BIO> cert_bio(BIO_new(BIO_s_mem()));
    if (!PEM_write_bio_X509(cert_bio.get(), cert.get())) {
      return absl::InternalError(absl::StrCat(
          "error marshaling X.509 certificate: ", SslErrorToString()));
    }
    BUF_MEM* cert_ptr;
    if (!BIO_get_mem_ptr(cert_bio.get(), &cert_ptr)) {
      return absl::InternalError(
          "failed to get pointer to written certificate.");
    }
    return std::string(cert_ptr->data, cert_ptr->length);
  }

  std::unique_ptr<fakekms::Server> fake_server_;
  std::unique_ptr<kms_v1::KeyManagementService::Stub> kms_stub_;
  kms_v1::KeyRing key_ring_;
  std::unique_ptr<KmsClient> client_;
};

TEST_F(BuildStateTest, EmptyKeyRingReturnsEmptyState) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

TEST_F(BuildStateTest, OutputContainsVersionProto) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));

  EXPECT_THAT(state.keys(), ElementsAre(Property("crypto_key_version",
                                                 &Key::crypto_key_version,
                                                 EqualsProto(ckv))));
}

TEST_F(BuildStateTest, OutputContainsGeneratedHandles) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 1);

  EXPECT_GT(state.keys(0).private_key_handle(), 0);
  EXPECT_GT(state.keys(0).public_key_handle(), 0);
}

TEST_F(BuildStateTest, OutputContainsPublicKey) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 1);

  EXPECT_OK(ParseX509PublicKeyDer(state.keys(0).public_key_der()));
}

TEST_F(BuildStateTest, OutputContainsCertificateWhenCertsAreEnabled) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 1);

  EXPECT_TRUE(state.keys(0).has_certificate());
  EXPECT_GT(state.keys(0).certificate().handle(), 0);
  EXPECT_OK(ParseX509CertificateDer(state.keys(0).certificate().x509_der()));
}

TEST_F(BuildStateTest, OutputContainsNoCertificateWhenCertsAreDisabled) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, false));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 1);

  EXPECT_FALSE(state.keys(0).has_certificate());
}

TEST_F(BuildStateTest, OutputContainsMatchingUserCert) {
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ASSERT_OK_AND_ASSIGN(std::string cert_pem, GenerateCertPemForCkv(ckv));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {&cert_pem}, false));
  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 1);

  EXPECT_TRUE(state.keys(0).has_certificate());
}

TEST_F(BuildStateTest, OutputDoesNotContainUnmatchedUserCert) {
  ASSERT_OK_AND_ASSIGN(std::string cert_pem,
                       LoadTestRunfile("ec_p256_cert.pem"));
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {&cert_pem}, false));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 1);

  EXPECT_FALSE(state.keys(0).has_certificate());
}

TEST_F(BuildStateTest, NoWarningWhenAllUserCertsAreUsed) {
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ASSERT_OK_AND_ASSIGN(std::string cert_pem, GenerateCertPemForCkv(ckv));

  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {&cert_pem}, false));

  CaptureStderr();
  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 1);
  EXPECT_THAT(GetCapturedStderr(), IsEmpty());
}

TEST_F(BuildStateTest, WarninOnUnusedUserCert) {
  ASSERT_OK_AND_ASSIGN(std::string cert_pem,
                       LoadTestRunfile("ec_p256_cert.pem"));
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {&cert_pem}, false));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  CaptureStderr();
  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 1);
  EXPECT_THAT(
      GetCapturedStderr(),
      HasSubstr("one or more provided certificates could not be matched"));
}

TEST_F(BuildStateTest, FallBackToGeneratedCertWhenNoMatchingUserCert) {
  ASSERT_OK_AND_ASSIGN(std::string cert_pem,
                       LoadTestRunfile("ec_p256_cert.pem"));
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {&cert_pem}, true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  ASSERT_EQ(state.keys_size(), 1);

  EXPECT_TRUE(state.keys(0).has_certificate());
}

TEST_F(BuildStateTest, UnmodifiedStateIsUnchangedAfterRefresh) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  EXPECT_THAT(loader_->BuildState(*client_), IsOkAndHolds(EqualsProto(state)));
}

TEST_F(BuildStateTest, PreviouslyRetrievedStateIsUnchangedAfterElementIsAdded) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv1 =
      AddKeyAndInitialVersion("ck1", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
  ASSERT_OK_AND_ASSIGN(ObjectStoreState original_state,
                       loader_->BuildState(*client_));
  ASSERT_EQ(original_state.keys_size(), 1);

  kms_v1::CryptoKeyVersion ckv2 = AddKeyAndInitialVersion(
      "ck2", kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
      kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
  ASSERT_OK_AND_ASSIGN(ObjectStoreState updated_state,
                       loader_->BuildState(*client_));

  EXPECT_THAT(updated_state.keys(),
              ElementsAre(
                  // The first element matches the previously retrieved result
                  // exactly.
                  EqualsProto(original_state.keys(0)),
                  // The second element refers to the newly added key.
                  Property("crypto_key_version", &Key::crypto_key_version,
                           EqualsProto(ckv2))));
}

TEST_F(BuildStateTest, KeyWithPurposeEncryptDecryptIsOmitted) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv = AddKeyAndInitialVersion(
      "ck", kms_v1::CryptoKey::ENCRYPT_DECRYPT,
      kms_v1::CryptoKeyVersion::GOOGLE_SYMMETRIC_ENCRYPTION);

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

TEST_F(BuildStateTest,
       KeyWithSoftwareProtectionLevelIsOmittedWhenSoftwareKeysAreDisallowed) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                              kms_v1::ProtectionLevel::SOFTWARE);

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

TEST_F(BuildStateTest,
       KeyWithSoftwareProtectionLevelIncludedWhenSoftwareKeysAreAllowed) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true,
                                         /*allow_software_keys=*/true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                              kms_v1::ProtectionLevel::SOFTWARE);

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  EXPECT_EQ(state.keys_size(), 1);
}

TEST_F(BuildStateTest, VersionWithStateDisabledIsOmitted) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

  ckv.set_state(kms_v1::CryptoKeyVersion::DISABLED);
  google::protobuf::FieldMask update_mask;
  update_mask.add_paths("state");
  ckv = UpdateCryptoKeyVersionOrDie(kms_stub_.get(), ckv, update_mask);

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

TEST_F(BuildStateTest, VersionWithAlgorithmP224IsOmitted) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true));
  kms_v1::CryptoKeyVersion ckv = AddKeyAndInitialVersion(
      "ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
      kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm(
          /* EC_SIGN_P224_SHA256 */ 11));

  EXPECT_THAT(loader_->BuildState(*client_),
              IsOkAndHolds(EqualsProto(ObjectStoreState())));
}

TEST_F(BuildStateTest, KeyWithSingleTenantProtectionLevelIncluded) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<ObjectLoader> loader_,
                       ObjectLoader::New(key_ring_.name(), {}, true,
                                         /*allow_software_keys=*/false));
  kms_v1::CryptoKeyVersion ckv =
      AddKeyAndInitialVersion("ck", kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                              kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                              kms_v1::ProtectionLevel::HSM_SINGLE_TENANT,
                              "test");

  ASSERT_OK_AND_ASSIGN(ObjectStoreState state, loader_->BuildState(*client_));
  EXPECT_EQ(state.keys_size(), 1);
}

}  // namespace
}  // namespace cloud_kms::kmsp11
