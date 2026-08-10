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

#include "absl/cleanup/cleanup.h"
#include "common/openssl.h"
#include "common/test/test_platform.h"
#include "common/test/test_status_macros.h"
#include "fakekms/cpp/fakekms.h"
#include "gmock/gmock.h"
#include "kmsp11/config/config.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/main/bridge.h"
#include "kmsp11/test/common_setup.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/test/resource_helpers.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Ge;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::IsSupersetOf;
using ::testing::Not;

struct AlgorithmInfo {
  kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm;
  CK_MECHANISM_TYPE allowedMechanism;
  const EVP_MD* evpHashAlg;
  int digest_size;
  int signature_size;
};

class AsymmetricSignTest : public testing::Test,
                           public testing::WithParamInterface<AlgorithmInfo> {};

const std::array kAsymmetricSignAlgorithms = {
    AlgorithmInfo{kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                  CKM_ECDSA_SHA256, EVP_sha256(), 32, 64},
    AlgorithmInfo{kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384,
                  CKM_ECDSA_SHA384, EVP_sha384(), 48, 96},
};

INSTANTIATE_TEST_SUITE_P(TestAsymmetricSigning, AsymmetricSignTest,
                         testing::ValuesIn(kAsymmetricSignAlgorithms));

TEST_P(AsymmetricSignTest, SignVerifySuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  std::vector<uint8_t> data(128);
  RAND_bytes(data.data(), data.size());

  std::vector<uint8_t> hash(GetParam().digest_size);
  SHA256(data.data(), data.size(), hash.data());

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};

  EXPECT_OK(SignInit(session, &mech, private_key));

  CK_ULONG signature_size;
  EXPECT_OK(Sign(session, hash.data(), hash.size(), nullptr, &signature_size));
  EXPECT_EQ(signature_size, GetParam().signature_size);

  std::vector<uint8_t> signature(signature_size);
  EXPECT_OK(Sign(session, hash.data(), hash.size(), signature.data(),
                 &signature_size));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  EXPECT_OK(VerifyInit(session, &mech, public_key));
  EXPECT_OK(Verify(session, hash.data(), hash.size(), signature.data(),
                   signature.size()));

  // Operation should be terminated after success
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), signature.data(),
                     signature.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, SignVerifyMultiPartSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  std::vector<uint8_t> data_part1 = {0xDE, 0xAD};
  std::vector<uint8_t> data_part2 = {0xBE, 0xEF};

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{GetParam().allowedMechanism, nullptr, 0};

  EXPECT_OK(SignInit(session, &mech, private_key));

  EXPECT_OK(SignUpdate(session, data_part1.data(), data_part1.size()));
  EXPECT_OK(SignUpdate(session, data_part2.data(), data_part2.size()));

  CK_ULONG signature_size;
  EXPECT_OK(SignFinal(session, nullptr, &signature_size));
  EXPECT_EQ(signature_size, GetParam().signature_size);

  std::vector<uint8_t> signature(signature_size);
  EXPECT_OK(SignFinal(session, signature.data(), &signature_size));

  // Operation should be terminated after success
  EXPECT_THAT(SignUpdate(session, data_part1.data(), data_part1.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  EXPECT_OK(VerifyInit(session, &mech, public_key));

  EXPECT_OK(VerifyUpdate(session, data_part1.data(), data_part1.size()));
  EXPECT_OK(VerifyUpdate(session, data_part2.data(), data_part2.size()));

  EXPECT_OK(VerifyFinal(session, signature.data(), signature_size));

  // Operation should be terminated after success
  EXPECT_THAT(VerifyUpdate(session, data_part1.data(), data_part1.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, SignHashTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));

  std::vector<uint8_t> hash(GetParam().digest_size - 1);
  std::vector<uint8_t> sig(GetParam().signature_size);
  CK_ULONG signature_size = sig.size();
  EXPECT_THAT(
      Sign(session, hash.data(), hash.size(), sig.data(), &signature_size),
      StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_P(AsymmetricSignTest, SignSameBuffer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));

  std::vector<uint8_t> digest(GetParam().digest_size);
  RAND_bytes(digest.data(), digest.size());

  std::vector<uint8_t> buf(GetParam().signature_size);
  std::copy(digest.begin(), digest.end(), buf.begin());
  CK_ULONG signature_size = buf.size();

  EXPECT_OK(Sign(session, buf.data(), GetParam().digest_size, buf.data(),
                 &signature_size));

  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<EVP_PKEY> pub_pkey,
                       GetEVPPublicKey(fake_server.get(), ckv));

  EXPECT_OK(EcdsaVerifyP1363(EVP_PKEY_get0_EC_KEY(pub_pkey.get()),
                             GetParam().evpHashAlg, digest, buf));
}

TEST_P(AsymmetricSignTest, SignBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));

  std::vector<uint8_t> hash(GetParam().digest_size),
      sig(GetParam().signature_size - 1);
  CK_ULONG signature_size = sig.size();
  EXPECT_THAT(
      Sign(session, hash.data(), hash.size(), sig.data(), &signature_size),
      StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(signature_size, GetParam().signature_size);

  sig.resize(signature_size);
  EXPECT_OK(
      Sign(session, hash.data(), hash.size(), sig.data(), &signature_size));

  // Operation should now be terminated.
  EXPECT_THAT(
      Sign(session, hash.data(), hash.size(), sig.data(), &signature_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, SignInitFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(SignInit(0, nullptr, 0), StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_P(AsymmetricSignTest, SignInitFailsInvalidKeyHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_THAT(SignInit(session, &mech, 0), StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(AsymmetricSignTest, SignInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));
  EXPECT_THAT(SignInit(session, &mech, private_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(AsymmetricSignTest, SignFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  std::vector<uint8_t> hash(GetParam().digest_size);
  CK_ULONG signature_size;
  EXPECT_THAT(Sign(session, hash.data(), hash.size(), nullptr, &signature_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, SignUpdateFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  uint8_t data[32];
  EXPECT_THAT(SignUpdate(session, data, sizeof(data)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, SignFinalFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_ULONG signature_size;
  EXPECT_THAT(SignFinal(session, nullptr, &signature_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, SignFinalFailsWithoutUpdate) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{GetParam().allowedMechanism, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));
  CK_ULONG signature_size = GetParam().signature_size;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(SignFinal(session, signature.data(), &signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("SignUpdate needs to be called")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_P(AsymmetricSignTest, SignSinglePartFailsAfterUpdate) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{GetParam().allowedMechanism, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_ULONG signature_size = GetParam().signature_size;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_OK(SignUpdate(session, data.data(), data.size()));
  EXPECT_THAT(Sign(session, data.data(), data.size(), signature.data(),
                   &signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("Sign cannot be used to terminate")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_P(AsymmetricSignTest, SignFailsNullHash) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));

  CK_ULONG signature_size;
  EXPECT_THAT(Sign(session, nullptr, 0, nullptr, &signature_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  std::vector<uint8_t> hash(GetParam().digest_size),
      sig(GetParam().signature_size);
  // Operation should now be terminated.
  EXPECT_THAT(
      Sign(session, hash.data(), hash.size(), sig.data(), &signature_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, SignUpdateInvalidMechanism) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));
  uint8_t data[32];
  EXPECT_THAT(SignUpdate(session, data, sizeof(data)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("does not support multi-part signing")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_P(AsymmetricSignTest, SignFinalInvalidMechanism) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));
  CK_ULONG signature_size = GetParam().signature_size;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(SignFinal(session, signature.data(), &signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("does not support multi-part signing")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_P(AsymmetricSignTest, VerifyFailsNullSignatureSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(SignInit(session, &mech, private_key));

  uint8_t hash[32];
  EXPECT_THAT(Sign(session, hash, sizeof(hash), nullptr, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));
}

TEST_P(AsymmetricSignTest, VerifyInvalidSignature) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));

  std::vector<uint8_t> hash(GetParam().digest_size),
      sig(GetParam().signature_size);
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_SIGNATURE_INVALID));

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, VerifyHashTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));

  std::vector<uint8_t> hash(GetParam().digest_size - 1),
      sig(GetParam().signature_size);
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_DATA_LEN_RANGE));

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, VerifyHashTooLarge) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));

  std::vector<uint8_t> hash(GetParam().digest_size + 1),
      sig(GetParam().signature_size);
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_DATA_LEN_RANGE));
}

TEST_P(AsymmetricSignTest, VerifySignatureTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));

  std::vector<uint8_t> hash(GetParam().digest_size),
      sig(GetParam().signature_size - 1);
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, VerifySignatureTooLarge) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));

  std::vector<uint8_t> hash(GetParam().digest_size),
      sig(GetParam().signature_size + 1);
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_SIGNATURE_LEN_RANGE));
}

TEST_P(AsymmetricSignTest, VerifyInitFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(VerifyInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_P(AsymmetricSignTest, VerifyInitFailsInvalidKeyHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_THAT(VerifyInit(session, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(AsymmetricSignTest, VerifyInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));
  EXPECT_THAT(VerifyInit(session, &mech, public_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(AsymmetricSignTest, VerifyFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  std::vector<uint8_t> hash(GetParam().digest_size),
      sig(GetParam().signature_size);
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, VerifyUpdateFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  uint8_t data[32];
  EXPECT_THAT(VerifyUpdate(session, data, sizeof(data)),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, VerifyFinalFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  CK_ULONG signature_size = GetParam().signature_size;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(VerifyFinal(session, signature.data(), signature_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, VerifyFinalFailsWithoutUpdate) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{GetParam().allowedMechanism, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));
  CK_ULONG signature_size = GetParam().signature_size;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(VerifyFinal(session, signature.data(), signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("VerifyUpdate needs to be called")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_P(AsymmetricSignTest, VerifySinglePartFailsAfterUpdate) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{GetParam().allowedMechanism, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));
  std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_ULONG signature_size = GetParam().signature_size;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_OK(VerifyUpdate(session, data.data(), data.size()));
  EXPECT_THAT(Verify(session, data.data(), data.size(), signature.data(),
                     signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("Verify cannot be used to terminate")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_P(AsymmetricSignTest, VerifyFailsNullHash) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));

  std::vector<uint8_t> sig(GetParam().signature_size);
  EXPECT_THAT(Verify(session, nullptr, 0, sig.data(), sig.size()),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  std::vector<uint8_t> hash(GetParam().digest_size);
  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, VerifyFailsNullSignature) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));

  std::vector<uint8_t> hash(GetParam().digest_size);
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), nullptr, 0),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  std::vector<uint8_t> sig(GetParam().signature_size);

  // Operation should be terminated after failure
  EXPECT_THAT(Verify(session, hash.data(), hash.size(), sig.data(), sig.size()),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricSignTest, VerifyUpdateInvalidMechanism) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));
  uint8_t data[32];
  EXPECT_THAT(VerifyUpdate(session, data, sizeof(data)),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("does not support multi-part verify")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

TEST_P(AsymmetricSignTest, VerifyFinalInvalidMechanism) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_MECHANISM mech{CKM_ECDSA, nullptr, 0};
  EXPECT_OK(VerifyInit(session, &mech, public_key));
  CK_ULONG signature_size = GetParam().signature_size;
  std::vector<uint8_t> signature(signature_size);
  EXPECT_THAT(VerifyFinal(session, signature.data(), signature_size),
              AllOf(StatusIs(absl::StatusCode::kFailedPrecondition,
                             HasSubstr("does not support multi-part verify")),
                    StatusRvIs(CKR_FUNCTION_FAILED)));
}

}  // namespace
}  // namespace cloud_kms::kmsp11
