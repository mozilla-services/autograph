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
  int ciphertext_size;
  const EVP_MD* evpHashAlg;
  CK_RSA_PKCS_MGF_TYPE mgfAlg;
  CK_MECHANISM_TYPE hashAlg;
};

class AsymmetricCryptTest : public testing::Test,
                            public testing::WithParamInterface<AlgorithmInfo> {
};

const std::array kAsymmetricCryptAlgorithms = {
    AlgorithmInfo{kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256, 256,
                  EVP_sha256(), CKG_MGF1_SHA256, CKM_SHA256},
    AlgorithmInfo{kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_3072_SHA256, 384,
                  EVP_sha256(), CKG_MGF1_SHA256, CKM_SHA256},
    AlgorithmInfo{kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA256, 512,
                  EVP_sha256(), CKG_MGF1_SHA256, CKM_SHA256},
    AlgorithmInfo{kms_v1::CryptoKeyVersion::RSA_DECRYPT_OAEP_4096_SHA512, 512,
                  EVP_sha512(), CKG_MGF1_SHA512, CKM_SHA512},
};

INSTANTIATE_TEST_SUITE_P(TestAsymmetricEncryption, AsymmetricCryptTest,
                         testing::ValuesIn(kAsymmetricCryptAlgorithms));

// Sets up a kms key and initializes bridge for this key. Then,
// it creates a random plaintext and encrypts it using the generated key.
// Returns the name of the configuration file used by bridge, the crypto key
// version, the generated plaintext and the generated ciphertext.
absl::StatusOr<std::string> InitializeBridgePlaintextAndCiphertext(
    fakekms::Server* fake_server,
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    kms_v1::CryptoKeyVersion* ckv, const EVP_MD* evpHashAlg,
    std::vector<uint8_t>* plaintext, std::vector<uint8_t>* ciphertext) {
  ASSIGN_OR_RETURN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(
          fake_server, kms_v1::CryptoKey::ASYMMETRIC_DECRYPT, algorithm, ckv));

  RAND_bytes((*plaintext).data(), (*plaintext).size());
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> pub_pkey,
                   GetEVPPublicKey(fake_server, *ckv));
  RETURN_IF_ERROR(EncryptRsaOaep(pub_pkey.get(), evpHashAlg, *plaintext,
                                 absl::MakeSpan(*ciphertext)));
  return config_file;
}

TEST_P(AsymmetricCryptTest, DecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());

  kms_v1::CryptoKeyVersion ckv;
  std::vector<uint8_t> plaintext(128);
  std::vector<uint8_t> ciphertext(GetParam().ciphertext_size);
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgePlaintextAndCiphertext(
                           fake_server.get(), GetParam().algorithm, &ckv,
                           GetParam().evpHashAlg, &plaintext, &ciphertext));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
  EXPECT_OK(DecryptInit(session, &mech, private_key));

  CK_ULONG plaintext_size;
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricCryptTest, DecryptSuccessSameBuffer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  std::vector<uint8_t> plaintext(128);
  std::vector<uint8_t> buf(GetParam().ciphertext_size);
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgePlaintextAndCiphertext(
                           fake_server.get(), GetParam().algorithm, &ckv,
                           GetParam().evpHashAlg, &plaintext, &buf));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
  EXPECT_OK(DecryptInit(session, &mech, private_key));

  CK_ULONG plaintext_size = buf.size();
  EXPECT_OK(
      Decrypt(session, buf.data(), buf.size(), buf.data(), &plaintext_size));
  EXPECT_EQ(plaintext_size, plaintext.size());

  buf.resize(plaintext_size);
  EXPECT_EQ(buf, plaintext);
}

TEST_P(AsymmetricCryptTest, DecryptBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  std::vector<uint8_t> plaintext(128);
  std::vector<uint8_t> ciphertext(GetParam().ciphertext_size);
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgePlaintextAndCiphertext(
                           fake_server.get(), GetParam().algorithm, &ckv,
                           GetParam().evpHashAlg, &plaintext, &ciphertext));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};
  EXPECT_OK(DecryptInit(session, &mech, private_key));

  std::vector<uint8_t> recovered_plaintext(32);
  CK_ULONG plaintext_size = recovered_plaintext.size();
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(),
                      recovered_plaintext.data(), &plaintext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(plaintext_size, plaintext.size());

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  recovered_plaintext.resize(plaintext_size);
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), &plaintext_size));
  EXPECT_EQ(plaintext, recovered_plaintext);

  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricCryptTest, DecryptParametersMismatch) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA384, CKG_MGF1_SHA384,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(DecryptInit(session, &mech, private_key),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_P(AsymmetricCryptTest, DecryptInitFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(DecryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_P(AsymmetricCryptTest, DecryptInitFailsInvalidKeyHandle) {
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

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(DecryptInit(session, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(AsymmetricCryptTest, DecryptInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session, &mech, private_key));
  EXPECT_THAT(DecryptInit(session, &mech, private_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(AsymmetricCryptTest, DecryptFailsOperationNotInitialized) {
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

  std::vector<uint8_t> ciphertext(GetParam().ciphertext_size);
  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricCryptTest, DecryptFailsNullCiphertext) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session, &mech, private_key));

  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session, nullptr, 0, nullptr, &plaintext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  std::vector<uint8_t> ciphertext(GetParam().ciphertext_size);
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricCryptTest, DecryptFailsNullPlaintextSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(DecryptInit(session, &mech, private_key));

  std::vector<uint8_t> ciphertext(GetParam().ciphertext_size);
  EXPECT_THAT(
      Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr, nullptr),
      StatusRvIs(CKR_ARGUMENTS_BAD));

  CK_ULONG plaintext_size;
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricCryptTest, EncryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  CK_ULONG ciphertext_size;
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, GetParam().ciphertext_size);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricCryptTest, EncryptSuccessSameBuffer) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE private_key,
                       GetPrivateKeyObjectHandle(session, ckv));
  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> buf(GetParam().ciphertext_size);
  std::copy(plaintext.begin(), plaintext.end(), buf.data());

  CK_ULONG ciphertext_size = buf.size();
  EXPECT_OK(Encrypt(session, buf.data(), 128, buf.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, GetParam().ciphertext_size);

  EXPECT_OK(DecryptInit(session, &mech, private_key));

  std::vector<uint8_t> recovered_plaintext(128);
  CK_ULONG recovered_plaintext_size = recovered_plaintext.size();
  EXPECT_OK(Decrypt(session, buf.data(), buf.size(), recovered_plaintext.data(),
                    &recovered_plaintext_size));

  EXPECT_EQ(recovered_plaintext, plaintext);
}

TEST_P(AsymmetricCryptTest, EncryptBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> ciphertext(GetParam().ciphertext_size - 1);
  CK_ULONG ciphertext_size = ciphertext.size();
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(),
                      ciphertext.data(), &ciphertext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(ciphertext_size, GetParam().ciphertext_size);

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  ciphertext.resize(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricCryptTest, EncryptParametersMismatch) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{CKM_SHA384, CKG_MGF1_SHA384,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(EncryptInit(session, &mech, public_key),
              StatusRvIs(CKR_MECHANISM_PARAM_INVALID));
}

TEST_P(AsymmetricCryptTest, EncryptInitFailsInvalidSessionHandle) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeBridgeForOneKmsKeyRing(fake_server.get()));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  EXPECT_THAT(EncryptInit(0, nullptr, 0),
              StatusRvIs(CKR_SESSION_HANDLE_INVALID));
}

TEST_P(AsymmetricCryptTest, EncryptInitFailsInvalidKeyHandle) {
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

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_THAT(EncryptInit(session, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(AsymmetricCryptTest, EncryptInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));
  EXPECT_THAT(EncryptInit(session, &mech, public_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(AsymmetricCryptTest, EncryptFailsOperationNotInitialized) {
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

  uint8_t plaintext[32];
  CK_ULONG ciphertext_size;
  EXPECT_THAT(
      Encrypt(session, plaintext, sizeof(plaintext), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricCryptTest, EncryptFailsNullPLaintext) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session, nullptr, 0, nullptr, &ciphertext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t plaintext[32];
  // Operation should now be terminated.
  EXPECT_THAT(
      Encrypt(session, plaintext, sizeof(plaintext), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(AsymmetricCryptTest, EncryptFailsNullCiphertextSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  ASSERT_OK_AND_ASSIGN(
      std::string config_file,
      InitializeBridgeForOneKmsKey(fake_server.get(),
                                   kms_v1::CryptoKey::ASYMMETRIC_DECRYPT,
                                   GetParam().algorithm, &ckv));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  CK_SESSION_HANDLE session;
  EXPECT_OK(OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &session));

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE public_key,
                       GetPublicKeyObjectHandle(session, ckv));

  CK_RSA_PKCS_OAEP_PARAMS params{GetParam().hashAlg, GetParam().mgfAlg,
                                 CKZ_DATA_SPECIFIED, nullptr, 0};
  CK_MECHANISM mech{CKM_RSA_PKCS_OAEP, &params, sizeof(params)};

  EXPECT_OK(EncryptInit(session, &mech, public_key));

  uint8_t plaintext[32];
  EXPECT_THAT(Encrypt(session, plaintext, sizeof(plaintext), nullptr, nullptr),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  CK_ULONG ciphertext_size;
  // Operation should now be terminated.
  EXPECT_THAT(
      Encrypt(session, plaintext, sizeof(plaintext), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

}  // namespace
}  // namespace cloud_kms::kmsp11
