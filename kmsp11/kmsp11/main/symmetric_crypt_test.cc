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

class SymmetricCryptBaseTest
    : public testing::Test,
      public testing::WithParamInterface<
          kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm> {};

class SymmetricCbcCryptTest : public SymmetricCryptBaseTest {};

class SymmetricCtrCryptTest : public SymmetricCryptBaseTest {};

class SymmetricGcmCryptTest : public SymmetricCryptBaseTest {};

const std::array kCbcAlgorithms = {kms_v1::CryptoKeyVersion::AES_128_CBC,
                                   kms_v1::CryptoKeyVersion::AES_256_CBC};

const std::array kCtrAlgorithms = {kms_v1::CryptoKeyVersion::AES_128_CTR,
                                   kms_v1::CryptoKeyVersion::AES_256_CTR};

const std::array kGcmAlgorithms = {kms_v1::CryptoKeyVersion::AES_128_GCM,
                                   kms_v1::CryptoKeyVersion::AES_256_GCM};

INSTANTIATE_TEST_SUITE_P(TestSymmetricEncryption, SymmetricCbcCryptTest,
                         testing::ValuesIn(kCbcAlgorithms));

INSTANTIATE_TEST_SUITE_P(TestSymmetricEncryption, SymmetricCtrCryptTest,
                         testing::ValuesIn(kCtrAlgorithms));

INSTANTIATE_TEST_SUITE_P(TestSymmetricEncryption, SymmetricGcmCryptTest,
                         testing::ValuesIn(kGcmAlgorithms));

// Initializes a KMS KeyRing, a key in this KeyRing and a crypto key version
// with the specified algorithm. Creates a configuration file with this keyring
// as a token that also enables raw encryption keys. Returns the configuration
// file, the created key, and a session for the created KeyRing.
absl::StatusOr<std::string> InitializeAsymmetricCryptTest(
    fakekms::Server* fake_server,
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    kms_v1::CryptoKeyVersion* ckv, CK_SESSION_HANDLE* session) {
  kms_v1::KeyRing kr;
  std::string config_file = CreateConfigFileWithOneKeyring(fake_server, &kr);

  auto init_args = InitArgs(config_file.c_str());

  *ckv = InitializeCryptoKeyAndKeyVersion(
      fake_server, kr, kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT, algorithm);

  RETURN_IF_ERROR(Initialize(&init_args));
  RETURN_IF_ERROR(
      OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, session));
  return config_file;
}

std::vector<uint8_t> EncryptPlaintext(CK_SESSION_HANDLE session,
                                      CK_MECHANISM mech,
                                      CK_OBJECT_HANDLE secret_key,
                                      std::vector<uint8_t> plaintext,
                                      int expected_ciphertext_size) {
  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  CK_ULONG ciphertext_size = expected_ciphertext_size;
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                    &ciphertext_size));
  EXPECT_EQ(ciphertext_size, expected_ciphertext_size);

  std::vector<uint8_t> ciphertext(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, expected_ciphertext_size);

  // Operation should be terminated after success
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
  return ciphertext;
}

std::vector<uint8_t> EncryptMultipart(CK_SESSION_HANDLE session,
                                      CK_MECHANISM mech,
                                      CK_OBJECT_HANDLE secret_key,
                                      std::vector<uint8_t> part1,
                                      std::vector<uint8_t> part2,
                                      CK_ULONG expected_ciphertext_size) {
  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  CK_ULONG partial_ciphertext_size = 0;
  std::vector<uint8_t> ciphertext(expected_ciphertext_size);

  EXPECT_OK(EncryptUpdate(session, part1.data(), part1.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  EXPECT_OK(EncryptUpdate(session, part2.data(), part2.size(),
                          ciphertext.data(), &partial_ciphertext_size));
  EXPECT_EQ(partial_ciphertext_size, 0);

  CK_ULONG ciphertext_size = expected_ciphertext_size;
  EXPECT_OK(EncryptFinal(session, ciphertext.data(), &ciphertext_size));
  EXPECT_EQ(ciphertext_size, expected_ciphertext_size);

  // Operation should be terminated after success
  EXPECT_THAT(
      Encrypt(session, part1.data(), part1.size(), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
  return ciphertext;
}

// Decrypts a given ciphertext and returns the recovered plaintext.
// Takes as input a pointer to the expected recovered plaintext size and updates
// it with the number of bytes in the recovered plaintext.
std::vector<uint8_t> DecryptCiphertext(CK_SESSION_HANDLE session,
                                       CK_MECHANISM mech,
                                       CK_OBJECT_HANDLE secret_key,
                                       std::vector<uint8_t> ciphertext,
                                       CK_ULONG_PTR recovered_plaintext_size) {
  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG plaintext_size = *recovered_plaintext_size;
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                    &plaintext_size));
  EXPECT_EQ(plaintext_size, *recovered_plaintext_size);

  std::vector<uint8_t> recovered_plaintext(plaintext_size);
  EXPECT_OK(Decrypt(session, ciphertext.data(), ciphertext.size(),
                    recovered_plaintext.data(), recovered_plaintext_size));

  // Operation should be terminated after success
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
  return recovered_plaintext;
}

// Decrypts a given ciphertext in two parts and returns the recovered plaintext.
// Takes as input a pointer to the expected recovered plaintext size and updates
// it with the number of bytes in the recovered plaintext.
std::vector<uint8_t> DecryptMultipart(CK_SESSION_HANDLE session,
                                      CK_MECHANISM mech,
                                      CK_OBJECT_HANDLE secret_key,
                                      std::vector<uint8_t> ciphertext,
                                      CK_ULONG_PTR recovered_plaintext_size) {
  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG partial_plaintext_size = 0;
  std::vector<uint8_t> recovered_plaintext(*recovered_plaintext_size);
  EXPECT_OK(DecryptUpdate(session, ciphertext.data(), 16,
                          recovered_plaintext.data(), &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptUpdate(session, ciphertext.data() + 16,
                          ciphertext.size() - 16, recovered_plaintext.data(),
                          &partial_plaintext_size));
  EXPECT_EQ(partial_plaintext_size, 0);

  EXPECT_OK(DecryptFinal(session, recovered_plaintext.data(),
                         recovered_plaintext_size));

  return recovered_plaintext;
}

TEST_P(SymmetricCbcCryptTest, EncryptDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());
  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_MECHANISM mech = {
      CKM_AES_CBC,  // mechanism
      iv.data(),    // pParameter
      iv.size(),    // ulParameterLen
  };

  std::vector<uint8_t> ciphertext =
      EncryptPlaintext(session, mech, secret_key, plaintext, plaintext.size());

  CK_ULONG recovered_plaintext_size = plaintext.size();
  std::vector<uint8_t> recovered_plaintext = DecryptCiphertext(
      session, mech, secret_key, ciphertext, &recovered_plaintext_size);
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(recovered_plaintext_size, plaintext.size());
}

TEST_P(SymmetricCbcCryptTest, EncryptDecryptMultiPartSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_MECHANISM mech = {
      CKM_AES_CBC_PAD,  // mechanism
      iv.data(),        // pParameter
      iv.size(),        // ulParameterLen
  };

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 144;  // 128 + 16 (full padding block)
  std::vector<uint8_t> ciphertext = EncryptMultipart(
      session, mech, secret_key, part1, part2, ciphertext_size);

  CK_ULONG recovered_plaintext_size = plaintext.size();
  std::vector<uint8_t> recovered_plaintext = DecryptMultipart(
      session, mech, secret_key, ciphertext, &recovered_plaintext_size);
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(recovered_plaintext_size, plaintext.size());
}

TEST_P(SymmetricCtrCryptTest, EncryptDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());
  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_AES_CTR_PARAMS params;
  params.ulCounterBits = 128;
  memcpy(params.cb, iv.data(), sizeof(params.cb));

  CK_MECHANISM mech = {
      CKM_AES_CTR,     // mechanism
      &params,         // pParameter
      sizeof(params),  // ulParameterLen
  };

  std::vector<uint8_t> ciphertext =
      EncryptPlaintext(session, mech, secret_key, plaintext, plaintext.size());

  CK_ULONG recovered_plaintext_size = plaintext.size();
  std::vector<uint8_t> recovered_plaintext = DecryptCiphertext(
      session, mech, secret_key, ciphertext, &recovered_plaintext_size);
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(recovered_plaintext_size, plaintext.size());
}

TEST_P(SymmetricCtrCryptTest, EncryptDecryptMultiPartSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(16);
  RAND_bytes(iv.data(), iv.size());

  CK_AES_CTR_PARAMS params;
  params.ulCounterBits = 128;
  memcpy(params.cb, iv.data(), sizeof(params.cb));

  CK_MECHANISM mech = {
      CKM_AES_CTR,     // mechanism
      &params,         // pParameter
      sizeof(params),  // ulParameterLen
  };

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 128;
  std::vector<uint8_t> ciphertext = EncryptMultipart(
      session, mech, secret_key, part1, part2, ciphertext_size);

  CK_ULONG recovered_plaintext_size = plaintext.size();
  std::vector<uint8_t> recovered_plaintext = DecryptMultipart(
      session, mech, secret_key, ciphertext, &recovered_plaintext_size);
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(recovered_plaintext_size, plaintext.size());
}

TEST_P(SymmetricGcmCryptTest, EncryptDecryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  std::vector<uint8_t> ciphertext = EncryptPlaintext(
      session, mech, secret_key, plaintext, plaintext.size() + 16);

  CK_ULONG recovered_plaintext_size = plaintext.size();
  std::vector<uint8_t> recovered_plaintext = DecryptCiphertext(
      session, mech, secret_key, ciphertext, &recovered_plaintext_size);
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(recovered_plaintext_size, plaintext.size());
}

TEST_P(SymmetricGcmCryptTest, EncryptDecryptMultiPartSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 144;
  std::vector<uint8_t> ciphertext = EncryptMultipart(
      session, mech, secret_key, part1, part2, ciphertext_size);

  CK_ULONG recovered_plaintext_size = plaintext.size();
  std::vector<uint8_t> recovered_plaintext = DecryptMultipart(
      session, mech, secret_key, ciphertext, &recovered_plaintext_size);
  EXPECT_EQ(recovered_plaintext, plaintext);
  EXPECT_EQ(recovered_plaintext_size, plaintext.size());
}

TEST_P(SymmetricGcmCryptTest, DecryptBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  std::vector<uint8_t> ciphertext = EncryptPlaintext(
      session, mech, secret_key, plaintext, plaintext.size() + 16);

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  std::vector<uint8_t> recovered_plaintext(32);
  CK_ULONG plaintext_size = recovered_plaintext.size();
  EXPECT_THAT(Decrypt(session, ciphertext.data(), ciphertext.size(),
                      recovered_plaintext.data(), &plaintext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));

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

TEST_P(SymmetricGcmCryptTest, DecryptInitFailsInvalidSessionHandle) {
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

TEST_P(SymmetricGcmCryptTest, DecryptInitFailsInvalidKeyHandle) {
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

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_THAT(DecryptInit(session, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, DecryptInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(DecryptInit(session, &mech, secret_key));
  EXPECT_THAT(DecryptInit(session, &mech, secret_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(SymmetricGcmCryptTest, DecryptFailsOperationNotInitialized) {
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

  uint8_t ciphertext[256];
  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptFailsNullCiphertext) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  CK_ULONG plaintext_size;
  EXPECT_THAT(Decrypt(session, nullptr, 0, nullptr, &plaintext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t ciphertext[256];
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, DecryptFailsNullPlaintextSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(DecryptInit(session, &mech, secret_key));

  uint8_t ciphertext[256];
  EXPECT_THAT(
      Decrypt(session, ciphertext, sizeof(ciphertext), nullptr, nullptr),
      StatusRvIs(CKR_ARGUMENTS_BAD));

  CK_ULONG plaintext_size;
  // Operation should now be terminated.
  EXPECT_THAT(Decrypt(session, ciphertext, sizeof(ciphertext), nullptr,
                      &plaintext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> ciphertext = EncryptPlaintext(
      session, mech, secret_key, plaintext, plaintext.size() + 16);

  EXPECT_NE(ciphertext.size(), 0);
  EXPECT_NE(ciphertext, plaintext);
}

TEST_P(SymmetricGcmCryptTest, EncryptMultiPartSuccess) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  std::vector<uint8_t> part1(64);
  std::vector<uint8_t> part2(64);
  RAND_bytes(part1.data(), part1.size());
  RAND_bytes(part2.data(), part2.size());
  std::vector<uint8_t> plaintext(part1);
  plaintext.insert(plaintext.end(), part2.begin(), part2.end());

  CK_ULONG ciphertext_size = 144;
  std::vector<uint8_t> ciphertext = EncryptMultipart(
      session, mech, secret_key, part1, part2, ciphertext_size);

  EXPECT_NE(ciphertext.size(), 0);
  EXPECT_NE(ciphertext, plaintext);
}

TEST_P(SymmetricGcmCryptTest, EncryptBufferTooSmall) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  std::vector<uint8_t> plaintext(128);
  RAND_bytes(plaintext.data(), plaintext.size());

  std::vector<uint8_t> ciphertext(143);
  CK_ULONG ciphertext_size = ciphertext.size();
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(),
                      ciphertext.data(), &ciphertext_size),
              StatusRvIs(CKR_BUFFER_TOO_SMALL));
  EXPECT_EQ(ciphertext_size, 144);

  // Operation should be able to proceed after CKR_BUFFER_TOO_SMALL.
  ciphertext.resize(ciphertext_size);
  EXPECT_OK(Encrypt(session, plaintext.data(), plaintext.size(),
                    ciphertext.data(), &ciphertext_size));

  // Operation should now be terminated.
  EXPECT_THAT(Encrypt(session, plaintext.data(), plaintext.size(), nullptr,
                      &ciphertext_size),
              StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptInitFailsInvalidSessionHandle) {
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

TEST_P(SymmetricGcmCryptTest, EncryptInitFailsInvalidKeyHandle) {
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

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_THAT(EncryptInit(session, &mech, 0),
              StatusRvIs(CKR_KEY_HANDLE_INVALID));
}

TEST_P(SymmetricGcmCryptTest, EncryptInitFailsOperationActive) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session, &mech, secret_key));
  EXPECT_THAT(EncryptInit(session, &mech, secret_key),
              StatusRvIs(CKR_OPERATION_ACTIVE));
}

TEST_P(SymmetricGcmCryptTest, EncryptFailsOperationNotInitialized) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  uint8_t plaintext[32];
  CK_ULONG ciphertext_size;
  EXPECT_THAT(
      Encrypt(session, plaintext, sizeof(plaintext), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptFailsNullPLaintext) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

  CK_ULONG ciphertext_size;
  EXPECT_THAT(Encrypt(session, nullptr, 0, nullptr, &ciphertext_size),
              StatusRvIs(CKR_ARGUMENTS_BAD));

  uint8_t plaintext[32];
  // Operation should now be terminated.
  EXPECT_THAT(
      Encrypt(session, plaintext, sizeof(plaintext), nullptr, &ciphertext_size),
      StatusRvIs(CKR_OPERATION_NOT_INITIALIZED));
}

TEST_P(SymmetricGcmCryptTest, EncryptFailsNullCiphertextSize) {
  ASSERT_OK_AND_ASSIGN(std::unique_ptr<fakekms::Server> fake_server,
                       fakekms::Server::New());
  kms_v1::CryptoKeyVersion ckv;
  CK_SESSION_HANDLE session;
  ASSERT_OK_AND_ASSIGN(std::string config_file,
                       InitializeAsymmetricCryptTest(
                           fake_server.get(), GetParam(), &ckv, &session));
  absl::Cleanup c = [config_file] {
    std::remove(config_file.c_str());
    EXPECT_OK(Finalize(nullptr));
  };

  ASSERT_OK_AND_ASSIGN(CK_OBJECT_HANDLE secret_key,
                       GetSecretKeyObjectHandle(session, ckv));

  std::vector<uint8_t> iv(12);
  std::vector<uint8_t> aad = {0xDE, 0xAD, 0xBE, 0xEF};
  CK_GCM_PARAMS params = {
      iv.data(),                                   // pIv
      12,                                          // ulIvLen
      96,                                          // ulIvBits
      aad.data(),                                  // pAAD
      static_cast<unsigned long int>(aad.size()),  // ulAADLen
      128,                                         // ulTagBits
  };
  CK_MECHANISM mech = {
      CKM_CLOUDKMS_AES_GCM,  // mechanism
      &params,               // pParameter
      sizeof(params),        // ulParameterLen
  };

  EXPECT_OK(EncryptInit(session, &mech, secret_key));

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
