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

#include "kmscng/main/bridge.h"

#include <fstream>

#include "absl/cleanup/cleanup.h"
#include "common/kms_v1.h"
#include "common/test/resource_helpers.h"
#include "common/test/test_platform.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmscng/cng_headers.h"
#include "kmscng/object.h"
#include "kmscng/object_loader.h"
#include "kmscng/operation/sign_utils.h"
#include "kmscng/provider.h"
#include "kmscng/test/matchers.h"
#include "kmscng/util/logging.h"
#include "kmscng/util/string_utils.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmscng {
namespace {

// TODO(b/270419822): drop these once crypto_utils has been migrated to common.
using cloud_kms::kmsp11::EcdsaVerifyP1363;
using cloud_kms::kmsp11::ParseX509PublicKeyDer;

using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::internal::CaptureStderr;
using ::testing::internal::GetCapturedStderr;

// TODO(b/277099517): replace default arguments with options struct.
kms_v1::CryptoKeyVersion NewCryptoKeyVersion(
    kms_v1::KeyManagementService::Stub* client,
    kms_v1::CryptoKey::CryptoKeyPurpose purpose =
        kms_v1::CryptoKey::ASYMMETRIC_SIGN,
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm =
        kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
    kms_v1::ProtectionLevel protection_level = kms_v1::ProtectionLevel::HSM) {
  kms_v1::KeyRing kr1;
  kr1 = CreateKeyRingOrDie(client, kTestLocation, RandomId(), kr1);

  kms_v1::CryptoKey ck;
  ck.set_purpose(purpose);
  ck.mutable_version_template()->set_algorithm(algorithm);
  ck.mutable_version_template()->set_protection_level(protection_level);
  ck = CreateCryptoKeyOrDie(client, kr1.name(), "ck", ck, true);

  kms_v1::CryptoKeyVersion ckv;
  ckv = CreateCryptoKeyVersionOrDie(client, ck.name(), ckv);
  ckv = WaitForEnablement(client, ckv);
  return ckv;
}

void SetFakeKmsProviderProperties(Provider* provider, std::string listen_addr) {
  // Set custom properties to hit fake KMS.
  EXPECT_OK(provider->SetProperty(kEndpointAddressProperty, listen_addr));
  EXPECT_OK(provider->SetProperty(kChannelCredentialsProperty, "insecure"));
}

std::string WriteConfigFileWithOneCKV(kms_v1::CryptoKeyVersion* ckv) {
  std::string config_file = std::tmpnam(nullptr);
  std::ofstream(config_file) << absl::StrFormat(R"(
resources:
  - crypto_key_version: "%s"
)",
                                                ckv->name());
  return config_file;
}

TEST(BridgeTest, BridgeVerboseLoggingEnabled) {
  SetEnvVariable(kVerboseLoggingEnvVariable, "1");
  absl::Cleanup c = [] { ClearEnvVariable(kVerboseLoggingEnvVariable); };
  CaptureStderr();

  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(GetCapturedStderr(), Not(IsEmpty()));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, BridgeVerboseLoggingDisabled) {
  CaptureStderr();

  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(GetCapturedStderr(), IsEmpty());

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, OpenProviderSuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, OpenProviderInvalidHandle) {
  EXPECT_THAT(OpenProvider(nullptr, kProviderName.data(), 0),
              StatusSsIs(NTE_INVALID_PARAMETER));
}

TEST(BridgeTest, OpenProviderUnexpectedName) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_THAT(OpenProvider(&provider_handle, MS_KEY_STORAGE_PROVIDER, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));
}

TEST(BridgeTest, OpenProviderInvalidFlag) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_THAT(OpenProvider(&provider_handle, kProviderName.data(),
                           NCRYPT_PERSIST_ONLY_FLAG),
              StatusSsIs(NTE_BAD_FLAGS));
}

TEST(BridgeTest, FreeProviderSuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, GetProviderPropertyGetSizeSuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output_size = 0;
  EXPECT_OK(GetProviderProperty(provider_handle, NCRYPT_IMPL_TYPE_PROPERTY,
                                nullptr, sizeof(DWORD), &output_size, 0));
  EXPECT_EQ(output_size, sizeof(DWORD));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, GetProviderPropertySuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output = 0;
  DWORD output_size = 0;
  EXPECT_OK(GetProviderProperty(provider_handle, NCRYPT_IMPL_TYPE_PROPERTY,
                                reinterpret_cast<uint8_t*>(&output),
                                sizeof(output), &output_size, 0));
  EXPECT_EQ(output_size, sizeof(output));
  EXPECT_EQ(output, NCRYPT_IMPL_HARDWARE_FLAG);

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, GetProviderPropertyInvalidHandle) {
  DWORD output_size;
  EXPECT_THAT(GetProviderProperty(0, NCRYPT_IMPL_TYPE_PROPERTY, nullptr,
                                  sizeof(DWORD), &output_size, 0),
              StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, GetProviderPropertyNameNull) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output_size;
  EXPECT_THAT(GetProviderProperty(provider_handle, nullptr, nullptr,
                                  sizeof(DWORD), &output_size, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, GetProviderPropertyInvalidName) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output_size;
  EXPECT_THAT(GetProviderProperty(provider_handle, NCRYPT_UI_POLICY_PROPERTY,
                                  nullptr, sizeof(DWORD), &output_size, 0),
              StatusSsIs(NTE_NOT_SUPPORTED));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, GetProviderPropertyOutputSizeBufferNull) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(GetProviderProperty(provider_handle, NCRYPT_IMPL_TYPE_PROPERTY,
                                  nullptr, sizeof(DWORD), nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, GetProviderPropertyOutputBufferTooShort) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  uint8_t output;
  DWORD output_size;
  EXPECT_THAT(GetProviderProperty(provider_handle, NCRYPT_IMPL_TYPE_PROPERTY,
                                  &output, 1, &output_size, 0),
              StatusSsIs(NTE_BUFFER_TOO_SMALL));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, GetProviderPropertyInvalidFlag) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output_size = 0;
  EXPECT_THAT(GetProviderProperty(provider_handle, NCRYPT_IMPL_TYPE_PROPERTY,
                                  nullptr, sizeof(DWORD), &output_size,
                                  NCRYPT_PERSIST_ONLY_FLAG),
              StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, SetProviderPropertySuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  std::string input = "insecure";
  EXPECT_OK(SetProviderProperty(
      provider_handle, kChannelCredentialsProperty.data(),
      reinterpret_cast<uint8_t*>(input.data()), input.size(), 0));

  // Check that the provider property has been updated.
  std::string output("0", input.size());
  DWORD output_size = 0;
  EXPECT_OK(GetProviderProperty(provider_handle,
                                kChannelCredentialsProperty.data(),
                                reinterpret_cast<uint8_t*>(output.data()),
                                input.size(), &output_size, 0));
  EXPECT_EQ(output_size, output.size());
  EXPECT_EQ(output, "insecure");

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, SetProviderPropertyInvalidHandle) {
  EXPECT_THAT(SetProviderProperty(0, NCRYPT_IMPL_TYPE_PROPERTY, nullptr,
                                  sizeof(DWORD), 0),
              StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, SetProviderPropertyNameNull) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(
      SetProviderProperty(provider_handle, nullptr, nullptr, sizeof(DWORD), 0),
      StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, SetProviderPropertyInputNull) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(
      SetProviderProperty(provider_handle, NCRYPT_IMPL_TYPE_PROPERTY, nullptr,
                          sizeof(DWORD), NCRYPT_PERSIST_ONLY_FLAG),
      StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, SetProviderPropertyInvalidName) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD input = 1337;
  EXPECT_THAT(
      SetProviderProperty(provider_handle, NCRYPT_UI_POLICY_PROPERTY,
                          reinterpret_cast<uint8_t*>(&input), sizeof(DWORD), 0),
      StatusSsIs(NTE_NOT_SUPPORTED));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, SetProviderPropertyImmutableProperty) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD input = NCRYPT_IMPL_SOFTWARE_FLAG;
  EXPECT_THAT(
      SetProviderProperty(provider_handle, NCRYPT_IMPL_TYPE_PROPERTY,
                          reinterpret_cast<uint8_t*>(&input), sizeof(input), 0),
      StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory and shut down logging.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, SetProviderPropertyInvalidFlag) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD input = NCRYPT_IMPL_SOFTWARE_FLAG;
  EXPECT_THAT(SetProviderProperty(provider_handle, NCRYPT_IMPL_TYPE_PROPERTY,
                                  reinterpret_cast<uint8_t*>(&input),
                                  sizeof(DWORD), NCRYPT_PERSIST_ONLY_FLAG),
              StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, OpenKeySuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();

  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));
  EXPECT_NE(key_handle, 0);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, OpenKeyEc384Success) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();

  kms_v1::CryptoKeyVersion ckv =
      NewCryptoKeyVersion(client.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                          kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384,
                          kms_v1::ProtectionLevel::HSM);

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));
  EXPECT_NE(key_handle, 0);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, OpenKeyRsa4096Success) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();

  kms_v1::CryptoKeyVersion ckv =
      NewCryptoKeyVersion(client.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                          kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256,
                          kms_v1::ProtectionLevel::HSM);

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));
  EXPECT_NE(key_handle, 0);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, OpenKeyInvalidHandle) {
  EXPECT_THAT(OpenKey(0, nullptr, L"some_key_name", 0, 0),
              StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, OpenKeyInvalidOutputHandle) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(OpenKey(provider_handle, nullptr, L"some_key_name", 0, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, OpenKeyInvalidName) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_THAT(OpenKey(provider_handle, &key_handle, nullptr, 0, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, OpenKeyInvalidLegacyKeySpec) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_THAT(OpenKey(provider_handle, &key_handle, L"some_key_name", 0, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, OpenKeyInvalidFlag) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_THAT(OpenKey(provider_handle, &key_handle, L"some_key_name",
                      AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG),
              StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, OpenKeyNotFound) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  std::string invalid_key_name = ckv.name();
  invalid_key_name[invalid_key_name.length() - 1] = '2';
  EXPECT_THAT(
      OpenKey(reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider), &key_handle,
              StringToWide(invalid_key_name).data(), AT_SIGNATURE, 0),
      StatusSsIs(NTE_BAD_KEYSET));
}

TEST(BridgeTest, OpenKeyInvalidAlgorithm) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();

  kms_v1::CryptoKeyVersion ckv =
      NewCryptoKeyVersion(client.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                          kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048,
                          kms_v1::ProtectionLevel::HSM);

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_THAT(
      OpenKey(reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider), &key_handle,
              StringToWide(ckv.name()).data(), AT_SIGNATURE, 0),
      StatusSsIs(NTE_NOT_SUPPORTED));
}

TEST(BridgeTest, OpenKeyInvalidProtectionLevel) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();

  kms_v1::CryptoKeyVersion ckv =
      NewCryptoKeyVersion(client.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                          kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256,
                          kms_v1::ProtectionLevel::SOFTWARE);

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_THAT(
      OpenKey(reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider), &key_handle,
              StringToWide(ckv.name()).data(), AT_SIGNATURE, 0),
      StatusSsIs(NTE_NOT_SUPPORTED));
}

TEST(BridgeTest, FreeKeySuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  NCRYPT_KEY_HANDLE key_handle;
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, FreeKeyInvalidProviderHandle) {
  EXPECT_THAT(FreeKey(0, 0), StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, FreeKeyInvalidKeyHandle) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(FreeKey(provider_handle, 0), StatusSsIs(NTE_INVALID_HANDLE));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, FreeKeyInvalidHandleCombination) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  NCRYPT_KEY_HANDLE key_handle;
  std::wstring key_name = StringToWide(ckv.name());
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    const_cast<PWSTR>(key_name.data()), AT_SIGNATURE, 0));

  // Get new provider handle, unrelated to the key opened previously.
  NCRYPT_PROV_HANDLE other_provider_handle;
  EXPECT_OK(OpenProvider(&other_provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(FreeKey(other_provider_handle, key_handle),
              StatusSsIs(NTE_INVALID_HANDLE));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
  EXPECT_OK(FreeProvider(other_provider_handle));
}

TEST(BridgeTest, ExportKeyGetSizeSuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  DWORD output_size = 0;
  EXPECT_OK(ExportKey(provider_handle, key_handle, 0, BCRYPT_ECCPUBLIC_BLOB,
                      nullptr, nullptr, 0, &output_size, 0));
  EXPECT_EQ(output_size, sizeof(BCRYPT_ECCKEY_BLOB) + 64);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, ExportKeySuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  DWORD output_size = 0;
  // Get output size.
  EXPECT_OK(ExportKey(provider_handle, key_handle, 0, BCRYPT_ECCPUBLIC_BLOB,
                      nullptr, nullptr, 0, &output_size, 0));

  std::vector<uint8_t> output(output_size);
  EXPECT_OK(ExportKey(provider_handle, key_handle, 0, BCRYPT_ECCPUBLIC_BLOB,
                      nullptr, output.data(), output.size(), &output_size, 0));
  EXPECT_EQ(output_size, output.size());
  BCRYPT_ECCKEY_BLOB* header =
      reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(output.data());
  EXPECT_EQ(header->dwMagic, BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
  EXPECT_EQ(header->cbKey, 32);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, ExportKeyRsa4096Success) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv =
      NewCryptoKeyVersion(client.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                          kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256,
                          kms_v1::ProtectionLevel::HSM);

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  DWORD output_size = 0;
  // Get output size.
  EXPECT_OK(ExportKey(provider_handle, key_handle, 0, BCRYPT_RSAPUBLIC_BLOB,
                      nullptr, nullptr, 0, &output_size, 0));

  std::vector<uint8_t> output(output_size);
  EXPECT_OK(ExportKey(provider_handle, key_handle, 0, BCRYPT_RSAPUBLIC_BLOB,
                      nullptr, output.data(), output.size(), &output_size, 0));
  EXPECT_EQ(output_size, output.size());
  BCRYPT_RSAKEY_BLOB* header =
      reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(output.data());
  EXPECT_EQ(header->Magic, BCRYPT_RSAPUBLIC_MAGIC);
  EXPECT_EQ(header->BitLength, 4096L);
  EXPECT_EQ(header->cbPrime1, 0L);
  EXPECT_EQ(header->cbPrime2, 0L);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, ExportKeyInvalidProviderHandle) {
  EXPECT_THAT(ExportKey(0, 0, 0, nullptr, nullptr, nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, ExportKeyInvalidKeyHandle) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(ExportKey(provider_handle, 0, 0, nullptr, nullptr, nullptr, 0,
                        nullptr, 0),
              StatusSsIs(NTE_INVALID_HANDLE));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, ExportKeyUnsupportedExportKeyHandle) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  EXPECT_THAT(ExportKey(provider_handle, key_handle, 1337, nullptr, nullptr,
                        nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, ExportKeyInvalidBlobType) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  EXPECT_THAT(ExportKey(provider_handle, key_handle, 0, BCRYPT_PRIVATE_KEY_BLOB,
                        nullptr, nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_BAD_TYPE));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, ExportKeyOutputBufferNull) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  EXPECT_THAT(ExportKey(provider_handle, key_handle, 0, BCRYPT_ECCPUBLIC_BLOB,
                        nullptr, nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, ExportKeyInvalidFlag) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  DWORD output_size;
  EXPECT_THAT(
      ExportKey(provider_handle, key_handle, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr,
                nullptr, 0, &output_size, NCRYPT_PERSIST_ONLY_FLAG),
      StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, ExportKeyOutputBufferTooShort) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  uint8_t output;
  DWORD output_size;
  EXPECT_THAT(
      ExportKey(provider_handle, key_handle, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr,
                &output, 1, &output_size, NCRYPT_PERSIST_ONLY_FLAG),
      StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, GetKeyPropertyGetSizeSuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  DWORD output_size = 0;
  EXPECT_OK(GetKeyProperty(provider_handle, key_handle,
                           NCRYPT_KEY_USAGE_PROPERTY, nullptr, sizeof(DWORD),
                           &output_size, 0));
  EXPECT_EQ(output_size, sizeof(DWORD));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, GetKeyDwordPropertySuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  DWORD output = 0;
  DWORD output_size = 0;
  EXPECT_OK(GetKeyProperty(
      provider_handle, key_handle, NCRYPT_KEY_USAGE_PROPERTY,
      reinterpret_cast<uint8_t*>(&output), sizeof(output), &output_size, 0));
  EXPECT_EQ(output_size, sizeof(output));
  EXPECT_EQ(output, NCRYPT_ALLOW_SIGNING_FLAG);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, GetKeyWstringPropertySuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  DWORD output_size = 0;
  // Get property size.
  EXPECT_OK(GetKeyProperty(provider_handle, key_handle,
                           NCRYPT_ALGORITHM_PROPERTY, nullptr, 0, &output_size,
                           0));

  std::vector<uint8_t> output(output_size);
  EXPECT_OK(GetKeyProperty(provider_handle, key_handle,
                           NCRYPT_ALGORITHM_PROPERTY,
                           reinterpret_cast<uint8_t*>(output.data()),
                           output.size(), &output_size, 0));
  EXPECT_EQ(output_size, output.size());
  EXPECT_EQ(std::wstring_view(reinterpret_cast<wchar_t*>(output.data())),
            BCRYPT_ECDSA_P256_ALGORITHM);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, GetKeyPropertyInvalidProviderHandle) {
  EXPECT_THAT(GetKeyProperty(0, 0, nullptr, nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, GetKeyPropertyInvalidKeyHandle) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(
      GetKeyProperty(provider_handle, 0, nullptr, nullptr, 0, nullptr, 0),
      StatusSsIs(NTE_INVALID_HANDLE));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, GetKeyPropertyNameNull) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  EXPECT_THAT(GetKeyProperty(provider_handle, key_handle, nullptr, nullptr, 0,
                             nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, GetKeyPropertyOutputBufferNull) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  EXPECT_THAT(GetKeyProperty(provider_handle, key_handle,
                             NCRYPT_KEY_USAGE_PROPERTY, nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, GetKeyPropertyInvalidFlag) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  uint8_t output;
  DWORD output_size;
  EXPECT_THAT(GetKeyProperty(provider_handle, key_handle,
                             NCRYPT_KEY_USAGE_PROPERTY, &output, sizeof(DWORD),
                             &output_size, NCRYPT_PERSIST_ONLY_FLAG),
              StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, GetKeyPropertyInvalidName) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  uint8_t output;
  DWORD output_size;
  EXPECT_THAT(
      GetKeyProperty(provider_handle, key_handle, NCRYPT_UI_POLICY_PROPERTY,
                     &output, sizeof(DWORD), &output_size, 0),
      StatusSsIs(NTE_NOT_SUPPORTED));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, GetKeyPropertyOutputBufferTooShort) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  uint8_t output;
  DWORD output_size;
  EXPECT_THAT(
      GetKeyProperty(provider_handle, key_handle, NCRYPT_KEY_USAGE_PROPERTY,
                     &output, 1, &output_size, 0),
      StatusSsIs(NTE_BUFFER_TOO_SMALL));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, SignHashGetSignatureSizeSuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  std::vector<uint8_t> digest(32, '\1');
  DWORD output_size = 0;
  EXPECT_OK(SignHash(provider_handle, key_handle, nullptr, digest.data(),
                     digest.size(), nullptr, 0, &output_size, 0));
  EXPECT_EQ(output_size, 64);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, EnumKeysSuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();

  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());
  std::string config_file = WriteConfigFileWithOneCKV(&ckv);
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);

  NCryptKeyName* output;
  PVOID enum_state = nullptr;
  EXPECT_OK(
      EnumKeys(provider_handle, nullptr, &output, &enum_state, 0, config_file));

  auto enum_result = reinterpret_cast<EnumState*>(enum_state);
  EXPECT_EQ(enum_result->current, 1);
  EXPECT_EQ(std::wstring(output->pszName), StringToWide(ckv.name()).data());
  EXPECT_EQ(std::wstring(output->pszAlgid), BCRYPT_ECDSA_P256_ALGORITHM);
  EXPECT_EQ(output->dwLegacyKeySpec, AT_SIGNATURE);
  EXPECT_EQ(output->dwFlags, NCRYPT_MACHINE_KEY_FLAG);

  // Clean up memory.
  EXPECT_OK(FreeBuffer(output));
  EXPECT_OK(FreeBuffer(enum_state));
}

TEST(BridgeTest, EnumMultipleKeysSuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();

  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());
  std::string config_file = WriteConfigFileWithOneCKV(&ckv);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "  - crypto_key_version: \"" << ckv.name() << "\"" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);

  NCryptKeyName* output;
  PVOID enum_state = nullptr;
  EXPECT_OK(
      EnumKeys(provider_handle, nullptr, &output, &enum_state, 0, config_file));
  EXPECT_OK(
      EnumKeys(provider_handle, nullptr, &output, &enum_state, 0, config_file));

  auto enum_result = reinterpret_cast<EnumState*>(enum_state);
  EXPECT_EQ(enum_result->current, 2);
  EXPECT_EQ(std::wstring(output->pszName), StringToWide(ckv.name()).data());
  EXPECT_EQ(std::wstring(output->pszAlgid), BCRYPT_ECDSA_P256_ALGORITHM);
  EXPECT_EQ(output->dwLegacyKeySpec, AT_SIGNATURE);
  EXPECT_EQ(output->dwFlags, NCRYPT_MACHINE_KEY_FLAG);

  // Clean up memory.
  EXPECT_OK(FreeBuffer(output));
  EXPECT_OK(FreeBuffer(enum_state));
}

TEST(BridgeTest, EnumAllKeysNoMoreItems) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();

  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());
  std::string config_file = WriteConfigFileWithOneCKV(&ckv);
  std::ofstream(config_file, std::ofstream::out | std::ofstream::app)
      << "  - crypto_key_version: \"" << ckv.name() << "\"" << std::endl;
  absl::Cleanup config_close = [config_file] {
    std::remove(config_file.c_str());
  };

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);

  NCryptKeyName* output;
  PVOID enum_state = nullptr;
  EXPECT_OK(
      EnumKeys(provider_handle, nullptr, &output, &enum_state, 0, config_file));
  EXPECT_OK(
      EnumKeys(provider_handle, nullptr, &output, &enum_state, 0, config_file));
  EXPECT_THAT(
      EnumKeys(provider_handle, nullptr, &output, &enum_state, 0, config_file),
      StatusSsIs(NTE_NO_MORE_ITEMS));

  // Clean up memory.
  EXPECT_OK(FreeBuffer(output));
  EXPECT_OK(FreeBuffer(enum_state));
}

TEST(BridgeTest, EnumKeysInvalidHandle) {
  EXPECT_THAT(EnumKeys(0, nullptr, nullptr, nullptr, 0),
              StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, EnumKeysInvalidPszScope) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(
      EnumKeys(provider_handle, kProviderName.data(), nullptr, nullptr, 0),
      StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, EnumKeysOutputBufferNull) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(EnumKeys(provider_handle, nullptr, nullptr, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, EnumKeysInvalidOutputEnumState) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  NCryptKeyName* output;
  EnumState invalid_enum_state = {
      .key_details = std::vector<HeapAllocatedKeyDetails>(),
      .current = 7337,
  };
  EnumState* enum_ptr = &invalid_enum_state;
  EXPECT_THAT(EnumKeys(provider_handle, nullptr, &output,
                       reinterpret_cast<PVOID*>(&enum_ptr), 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, EnumKeysInvalidFlag) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  NCryptKeyName* output;
  EXPECT_THAT(EnumKeys(provider_handle, nullptr, &output, nullptr,
                       NCRYPT_PERSIST_ONLY_FLAG),
              StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, SignHashSuccess) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  std::vector<uint8_t> digest(32, '\1');
  std::vector<uint8_t> signature(64);
  DWORD output_size = 0;
  EXPECT_OK(SignHash(provider_handle, key_handle, nullptr, digest.data(),
                     digest.size(), signature.data(), signature.size(),
                     &output_size, 0));

  ASSERT_OK_AND_ASSIGN(Object * object,
                       ValidateKeyHandle(provider_handle, key_handle));
  EXPECT_OK(EcdsaVerifyP1363(
      object->ec_public_key(), EVP_sha256(),
      absl::MakeConstSpan(digest.data(), digest.size()),
      absl::MakeConstSpan(signature.data(), signature.size())));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, SignHashEc384Success) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv =
      NewCryptoKeyVersion(client.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                          kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384,
                          kms_v1::ProtectionLevel::HSM);

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  std::vector<uint8_t> digest(48, '\1');
  std::vector<uint8_t> signature(96);
  DWORD output_size = 0;
  EXPECT_OK(SignHash(provider_handle, key_handle, nullptr, digest.data(),
                     digest.size(), signature.data(), signature.size(),
                     &output_size, 0));

  ASSERT_OK_AND_ASSIGN(Object * object,
                       ValidateKeyHandle(provider_handle, key_handle));
  EXPECT_OK(EcdsaVerifyP1363(
      object->ec_public_key(), EVP_sha384(),
      absl::MakeConstSpan(digest.data(), digest.size()),
      absl::MakeConstSpan(signature.data(), signature.size())));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, SignHashRsa4096Success) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv =
      NewCryptoKeyVersion(client.get(), kms_v1::CryptoKey::ASYMMETRIC_SIGN,
                          kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256,
                          kms_v1::ProtectionLevel::HSM);

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  std::vector<uint8_t> digest(32, '\1');
  std::vector<uint8_t> signature(512);  // sig is 4096 bits -> 512 bytes
  DWORD output_size = 0;
  EXPECT_OK(SignHash(provider_handle, key_handle, nullptr, digest.data(),
                     digest.size(), signature.data(), signature.size(),
                     &output_size, 0));

  ASSERT_OK_AND_ASSIGN(Object * object,
                       ValidateKeyHandle(provider_handle, key_handle));

  EXPECT_EQ(
      RSA_verify(NID_sha256, digest.data(), digest.size(), signature.data(),
                 signature.size(), object->rsa_public_key()),
      1);

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, SignHashInvalidProviderHandle) {
  EXPECT_THAT(SignHash(0, 0, nullptr, nullptr, 0, nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, SignHashInvalidKeyHandle) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(
      SignHash(provider_handle, 0, nullptr, nullptr, 0, nullptr, 0, nullptr, 0),
      StatusSsIs(NTE_INVALID_HANDLE));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, SignHashPaddingInfoNotNull) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  DWORD padding_info = 1337;
  EXPECT_THAT(SignHash(provider_handle, key_handle, &padding_info, nullptr, 0,
                       nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, SignHashInputDigestNull) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  EXPECT_THAT(SignHash(provider_handle, key_handle, nullptr, nullptr, 0,
                       nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, SignHashOutputLengthBufferNull) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  std::vector<uint8_t> digest(32, '\1');
  EXPECT_THAT(SignHash(provider_handle, key_handle, nullptr, digest.data(),
                       digest.size(), nullptr, 0, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, SignHashInvalidFlag) {
  ASSERT_OK_AND_ASSIGN(auto fake_server, fakekms::Server::New());
  auto client = fake_server->NewClient();
  kms_v1::CryptoKeyVersion ckv = NewCryptoKeyVersion(client.get());

  Provider provider;
  SetFakeKmsProviderProperties(&provider, fake_server->listen_addr());

  NCRYPT_KEY_HANDLE key_handle;
  NCRYPT_PROV_HANDLE provider_handle =
      reinterpret_cast<NCRYPT_PROV_HANDLE>(&provider);
  EXPECT_OK(OpenKey(provider_handle, &key_handle,
                    StringToWide(ckv.name()).data(), AT_SIGNATURE, 0));

  uint8_t output;
  DWORD output_size;
  std::vector<uint8_t> digest(32, '\1');
  EXPECT_THAT(SignHash(provider_handle, key_handle, nullptr, digest.data(),
                       digest.size(), &output, 0, &output_size,
                       NCRYPT_PERSIST_ONLY_FLAG),
              StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeKey(provider_handle, key_handle));
}

TEST(BridgeTest, IsAlgSupportedSuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_OK(IsAlgSupported(provider_handle, BCRYPT_ECDSA_P256_ALGORITHM, 0));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, IsAlgSupportedInvalidHandle) {
  EXPECT_THAT(IsAlgSupported(0, nullptr, 0), StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, IsAlgSupportedNameNull) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output_size;
  EXPECT_THAT(IsAlgSupported(provider_handle, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, IsAlgSupportedInvalidFlag) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output_size = 0;
  EXPECT_THAT(IsAlgSupported(provider_handle, BCRYPT_ECDSA_P256_ALGORITHM,
                             NCRYPT_PERSIST_ONLY_FLAG),
              StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, IsAlgSupportedAlgorithmUnsupported) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output_size = 0;
  EXPECT_THAT(IsAlgSupported(provider_handle, BCRYPT_MD5_ALGORITHM, 0),
              StatusSsIs(NTE_NOT_SUPPORTED));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, EnumAlgorithmsSuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  NCryptAlgorithmName alg_array[kAlgorithmNames.size()];
  NCryptAlgorithmName* alg = alg_array;
  DWORD output_size = 0;
  EXPECT_OK(EnumAlgorithms(provider_handle, NCRYPT_SIGNATURE_OPERATION,
                           &output_size, &alg, 0));
  EXPECT_EQ(output_size, kAlgorithmNames.size());
  for (int i = 0; i < output_size; i++) {
    EXPECT_STREQ(alg[i].pszName, kAlgorithmNames[i].pszName);
    EXPECT_EQ(alg[i].dwClass, kAlgorithmNames[i].dwClass);
    EXPECT_EQ(alg[i].dwAlgOperations, kAlgorithmNames[i].dwAlgOperations);
    EXPECT_EQ(alg[i].dwFlags, kAlgorithmNames[i].dwFlags);
  }

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
  EXPECT_OK(FreeBuffer(alg));
}

TEST(BridgeTest, EnumAlgorithmsInvalidHandle) {
  EXPECT_THAT(EnumAlgorithms(0, 0, nullptr, nullptr, 0),
              StatusSsIs(NTE_INVALID_HANDLE));
}

TEST(BridgeTest, EnumAlgorithmsInvalidAlgOperation) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(EnumAlgorithms(provider_handle, NCRYPT_SECRET_AGREEMENT_OPERATION,
                             nullptr, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, EnumAlgorithmsOutputSizeBufferNull) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  EXPECT_THAT(EnumAlgorithms(provider_handle, NCRYPT_SIGNATURE_OPERATION,
                             nullptr, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, EnumAlgorithmsOutputBufferNull) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output_size = 0;
  EXPECT_THAT(EnumAlgorithms(provider_handle, NCRYPT_SIGNATURE_OPERATION,
                             &output_size, nullptr, 0),
              StatusSsIs(NTE_INVALID_PARAMETER));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, EnumAlgorithmsInvalidFlag) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  DWORD output_size = 0;
  NCryptAlgorithmName alg;
  NCryptAlgorithmName* alg_pointer;
  EXPECT_THAT(
      EnumAlgorithms(provider_handle, NCRYPT_SIGNATURE_OPERATION, &output_size,
                     &alg_pointer, NCRYPT_PERSIST_ONLY_FLAG),
      StatusSsIs(NTE_BAD_FLAGS));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, FreeBufferSuccess) {
  NCRYPT_PROV_HANDLE provider_handle;
  EXPECT_OK(OpenProvider(&provider_handle, kProviderName.data(), 0));

  NCryptAlgorithmName alg;
  NCryptAlgorithmName* alg_pointer = &alg;
  DWORD output_size = 0;
  EXPECT_OK(EnumAlgorithms(provider_handle, NCRYPT_SIGNATURE_OPERATION,
                           &output_size, &alg_pointer, 0));

  EXPECT_OK(FreeBuffer(alg_pointer));

  // Clean up memory.
  EXPECT_OK(FreeProvider(provider_handle));
}

TEST(BridgeTest, FreeBufferInvalidBuffer) {
  EXPECT_THAT(FreeBuffer(nullptr), StatusSsIs(NTE_INVALID_PARAMETER));
}

}  // namespace
}  // namespace cloud_kms::kmscng
