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

#include "kmsp11/cert_authority.h"

#include "absl/time/clock.h"
#include "common/test/runfiles.h"
#include "common/test/test_status_macros.h"
#include "gmock/gmock.h"
#include "kmsp11/test/matchers.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

using ::testing::AnyOf;

class CertAuthorityTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(authority_, CertAuthority::New());

    ckv_.set_name(
        "projects/foo/locations/global/keyRings/bar/cryptoKeys/baz/"
        "cryptoKeyVersions/1");
    ckv_.set_algorithm(kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256);

    ASSERT_OK_AND_ASSIGN(std::string test_key,
                         LoadTestRunfile("ec_p256_private.pem"));
    ASSERT_OK_AND_ASSIGN(test_key_, ParsePkcs8PrivateKeyPem(test_key));
  }

  std::unique_ptr<CertAuthority> authority_;
  kms_v1::CryptoKeyVersion ckv_;
  bssl::UniquePtr<EVP_PKEY> test_key_;
};

TEST_F(CertAuthorityTest, CertMatchesPrivateKey) {
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<X509> cert,
                       authority_->GenerateCert(ckv_, test_key_.get()));

  EXPECT_EQ(X509_check_private_key(cert.get(), test_key_.get()), 1);
}

TEST_F(CertAuthorityTest, CertSelfVerifies) {
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<X509> cert,
                       authority_->GenerateCert(ckv_, test_key_.get()));

  bssl::UniquePtr<X509_STORE> store(X509_STORE_new());
  EXPECT_EQ(X509_STORE_add_cert(store.get(), cert.get()), 1);

  bssl::UniquePtr<X509_STORE_CTX> store_ctx(X509_STORE_CTX_new());
  EXPECT_EQ(
      X509_STORE_CTX_init(store_ctx.get(), store.get(), cert.get(), nullptr),
      1);
  X509_STORE_CTX_set_flags(store_ctx.get(), X509_V_FLAG_PARTIAL_CHAIN);

  EXPECT_EQ(X509_verify_cert(store_ctx.get()), 1);
}

TEST_F(CertAuthorityTest, CertVersionIs2) {
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<X509> cert,
                       authority_->GenerateCert(ckv_, test_key_.get()));
  // https://tools.ietf.org/html/rfc5280#section-4.1.2.1
  EXPECT_EQ(X509_get_version(cert.get()), 0x02);
}

TEST_F(CertAuthorityTest, CertSerialIsPositiveAndAtMost20Bytes) {
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<X509> cert,
                       authority_->GenerateCert(ckv_, test_key_.get()));
  // https://tools.ietf.org/html/rfc5280#section-4.1.2.2
  // At most 20 bytes long, because if the randomly generated serial number has
  // leading zeros, it will be represented with less than 20 bytes.
  // It should never be negative though, per DER encoding rules.
  bssl::UniquePtr<BIGNUM> serial_bn(
      ASN1_INTEGER_to_BN(X509_get_serialNumber(cert.get()), nullptr));
  EXPECT_FALSE(BN_is_negative(serial_bn.get()));
  EXPECT_LE(BN_num_bytes(serial_bn.get()), 20);
}

TEST_F(CertAuthorityTest, StartDateBeforeNow) {
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<X509> cert,
                       authority_->GenerateCert(ckv_, test_key_.get()));

  EXPECT_THAT(ASN1_UTCTIME_cmp_time_t(X509_get0_notBefore(cert.get()),
                                      absl::ToTimeT(absl::Now())),
              // The cert may have been generated in the same second as now,
              // or it could be before. Note that -2 indicates an error, so
              // Le(0) is not sufficient.
              AnyOf(-1, 0));
}

TEST_F(CertAuthorityTest, EndDateMatchesRFC) {
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<X509> cert,
                       authority_->GenerateCert(ckv_, test_key_.get()));

  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  EXPECT_EQ(ASN1_TIME_print(bio.get(), X509_get0_notAfter(cert.get())), 1);

  char* buf;
  size_t len = BIO_get_mem_data(bio.get(), &buf);

  // Format Mmm DD HH:MM:SS YYYY [GMT] is specified at
  // https://www.openssl.org/docs/manmaster/man3/ASN1_TIME_adj.html
  EXPECT_EQ(std::string_view(buf, len), "Dec 31 23:59:59 9999 GMT");
}

TEST_F(CertAuthorityTest, SubjectCnEqualsKeyId) {
  ASSERT_OK_AND_ASSIGN(std::string expected_cn, ExtractKeyId(ckv_.name()));
  ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<X509> cert,
                       authority_->GenerateCert(ckv_, test_key_.get()));

  std::string actual_cn(expected_cn.size(), ' ');
  EXPECT_EQ(
      X509_NAME_get_text_by_NID(
          X509_get_subject_name(cert.get()), NID_commonName, actual_cn.data(),
          actual_cn.size() + 1 /* account for trailing NUL */),
      expected_cn.size());

  EXPECT_EQ(expected_cn, actual_cn);
}

}  // namespace
}  // namespace cloud_kms::kmsp11
