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

#include "absl/strings/escaping.h"
#include "absl/time/clock.h"
#include "common/status_macros.h"
#include "kmsp11/algorithm_details.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

// For OpenSSL sequence functions that take an `int location`, -1 means add to
// the end of the sequence.
constexpr int kLocationEnd = -1;

absl::Status SetRandomSerial(X509* x509) {
  // Conforming implementations must be able to handle serials up to 20 bytes in
  // length. https://tools.ietf.org/html/rfc5280#section-4.1.2.2
  constexpr size_t kSerialByteLength = 20;

  std::string serial_bytes = RandBytes(kSerialByteLength);

  // Ensure that the serial number is a positive integer, and that the DER
  // encoding will not exceed 20 bytes.
  //
  // Verbose explanation:
  // - the leftmost bit of the serial is interpreted as the sign bit
  // - DER requires non-negative integers
  // - 0x7F is 01111111
  // - so we force a "0" as the leftmost bit with a bitwise AND operation
  serial_bytes[0] &= 0x7F;

  bssl::UniquePtr<BIGNUM> serial(
      BN_bin2bn(reinterpret_cast<const uint8_t*>(serial_bytes.data()),
                serial_bytes.size(), nullptr));
  if (!BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(x509))) {
    return NewInternalError(
        absl::StrCat("error setting serial: ", SslErrorToString()),
        SOURCE_LOCATION);
  }
  return absl::OkStatus();
}

// Adds the extension identified by nid with the specified value to the
// list of extensions in the X509 ctx.
absl::Status AddExtension(X509V3_CTX* ctx, X509* cert, int nid,
                          const char* value) {
  bssl::UniquePtr<X509_EXTENSION> ext(X509V3_EXT_nconf_nid(
      /* conf */ nullptr, ctx, nid, const_cast<char*>(value)));
  if (!ext || X509_add_ext(cert, ext.get(), kLocationEnd) != 1) {
    return NewInternalError(absl::StrFormat("error adding extension %d: %s",
                                            nid, SslErrorToString()),
                            SOURCE_LOCATION);
  }
  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<std::unique_ptr<CertAuthority>> CertAuthority::New() {
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));

  // Generate a new P-256 key for certificate signing.
  EVP_PKEY* signing_key = nullptr;
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) !=
          1 ||
      EVP_PKEY_keygen(ctx.get(), &signing_key) != 1 || !signing_key) {
    return NewInternalError(
        absl::StrCat("error generating signing key: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  return std::unique_ptr<CertAuthority>(
      new CertAuthority(bssl::UniquePtr<EVP_PKEY>(signing_key)));
}

CertAuthority::CertAuthority(bssl::UniquePtr<EVP_PKEY> signing_key)
    : signing_key_(std::move(signing_key)),
      issuer_cn_(
          // add randomness to the CN to ensure clients don't hardcode
          absl::StrFormat("cloud-kms-pkcs11-%s",
                          absl::BytesToHexString(RandBytes(4)))) {}

absl::StatusOr<bssl::UniquePtr<X509>> CertAuthority::GenerateCert(
    const kms_v1::CryptoKeyVersion& ckv, EVP_PKEY* public_key) const {
  bssl::UniquePtr<X509> cert(X509_new());

  // Set certificate version = 0x02 (x509 v3)
  if (X509_set_version(cert.get(), 2) != 1) {
    return NewInternalError(
        absl::StrCat("error setting version: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  RETURN_IF_ERROR(SetRandomSerial(cert.get()));

  X509_NAME* issuer = X509_get_issuer_name(cert.get());
  if (X509_NAME_add_entry_by_NID(
          issuer, NID_commonName, MBSTRING_ASC,
          reinterpret_cast<uint8_t*>(const_cast<char*>(issuer_cn_.data())),
          issuer_cn_.size(), kLocationEnd, 0) != 1) {
    return NewInternalError(
        absl::StrCat("error setting issuer: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  // This will start failing in 2038 on platforms that use 32-bit time_t.
  // Hopefully we have a better library for dealing with ASN.1 times by then.
  ASN1_TIME_set(X509_get_notBefore(cert.get()), absl::ToTimeT(absl::Now()));

  // No well-defined expiration date, per
  // https://tools.ietf.org/html/rfc5280#section-4.1.2.5
  if (ASN1_TIME_set_string(X509_get_notAfter(cert.get()), "99991231235959Z") !=
      1) {
    return NewInternalError(
        absl::StrCat("error setting notAfter: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(std::string subject_cn, ExtractKeyId(ckv.name()));
  X509_NAME* subj = X509_get_subject_name(cert.get());
  if (X509_NAME_add_entry_by_NID(
          subj, NID_commonName, MBSTRING_ASC,
          reinterpret_cast<uint8_t*>(const_cast<char*>(subject_cn.data())),
          subject_cn.size(), kLocationEnd, 0) != 1) {
    return NewInternalError(
        absl::StrCat("error setting subject: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  if (X509_set_pubkey(cert.get(), public_key) != 1) {
    return NewInternalError(
        absl::StrCat("error setting public key: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  X509V3_CTX ctx;
  X509V3_set_ctx(&ctx, nullptr, cert.get(), nullptr, nullptr, 0);

  bssl::UniquePtr<CONF> ext_conf(NCONF_new(nullptr));
  X509V3_set_nconf(&ctx, ext_conf.get());

  RETURN_IF_ERROR(AddExtension(&ctx, cert.get(), NID_basic_constraints,
                               "critical,CA:false"));
  RETURN_IF_ERROR(AddExtension(
      &ctx, cert.get(), NID_certificate_policies,
      // any policy, from https://tools.ietf.org/html/rfc5280#section-4.2.1.4
      "2.5.29.32.0"));
  RETURN_IF_ERROR(
      AddExtension(&ctx, cert.get(), NID_subject_key_identifier, "hash"));

  // We don't add authority key identifier, which is a fairly standard
  // extension. It's complicated here because we don't actually generate a
  // self-signed CA cert for the signing key (maybe we should?).

  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));
  switch (algorithm.purpose) {
    case kms_v1::CryptoKey::ASYMMETRIC_SIGN:
      RETURN_IF_ERROR(AddExtension(&ctx, cert.get(), NID_key_usage,
                                   "critical,digitalSignature"));
      break;
    case kms_v1::CryptoKey::ASYMMETRIC_DECRYPT:
      RETURN_IF_ERROR(
          AddExtension(&ctx, cert.get(), NID_key_usage,
                       "critical,keyEncipherment,dataEncipherment"));
      break;
    default:
      return NewInternalError(
          absl::StrFormat("unexpected key purpose: %d", algorithm.purpose),
          SOURCE_LOCATION);
  }

  if (!X509_sign(cert.get(), signing_key_.get(), EVP_sha256())) {
    return NewInternalError(
        absl::StrCat("error signing certificate: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  return std::move(cert);
}

}  // namespace cloud_kms::kmsp11
