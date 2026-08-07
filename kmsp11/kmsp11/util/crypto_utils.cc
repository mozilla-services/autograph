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

#include "kmsp11/util/crypto_utils.h"

#include <limits>

#include "absl/random/random.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "common/status_macros.h"
#include "glog/logging.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {
namespace {

static const ASN1_TIME kUnixEpoch = [] {
  ASN1_TIME time;
  ASN1_TIME_set(&time, absl::ToTimeT(absl::UnixEpoch()));
  return time;
}();

// A helper for invoking an OpenSSL function of the form i2d_FOO, and returning
// the DER output as a string.
template <typename T>
absl::StatusOr<std::string> MarshalDer(T* obj,
                                       int i2d_function(T*, uint8_t**)) {
  size_t len = i2d_function(obj, nullptr);
  if (len <= 0) {
    return NewInternalError(
        absl::StrCat("failed to compute output length during DER marshaling: ",
                     SslErrorToString()),
        SOURCE_LOCATION);
  }

  std::string result(len, ' ');
  uint8_t* result_data = reinterpret_cast<uint8_t*>(result.data());

  len = i2d_function(obj, &result_data);
  if (len != result.size()) {
    return NewInternalError(
        absl::StrFormat(
            "length mismatch during DER marshaling (got %d, want %d)", len,
            result.size()),
        SOURCE_LOCATION);
  }

  return result;
}

// A helper for invoking an OpenSSL function of the form i2d_FOO, and returning
// the DER output as a string.
template <typename T>
absl::StatusOr<std::string> MarshalDer(const T* obj,
                                       int i2d_function(const T*, uint8_t**)) {
  size_t len = i2d_function(obj, nullptr);
  if (len <= 0) {
    return NewInternalError(
        absl::StrCat("failed to compute output length during DER marshaling: ",
                     SslErrorToString()),
        SOURCE_LOCATION);
  }

  std::string result(len, ' ');
  uint8_t* result_data = reinterpret_cast<uint8_t*>(result.data());

  len = i2d_function(obj, &result_data);
  if (len != result.size()) {
    return NewInternalError(
        absl::StrFormat(
            "length mismatch during DER marshaling (got %d, want %d)", len,
            result.size()),
        SOURCE_LOCATION);
  }

  return result;
}

// A helper for invoking an OpenSSL function of the form d2i_FOO, and returning
// the deserialized object.
template <typename T>
absl::StatusOr<bssl::UniquePtr<T>> ParseDer(
    std::string_view der_string, T* d2i_function(T**, const uint8_t**, long)) {
  const uint8_t* der_bytes =
      reinterpret_cast<const uint8_t*>(der_string.data());

  bssl::UniquePtr<T> result(
      d2i_function(nullptr, &der_bytes, der_string.size()));
  if (!result) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing DER: ", SslErrorToString()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }
  return std::move(result);
}

// A UniformRandomBitGenerator backed by Boring's CSPRNG.
// https://en.cppreference.com/w/cpp/named_req/UniformRandomBitGenerator
class BoringBitGenerator {
 public:
  using result_type = uint64_t;

  static constexpr uint64_t min() {
    return std::numeric_limits<uint64_t>::min();
  }

  static constexpr uint64_t max() {
    return std::numeric_limits<uint64_t>::max();
  }

  uint64_t operator()() {
    uint64_t result;
    RAND_bytes(reinterpret_cast<uint8_t*>(&result), sizeof(result));
    return result;
  }
};

}  // namespace

absl::StatusOr<absl::Time> Asn1TimeToAbsl(const ASN1_TIME* time) {
  int diff_days, diff_secs;
  if (ASN1_TIME_diff(&diff_days, &diff_secs, &kUnixEpoch, time) != 1) {
    return NewInternalError(
        absl::StrCat("error processing ASN1_TIME: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  absl::CivilDay day = absl::CivilDay() + diff_days;
  absl::CivilSecond second = absl::CivilSecond(day) + diff_secs;

  return absl::FromCivil(second, absl::UTCTimeZone());
}

absl::Status BignumToBinary(const BIGNUM* src, absl::Span<uint8_t> dest) {
  size_t unpadded_length(BN_num_bytes(src));
  if (dest.size() < unpadded_length) {
    return NewError(
        absl::StatusCode::kOutOfRange,
        absl::StrFormat(
            "output data length is %d bytes; buffer length is %d bytes",
            unpadded_length, dest.size()),
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }
  size_t pad_size = dest.size() - unpadded_length;

  int bytes_written = BN_bn2bin(src, &dest[pad_size]);
  if (bytes_written != int(unpadded_length)) {
    return NewInternalError(
        absl::StrFormat("expected to write %d bytes but wrote %d",
                        bytes_written, unpadded_length),
        SOURCE_LOCATION);
  }
  std::memset(dest.data(), 0, pad_size);
  return absl::OkStatus();
}

absl::Status CheckFipsSelfTest() {
  if (FIPS_mode() != 1) {
    return absl::FailedPreconditionError(
        absl::StrFormat("FIPS_mode()=%d, want 1", FIPS_mode()));
  }

#ifdef OPENSSL_IS_BORINGSSL  // BORINGSSL_self_test is of course BoringSSL-only.
  int self_test_result = BORINGSSL_self_test();
  if (self_test_result != 1) {
    return absl::InternalError(
        absl::StrFormat("BORINGSSL_self_test()=%d, want 1", self_test_result));
  }
#endif
  return absl::OkStatus();
}

absl::StatusOr<const EVP_MD*> DigestForMechanism(CK_MECHANISM_TYPE mechanism) {
  switch (mechanism) {
    case CKM_SHA256:
    case CKM_ECDSA_SHA256:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
      return EVP_sha256();
    case CKM_SHA384:
    case CKM_ECDSA_SHA384:
      return EVP_sha384();
    case CKM_SHA512:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
      return EVP_sha512();
    default:
      return NewInternalError(
          absl::StrFormat("invalid digest mechanism: %#x", mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::vector<uint8_t>> EcdsaSigAsn1ToP1363(
    std::string_view asn1_sig, const EC_GROUP* group) {
  const uint8_t* sig_data = reinterpret_cast<const uint8_t*>(asn1_sig.data());
  bssl::UniquePtr<ECDSA_SIG> sig(
      d2i_ECDSA_SIG(nullptr, &sig_data, asn1_sig.size()));
  if (!sig) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing asn.1 signature: ", SslErrorToString()),
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  int sig_len = EcdsaSigLengthP1363(group);
  int n_len = sig_len / 2;
  const BIGNUM *r, *s;
  ECDSA_SIG_get0(sig.get(), &r, &s);

  std::vector<uint8_t> result(sig_len);
  RETURN_IF_ERROR(BignumToBinary(r, absl::Span<uint8_t>(&result[0], n_len)));
  RETURN_IF_ERROR(
      BignumToBinary(s, absl::Span<uint8_t>(&result[n_len], n_len)));

  return result;
}

int EcdsaSigLengthP1363(const EC_GROUP* group) {
  // We can move to EC_GROUP_get0_order if/when we no longer need to
  // support OpenSSL 1.0.2.
  bssl::UniquePtr<BIGNUM> bn(BN_new());
  CHECK_EQ(EC_GROUP_get_order(group, bn.get(), nullptr), 1);
  return 2 * BN_num_bytes(bn.get());
}

absl::Status EcdsaVerifyP1363(EC_KEY* public_key, const EVP_MD* hash,
                              absl::Span<const uint8_t> digest,
                              absl::Span<const uint8_t> signature) {
  if (digest.length() != EVP_MD_size(hash)) {
    return NewInvalidArgumentError(
        absl::StrFormat("digest length mismatches expected (got %d, want %d)",
                        digest.length(), EVP_MD_size(hash)),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.length() % 2 == 1) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "signature of length %d contains an uneven number of bytes",
            signature.length()),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  size_t max_len = EcdsaSigLengthP1363(EC_KEY_get0_group(public_key));
  if (signature.length() > max_len) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "provided signature length exceeds maximum (got %d, want <= %d)",
            signature.length(), max_len),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
  int n_len = signature.length() / 2;

  bssl::UniquePtr<BIGNUM> r(BN_new());
  bssl::UniquePtr<BIGNUM> s(BN_new());
  if (!BN_bin2bn(&signature[0], n_len, r.get()) ||
      !BN_bin2bn(&signature[n_len], n_len, s.get()) ||
      !ECDSA_SIG_set0(sig.get(), r.release(), s.release())) {
    return NewInternalError(
        absl::StrCat("error parsing signature component: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  if (ECDSA_do_verify(digest.data(), digest.size(), sig.get(), public_key) !=
      1) {
    return NewInvalidArgumentError(
        absl::StrCat("verification failed: ", SslErrorToString()),
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::Status EncryptRsaOaep(EVP_PKEY* key, const EVP_MD* hash,
                            absl::Span<const uint8_t> plaintext,
                            absl::Span<uint8_t> ciphertext) {
  if (!key) {
    return NewInvalidArgumentError("missing required argument: key",
                                   CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }
  if (!hash) {
    return NewInvalidArgumentError("missing required argument: hash",
                                   CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  const RSA* rsa_key = EVP_PKEY_get0_RSA(key);
  if (!rsa_key) {
    return NewInvalidArgumentError(
        absl::StrFormat("unexpected key type %d provided to EncryptRsaOaep",
                        EVP_PKEY_id(key)),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  size_t modulus_size = RSA_size(rsa_key);
  if (ciphertext.size() != modulus_size) {
    return NewInvalidArgumentError(
        absl::StrFormat("unexpected ciphertext size (got %d, want %d)",
                        ciphertext.size(), modulus_size),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  // Size limit from https://tools.ietf.org/html/rfc8017#section-7.1.1
  size_t max_plaintext_size = modulus_size - (2 * EVP_MD_size(hash)) - 2;
  if (plaintext.size() > max_plaintext_size) {
    return NewInvalidArgumentError(
        absl::StrFormat("plaintext size %d exceeds maximum %d",
                        plaintext.size(), max_plaintext_size),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(key, nullptr));

  if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) != 1 ||
      EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) != 1 ||
      EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), hash) != 1 ||
      EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), hash) != 1) {
    return NewInternalError(
        absl::StrCat("error building encryption context: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  size_t out_len = ciphertext.size();
  if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &out_len, plaintext.data(),
                       plaintext.size()) != 1) {
    return NewInternalError(
        absl::StrCat("failed to encrypt: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  if (out_len != modulus_size) {
    std::fill(ciphertext.begin(), ciphertext.end(), 0);
    return NewInternalError(
        absl::StrFormat(
            "actual encrypted length mismatches expected (got %d, expected %d)",
            out_len, modulus_size),
        SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::StatusOr<std::string> MarshalAsn1Integer(ASN1_INTEGER* value) {
  return MarshalDer(value, &i2d_ASN1_INTEGER);
}

absl::StatusOr<std::string> MarshalEcParametersDer(BSSL_CONST EC_KEY* key) {
  int curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
  if (curve_nid == 0) {
    return NewInternalError("could not determine curve NID", SOURCE_LOCATION);
  }
  // const_cast is needed for the older FIPS-mode BoringSSL.
  // See discussion on this requirement being relaxed in
  // https://boringssl-review.googlesource.com/c/boringssl/+/46164
  return MarshalDer(const_cast<ASN1_OBJECT*>(OBJ_nid2obj(curve_nid)),
                    &i2d_ASN1_OBJECT);
}

absl::StatusOr<std::string> MarshalEcPointToAsn1OctetStringDer(
    BSSL_CONST EC_KEY* key) {
  ASSIGN_OR_RETURN(std::string ec_point_der, MarshalDer(key, &i2o_ECPublicKey));
  bssl::UniquePtr<ASN1_OCTET_STRING> octet_string(ASN1_OCTET_STRING_new());
  if (!octet_string || ASN1_OCTET_STRING_set(octet_string.get(),
                                             reinterpret_cast<const uint8_t*>(
                                                 ec_point_der.data()),
                                             ec_point_der.size()) != 1) {
    return NewInternalError(
        absl::StrCat("error creating ASN.1 octet string from EC Point DER: ",
                     SslErrorToString()),
        SOURCE_LOCATION);
  }
  return MarshalDer(octet_string.get(), &i2d_ASN1_OCTET_STRING);
}

absl::StatusOr<std::string> MarshalX509CertificateDer(X509* cert) {
  return MarshalDer(cert, &i2d_X509);
}

absl::StatusOr<std::string> MarshalX509Name(X509_NAME* value) {
  return MarshalDer(value, &i2d_X509_NAME);
}

absl::StatusOr<std::string> MarshalX509PublicKeyDer(BSSL_CONST EVP_PKEY* key) {
  return MarshalDer(key, &i2d_PUBKEY);
}

absl::StatusOr<std::string> MarshalX509Sig(X509_SIG* value) {
  return MarshalDer(value, &i2d_X509_SIG);
}

absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> ParsePkcs8PrivateKeyPem(
    std::string_view private_key_pem) {
  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(private_key_pem.data(), private_key_pem.size()));
  if (!bio) {
    return NewInternalError(
        absl::StrCat("error allocating bio: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  bssl::UniquePtr<EVP_PKEY> result(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!result) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing private key: ", SslErrorToString()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  return std::move(result);
}

absl::StatusOr<bssl::UniquePtr<X509>> ParseX509CertificateDer(
    std::string_view certificate_der) {
  return ParseDer(certificate_der, &d2i_X509);
}

absl::StatusOr<bssl::UniquePtr<X509>> ParseX509CertificatePem(
    std::string_view certificate_pem) {
  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(certificate_pem.data(), certificate_pem.size()));
  if (!bio) {
    return NewInternalError(
        absl::StrCat("error allocating bio: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  bssl::UniquePtr<X509> result(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  if (!result) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing certificate: ", SslErrorToString()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }
  return std::move(result);
}

absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyDer(
    std::string_view public_key_der) {
  return ParseDer(public_key_der, &d2i_PUBKEY);
}

absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyPem(
    std::string_view public_key_pem) {
  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(public_key_pem.data(), public_key_pem.size()));
  if (!bio) {
    return NewInternalError(
        absl::StrCat("error allocating bio: ", SslErrorToString()),
        SOURCE_LOCATION);
  }

  bssl::UniquePtr<EVP_PKEY> result(
      PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  if (!result) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing public key: ", SslErrorToString()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }
  return std::move(result);
}

std::string RandBytes(size_t len) {
  std::string result;
  result.resize(len);
  RAND_bytes(reinterpret_cast<uint8_t*>(result.data()), len);
  return result;
}

CK_ULONG RandomHandle() {
  static absl::Mutex bit_generator_mutex;
  static BoringBitGenerator bit_generator ABSL_GUARDED_BY(bit_generator_mutex);

  absl::MutexLock lock(&bit_generator_mutex);
  return absl::Uniform<CK_ULONG>(bit_generator, 1,
                                 std::numeric_limits<CK_ULONG>::max());
}

absl::Status RsaVerifyPkcs1(RSA* public_key, const EVP_MD* hash,
                            absl::Span<const uint8_t> digest,
                            absl::Span<const uint8_t> signature) {
  if (digest.length() != EVP_MD_size(hash)) {
    return NewInvalidArgumentError(
        absl::StrFormat("digest length mismatches expected (got %d, want %d)",
                        digest.length(), EVP_MD_size(hash)),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.length() != RSA_size(public_key)) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "signature length mismatches expected (got %d, want %d)",
            signature.length(), RSA_size(public_key)),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  if (RSA_verify(EVP_MD_type(hash), digest.data(), digest.size(),
                 signature.data(), signature.size(), public_key) != 1) {
    return NewInvalidArgumentError(
        absl::StrCat("verification failed: ", SslErrorToString()),
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::Status RsaVerifyPss(EVP_PKEY* public_key, const EVP_MD* hash,
                          absl::Span<const uint8_t> digest,
                          absl::Span<const uint8_t> signature) {
  if (digest.length() != EVP_MD_size(hash)) {
    return NewInvalidArgumentError(
        absl::StrFormat("digest length mismatches expected (got %d, want %d)",
                        digest.length(), EVP_MD_size(hash)),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  int rsa_size = RSA_size(EVP_PKEY_get0_RSA(public_key));
  if (int(signature.length()) != rsa_size) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "signature length mismatches expected (got %d, want %d)",
            signature.length(), rsa_size),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(public_key, nullptr));
  if (!ctx || EVP_PKEY_verify_init(ctx.get()) != 1 ||
      EVP_PKEY_CTX_set_signature_md(ctx.get(), hash) != 1 ||
      EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_PSS_PADDING) != 1 ||
      EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), hash) != 1 ||
      EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.get(), -1) != 1) {
    return NewInternalError(
        absl::StrCat("error building verification context: ",
                     SslErrorToString()),
        SOURCE_LOCATION);
  }

  if (EVP_PKEY_verify(ctx.get(), signature.data(), signature.size(),
                      digest.data(), digest.size()) != 1) {
    return NewInvalidArgumentError(
        absl::StrCat("verification failed: ", SslErrorToString()),
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::Status RsaVerifyRawPkcs1(RSA* public_key, absl::Span<const uint8_t> data,
                               absl::Span<const uint8_t> signature) {
  constexpr size_t kMinRsaKeyBitLength = 2048;
  if (RSA_bits(public_key) < kMinRsaKeyBitLength) {
    return NewInternalError(
        absl::StrFormat("minimum RSA key size is %d bits (got %d)",
                        kMinRsaKeyBitLength, RSA_bits(public_key)),
        SOURCE_LOCATION);
  }

  constexpr size_t kPkcs1OverheadBytes = 11;  // per RFC 3447 section 9.2
  size_t max_data_bytes = RSA_size(public_key) - kPkcs1OverheadBytes;
  if (data.length() > max_data_bytes) {
    return NewInvalidArgumentError(
        absl::StrFormat("data is too large (got %d bytes, want <= %d bytes)",
                        data.length(), max_data_bytes),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.length() != RSA_size(public_key)) {
    return NewInvalidArgumentError(
        absl::StrFormat(
            "signature length mismatches expected (got %d, want %d)",
            signature.length(), RSA_size(public_key)),
        CKR_SIGNATURE_LEN_RANGE, SOURCE_LOCATION);
  }

  std::vector<uint8_t> recovered(RSA_size(public_key));
  int decrypt_result =
      RSA_public_decrypt(signature.size(), signature.data(), recovered.data(),
                         public_key, RSA_PKCS1_PADDING);
  if (decrypt_result == -1) {
    return NewInvalidArgumentError(
        absl::StrCat("verification failed: ", SslErrorToString()),
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  size_t out_length = decrypt_result;
  if (!std::equal(data.begin(), data.end(), recovered.begin(),
                  recovered.begin() + out_length)) {
    return NewInvalidArgumentError(
        "verification failed: recovered data mismatches expected",
        CKR_SIGNATURE_INVALID, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

bool IsRawRsaAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  if (algorithm == kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048 ||
      algorithm == kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_3072 ||
      algorithm == kms_v1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_4096) {
    return true;
  }
  return false;
}

// Build a DigestInfo structure, which is the expected input into a CKM_RSA_PKCS
// signing operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850410
absl::StatusOr<std::vector<uint8_t>> BuildRsaDigestInfo(
    int digest_nid, absl::Span<const uint8_t> digest) {
  X509_ALGOR* algorithm;
  ASN1_OCTET_STRING* dig;
  bssl::UniquePtr<X509_SIG> digest_info(X509_SIG_new());
  X509_SIG_getm(digest_info.get(), &algorithm, &dig);

  if (X509_ALGOR_set0(algorithm, OBJ_nid2obj(digest_nid), V_ASN1_NULL,
                      nullptr) != 1) {
    return absl::InternalError(absl::StrCat(
        "failure setting algorithm parameters: ", SslErrorToString()));
  }
  if (ASN1_OCTET_STRING_set(dig, digest.data(), digest.size()) != 1) {
    return absl::InternalError(
        absl::StrCat("failure setting digest value: ", SslErrorToString()));
  }

  ASSIGN_OR_RETURN(std::string digest_info_der,
                   MarshalX509Sig(digest_info.get()));
  return std::vector<uint8_t>(
      reinterpret_cast<const uint8_t*>(digest_info_der.data()),
      reinterpret_cast<const uint8_t*>(digest_info_der.data() +
                                       digest_info_der.size()));
}

std::string SslErrorToString(std::string_view default_message) {
  CHECK(kCryptoLibraryInitialized);
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  ERR_print_errors(bio.get());
  char* contents;
  int len = BIO_get_mem_data(bio.get(), &contents);
  if (len <= 0) {
    return std::string(default_message);
  }
  return std::string(contents, size_t(len));
}

}  // namespace cloud_kms::kmsp11
