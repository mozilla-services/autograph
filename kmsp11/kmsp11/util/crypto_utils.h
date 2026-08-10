/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef KMSP11_UTIL_CRYPTO_UTILS_H_
#define KMSP11_UTIL_CRYPTO_UTILS_H_

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "common/kms_v1.h"
#include "common/openssl.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {

// Convert an ASN1_TIME structure to an absl::Time.
absl::StatusOr<absl::Time> Asn1TimeToAbsl(const ASN1_TIME* time);

// Convert the provided BIGNUM to big-endian binary, padding with leading zeroes
// to fill dest.
absl::Status BignumToBinary(const BIGNUM* src, absl::Span<uint8_t> dest);

// Checks that BoringSSL is operating in FIPS mode, and that FIPS self-tests
// pass. Returns FailedPrecondition if BoringSSL is not in FIPS mode; or
// Internal if the self-tests fail.
absl::Status CheckFipsSelfTest();

// Returns an EVP_MD* for the provided digest mechanism, or returns
// InternalError if the provided mechanism is not a recognized digest.
absl::StatusOr<const EVP_MD*> DigestForMechanism(CK_MECHANISM_TYPE mechanism);

// Converts a signature in ASN.1 format (as returned by OpenSSL and Cloud KMS)
// into IEEE P-1363 format (as required by PKCS #11).
absl::StatusOr<std::vector<uint8_t>> EcdsaSigAsn1ToP1363(
    std::string_view asn1_sig, const EC_GROUP* group);

// Returns the length of a signature in IEEE P-1363 format (with leading zeroes)
// for the provided group.
int EcdsaSigLengthP1363(const EC_GROUP* group);

// Verifies that the provided signature in IEEE P-1363 format is a valid
// signature over digest.
absl::Status EcdsaVerifyP1363(EC_KEY* public_key, const EVP_MD* hash,
                              absl::Span<const uint8_t> digest,
                              absl::Span<const uint8_t> signature);

// Encrypts plaintext using RSAES-OAEP with MGF-1, and writes it to ciphertext.
// Ciphertext size must be exactly equal to the RSA modulus size. Hash is used
// in both OAEP and MGF-1; OAEP labels are not supported.
absl::Status EncryptRsaOaep(EVP_PKEY* key, const EVP_MD* hash,
                            absl::Span<const uint8_t> plaintext,
                            absl::Span<uint8_t> ciphertext);

// Marshals an ASN.1 integer in DER format.
absl::StatusOr<std::string> MarshalAsn1Integer(ASN1_INTEGER* value);

// Marshals EC Parameters (always of choice NamedCurve) in DER format for the
// provided key.
//
// Required to populate the attribute CKA_EC_PARAMS:
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc468937842
absl::StatusOr<std::string> MarshalEcParametersDer(BSSL_CONST EC_KEY* key);

// Marshals the provided EC public key to an ASN.1 Octet String in DER format.
//
// Required to populate the attribute CKA_EC_POINT:
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc416960012
absl::StatusOr<std::string> MarshalEcPointToAsn1OctetStringDer(
    BSSL_CONST EC_KEY* key);

// Marshals an X.509 certificate in DER format.
absl::StatusOr<std::string> MarshalX509CertificateDer(X509* cert);

// Marshals an X.509 name (subject or issuer) in DER format.
absl::StatusOr<std::string> MarshalX509Name(X509_NAME* value);

// Marshals a public key to X.509 SubjectPublicKeyInfo DER format.
//
// Required to populate the attribute CKA_PUBLIC_KEY_INFO:
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc441755781
absl::StatusOr<std::string> MarshalX509PublicKeyDer(BSSL_CONST EVP_PKEY* key);

// Parses a private key in PKCS #8 PrivateKey PEM format. Returns
// InvalidArgument if the provided key is malformed.
absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> ParsePkcs8PrivateKeyPem(
    std::string_view private_key_pem);

// Marshals an ASN.1 DigestInfo in DER format.
absl::StatusOr<std::string> MarshalX509Sig(X509_SIG* value);

// Parses an X.509 certificate in DER format. Returns InvalidArgument if
// the provided certificate is malformed.
absl::StatusOr<bssl::UniquePtr<X509>> ParseX509CertificateDer(
    std::string_view certificate_der);

// Parses an X.509 certificate in PEM format. Returns InvalidArgument if
// the provided certificate is malformed.
absl::StatusOr<bssl::UniquePtr<X509>> ParseX509CertificatePem(
    std::string_view certificate_pem);

// Parses a public key in X.509 SubjectPublicKeyInfo DER format. Returns
// InvalidArgument if the provided key is malformed.
absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyDer(
    std::string_view public_key_der);

// Parses a public key in X.509 SubjectPublicKeyInfo PEM format. Returns
// InvalidArgument if the provided key is malformed.
// Required to parse PEM public keys retrieved from Cloud KMS.
absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> ParseX509PublicKeyPem(
    std::string_view public_key_pem);

// Retrieves len bytes of randomness from Boring's CSPRNG.
std::string RandBytes(size_t len);

// Uses Boring's CSPRNG to generate a random CK_ULONG for use as a Cryptoki
// handle. Note that 0 is never returned, since 0 is CK_INVALID_HANDLE.
CK_ULONG RandomHandle();

// Verifies that the provided RSA PKCS1 signature is valid over digest.
absl::Status RsaVerifyPkcs1(RSA* public_key, const EVP_MD* hash,
                            absl::Span<const uint8_t> digest,
                            absl::Span<const uint8_t> signature);

// Verifies that the provided RSA PSS signature is valid over digest.
// PSS options are not configurable: MGF1 hash is always the same as the data
// hash, and salt length always equals hash length.
absl::Status RsaVerifyPss(EVP_PKEY* public_key, const EVP_MD* hash,
                          absl::Span<const uint8_t> digest,
                          absl::Span<const uint8_t> signature);

// Verifies that the provided raw RSA PKCS #1 signature is valid over data.
absl::Status RsaVerifyRawPkcs1(RSA* public_key, absl::Span<const uint8_t> data,
                               absl::Span<const uint8_t> signature);

// Returns whether or not the algorithm is a raw RSA PKCS #1 algorithm.
bool IsRawRsaAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

// Build a DigestInfo structure, which is the expected input into a CKM_RSA_PKCS
// signing operation.
// http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850410
absl::StatusOr<std::vector<uint8_t>> BuildRsaDigestInfo(
    int digest_nid, absl::Span<const uint8_t> digest);

// Retrieves the contents of BoringSSL's error stack, and dumps it to a string.
// If no errors are found on the stack, `default_message` is returned instead.
std::string SslErrorToString(
    std::string_view default_message =
        "(error could not be retrieved from the SSL stack)");

// A replacement for std::allocator that zeroes before deallocating.
//
// Suggested usage:
//   std::vector<uint8_t, ZeroDeallocator<uint8_t>> t;
template <typename T>
struct ZeroDeallocator {
  using value_type = T;

  ZeroDeallocator() = default;

  template <class U>
  constexpr ZeroDeallocator(const ZeroDeallocator<U>&) noexcept {}

  T* allocate(std::size_t len) { return static_cast<T*>(std::malloc(len)); }
  void deallocate(T* ptr, std::size_t len) {
    OPENSSL_cleanse(ptr, len);
    std::free(ptr);
  }
};

// A replacement for std::default_delete that zeroes before deleting.
//
// Suggested usage:
//   std::unique_ptr<std::string, ZeroDelete<std::string>> t;
template <typename T>
struct ZeroDelete {
  void operator()(T* value) const {
    if (value) {
      OPENSSL_cleanse(value->data(), value->size());
    }
    delete value;
  }
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_UTIL_CRYPTO_UTILS_H_
