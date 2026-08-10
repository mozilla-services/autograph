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

#include "kmscng/operation/sign_utils.h"

#include "absl/strings/str_format.h"
#include "common/kms_client.h"
#include "common/status_macros.h"
#include "kmscng/algorithm_details.h"
#include "kmscng/cng_headers.h"
#include "kmscng/object.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/status_utils.h"
#include "kmscng/util/string_utils.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmscng {
namespace {

// TODO(b/270419822): drop these once crypto_utils has been migrated to common.
using cloud_kms::kmsp11::EcdsaSigAsn1ToP1363;
using cloud_kms::kmsp11::EcdsaSigLengthP1363;
using cloud_kms::kmsp11::ParseX509PublicKeyDer;
using cloud_kms::kmsp11::SslErrorToString;

absl::Status CopyEcSignature(Object* object, std::string_view src,
                             absl::Span<uint8_t> dest) {
  ASSIGN_OR_RETURN(int curve, CurveIdForAlgorithm(object->algorithm()));
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(curve));
  absl::StatusOr<std::vector<uint8_t>> ec_sig =
      EcdsaSigAsn1ToP1363(src, group.get());
  if (!ec_sig.ok()) {
    absl::Status result = ec_sig.status();
    SetErrorSs(result, NTE_INTERNAL_ERROR);
    return result;
  }

  if (ec_sig->size() != dest.size()) {
    return NewInternalError(
        absl::StrFormat("unexpected signature length (got %d, want %d)",
                        ec_sig->size(), dest.size()),
        SOURCE_LOCATION);
  }
  std::copy(ec_sig->begin(), ec_sig->end(), dest.data());
  return absl::OkStatus();
}

absl::Status CopyRsaSignature(Object* object, std::string_view src,
                              absl::Span<uint8_t> dest) {
  if (src.size() != dest.size()) {
    return NewInternalError(
        absl::StrFormat("unexpected signature length (got %d, want %d)",
                        src.size(), dest.size()),
        SOURCE_LOCATION);
  }
  const uint8_t* sig_data = reinterpret_cast<const uint8_t*>(src.data());
  std::copy(sig_data, sig_data + src.size(), dest.data());
  return absl::OkStatus();
}

absl::Status CopySignature(Object* object, std::string_view src,
                           absl::Span<uint8_t> dest) {
  switch (object->algorithm()) {
    case kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256:
    case kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384:
      return CopyEcSignature(object, src, dest);
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return CopyRsaSignature(object, src, dest);
    default:
      return NewInternalError(
          absl::StrFormat("unsupported signature algorithm %s)",
                          object->algorithm()),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::vector<uint8_t>> SerializePublicEcKey(Object* object) {
  ASSIGN_OR_RETURN(int curve, CurveIdForAlgorithm(object->algorithm()));
  size_t header_size = sizeof(BCRYPT_ECCKEY_BLOB);
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(curve));
  size_t uncompressed_length =
      2 * BN_num_bytes(EC_GROUP_get0_order(group.get()));  // == 32 for P-256

  std::vector<uint8_t> result(header_size + uncompressed_length);
  // The uncompressed public key includes a 0x04 prefix byte to indicate that
  // the key is in uncompressed format, but the BCRYPT_ECCPUBLIC_BLOB struct
  // should only include the X and Y coordinates, so we write starting from
  // header_size - 1 (since we override the other struct fields below anyways).
  uint8_t* pub_minus_one = result.data() + header_size - 1;
  size_t bytes_written = EC_POINT_point2oct(
      group.get(), EC_KEY_get0_public_key(object->ec_public_key()),
      POINT_CONVERSION_UNCOMPRESSED, pub_minus_one, uncompressed_length + 1,
      nullptr);
  if (bytes_written != uncompressed_length + 1) {
    return NewInternalError(
        absl::StrFormat(
            "Error serializing public key: %d bytes written, wanted %d. %s",
            bytes_written, uncompressed_length, SslErrorToString()),
        SOURCE_LOCATION);
  }
  BCRYPT_ECCKEY_BLOB* header =
      reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(result.data());
  ASSIGN_OR_RETURN(header->dwMagic, MagicIdForAlgorithm(object->algorithm()));
  header->cbKey = uncompressed_length / 2;
  return result;
}

absl::StatusOr<std::vector<uint8_t>> SerializePublicRsaKey(Object* object) {
  RSA* rsa = object->rsa_public_key();
  const BIGNUM* public_exponent = RSA_get0_e(rsa);
  const BIGNUM* modulus = RSA_get0_n(rsa);
  unsigned int public_exponent_size = BN_num_bytes(public_exponent);
  unsigned int modulus_size = BN_num_bytes(modulus);

  // Build the BCRYPT_RSAPUBLIC_BLOB structure, as specified in
  // https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob#remarks
  size_t header_size = sizeof(BCRYPT_RSAKEY_BLOB);
  size_t payload_size = public_exponent_size + modulus_size;
  std::vector<uint8_t> result(header_size + payload_size);
  // Header
  BCRYPT_RSAKEY_BLOB* header =
      reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(result.data());
  ASSIGN_OR_RETURN(header->Magic, MagicIdForAlgorithm(object->algorithm()));
  header->BitLength = RSA_bits(rsa);
  header->cbPublicExp = public_exponent_size;
  header->cbModulus = modulus_size;
  header->cbPrime1 = 0L;  // not used by public keys
  header->cbPrime2 = 0L;  // not used by public keys
  // Public key data, Big Endian
  size_t bytes_written;
  uint8_t* exponent_data = result.data() + header_size;
  bytes_written = BN_bn2bin(public_exponent, exponent_data);
  if (bytes_written != public_exponent_size) {
    return NewInternalError(
        absl::StrFormat("Error serializing public key (RSA public exponent): "
                        "%d bytes written, wanted %d. %s",
                        bytes_written, public_exponent_size,
                        SslErrorToString()),
        SOURCE_LOCATION);
  }
  uint8_t* modulus_data = exponent_data + public_exponent_size;
  bytes_written = BN_bn2bin(modulus, modulus_data);
  if (bytes_written != modulus_size) {
    return NewInternalError(
        absl::StrFormat("Error serializing public key (RSA modulus): %d bytes "
                        "written, wanted %d. %s",
                        bytes_written, modulus_size, SslErrorToString()),
        SOURCE_LOCATION);
  }
  return result;
}

}  // namespace

absl::Status IsValidSigningAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256:
    case kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return absl::OkStatus();
    default:
      return NewInternalError(
          absl::StrFormat("invalid asymmetric signing algorithm: %d",
                          algorithm),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<const EVP_MD*> DigestForAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
      return EVP_sha256();
    case kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384:
      return EVP_sha384();
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return EVP_sha512();
    default:
      return NewInternalError(
          absl::StrFormat("cannot get digest type for algorithm: %d",
                          algorithm),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<int> CurveIdForAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256:
      return NID_X9_62_prime256v1;
    case kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384:
      return NID_secp384r1;
    default:
      return NewInternalError(
          absl::StrFormat("cannot get curve NID for algorithm: %d", algorithm),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<uint32_t> MagicIdForAlgorithm(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256:
      return BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    case kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384:
      return BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return BCRYPT_RSAPUBLIC_MAGIC;
    default:
      return NewInternalError(
          absl::StrFormat("cannot get magic ID for algorithm: %d", algorithm),
          SOURCE_LOCATION);
  }
}

absl::Status ValidateKeyPreconditions(Object* object) {
  RETURN_IF_ERROR(IsValidSigningAlgorithm(object->algorithm()));
  ASSIGN_OR_RETURN(AlgorithmDetails details, GetDetails(object->algorithm()));
  ASSIGN_OR_RETURN(auto algorithm_group,
                   object->GetProperty(NCRYPT_ALGORITHM_GROUP_PROPERTY));
  if (algorithm_group != WideToBytes(details.algorithm_group)) {
    return NewInternalError(
        absl::StrFormat("invalid algorithm_group property, expected %s",
                        WideToString(details.algorithm_group)),
        SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(auto algorithm_property,
                   object->GetProperty(NCRYPT_ALGORITHM_PROPERTY));
  if (algorithm_property != WideToBytes(details.algorithm_property)) {
    return NewInternalError(
        absl::StrFormat("invalid algorithm_property, expected %s",
                        WideToString(details.algorithm_property)),
        SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(auto key_usage,
                   object->GetProperty(NCRYPT_KEY_USAGE_PROPERTY));
  if (key_usage != Uint32ToBytes(details.key_usage)) {
    return NewInternalError(
        absl::StrFormat("invalid key_usage property, expected %u",
                        details.key_usage),
        SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::StatusOr<std::vector<uint8_t>> SerializePublicKey(Object* object) {
  switch (object->algorithm()) {
    case kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256:
    case kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384:
      return SerializePublicEcKey(object);
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return SerializePublicRsaKey(object);
    default:
      return NewInternalError(
          absl::StrFormat("invalid asymmetric signing algorithm: %d",
                          object->algorithm()),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<size_t> SignatureLength(Object* object) {
  switch (object->algorithm()) {
    case kms_v1::CryptoKeyVersion::EC_SIGN_P256_SHA256:
    case kms_v1::CryptoKeyVersion::EC_SIGN_P384_SHA384: {
      ASSIGN_OR_RETURN(int curve, CurveIdForAlgorithm(object->algorithm()));
      bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(curve));
      return EcdsaSigLengthP1363(group.get());
    }
    // RSA signatures have the same size as the key bit size (in bytes here).
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
      return 2048 / 8;
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
      return 3072 / 8;
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
    case kms_v1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return 4096 / 8;
    default:
      return NewInternalError(
          absl::StrFormat("cannot get signature length for algorithm: %d",
                          object->algorithm()),
          SOURCE_LOCATION);
  }
}

absl::Status SignDigest(Object* object, absl::Span<const uint8_t> digest,
                        absl::Span<uint8_t> signature) {
  ASSIGN_OR_RETURN(const EVP_MD* md, DigestForAlgorithm(object->algorithm()));

  if (digest.size() != EVP_MD_size(md)) {
    return NewInvalidArgumentError(
        absl::StrFormat("provided digest has incorrect size (got %d, want %d)",
                        digest.size(), EVP_MD_size(md)),
        NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(auto expected_sig_length, SignatureLength(object));
  if (signature.size() != expected_sig_length) {
    return NewInternalError(
        absl::StrFormat(
            "provided signature buffer has incorrect size (got %d, want %d)",
            signature.size(), expected_sig_length),
        SOURCE_LOCATION);
  }

  kms_v1::AsymmetricSignRequest req;
  req.set_name(std::string(object->kms_key_name()));

  int digest_nid = EVP_MD_type(md);
  switch (digest_nid) {
    case NID_sha256:
      req.mutable_digest()->set_sha256(digest.data(), digest.size());
      break;
    case NID_sha384:
      req.mutable_digest()->set_sha384(digest.data(), digest.size());
      break;
    case NID_sha512:
      req.mutable_digest()->set_sha512(digest.data(), digest.size());
      break;
    default:
      return NewInternalError(
          absl::StrFormat("unhandled digest type: %d", digest_nid),
          SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(kms_v1::AsymmetricSignResponse resp,
                   object->kms_client()->AsymmetricSign(req));
  RETURN_IF_ERROR(CopySignature(object, resp.signature(), signature));
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmscng
