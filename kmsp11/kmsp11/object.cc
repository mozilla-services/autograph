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

#include "kmsp11/object.h"

#include "absl/strings/str_split.h"
#include "common/openssl.h"
#include "common/status_macros.h"
#include "kmsp11/kmsp11.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {
namespace {

absl::Status AddStorageAttributes(AttributeMap* attrs,
                                  const kms_v1::CryptoKeyVersion& ckv) {
  ASSIGN_OR_RETURN(std::string key_id, ExtractKeyId(ckv.name()));

  // 4.4 Storage objects
  attrs->PutBool(CKA_TOKEN, true);
  attrs->PutBool(CKA_PRIVATE, false);
  attrs->PutBool(CKA_MODIFIABLE, false);
  attrs->Put(CKA_LABEL, key_id);
  attrs->PutBool(CKA_COPYABLE, false);
  attrs->PutBool(CKA_DESTROYABLE, false);

  // Custom attributes
  attrs->PutULong(CKA_KMS_ALGORITHM, ckv.algorithm());

  return absl::OkStatus();
};

absl::Status AddKeyAttributes(AttributeMap* attrs,
                              const kms_v1::CryptoKeyVersion& ckv) {
  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));

  // 4.7 Key objects
  attrs->PutULong(CKA_KEY_TYPE, algorithm.key_type);
  attrs->Put(CKA_ID, ckv.name());
  attrs->Put(CKA_START_DATE, "");
  attrs->Put(CKA_END_DATE, "");
  attrs->PutBool(CKA_DERIVE, false);
  attrs->PutBool(CKA_LOCAL, ckv.import_job().empty());
  attrs->PutULong(CKA_KEY_GEN_MECHANISM, ckv.import_job().empty()
                                             ? algorithm.key_gen_mechanism
                                             : CK_UNAVAILABLE_INFORMATION);
  attrs->PutULongList(CKA_ALLOWED_MECHANISMS, algorithm.allowed_mechanisms);

  return absl::OkStatus();
}

absl::Status AddPublicKeyAttributes(AttributeMap* attrs,
                                    const kms_v1::CryptoKeyVersion& ckv,
                                    std::string_view public_key_der) {
  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));

  // 4.8 Public key objects
  attrs->Put(CKA_SUBJECT, "");
  attrs->PutBool(CKA_ENCRYPT,
                 algorithm.purpose == kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  attrs->PutBool(CKA_VERIFY,
                 algorithm.purpose == kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  attrs->PutBool(CKA_VERIFY_RECOVER, false);
  attrs->PutBool(CKA_WRAP, false);
  attrs->PutBool(CKA_TRUSTED, false);
  attrs->Put(CKA_WRAP_TEMPLATE, "");
  attrs->Put(CKA_PUBLIC_KEY_INFO, public_key_der);
  return absl::OkStatus();
}

absl::Status AddPrivateKeyAttributes(AttributeMap* attrs,
                                     const kms_v1::CryptoKeyVersion& ckv,
                                     std::string_view public_key_der) {
  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));

  // Override CKA_DESTROYABLE (from 4.4 Storage Objects)
  attrs->PutBool(CKA_DESTROYABLE, true);

  // 4.9 Private key objects
  attrs->Put(CKA_SUBJECT, "");
  attrs->PutBool(CKA_SENSITIVE, true);
  attrs->PutBool(CKA_DECRYPT,
                 algorithm.purpose == kms_v1::CryptoKey::ASYMMETRIC_DECRYPT);
  attrs->PutBool(CKA_SIGN,
                 algorithm.purpose == kms_v1::CryptoKey::ASYMMETRIC_SIGN);
  attrs->PutBool(CKA_SIGN_RECOVER, false);
  attrs->PutBool(CKA_UNWRAP, false);
  attrs->PutBool(CKA_EXTRACTABLE, false);
  attrs->PutBool(CKA_ALWAYS_SENSITIVE, ckv.import_job().empty());
  attrs->PutBool(CKA_NEVER_EXTRACTABLE, ckv.import_job().empty());
  attrs->PutBool(CKA_WRAP_WITH_TRUSTED, false);
  attrs->Put(CKA_UNWRAP_TEMPLATE, "");
  attrs->PutBool(CKA_ALWAYS_AUTHENTICATE, false);
  attrs->Put(CKA_PUBLIC_KEY_INFO, public_key_der);
  return absl::OkStatus();
}

absl::Status AddEcPublicKeyAttributes(AttributeMap* attrs,
                                      BSSL_CONST EC_KEY* public_key) {
  ASSIGN_OR_RETURN(std::string params, MarshalEcParametersDer(public_key));
  ASSIGN_OR_RETURN(std::string ec_point,
                   MarshalEcPointToAsn1OctetStringDer(public_key));

  // 2.3.3 ECDSA public key objects
  attrs->Put(CKA_EC_PARAMS, params);
  attrs->Put(CKA_EC_POINT, ec_point);

  return absl::OkStatus();
}

absl::Status AddEcPrivateKeyAttributes(AttributeMap* attrs,
                                       BSSL_CONST EC_KEY* public_key) {
  ASSIGN_OR_RETURN(std::string params, MarshalEcParametersDer(public_key));

  // Some implementations seem to expect that EC private keys contain the EC
  // public key attributes as well.
  RETURN_IF_ERROR(AddEcPublicKeyAttributes(attrs, public_key));

  // 2.3.4 Elliptic curve private key objects
  attrs->PutSensitive(CKA_VALUE);

  return absl::OkStatus();
}

absl::Status AddRsaPublicKeyAttributes(AttributeMap* attrs,
                                       BSSL_CONST RSA* public_key) {
  const BIGNUM *n, *e;
  RSA_get0_key(public_key, &n, &e, /*d=*/nullptr);

  // 2.1.2 RSA public key objects
  attrs->PutBigNum(CKA_MODULUS, n);
  attrs->PutULong(CKA_MODULUS_BITS, RSA_bits(public_key));
  attrs->PutBigNum(CKA_PUBLIC_EXPONENT, e);
  return absl::OkStatus();
}

absl::Status AddRsaPrivateKeyAttributes(AttributeMap* attrs,
                                        BSSL_CONST RSA* public_key) {
  // Some implementations seem to expect that RSA private keys contain the RSA
  // public key attributes as well.
  RETURN_IF_ERROR(AddRsaPublicKeyAttributes(attrs, public_key));

  // 2.1.3 RSA private key objects
  attrs->PutSensitive(CKA_PRIVATE_EXPONENT);
  attrs->PutSensitive(CKA_PRIME_1);
  attrs->PutSensitive(CKA_PRIME_2);
  attrs->PutSensitive(CKA_EXPONENT_1);
  attrs->PutSensitive(CKA_EXPONENT_2);
  attrs->PutSensitive(CKA_COEFFICIENT);

  return absl::OkStatus();
}

absl::Status AddSecretKeyAttributes(AttributeMap* attrs,
                                    const kms_v1::CryptoKeyVersion& ckv) {
  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));

  // CKA_VALUE and CKA_VALUE_LEN are tied to the mechanisms in the spec, but
  // in practice they are the same for all secret keys.
  // eg.
  // http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228894691
  attrs->PutSensitive(CKA_VALUE);
  // CKA_VALUE_LEN = key size in bytes.
  attrs->PutULong(CKA_VALUE_LEN, algorithm.key_bit_length / 8);

  // Override CKA_DESTROYABLE (from 4.4 Storage Objects)
  attrs->PutBool(CKA_DESTROYABLE, true);

  // 4.10 Secret key objects
  attrs->Put(CKA_SUBJECT, "");
  attrs->PutBool(CKA_SENSITIVE, true);
  attrs->PutBool(CKA_ENCRYPT,
                 algorithm.purpose == kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  attrs->PutBool(CKA_DECRYPT,
                 algorithm.purpose == kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT);
  attrs->PutBool(CKA_SIGN, algorithm.purpose == kms_v1::CryptoKey::MAC);
  attrs->PutBool(CKA_VERIFY, algorithm.purpose == kms_v1::CryptoKey::MAC);
  attrs->PutBool(CKA_WRAP, false);
  attrs->PutBool(CKA_UNWRAP, false);
  attrs->PutBool(CKA_EXTRACTABLE, false);
  attrs->PutBool(CKA_ALWAYS_SENSITIVE, ckv.import_job().empty());
  attrs->PutBool(CKA_NEVER_EXTRACTABLE, ckv.import_job().empty());
  // CKA_CHECK_VALUE is intentionally skipped, as permitted by the spec.
  // http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html#_Ref320515101
  attrs->PutBool(CKA_WRAP_WITH_TRUSTED, false);
  attrs->PutBool(CKA_TRUSTED, false);
  attrs->Put(CKA_WRAP_TEMPLATE, "");
  attrs->Put(CKA_UNWRAP_TEMPLATE, "");
  return absl::OkStatus();
}

absl::Status AddX509CertificateAttributes(AttributeMap* attrs,
                                          const kms_v1::CryptoKeyVersion& ckv,
                                          X509* cert) {
  ASSIGN_OR_RETURN(absl::Time not_before,
                   Asn1TimeToAbsl(X509_get_notBefore(cert)));
  ASSIGN_OR_RETURN(absl::Time not_after,
                   Asn1TimeToAbsl(X509_get_notAfter(cert)));

  bssl::UniquePtr<EVP_PKEY> pub(X509_get_pubkey(cert));
  ASSIGN_OR_RETURN(std::string public_key_info,
                   MarshalX509PublicKeyDer(pub.get()));

  ASSIGN_OR_RETURN(std::string subject_der,
                   MarshalX509Name(X509_get_subject_name(cert)));
  ASSIGN_OR_RETURN(std::string issuer_der,
                   MarshalX509Name(X509_get_issuer_name(cert)));
  ASSIGN_OR_RETURN(std::string serial,
                   MarshalAsn1Integer(X509_get_serialNumber(cert)));
  ASSIGN_OR_RETURN(std::string cert_der, MarshalX509CertificateDer(cert));

  char cert_der_sha1[20];
  SHA1(reinterpret_cast<const uint8_t*>(cert_der.data()), cert_der.size(),
       reinterpret_cast<uint8_t*>(cert_der_sha1));

  // 4.6.2 Certificate objects
  attrs->PutULong(CKA_CERTIFICATE_TYPE, CKC_X_509);
  attrs->PutBool(CKA_TRUSTED, false);
  attrs->PutULong(CKA_CERTIFICATE_CATEGORY,
                  CK_CERTIFICATE_CATEGORY_UNSPECIFIED);
  attrs->Put(CKA_CHECK_VALUE, std::string_view(cert_der_sha1, 3));
  attrs->PutDate(CKA_START_DATE, not_before);
  attrs->PutDate(CKA_END_DATE, not_after);
  attrs->Put(CKA_PUBLIC_KEY_INFO, public_key_info);

  // 4.6.3 X.509 public key certificate objects
  attrs->Put(CKA_SUBJECT, subject_der);
  attrs->Put(CKA_ID, ckv.name());
  attrs->Put(CKA_ISSUER, issuer_der);
  attrs->Put(CKA_SERIAL_NUMBER, serial);
  attrs->Put(CKA_VALUE, cert_der);
  attrs->Put(CKA_URL, "");
  attrs->Put(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "");
  attrs->Put(CKA_HASH_OF_ISSUER_PUBLIC_KEY, "");
  attrs->PutULong(CKA_JAVA_MIDP_SECURITY_DOMAIN,
                  CK_SECURITY_DOMAIN_UNSPECIFIED);

  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<KeyPair> Object::NewKeyPair(const kms_v1::CryptoKeyVersion& ckv,
                                           BSSL_CONST EVP_PKEY* public_key) {
  ASSIGN_OR_RETURN(std::string pub_der, MarshalX509PublicKeyDer(public_key));

  AttributeMap pub_attrs;
  pub_attrs.PutULong(CKA_CLASS, CKO_PUBLIC_KEY);
  RETURN_IF_ERROR(AddStorageAttributes(&pub_attrs, ckv));
  RETURN_IF_ERROR(AddKeyAttributes(&pub_attrs, ckv));
  RETURN_IF_ERROR(AddPublicKeyAttributes(&pub_attrs, ckv, pub_der));

  AttributeMap prv_attrs;
  prv_attrs.PutULong(CKA_CLASS, CKO_PRIVATE_KEY);
  RETURN_IF_ERROR(AddStorageAttributes(&prv_attrs, ckv));
  RETURN_IF_ERROR(AddKeyAttributes(&prv_attrs, ckv));
  RETURN_IF_ERROR(AddPrivateKeyAttributes(&prv_attrs, ckv, pub_der));

  int pkey_id = EVP_PKEY_id(public_key);
  switch (pkey_id) {
    case EVP_PKEY_EC: {
      BSSL_CONST EC_KEY* ec_public_key = EVP_PKEY_get0_EC_KEY(public_key);
      RETURN_IF_ERROR(AddEcPublicKeyAttributes(&pub_attrs, ec_public_key));
      RETURN_IF_ERROR(AddEcPrivateKeyAttributes(&prv_attrs, ec_public_key));
      break;
    }
    case EVP_PKEY_RSA: {
      BSSL_CONST RSA* rsa_public_key = EVP_PKEY_get0_RSA(public_key);
      RETURN_IF_ERROR(AddRsaPublicKeyAttributes(&pub_attrs, rsa_public_key));
      RETURN_IF_ERROR(AddRsaPrivateKeyAttributes(&prv_attrs, rsa_public_key));
      break;
    }
    default:
      return NewError(absl::StatusCode::kUnimplemented,
                      absl::StrFormat("unsupported EVP_PKEY type: %d", pkey_id),
                      CKR_GENERAL_ERROR, SOURCE_LOCATION);
  }

  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));
  return KeyPair{Object(ckv.name(), CKO_PUBLIC_KEY, algorithm, pub_attrs),
                 Object(ckv.name(), CKO_PRIVATE_KEY, algorithm, prv_attrs)};
}

absl::StatusOr<Object> Object::NewSecretKey(
    const kms_v1::CryptoKeyVersion& ckv) {
  AttributeMap attrs;
  attrs.PutULong(CKA_CLASS, CKO_SECRET_KEY);
  RETURN_IF_ERROR(AddStorageAttributes(&attrs, ckv));
  RETURN_IF_ERROR(AddKeyAttributes(&attrs, ckv));
  RETURN_IF_ERROR(AddSecretKeyAttributes(&attrs, ckv));

  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));
  return Object(ckv.name(), CKO_SECRET_KEY, algorithm, attrs);
}

absl::StatusOr<Object> Object::NewCertificate(
    const kms_v1::CryptoKeyVersion& ckv, X509* certificate) {
  ASSIGN_OR_RETURN(AlgorithmDetails algorithm, GetDetails(ckv.algorithm()));

  AttributeMap cert_attrs;
  cert_attrs.PutULong(CKA_CLASS, CKO_CERTIFICATE);
  RETURN_IF_ERROR(AddStorageAttributes(&cert_attrs, ckv));
  RETURN_IF_ERROR(AddX509CertificateAttributes(&cert_attrs, ckv, certificate));

  return Object(ckv.name(), CKO_CERTIFICATE, algorithm, cert_attrs);
}

}  // namespace cloud_kms::kmsp11
