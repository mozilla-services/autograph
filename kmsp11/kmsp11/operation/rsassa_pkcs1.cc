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

#include "kmsp11/operation/rsassa_pkcs1.h"

#include <string_view>

#include "common/openssl.h"
#include "common/status_macros.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/operation/kms_digesting_signer.h"
#include "kmsp11/operation/kms_digesting_verifier.h"
#include "kmsp11/operation/kms_prehashed_signer.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

// Enum representing if the input data is a plain digest or an ASN.1 DigestInfo.
enum class ExpectedInput { kDigest, kAsn1DigestInfo };

namespace {

absl::StatusOr<std::vector<uint8_t>> ExtractDigest(
    absl::Span<const uint8_t> digest_info_der, int expected_digest_nid) {
  const uint8_t* data = digest_info_der.data();

  bssl::UniquePtr<X509_SIG> digest_info(
      d2i_X509_SIG(nullptr, &data, digest_info_der.size()));
  if (!digest_info) {
    return NewInvalidArgumentError(
        absl::StrCat("error parsing DigestInfo: ", SslErrorToString()),
        CKR_DATA_INVALID, SOURCE_LOCATION);
  }

  const X509_ALGOR* algorithm;
  const ASN1_OCTET_STRING* digest;
  X509_SIG_get0(digest_info.get(), &algorithm, &digest);

  int got_nid = OBJ_obj2nid(algorithm->algorithm);
  if (got_nid != expected_digest_nid) {
    return NewInvalidArgumentError(
        absl::StrFormat("digest algorithm NID mismatch (got %d, want %d)",
                        got_nid, expected_digest_nid),
        CKR_DATA_INVALID, SOURCE_LOCATION);
  }

  return std::vector<uint8_t>(digest->data, digest->data + digest->length);
}

}  // namespace

// An implementation of SignerInterface that makes RSASSA-PKCS1 signatures using
// Cloud KMS.
class RsaPkcs1Signer : public KmsPrehashedSigner {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism,
      ExpectedInput input_type = ExpectedInput::kAsn1DigestInfo);

  size_t signature_length() override;

  absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> data,
                    absl::Span<uint8_t> signature) override;

  virtual ~RsaPkcs1Signer() {}

 private:
  RsaPkcs1Signer(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key,
                 ExpectedInput input_type)
      : KmsPrehashedSigner(object),
        key_(std::move(key)),
        input_type_(input_type) {}

  bssl::UniquePtr<RSA> key_;
  ExpectedInput input_type_;
};

absl::StatusOr<std::unique_ptr<SignerInterface>> NewRsaPkcs1Signer(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  CK_MECHANISM inner_mechanism = {CKM_RSA_PKCS_PSS, mechanism->pParameter,
                                  mechanism->ulParameterLen};
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS:
      return RsaPkcs1Signer::New(key, &inner_mechanism);
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS: {
      ASSIGN_OR_RETURN(
          auto signer,
          RsaPkcs1Signer::New(key, &inner_mechanism, ExpectedInput::kDigest));
      return KmsDigestingSigner::New(key, std::move(signer), mechanism);
    }
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for RSA-PKCS#1 signing",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<SignerInterface>> RsaPkcs1Signer::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism,
    ExpectedInput input_type) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY, CKM_RSA_PKCS, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(std::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<SignerInterface>(new RsaPkcs1Signer(
      key, bssl::UniquePtr<RSA>(EVP_PKEY_get1_RSA(parsed_key.get())),
      input_type));
}

size_t RsaPkcs1Signer::signature_length() { return RSA_size(key_.get()); }

absl::Status RsaPkcs1Signer::Sign(KmsClient* client,
                                  absl::Span<const uint8_t> data,
                                  absl::Span<uint8_t> signature) {
  if (input_type_ == ExpectedInput::kDigest) {
    return KmsPrehashedSigner::Sign(client, data, signature);
  }

  ASSIGN_OR_RETURN(const EVP_MD* md,
                   DigestForMechanism(*object()->algorithm().digest_mechanism));
  ASSIGN_OR_RETURN(std::vector<uint8_t> digest,
                   ExtractDigest(data, EVP_MD_type(md)));
  return KmsPrehashedSigner::Sign(client, digest, signature);
}

class RsaPkcs1Verifier : public VerifierInterface {
 public:
  static absl::StatusOr<std::unique_ptr<VerifierInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism,
      ExpectedInput input_type = ExpectedInput::kAsn1DigestInfo);

  Object* object() override { return object_.get(); };

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> data,
                      absl::Span<const uint8_t> signature) override;

  virtual ~RsaPkcs1Verifier() {}

 private:
  RsaPkcs1Verifier(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key,
                   ExpectedInput input_type)
      : object_(object), key_(std::move(key)), input_type_(input_type) {}

  std::shared_ptr<Object> object_;
  bssl::UniquePtr<RSA> key_;
  ExpectedInput input_type_;
};

absl::StatusOr<std::unique_ptr<VerifierInterface>> NewRsaPkcs1Verifier(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  CK_MECHANISM inner_mechanism = {CKM_RSA_PKCS, mechanism->pParameter,
                                  mechanism->ulParameterLen};
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS:
      return RsaPkcs1Verifier::New(key, &inner_mechanism);
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS: {
      ASSIGN_OR_RETURN(
          auto verifier,
          RsaPkcs1Verifier::New(key, &inner_mechanism, ExpectedInput::kDigest));
      return KmsDigestingVerifier::New(key, std::move(verifier), mechanism);
    }
    default:
      return NewInternalError(
          absl::StrFormat(
              "Mechanism %#x not supported for RSA-PKCS#1 verification",
              mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<VerifierInterface>> RsaPkcs1Verifier::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism,
    ExpectedInput input_type) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_RSA, CKO_PUBLIC_KEY, CKM_RSA_PKCS, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(std::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<VerifierInterface>(new RsaPkcs1Verifier(
      key, bssl::UniquePtr<RSA>(EVP_PKEY_get1_RSA(parsed_key.get())),
      input_type));
}

absl::Status RsaPkcs1Verifier::Verify(KmsClient* client,
                                      absl::Span<const uint8_t> data,
                                      absl::Span<const uint8_t> signature) {
  ASSIGN_OR_RETURN(const EVP_MD* md,
                   DigestForMechanism(*object_->algorithm().digest_mechanism));
  if (input_type_ == ExpectedInput::kDigest) {
    return RsaVerifyPkcs1(key_.get(), md, data, signature);
  }

  ASSIGN_OR_RETURN(std::vector<uint8_t> digest,
                   ExtractDigest(data, EVP_MD_type(md)));
  return RsaVerifyPkcs1(key_.get(), md, digest, signature);
}

}  // namespace cloud_kms::kmsp11
