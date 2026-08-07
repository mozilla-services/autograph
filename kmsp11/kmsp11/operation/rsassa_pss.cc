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

#include "kmsp11/operation/rsassa_pss.h"

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
namespace {

absl::Status ValidatePssParameters(Object* key, void* parameters,
                                   CK_ULONG parameters_size) {
  if (parameters_size != sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
    return InvalidMechanismParamError(
        "mechanism parameters must be of type CK_RSA_PKCS_PSS_PARAMS",
        SOURCE_LOCATION);
  }
  CK_RSA_PKCS_PSS_PARAMS* params = (CK_RSA_PKCS_PSS_PARAMS*)parameters;

  ASSIGN_OR_RETURN(const EVP_MD* digest,
                   DigestForMechanism(*key->algorithm().digest_mechanism));
  RETURN_IF_ERROR(EnsureHashMatches(params->hashAlg, digest));
  RETURN_IF_ERROR(EnsureMgf1HashMatches(params->mgf, digest));

  size_t expected_salt_length = EVP_MD_size(digest);
  if (params->sLen != expected_salt_length) {
    return InvalidMechanismParamError(
        absl::StrFormat("expected salt length for key %s is %d, but %d "
                        "was supplied in the parameters",
                        key->kms_key_name(), expected_salt_length,
                        params->sLen),
        SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

}  // namespace

// An implementation of SignerInterface that makes RSASSA-PSS signatures using
// Cloud KMS.
class RsaPssSigner : public KmsPrehashedSigner {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  size_t signature_length() override;

  virtual ~RsaPssSigner() {}

 private:
  RsaPssSigner(std::shared_ptr<Object> object, bssl::UniquePtr<EVP_PKEY> key)
      : KmsPrehashedSigner(object), key_(std::move(key)) {}

  bssl::UniquePtr<EVP_PKEY> key_;
};

absl::StatusOr<std::unique_ptr<SignerInterface>> NewRsaPssSigner(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  CK_MECHANISM inner_mechanism = {CKM_RSA_PKCS_PSS, mechanism->pParameter,
                                  mechanism->ulParameterLen};
  ASSIGN_OR_RETURN(auto signer, RsaPssSigner::New(key, &inner_mechanism));
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS_PSS:
      return signer;
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      return KmsDigestingSigner::New(key, std::move(signer), mechanism);
    default:
      return NewInternalError(
          absl::StrFormat("Mechanism %#x not supported for RSA-PSS signing",
                          mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<SignerInterface>> RsaPssSigner::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY,
                                        CKM_RSA_PKCS_PSS, key.get()));
  RETURN_IF_ERROR(ValidatePssParameters(key.get(), mechanism->pParameter,
                                        mechanism->ulParameterLen));

  ASSIGN_OR_RETURN(std::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<SignerInterface>(
      new RsaPssSigner(key, std::move(parsed_key)));
}

size_t RsaPssSigner::signature_length() {
  return RSA_size(EVP_PKEY_get0_RSA(key_.get()));
}

class RsaPssVerifier : public VerifierInterface {
 public:
  static absl::StatusOr<std::unique_ptr<VerifierInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  Object* object() override { return object_.get(); };

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> digest,
                      absl::Span<const uint8_t> signature) override;

  virtual ~RsaPssVerifier() {}

 private:
  RsaPssVerifier(std::shared_ptr<Object> object, bssl::UniquePtr<EVP_PKEY> key)
      : object_(object), key_(std::move(key)) {}

  std::shared_ptr<Object> object_;
  bssl::UniquePtr<EVP_PKEY> key_;
};

absl::StatusOr<std::unique_ptr<VerifierInterface>> NewRsaPssVerifier(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  CK_MECHANISM inner_mechanism = {CKM_RSA_PKCS_PSS, mechanism->pParameter,
                                  mechanism->ulParameterLen};
  ASSIGN_OR_RETURN(auto verifier, RsaPssVerifier::New(key, &inner_mechanism));
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS_PSS:
      return verifier;
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
      return KmsDigestingVerifier::New(key, std::move(verifier), mechanism);
    default:
      return NewInternalError(
          absl::StrFormat(
              "Mechanism %#x not supported for RSA-PSS verification",
              mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<VerifierInterface>> RsaPssVerifier::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(CheckKeyPreconditions(CKK_RSA, CKO_PUBLIC_KEY,
                                        CKM_RSA_PKCS_PSS, key.get()));
  RETURN_IF_ERROR(ValidatePssParameters(key.get(), mechanism->pParameter,
                                        mechanism->ulParameterLen));

  ASSIGN_OR_RETURN(std::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<VerifierInterface>(
      new RsaPssVerifier(key, std::move(parsed_key)));
}

absl::Status RsaPssVerifier::Verify(KmsClient* client,
                                    absl::Span<const uint8_t> digest,
                                    absl::Span<const uint8_t> signature) {
  ASSIGN_OR_RETURN(const EVP_MD* md,
                   DigestForMechanism(*object_->algorithm().digest_mechanism));
  return RsaVerifyPss(key_.get(), md, digest, signature);
}

}  // namespace cloud_kms::kmsp11
