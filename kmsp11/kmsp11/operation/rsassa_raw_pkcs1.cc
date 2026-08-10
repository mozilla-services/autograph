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

#include "kmsp11/operation/rsassa_raw_pkcs1.h"

#include <string_view>

#include "common/openssl.h"
#include "common/status_macros.h"
#include "glog/logging.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/operation/kms_digesting_signer.h"
#include "kmsp11/operation/kms_digesting_verifier.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

// An implementation of SignerInterface that makes "raw" RSASSA-PKCS1 signatures
// (i.e., without hashing/DigestInfo) using Cloud KMS.
class RsaRawPkcs1Signer : public SignerInterface {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  size_t signature_length() override;
  Object* object() override { return object_.get(); };

  absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> data,
                    absl::Span<uint8_t> signature) override;

  virtual ~RsaRawPkcs1Signer() {}

 private:
  RsaRawPkcs1Signer(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key)
      : object_(object), key_(std::move(key)) {}

  std::shared_ptr<Object> object_;
  bssl::UniquePtr<RSA> key_;
};

absl::StatusOr<std::unique_ptr<SignerInterface>> NewRsaRawPkcs1Signer(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  CK_MECHANISM inner_mechanism = {CKM_RSA_PKCS_PSS, mechanism->pParameter,
                                  mechanism->ulParameterLen};
  ASSIGN_OR_RETURN(auto signer, RsaRawPkcs1Signer::New(key, &inner_mechanism));
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS:
      return signer;
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS: {
      return KmsDigestingSigner::New(key, std::move(signer), mechanism);
    }
    default:
      return NewInternalError(
          absl::StrFormat(
              "Mechanism %#x not supported for raw RSA-PKCS#1 signing",
              mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<SignerInterface>> RsaRawPkcs1Signer::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_RSA, CKO_PRIVATE_KEY, CKM_RSA_PKCS, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(std::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<SignerInterface>(new RsaRawPkcs1Signer(
      key, bssl::UniquePtr<RSA>(EVP_PKEY_get1_RSA(parsed_key.get()))));
}

size_t RsaRawPkcs1Signer::signature_length() { return RSA_size(key_.get()); }

absl::Status RsaRawPkcs1Signer::Sign(KmsClient* client,
                                     absl::Span<const uint8_t> data,
                                     absl::Span<uint8_t> signature) {
  size_t key_byte_length = RSA_size(key_.get());
  constexpr size_t kRsaPkcs1OverheadBytes = 11;
  // I don't know how we'd end up with a <11-byte key, but for completeness, and
  // to avoid unsigned underflow...
  CHECK_GE(key_byte_length, kRsaPkcs1OverheadBytes);
  size_t max_data_byte_length = key_byte_length - kRsaPkcs1OverheadBytes;

  if (data.size() > max_data_byte_length) {
    return NewInvalidArgumentError(
        absl::StrFormat("data length (%d bytes) exceeds maximum allowed "
                        "for a %d-bit key (%d bytes)",
                        data.size(), RSA_bits(key_.get()),
                        max_data_byte_length),
        CKR_DATA_LEN_RANGE, SOURCE_LOCATION);
  }

  if (signature.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat(
            "provided signature buffer has incorrect size (got %d, want %d)",
            signature.size(), signature_length()),
        SOURCE_LOCATION);
  }

  kms_v1::AsymmetricSignRequest req;
  req.set_name(std::string(object_->kms_key_name()));
  req.set_data(
      std::string(reinterpret_cast<const char*>(data.data()), data.size()));

  ASSIGN_OR_RETURN(kms_v1::AsymmetricSignResponse resp,
                   client->AsymmetricSign(req));
  std::copy(resp.signature().begin(), resp.signature().end(),
            signature.begin());
  return absl::OkStatus();
}

class RsaRawPkcs1Verifier : public VerifierInterface {
 public:
  static absl::StatusOr<std::unique_ptr<VerifierInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  Object* object() override { return object_.get(); };

  absl::Status Verify(KmsClient* client, absl::Span<const uint8_t> data,
                      absl::Span<const uint8_t> signature) override;

  virtual ~RsaRawPkcs1Verifier() {}

 private:
  RsaRawPkcs1Verifier(std::shared_ptr<Object> object, bssl::UniquePtr<RSA> key)
      : object_(object), key_(std::move(key)) {}

  std::shared_ptr<Object> object_;
  bssl::UniquePtr<RSA> key_;
};

absl::StatusOr<std::unique_ptr<VerifierInterface>> NewRsaRawPkcs1Verifier(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  CK_MECHANISM inner_mechanism = {CKM_RSA_PKCS, mechanism->pParameter,
                                  mechanism->ulParameterLen};
  ASSIGN_OR_RETURN(auto verifier,
                   RsaRawPkcs1Verifier::New(key, &inner_mechanism));
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS:
      return verifier;
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS: {
      return KmsDigestingVerifier::New(key, std::move(verifier), mechanism);
    }
    default:
      return NewInternalError(
          absl::StrFormat(
              "Mechanism %#x not supported for raw RSA-PKCS#1 verification",
              mechanism->mechanism),
          SOURCE_LOCATION);
  }
}

absl::StatusOr<std::unique_ptr<VerifierInterface>> RsaRawPkcs1Verifier::New(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism) {
  RETURN_IF_ERROR(
      CheckKeyPreconditions(CKK_RSA, CKO_PUBLIC_KEY, CKM_RSA_PKCS, key.get()));
  RETURN_IF_ERROR(EnsureNoParameters(mechanism));

  ASSIGN_OR_RETURN(std::string_view key_der,
                   key->attributes().Value(CKA_PUBLIC_KEY_INFO));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> parsed_key,
                   ParseX509PublicKeyDer(key_der));

  return std::unique_ptr<VerifierInterface>(new RsaRawPkcs1Verifier(
      key, bssl::UniquePtr<RSA>(EVP_PKEY_get1_RSA(parsed_key.get()))));
}

absl::Status RsaRawPkcs1Verifier::Verify(KmsClient* client,
                                         absl::Span<const uint8_t> data,
                                         absl::Span<const uint8_t> signature) {
  return RsaVerifyRawPkcs1(key_.get(), data, signature);
}

}  // namespace cloud_kms::kmsp11
