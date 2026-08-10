// Copyright 2022 Google LLC
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

#include "kmsp11/operation/kms_digesting_verifier.h"

#include "common/kms_client.h"
#include "common/status_macros.h"
#include "kmsp11/operation/preconditions.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

absl::StatusOr<std::unique_ptr<VerifierInterface>> KmsDigestingVerifier::New(
    std::shared_ptr<Object> key,
    std::unique_ptr<VerifierInterface> inner_verifier,
    const CK_MECHANISM* mechanism) {
  ASSIGN_OR_RETURN(const EVP_MD* md, DigestForMechanism(mechanism->mechanism));
  return std::unique_ptr<VerifierInterface>(
      new KmsDigestingVerifier(std::move(inner_verifier), md));
}

absl::Status KmsDigestingVerifier::Verify(KmsClient* client,
                                          absl::Span<const uint8_t> data,
                                          absl::Span<const uint8_t> signature) {
  if (md_ctx_) {
    return FailedPreconditionError(
        "Verify cannot be used to terminate a multi-part verify operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  const size_t md_size = EVP_MD_size(md_);
  std::vector<uint8_t> evp_digest(md_size);
  unsigned int digest_len;
  bssl::UniquePtr<EVP_MD_CTX> ctx(EVP_MD_CTX_new());
  if (EVP_Digest(data.data(), data.size(), evp_digest.data(), &digest_len, md_,
                 nullptr) != 1) {
    return NewInternalError(
        absl::StrFormat(
            "failed while computing EVP digest with digest size %d: %s",
            md_size, SslErrorToString()),
        SOURCE_LOCATION);
  }

  if (digest_len != md_size) {
    return NewInternalError(
        absl::StrFormat(
            "computed digest has incorrect size (got %d, want %d): %s",
            digest_len, md_size, SslErrorToString()),
        SOURCE_LOCATION);
  }

  if (IsRawRsaAlgorithm(object()->algorithm().algorithm)) {
    ASSIGN_OR_RETURN(std::vector<uint8_t> digest_info,
                     BuildRsaDigestInfo(EVP_MD_type(md_), evp_digest));
    return inner_verifier_->Verify(client, digest_info, signature);
  }

  return inner_verifier_->Verify(client, evp_digest, signature);
}

absl::Status KmsDigestingVerifier::VerifyUpdate(
    KmsClient* client, absl::Span<const uint8_t> data) {
  if (!md_ctx_) {
    md_ctx_ = bssl::UniquePtr<EVP_MD_CTX>(EVP_MD_CTX_new());
    if (EVP_DigestInit(md_ctx_.get(), md_) != 1) {
      return NewInternalError(
          absl::StrFormat(
              "failed while initializing EVP digest with digest size %d: %s",
              EVP_MD_size(md_), SslErrorToString()),
          SOURCE_LOCATION);
    }
  }

  if (EVP_DigestUpdate(md_ctx_.get(), data.data(), data.size()) != 1) {
    return NewInternalError(
        absl::StrCat("failed while updating EVP digest with input data: ",
                     SslErrorToString()),
        SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::Status KmsDigestingVerifier::VerifyFinal(
    KmsClient* client, absl::Span<const uint8_t> signature) {
  if (!md_ctx_) {
    return FailedPreconditionError(
        "VerifyUpdate needs to be called prior to terminating a multi-part "
        "verify operation",
        CKR_FUNCTION_FAILED, SOURCE_LOCATION);
  }

  std::vector<uint8_t> evp_digest(EVP_MD_size(md_));
  unsigned int digest_len;
  if (EVP_DigestFinal(md_ctx_.get(), evp_digest.data(), &digest_len) != 1) {
    return NewInternalError(absl::StrCat("failed while finalizing EVP digest: ",
                                         SslErrorToString()),
                            SOURCE_LOCATION);
  }

  if (digest_len != EVP_MD_size(md_)) {
    return NewInternalError(
        absl::StrFormat(
            "computed digest has incorrect size (got %d, want %d): %s",
            digest_len, EVP_MD_size(md_), SslErrorToString()),
        SOURCE_LOCATION);
  }

  if (IsRawRsaAlgorithm(object()->algorithm().algorithm)) {
    ASSIGN_OR_RETURN(std::vector<uint8_t> digest_info,
                     BuildRsaDigestInfo(EVP_MD_type(md_), evp_digest));
    return inner_verifier_->Verify(client, digest_info, signature);
  }

  return inner_verifier_->Verify(client, evp_digest, signature);
}

}  // namespace cloud_kms::kmsp11
