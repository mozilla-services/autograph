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

#include "kmsp11/operation/kms_prehashed_signer.h"

#include "common/kms_client.h"
#include "common/status_macros.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

absl::Status KmsPrehashedSigner::Sign(KmsClient* client,
                                      absl::Span<const uint8_t> digest,
                                      absl::Span<uint8_t> signature) {
  ASSIGN_OR_RETURN(const EVP_MD* md,
                   DigestForMechanism(*object_->algorithm().digest_mechanism));

  if (digest.size() != EVP_MD_size(md)) {
    return NewInvalidArgumentError(
        absl::StrFormat("provided digest has incorrect size (got %d, want %d)",
                        digest.size(), EVP_MD_size(md)),
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
                   client->AsymmetricSign(req));
  RETURN_IF_ERROR(CopySignature(resp.signature(), signature));
  return absl::OkStatus();
}

absl::Status KmsPrehashedSigner::CopySignature(std::string_view src,
                                            absl::Span<uint8_t> dest) {
  if (src.size() != signature_length()) {
    return NewInternalError(
        absl::StrFormat("unexpected signature length (got %d, want %d)",
                        src.size(), signature_length()),
        SOURCE_LOCATION);
  }
  std::copy(src.begin(), src.end(), dest.data());
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmsp11
