/*
 * Copyright 2022 Google LLC
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

#ifndef KMSP11_OPERATION_KMS_DIGESTING_SIGNER_H_
#define KMSP11_OPERATION_KMS_DIGESTING_SIGNER_H_

#include <string_view>

#include "common/openssl.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/operation/kms_prehashed_signer.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {

// An implementation of SignerInterface that computes the appropriate digest of
// plain input data and uses an inner KmsPrehashedSigner to compute signatures.
class KmsDigestingSigner : public SignerInterface {
 public:
  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

  static absl::StatusOr<std::unique_ptr<SignerInterface>> New(
      std::shared_ptr<Object> key,
      std::unique_ptr<SignerInterface> inner_signer,
      const CK_MECHANISM* mechanism);

  absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> data,
                    absl::Span<uint8_t> signature) override;
  absl::Status SignUpdate(KmsClient* client,
                          absl::Span<const uint8_t> data) override;
  absl::Status SignFinal(KmsClient* client,
                         absl::Span<uint8_t> signature) override;

  size_t signature_length() override;
  Object* object() override { return inner_signer_->object(); };

  virtual ~KmsDigestingSigner() {}

 protected:
  KmsDigestingSigner(std::unique_ptr<SignerInterface> signer, const EVP_MD* md)
      : inner_signer_(std::move(signer)), md_(md) {}

 private:
  std::unique_ptr<SignerInterface> inner_signer_;
  bssl::UniquePtr<EVP_MD_CTX> md_ctx_;
  const EVP_MD* md_;
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_OPERATION_KMS_DIGESTING_SIGNER_H_
