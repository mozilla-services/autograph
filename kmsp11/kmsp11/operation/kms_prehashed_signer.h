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

#ifndef KMSP11_OPERATION_KMS_PREHASHED_SIGNER_H_
#define KMSP11_OPERATION_KMS_PREHASHED_SIGNER_H_

#include <string_view>

#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {

// An abstract SignerInterface that makes signatures using Cloud KMS.
class KmsPrehashedSigner : public SignerInterface {
 public:
  Object* object() override { return object_.get(); }

  virtual absl::Status Sign(KmsClient* client, absl::Span<const uint8_t> digest,
                            absl::Span<uint8_t> signature) override;

  virtual ~KmsPrehashedSigner() {}

 protected:
  KmsPrehashedSigner(std::shared_ptr<Object> object) : object_(object) {}

  // Copy a signature from src to dest. Virtual in order to allow conversion
  // between signature types for ECDSA signatures.
  virtual absl::Status CopySignature(std::string_view src,
                                     absl::Span<uint8_t> dest);

 private:
  std::shared_ptr<Object> object_;
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_OPERATION_KMS_PREHASHED_SIGNER_H_
