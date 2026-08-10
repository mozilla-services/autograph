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

#ifndef KMSP11_OPERATION_CRYPTER_OPS_H_
#define KMSP11_OPERATION_CRYPTER_OPS_H_

#include "kmsp11/operation/crypter_interfaces.h"

namespace cloud_kms::kmsp11 {

using DecryptOp = std::unique_ptr<DecrypterInterface>;

absl::StatusOr<DecryptOp> NewDecryptOp(std::shared_ptr<Object> key,
                                       const CK_MECHANISM* mechanism);

using EncryptOp = std::unique_ptr<EncrypterInterface>;

absl::StatusOr<EncryptOp> NewEncryptOp(std::shared_ptr<Object> key,
                                       const CK_MECHANISM* mechanism);

using SignOp = std::unique_ptr<SignerInterface>;

absl::StatusOr<SignOp> NewSignOp(std::shared_ptr<Object> key,
                                 const CK_MECHANISM* mechanism);

using VerifyOp = std::unique_ptr<VerifierInterface>;

absl::StatusOr<VerifyOp> NewVerifyOp(std::shared_ptr<Object> key,
                                     const CK_MECHANISM* mechanism);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_OPERATION_CRYPTER_OPS_H_
