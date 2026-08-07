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

#ifndef KMSP11_OPERATION_AES_CBC_H_
#define KMSP11_OPERATION_AES_CBC_H_

#include <string_view>

#include "common/kms_client.h"
#include "kmsp11/operation/crypter_interfaces.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/string_utils.h"

namespace cloud_kms::kmsp11 {

// Returns an AesCbcEncrypter.
absl::StatusOr<std::unique_ptr<EncrypterInterface>> NewAesCbcEncrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

// Returns an AesCbcDecrypter.
absl::StatusOr<std::unique_ptr<DecrypterInterface>> NewAesCbcDecrypter(
    std::shared_ptr<Object> key, const CK_MECHANISM* mechanism);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_OPERATION_AES_CBC_H_
