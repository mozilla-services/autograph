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

#ifndef KMSP11_ALGORITHM_DETAILS_H_
#define KMSP11_ALGORITHM_DETAILS_H_

#include <optional>

#include "absl/status/statusor.h"
#include "common/kms_v1.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {

struct AlgorithmDetails {
  kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm;
  kms_v1::CryptoKey::CryptoKeyPurpose purpose;
  std::vector<CK_MECHANISM_TYPE> allowed_mechanisms;
  CK_KEY_TYPE key_type;
  size_t key_bit_length;
  CK_MECHANISM_TYPE key_gen_mechanism;
  std::optional<CK_MECHANISM_TYPE> digest_mechanism;
};

absl::StatusOr<AlgorithmDetails> GetDetails(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_ALGORITHM_DETAILS_H_
