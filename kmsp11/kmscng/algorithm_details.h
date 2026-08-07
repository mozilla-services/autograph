/*
 * Copyright 2023 Google LLC
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

#ifndef KMSCNG_ALGORITHM_DETAILS_H_
#define KMSCNG_ALGORITHM_DETAILS_H_

#include <optional>

#include "absl/status/statusor.h"
#include "common/kms_v1.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "google/cloud/kms/v1/service.pb.h"
#include "kmscng/cng_headers.h"

namespace cloud_kms::kmscng {

struct AlgorithmDetails {
  kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm;
  kms_v1::CryptoKey::CryptoKeyPurpose purpose;
  std::wstring algorithm_group;
  std::wstring algorithm_property;
  uint32_t key_usage;
};

absl::StatusOr<AlgorithmDetails> GetDetails(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm);

absl::Status IsSupportedAlgorithmIdentifier(std::wstring_view algorithm);

}  // namespace cloud_kms::kmscng

#endif  // KMSCNG_ALGORITHM_DETAILS_H_
