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

#ifndef KMSP11_MECHANISM_H_
#define KMSP11_MECHANISM_H_

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/types/span.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {

// Returns the mechanism types supported in this library and their corresponding
// mechanism info.
const absl::flat_hash_map<CK_MECHANISM_TYPE, const CK_MECHANISM_INFO>&
AllMechanisms();

// Returns all mechanisms corresponding to KMS algorithms for MAC keys.
const absl::flat_hash_set<CK_MECHANISM_TYPE>& AllMacMechanisms();

// Returns all mechanisms corresponding to KMS algorithms for
// RAW_ENCRYPT_DECRYPT keys.
const absl::flat_hash_set<CK_MECHANISM_TYPE>& AllRawEncryptionMechanisms();

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_MECHANISM_H_
