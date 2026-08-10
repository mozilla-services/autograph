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

#ifndef KMSP11_OBJECT_H_
#define KMSP11_OBJECT_H_

#include <string_view>

#include "absl/status/statusor.h"
#include "common/kms_v1.h"
#include "google/cloud/kms/v1/resources.pb.h"
#include "kmsp11/algorithm_details.h"
#include "kmsp11/attribute_map.h"
#include "kmsp11/cryptoki.h"

namespace cloud_kms::kmsp11 {

struct KeyPair;

// Object models a PKCS #11 Object, and logically maps to a CryptoKeyVersion in
// Cloud KMS.
//
// See go/kms-pkcs11-model
class Object {
 public:
  static absl::StatusOr<KeyPair> NewKeyPair(const kms_v1::CryptoKeyVersion& ckv,
                                            BSSL_CONST EVP_PKEY* public_key);
  static absl::StatusOr<Object> NewSecretKey(
      const kms_v1::CryptoKeyVersion& ckv);

  static absl::StatusOr<Object> NewCertificate(
      const kms_v1::CryptoKeyVersion& ckv, X509* certificate);

  std::string_view kms_key_name() const { return kms_key_name_; }
  CK_OBJECT_CLASS object_class() const { return object_class_; }
  const AlgorithmDetails& algorithm() const { return algorithm_; }
  const AttributeMap& attributes() const { return attributes_; }

 private:
  Object(std::string kms_key_name, CK_OBJECT_CLASS object_class,
         AlgorithmDetails algorithm, AttributeMap attributes)
      : kms_key_name_(kms_key_name),
        object_class_(object_class),
        algorithm_(algorithm),
        attributes_(attributes) {}

  const std::string kms_key_name_;
  const CK_OBJECT_CLASS object_class_;
  const AlgorithmDetails algorithm_;
  const AttributeMap attributes_;
};

struct KeyPair {
  Object public_key;
  Object private_key;
};

}  // namespace cloud_kms::kmsp11

#endif  // KMSP11_OBJECT_H_
