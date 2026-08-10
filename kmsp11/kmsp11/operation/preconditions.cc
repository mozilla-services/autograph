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

#include "kmsp11/operation/preconditions.h"

#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {

absl::Status CheckKeyPreconditions(CK_KEY_TYPE key_type,
                                   CK_OBJECT_CLASS object_class,
                                   CK_MECHANISM_TYPE mechanism_type,
                                   Object* object) {
  if (object->algorithm().key_type != key_type) {
    return FailedPreconditionError(
        absl::StrFormat("object %s has type %#x, want %#x",
                        object->kms_key_name(), object->algorithm().key_type,
                        key_type),
        CKR_KEY_TYPE_INCONSISTENT, SOURCE_LOCATION);
  }

  if (object->object_class() != object_class) {
    return FailedPreconditionError(
        absl::StrFormat("object %s has object class %#x, want %#x",
                        object->kms_key_name(), object->object_class(),
                        object_class),
        CKR_KEY_FUNCTION_NOT_PERMITTED, SOURCE_LOCATION);
  }

  const std::vector<CK_MECHANISM_TYPE>& m =
      object->algorithm().allowed_mechanisms;
  if (std::find(m.begin(), m.end(), mechanism_type) == m.end()) {
    return FailedPreconditionError(
        absl::StrFormat("mechanism %#x is not permitted for key %s",
                        mechanism_type, object->kms_key_name()),
        CKR_KEY_FUNCTION_NOT_PERMITTED, SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::Status EnsureNoParameters(const CK_MECHANISM* mechanism) {
  if (mechanism->pParameter || mechanism->ulParameterLen > 0) {
    return NewInvalidArgumentError(
        absl::StrFormat("mechanism %#x does not take parameters",
                        mechanism->mechanism),
        CKR_MECHANISM_PARAM_INVALID, SOURCE_LOCATION);
  }
  return absl::OkStatus();
}

absl::Status EnsureHashMatches(CK_MECHANISM_TYPE actual,
                               const EVP_MD* expected) {
  CK_MECHANISM_TYPE expected_ckm;
  switch (EVP_MD_type(expected)) {
    case NID_sha256:
      expected_ckm = CKM_SHA256;
      break;
    case NID_sha384:
      expected_ckm = CKM_SHA384;
      break;
    case NID_sha512:
      expected_ckm = CKM_SHA512;
      break;
    default:
      return NewInternalError(
          absl::StrFormat("unsupported EVP_MD: %d", EVP_MD_type(expected)),
          SOURCE_LOCATION);
  }

  if (expected_ckm != actual) {
    return InvalidMechanismParamError(
        absl::StrFormat("expected hash algorithm is %#x, but %#x "
                        "was supplied in the parameters",
                        expected_ckm, actual),
        SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

absl::Status EnsureMgf1HashMatches(CK_RSA_PKCS_MGF_TYPE actual,
                                   const EVP_MD* expected) {
  CK_RSA_PKCS_MGF_TYPE expected_mgf;
  switch (EVP_MD_type(expected)) {
    case NID_sha256:
      expected_mgf = CKG_MGF1_SHA256;
      break;
    case NID_sha512:
      expected_mgf = CKG_MGF1_SHA512;
      break;
    default:
      return NewInternalError(absl::StrFormat("unsupported EVP_MD for MGF1: %d",
                                              EVP_MD_type(expected)),
                              SOURCE_LOCATION);
  }

  if (expected_mgf != actual) {
    return InvalidMechanismParamError(
        absl::StrFormat(
            "expected MGF is %#x, but %#x was supplied in the parameters",
            expected_mgf, actual),
        SOURCE_LOCATION);
  }

  return absl::OkStatus();
}

}  // namespace cloud_kms::kmsp11