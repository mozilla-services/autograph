// Copyright 2023 Google LLC
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

#include "kmscng/object.h"

#include <cwchar>

#include "absl/strings/str_format.h"
#include "common/kms_client.h"
#include "common/kms_v1.h"
#include "common/status_macros.h"
#include "kmscng/algorithm_details.h"
#include "kmscng/cng_headers.h"
#include "kmscng/provider.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/status_utils.h"
#include "kmscng/util/string_utils.h"
#include "kmscng/version.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmscng {
namespace {

// TODO(b/270419822): drop these once crypto_utils has been migrated to common.
using cloud_kms::kmsp11::MarshalX509PublicKeyDer;
using cloud_kms::kmsp11::ParseX509PublicKeyPem;

absl::StatusOr<kms_v1::PublicKey> GetPublicKey(const KmsClient& client,
                                               std::string key_name) {
  kms_v1::GetPublicKeyRequest pub_req;
  pub_req.set_name(key_name);
  auto pub_resp = client.GetPublicKey(pub_req);
  if (!pub_resp.ok()) {
    // Populate status with more descriptive SECURITY_STATUS if not found.
    absl::Status resp_status = pub_resp.status();
    if (pub_resp.status().code() == absl::StatusCode::kNotFound) {
      SetErrorSs(resp_status, NTE_BAD_KEYSET);
    }
    return resp_status;
  }

  if (pub_resp->protection_level() != kms_v1::ProtectionLevel::HSM) {
    return NewError(
        absl::StatusCode::kFailedPrecondition,
        "the key is not loadable due to unsupported protection level",
        NTE_NOT_SUPPORTED, SOURCE_LOCATION);
  }

  return *pub_resp;
}

absl::flat_hash_map<std::wstring, std::string> BuildInfo(
    NCRYPT_PROV_HANDLE prov_handle, std::string key_name,
    AlgorithmDetails details) {
  return {
      {NCRYPT_ALGORITHM_GROUP_PROPERTY, WideToBytes(details.algorithm_group)},
      {NCRYPT_ALGORITHM_PROPERTY, WideToBytes(details.algorithm_property)},
      {NCRYPT_KEY_USAGE_PROPERTY, Uint32ToBytes(details.key_usage)},
      {NCRYPT_NAME_PROPERTY, key_name},
      {NCRYPT_PROVIDER_HANDLE_PROPERTY,
       std::string(reinterpret_cast<char*>(&prov_handle),
                   sizeof(NCRYPT_PROV_HANDLE))},
  };
}

}  // namespace

absl::StatusOr<Object*> ValidateKeyHandle(NCRYPT_PROV_HANDLE prov_handle,
                                          NCRYPT_KEY_HANDLE key_handle) {
  if (prov_handle == 0) {
    return NewInvalidArgumentError("The provider handle cannot be null",
                                   NTE_INVALID_HANDLE, SOURCE_LOCATION);
  }
  if (key_handle == 0) {
    return NewInvalidArgumentError("The key handle cannot be null",
                                   NTE_INVALID_HANDLE, SOURCE_LOCATION);
  }

  Object* object = reinterpret_cast<Object*>(key_handle);
  absl::StatusOr<std::string_view> stored_prov_handle =
      object->GetProperty(NCRYPT_PROVIDER_HANDLE_PROPERTY);
  // If FreeKey() is called after FreeProvider(), silently ignore the error and
  // return nullptr, which is handled appropriately by FreeKey().
  // TODO(b/288298206): figure out why this can happen during the SignTool flow.
  if (!stored_prov_handle.status().ok() &&
      stored_prov_handle.status().code() == absl::StatusCode::kNotFound) {
    return nullptr;
  }
  if (*stored_prov_handle != ProvHandleToBytes(prov_handle)) {
    return NewInvalidArgumentError(
        "The key handle does not match the provider handle", NTE_INVALID_HANDLE,
        SOURCE_LOCATION);
  }

  return object;
}

Object::Object(std::string kms_key_name, std::unique_ptr<KmsClient> client,
               kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
               bssl::UniquePtr<EVP_PKEY> public_key,
               absl::flat_hash_map<std::wstring, std::string> info)
    : kms_key_name_(kms_key_name),
      kms_client_(std::move(client)),
      algorithm_(algorithm),
      public_key_(std::move(public_key)),
      key_info_(info) {}

absl::StatusOr<Object*> Object::New(NCRYPT_PROV_HANDLE prov_handle,
                                    std::string key_name) {
  ASSIGN_OR_RETURN(std::unique_ptr<KmsClient> client,
                   NewKmsClient(prov_handle));
  ASSIGN_OR_RETURN(auto public_key, GetPublicKey(*client, key_name));
  absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> pub =
      ParseX509PublicKeyPem(public_key.pem());
  if (!pub.ok()) {
    absl::Status result = pub.status();
    SetErrorSs(result, NTE_INTERNAL_ERROR);
    return result;
  }
  ASSIGN_OR_RETURN(AlgorithmDetails alg_details,
                   GetDetails(public_key.algorithm()));
  auto info = BuildInfo(prov_handle, key_name, alg_details);

  // using `new` to invoke a private constructor
  return new Object(key_name, std::move(client), public_key.algorithm(),
                    *std::move(pub), info);
}

absl::StatusOr<std::string_view> Object::GetProperty(std::wstring_view name) {
  auto it = key_info_.find(name);
  if (it == key_info_.end()) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("unsupported property specified: %s",
                                    WideToString(name.data())),
                    NTE_NOT_SUPPORTED, SOURCE_LOCATION);
  }

  return it->second;
}

}  // namespace cloud_kms::kmscng
