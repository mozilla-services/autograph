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

#include "kmscng/object_loader.h"

#include "common/kms_client.h"
#include "common/status_macros.h"
#include "kmscng/algorithm_details.h"
#include "kmscng/provider.h"
#include "kmscng/util/logging.h"
#include "kmscng/util/string_utils.h"

namespace cloud_kms::kmscng {
namespace {

std::string EnumNameOrValue(std::string name, int value) {
  return name.empty() ? std::to_string(value) : name;
}

bool IsLoadable(const kms_v1::CryptoKeyVersion& ckv) {
  if (ckv.protection_level() != kms_v1::ProtectionLevel::HSM) {
    LOG(INFO) << "INFO: version " << ckv.name()
              << " is not loadable due to unsupported protection level "
              << EnumNameOrValue(
                     kms_v1::ProtectionLevel_Name(ckv.protection_level()),
                     ckv.protection_level());
    return false;
  }

  if (ckv.state() != kms_v1::CryptoKeyVersion::ENABLED) {
    LOG(INFO) << "INFO: version " << ckv.name()
              << " is not loadable due to unsupported state "
              << EnumNameOrValue(
                     kms_v1::CryptoKeyVersion::CryptoKeyVersionState_Name(
                         ckv.state()),
                     ckv.state());
    return false;
  }

  if (!GetDetails(ckv.algorithm()).ok()) {
    LOG(INFO) << "INFO: version " << ckv.name()
              << " is not loadable due to unsupported algorithm "
              << EnumNameOrValue(
                     kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(
                         ckv.algorithm()),
                     ckv.algorithm());
    return false;
  }

  return true;
}

}  // namespace

absl::StatusOr<std::vector<HeapAllocatedKeyDetails>> BuildCkvList(
    NCRYPT_PROV_HANDLE prov_handle, const ProviderConfig& config) {
  ASSIGN_OR_RETURN(std::unique_ptr<KmsClient> client,
                   NewKmsClient(prov_handle));
  std::vector<HeapAllocatedKeyDetails> result;
  if (config.ByteSizeLong() == 0) {
    return result;
  }

  for (const ResourceConfig& resource_config : config.resources()) {
    kms_v1::GetCryptoKeyVersionRequest ckv_req;
    ckv_req.set_name(resource_config.crypto_key_version());
    auto ckv_resp = client->GetCryptoKeyVersion(ckv_req);
    if (!ckv_resp.ok() &&
        ckv_resp.status().code() == absl::StatusCode::kNotFound) {
      // Key not found, log warning.
      LOG(INFO) << "INFO: version " << resource_config.crypto_key_version()
                << " not found.";
    }

    if (!IsLoadable(*ckv_resp)) {
      continue;
    }
    ASSIGN_OR_RETURN(AlgorithmDetails alg_details,
                     GetDetails(ckv_resp->algorithm()));
    result.push_back(HeapAllocatedKeyDetails{
        StringToWide(resource_config.crypto_key_version()),  // pszName
        alg_details.algorithm_property,                      // pszAlgid
        AT_SIGNATURE,                                        // dwLegacyKeySpec
        NCRYPT_MACHINE_KEY_FLAG                              // dwFlags
    });
  }

  return result;
}

}  // namespace cloud_kms::kmscng
