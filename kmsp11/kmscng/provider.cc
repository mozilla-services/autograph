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

#include "kmscng/provider.h"

#include <cwchar>

#include "absl/container/flat_hash_set.h"
#include "common/status_macros.h"
#include "kmscng/cng_headers.h"
#include "kmscng/util/errors.h"
#include "kmscng/util/status_utils.h"
#include "kmscng/util/string_utils.h"
#include "kmscng/version.h"

namespace cloud_kms::kmscng {
namespace {

static_assert(std::numeric_limits<NCRYPT_PROV_HANDLE>::max ==
                  std::numeric_limits<ULONG_PTR>::max,
              "NCRYPT_PROV_HANDLE width mismatches pointer width.");

absl::flat_hash_set<std::wstring> mutable_properties = {
    {kEndpointAddressProperty.data()},
    {kChannelCredentialsProperty.data()},
    {kUserProjectProperty.data()},
};

absl::flat_hash_map<std::wstring, std::string> BuildInfo() {
  const char* env_endpoint_address = std::getenv(kEndpointAddressEnvVariable);
  std::string endpoint_address = env_endpoint_address
                                     ? env_endpoint_address
                                     : "cloudkms.googleapis.com:443";
  const char* env_channel_credentials =
      std::getenv(kChannelCredentialsEnvVariable);
  std::string channel_credentials =
      env_channel_credentials ? env_channel_credentials : "default";
  const char* env_user_project = std::getenv(kUserProjectEnvVariable);
  std::string user_project = env_user_project ? env_user_project : "";

  return {
      {NCRYPT_IMPL_TYPE_PROPERTY, Uint32ToBytes(NCRYPT_IMPL_HARDWARE_FLAG)},
      {NCRYPT_VERSION_PROPERTY, Uint32ToBytes(kLibraryVersionHex)},
      {std::wstring(kEndpointAddressProperty), endpoint_address},
      {std::wstring(kChannelCredentialsProperty), channel_credentials},
      {std::wstring(kUserProjectProperty), user_project},
  };
}

}  // namespace

absl::StatusOr<std::unique_ptr<KmsClient>> NewKmsClient(
    NCRYPT_PROV_HANDLE prov_handle) {
  ASSIGN_OR_RETURN(Provider * prov, ValidateProviderHandle(prov_handle));
  KmsClient::Options options;
  ASSIGN_OR_RETURN(options.endpoint_address,
                   prov->GetProperty(kEndpointAddressProperty));
  ASSIGN_OR_RETURN(std::string_view creds_type,
                   prov->GetProperty(kChannelCredentialsProperty));
  options.creds = (creds_type == "insecure")
                      ? grpc::InsecureChannelCredentials()
                      : grpc::GoogleDefaultCredentials();
  if (!options.creds) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "Invalid Application Default Credentials. See "
                    "https://cloud.google.com/docs/authentication/"
                    "external/about-adc",
                    NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }
  ASSIGN_OR_RETURN(options.user_project_override,
                   prov->GetProperty(kUserProjectProperty));
  options.rpc_timeout = absl::Seconds(30);
  options.version_major = kLibraryVersionMajor;
  options.version_minor = kLibraryVersionMinor;
  options.user_agent = UserAgent::kCng;
  options.error_decorator = [](absl::Status& status) {
    SetErrorSs(status, NTE_INTERNAL_ERROR);
  };

  return std::make_unique<KmsClient>(options);
}

absl::StatusOr<Provider*> ValidateProviderHandle(
    NCRYPT_PROV_HANDLE prov_handle) {
  if (prov_handle == 0) {
    return NewInvalidArgumentError("The provider handle cannot be null",
                                   NTE_INVALID_HANDLE, SOURCE_LOCATION);
  }
  return reinterpret_cast<Provider*>(prov_handle);
}

Provider::Provider() : provider_info_(BuildInfo()) {}

absl::StatusOr<std::string_view> Provider::GetProperty(std::wstring_view name) {
  auto it = provider_info_.find(name);
  if (it == provider_info_.end()) {
    return NewError(absl::StatusCode::kNotFound,
                    "unsupported property specified", NTE_NOT_SUPPORTED,
                    SOURCE_LOCATION);
  }
  return it->second;
}

absl::Status Provider::SetProperty(std::wstring_view name,
                                   std::string_view value) {
  auto it = provider_info_.find(name);
  if (it == provider_info_.end()) {
    return NewError(absl::StatusCode::kNotFound,
                    "unsupported property specified", NTE_NOT_SUPPORTED,
                    SOURCE_LOCATION);
  }
  if (!mutable_properties.contains(name)) {
    return NewInvalidArgumentError("the specified property cannot be updated",
                                   NTE_INVALID_PARAMETER, SOURCE_LOCATION);
  }

  it->second = value;
  return absl::OkStatus();
}

}  // namespace cloud_kms::kmscng
