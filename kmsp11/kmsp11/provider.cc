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

#include "kmsp11/provider.h"

#include "common/kms_client.h"
#include "common/status_macros.h"
#include "glog/logging.h"
#include "kmsp11/cert_authority.h"
#include "kmsp11/mechanism.h"
#include "kmsp11/util/string_utils.h"
#include "kmsp11/version.h"

namespace cloud_kms::kmsp11 {
namespace {

static const char* kDefaultKmsEndpoint = "cloudkms.googleapis.com:443";
constexpr absl::Duration kDefaultRpcTimeout = absl::Seconds(30);

absl::StatusOr<CK_INFO> NewCkInfo() {
  CK_INFO info = {
      {CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR},  // cryptokiVersion
      {0},              // manufacturerID (set with ' ' padding below)
      0,                // flags
      {0},              // libraryDescription (set with ' ' padding below)
      kLibraryVersion,  // libraryVersion
  };
  RETURN_IF_ERROR(CryptokiStrCopy("Google", info.manufacturerID));
  RETURN_IF_ERROR(CryptokiStrCopy("Cryptoki Library for Cloud KMS",
                                  info.libraryDescription));
  return info;
}

absl::StatusOr<std::unique_ptr<KmsClient>> NewKmsClient(
    const LibraryConfig& config) {
  KmsClient::Options options;
  options.endpoint_address = config.kms_endpoint().empty()
                                 ? kDefaultKmsEndpoint
                                 : config.kms_endpoint();
  if (config.use_google_compute_engine_credentials()) {
    options.creds = grpc::CompositeChannelCredentials(
        grpc::SslCredentials(grpc::SslCredentialsOptions()),
        grpc::GoogleComputeEngineCredentials());
  } else {
    options.creds = config.use_insecure_grpc_channel_credentials()
                        ? grpc::InsecureChannelCredentials()
                        : grpc::GoogleDefaultCredentials();
  }
  if (!options.creds) {
    return NewError(absl::StatusCode::kInvalidArgument,
                    "Invalid Application Default Credentials. See "
                    "https://cloud.google.com/docs/authentication/"
                    "external/about-adc",
                    CKR_ARGUMENTS_BAD, SOURCE_LOCATION);
  }
  options.rpc_timeout = config.rpc_timeout_secs() == 0
                            ? kDefaultRpcTimeout
                            : absl::Seconds(config.rpc_timeout_secs());
  options.version_major = kLibraryVersion.major;
  options.version_minor = kLibraryVersion.minor;
  options.error_decorator = [](absl::Status& status) {
    SetErrorRv(status, CKR_DEVICE_ERROR);
  };
  options.rpc_feature_flags = config.experimental_rpc_feature_flags();
  options.user_project_override = config.user_project_override();

  return std::make_unique<KmsClient>(options);
}

}  // namespace

absl::StatusOr<std::unique_ptr<Provider>> Provider::New(LibraryConfig config) {
  ASSIGN_OR_RETURN(CK_INFO info, NewCkInfo());
  ASSIGN_OR_RETURN(std::unique_ptr<KmsClient> client, NewKmsClient(config));

  std::vector<std::unique_ptr<Token>> tokens;
  tokens.reserve(config.tokens_size());
  for (const TokenConfig& tokenConfig : config.tokens()) {
    ASSIGN_OR_RETURN(std::unique_ptr<Token> token,
                     Token::New(tokens.size(), tokenConfig, client.get(),
                                config.generate_certs(), config.allow_software_keys()));
    tokens.emplace_back(std::move(token));
  }

  // using `new` to invoke a private constructor
  return std::unique_ptr<Provider>(
      new Provider(config, info, std::move(tokens), std::move(client),
                   absl::Seconds(config.refresh_interval_secs())));
}

absl::StatusOr<Token*> Provider::TokenAt(CK_SLOT_ID slot_id) {
  if (slot_id >= tokens_.size()) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("slot with ID %d does not exist", slot_id),
                    CKR_SLOT_ID_INVALID, SOURCE_LOCATION);
  }
  return tokens_[slot_id].get();
}

absl::StatusOr<CK_SESSION_HANDLE> Provider::OpenSession(
    CK_SLOT_ID slot_id, SessionType session_type) {
  ASSIGN_OR_RETURN(Token * token, TokenAt(slot_id));
  return sessions_.Add(token, session_type, kms_client_.get());
}

absl::StatusOr<std::shared_ptr<Session>> Provider::GetSession(
    CK_SESSION_HANDLE session_handle) {
  return sessions_.Get(session_handle);
}

absl::Status Provider::CloseSession(CK_SESSION_HANDLE session_handle) {
  return sessions_.Remove(session_handle);
}

absl::Status Provider::CloseAllSessions(CK_SLOT_ID slot_id) {
  RETURN_IF_ERROR(TokenAt(slot_id));
  sessions_.RemoveIf(
      [&](const Session& s) { return s.token()->slot_id() == slot_id; });
  return absl::OkStatus();
}

Provider::Refresher::Refresher(Provider* provider, absl::Duration interval)
    : thread_(
          [](Provider* provider, const absl::Duration interval,
             const absl::Notification* shutdown) {
            while (!shutdown->WaitForNotificationWithTimeout(interval)) {
              for (const std::unique_ptr<Token>& token : provider->tokens_) {
                absl::Status refresh_result =
                    token->RefreshState(*provider->kms_client_);
                if (!refresh_result.ok()) {
                  LOG(ERROR)
                      << "error refreshing state for key ring "
                      << token->key_ring_name() << ": " << refresh_result;
                }
              }
            }
          },
          provider, interval, &shutdown_) {}

Provider::Refresher::~Refresher() {
  shutdown_.Notify();
  thread_.join();
}

absl::Span<const CK_MECHANISM_TYPE> Provider::Mechanisms() {
  return mechanism_types_;
}

absl::StatusOr<CK_MECHANISM_INFO> Provider::MechanismInfo(
    CK_MECHANISM_TYPE type) {
  const auto& entry = AllMechanisms().find(type);
  if (entry == AllMechanisms().end()) {
    return NewError(absl::StatusCode::kNotFound,
                    absl::StrFormat("mechanism %#x not found", type),
                    CKR_MECHANISM_INVALID, SOURCE_LOCATION);
  }
  return entry->second;
}

}  // namespace cloud_kms::kmsp11
