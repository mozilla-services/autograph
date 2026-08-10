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

#include "common/kms_client.h"

#include "absl/crc/crc32c.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "cloudkms_grpc_service_config.h"
#include "common/backoff.h"
#include "common/openssl.h"
#include "common/platform.h"
#include "common/source_location.h"
#include "common/status_macros.h"
#include "grpcpp/client_context.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"

namespace cloud_kms {
namespace {

// clang-format off
// Sample value:
// `cloud-kms-pkcs11/0.21 (amd64; BoringSSL; Linux/4.15.0-1096-gcp-x86_64; glibc/2.23)`
// clang-format on
std::string ComputeUserAgentPrefix(UserAgent user_agent,
                                   const int version_major,
                                   const int version_minor) {
  // New user agents need to be registered in Concord, see cl/315314203.
  switch (user_agent) {
    case UserAgent::kPkcs11:
      return absl::StrFormat(
          "cloud-kms-pkcs11/%d.%d (%s; %s%s; %s)", version_major, version_minor,
          GetTargetPlatform(), OpenSSL_version(OPENSSL_VERSION),
          FIPS_mode() == 1 ? " FIPS" : "", GetHostPlatformInfo());
    case UserAgent::kCng:
      return absl::StrFormat(
          "cloud-kms-cng/%d.%d (%s; %s%s; %s)", version_major, version_minor,
          GetTargetPlatform(), OpenSSL_version(OPENSSL_VERSION),
          FIPS_mode() == 1 ? " FIPS" : "", GetHostPlatformInfo());
  }
}

absl::StatusOr<std::string> GetDigestString(const kms_v1::Digest& digest) {
  switch (digest.digest_case()) {
    case kms_v1::Digest::kSha256:
      return digest.sha256();
      break;
    case kms_v1::Digest::kSha384:
      return digest.sha384();
      break;
    case kms_v1::Digest::kSha512:
      return digest.sha512();
    default:
      return absl::InternalError(
          absl::StrFormat("at %s: could not get digest field of the request",
                          SOURCE_LOCATION.ToString()));
  }
}

uint32_t ComputeCRC32C(std::string_view data) {
  return static_cast<uint32_t>(absl::ComputeCrc32c(data));
}

bool CRC32CMatches(std::string_view data, uint32_t crc32c) {
  return crc32c == ComputeCRC32C(data);
}

}  // namespace

void KmsClient::AddContextSettings(grpc::ClientContext* ctx,
                                   std::string_view relative_resource,
                                   std::string_view resource_name,
                                   absl::Time rpc_deadline) const {
  // See https://cloud.google.com/kms/docs/grpc
  ctx->AddMetadata("x-goog-request-params",
                   absl::StrCat(relative_resource, "=", resource_name));
  ctx->set_deadline(absl::ToChronoTime(rpc_deadline));

  if (!user_project_override_.empty()) {
    ctx->AddMetadata("x-goog-user-project", user_project_override_);
  }
  if (!rpc_feature_flags_.empty()) {
    ctx->AddMetadata("x-cloud-kms-features", rpc_feature_flags_);
  }
}

absl::Status KmsClient::DecorateStatus(absl::Status& status) const {
  if (error_decorator_.has_value()) {
    (*error_decorator_)(status);
  }
  return status;
}

KmsClient::KmsClient(const Options& options)
    : rpc_timeout_(options.rpc_timeout),
      rpc_feature_flags_(options.rpc_feature_flags),
      user_project_override_(options.user_project_override),
      error_decorator_(options.error_decorator) {
  grpc::ChannelArguments args;
  args.SetUserAgentPrefix(ComputeUserAgentPrefix(
      options.user_agent, options.version_major, options.version_minor));
  args.SetServiceConfigJSON(std::string(kDefaultCloudKmsGrpcServiceConfig));

  std::shared_ptr<grpc::Channel> channel = grpc::CreateCustomChannel(
      std::string(options.endpoint_address), options.creds, args);

  kms_stub_ = kms_v1::KeyManagementService::NewStub(channel);
}

absl::StatusOr<kms_v1::AsymmetricDecryptResponse> KmsClient::AsymmetricDecrypt(
    kms_v1::AsymmetricDecryptRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  request.mutable_ciphertext_crc32c()->set_value(
      ComputeCRC32C(request.ciphertext()));

  kms_v1::AsymmetricDecryptResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->AsymmetricDecrypt(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }

  if (!CRC32CMatches(response.plaintext(),
                     response.plaintext_crc32c().value())) {
    rpc_result = absl::InternalError(absl::StrFormat(
        "at %s: the response crc32c did not match the expected checksum value",
        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  if (!response.verified_ciphertext_crc32c()) {
    rpc_result = absl::InternalError(
        absl::StrFormat("at %s: the server did not verify the checksum values "
                        "provided in the request",
                        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  return response;
}

absl::StatusOr<kms_v1::AsymmetricSignResponse> KmsClient::AsymmetricSign(
    kms_v1::AsymmetricSignRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  bool use_data = false;
  if (!request.data().empty()) {
    use_data = true;
    request.mutable_data_crc32c()->set_value(ComputeCRC32C(request.data()));
  } else {
    absl::StatusOr<std::string> digest_string =
        GetDigestString(request.digest());
    if (!digest_string.ok()) {
      absl::Status status = digest_string.status();
      return DecorateStatus(status);
    }
    request.mutable_digest_crc32c()->set_value(ComputeCRC32C(*digest_string));
  }

  kms_v1::AsymmetricSignResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->AsymmetricSign(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }

  if (!CRC32CMatches(response.signature(),
                     response.signature_crc32c().value())) {
    rpc_result = absl::InternalError(absl::StrFormat(
        "at %s: the response crc32c did not match the expected checksum value",
        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  if (use_data && !response.verified_data_crc32c()) {
    rpc_result = absl::InternalError(
        absl::StrFormat("at %s: the server did not verify the checksum values "
                        "provided in the request",
                        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }
  if (!use_data && !response.verified_digest_crc32c()) {
    rpc_result = absl::InternalError(
        absl::StrFormat("at %s: the server did not verify the checksum values "
                        "provided in the request",
                        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  return response;
}

absl::StatusOr<kms_v1::MacSignResponse> KmsClient::MacSign(
    kms_v1::MacSignRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  request.mutable_data_crc32c()->set_value(ComputeCRC32C(request.data()));

  kms_v1::MacSignResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->MacSign(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }

  if (!CRC32CMatches(response.mac(), response.mac_crc32c().value())) {
    rpc_result = absl::InternalError(absl::StrFormat(
        "at %s: the response crc32c did not match the expected checksum value",
        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  if (!response.verified_data_crc32c()) {
    rpc_result = absl::InternalError(
        absl::StrFormat("at %s: the server did not verify the checksum values "
                        "provided in the request",
                        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  return response;
}

absl::StatusOr<kms_v1::MacVerifyResponse> KmsClient::MacVerify(
    kms_v1::MacVerifyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  request.mutable_data_crc32c()->set_value(ComputeCRC32C(request.data()));
  request.mutable_mac_crc32c()->set_value(ComputeCRC32C(request.mac()));

  kms_v1::MacVerifyResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->MacVerify(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }

  if (response.success() != response.verified_success_integrity()) {
    rpc_result = absl::InternalError(absl::StrFormat(
        "at %s: the response crc32c did not match the expected checksum value",
        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  if (!response.verified_data_crc32c() || !response.verified_mac_crc32c()) {
    rpc_result = absl::InternalError(
        absl::StrFormat("at %s: the server did not verify the checksum values "
                        "provided in the request",
                        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  return response;
}

absl::StatusOr<kms_v1::RawDecryptResponse> KmsClient::RawDecrypt(
    kms_v1::RawDecryptRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  request.mutable_ciphertext_crc32c()->set_value(
      ComputeCRC32C(request.ciphertext()));
  request.mutable_initialization_vector_crc32c()->set_value(
      ComputeCRC32C(request.initialization_vector()));
  request.mutable_additional_authenticated_data_crc32c()->set_value(
      ComputeCRC32C(request.additional_authenticated_data()));

  kms_v1::RawDecryptResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->RawDecrypt(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }

  if (!CRC32CMatches(response.plaintext(),
                     response.plaintext_crc32c().value())) {
    rpc_result = absl::InternalError(absl::StrFormat(
        "at %s: the response crc32c did not match the expected checksum value",
        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  return response;
}

absl::StatusOr<kms_v1::RawEncryptResponse> KmsClient::RawEncrypt(
    kms_v1::RawEncryptRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  request.mutable_plaintext_crc32c()->set_value(
      ComputeCRC32C(request.plaintext()));
  request.mutable_additional_authenticated_data_crc32c()->set_value(
      ComputeCRC32C(request.additional_authenticated_data()));
  request.mutable_initialization_vector_crc32c()->set_value(
      ComputeCRC32C(request.initialization_vector()));

  kms_v1::RawEncryptResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->RawEncrypt(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }

  if (!CRC32CMatches(response.ciphertext(),
                     response.ciphertext_crc32c().value())) {
    rpc_result = absl::InternalError(absl::StrFormat(
        "at %s: the response crc32c did not match the expected checksum value",
        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  if (!response.verified_plaintext_crc32c() ||
      !response.verified_additional_authenticated_data_crc32c() ||
      !response.verified_initialization_vector_crc32c()) {
    rpc_result = absl::InternalError(
        absl::StrFormat("at %s: the server did not verify the checksum values "
                        "provided in the request",
                        SOURCE_LOCATION.ToString()));
    return DecorateStatus(rpc_result);
  }

  return response;
}

absl::StatusOr<kms_v1::CryptoKey> KmsClient::CreateCryptoKey(
    const kms_v1::CreateCryptoKeyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "parent", request.parent());

  kms_v1::CryptoKey response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->CreateCryptoKey(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }
  return response;
}

absl::StatusOr<CryptoKeyAndVersion>
KmsClient::CreateCryptoKeyAndWaitForFirstVersion(
    const kms_v1::CreateCryptoKeyRequest& request) const {
  absl::Time deadline = absl::Now() + rpc_timeout_;

  ASSIGN_OR_RETURN(kms_v1::CryptoKey ck, CreateCryptoKey(request));

  kms_v1::CryptoKeyVersion ckv;
  if (ck.has_primary()) {
    ckv = ck.primary();
  } else {
    std::string name = absl::StrCat(ck.name(), "/cryptoKeyVersions/1");

    grpc::ClientContext ctx;
    AddContextSettings(&ctx, "name", name, deadline);

    kms_v1::GetCryptoKeyVersionRequest get_ckv_req;
    get_ckv_req.set_name(name);

    absl::Status rpc_result =
        ToStatus(kms_stub_->GetCryptoKeyVersion(&ctx, get_ckv_req, &ckv));
    if (!rpc_result.ok()) {
      return DecorateStatus(rpc_result);
    }
  }

  RETURN_IF_ERROR(WaitForGeneration(ckv, deadline));
  return CryptoKeyAndVersion{ck, ckv};
}

absl::StatusOr<kms_v1::CryptoKeyVersion>
KmsClient::CreateCryptoKeyVersionAndWait(
    const kms_v1::CreateCryptoKeyVersionRequest& request) const {
  absl::Time deadline = absl::Now() + rpc_timeout_;

  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "parent", request.parent(), deadline);

  kms_v1::CryptoKeyVersion response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->CreateCryptoKeyVersion(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }
  RETURN_IF_ERROR(WaitForGeneration(response, deadline));
  return response;
}

absl::StatusOr<kms_v1::CryptoKeyVersion> KmsClient::DestroyCryptoKeyVersion(
    const kms_v1::DestroyCryptoKeyVersionRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::CryptoKeyVersion response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->DestroyCryptoKeyVersion(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }
  return response;
}

absl::StatusOr<kms_v1::CryptoKey> KmsClient::GetCryptoKey(
    const kms_v1::GetCryptoKeyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::CryptoKey response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->GetCryptoKey(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }
  return response;
}

absl::StatusOr<kms_v1::CryptoKeyVersion> KmsClient::GetCryptoKeyVersion(
    const kms_v1::GetCryptoKeyVersionRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::CryptoKeyVersion response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->GetCryptoKeyVersion(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }
  return response;
}

absl::StatusOr<kms_v1::PublicKey> KmsClient::GetPublicKey(
    const kms_v1::GetPublicKeyRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "name", request.name());

  kms_v1::PublicKey response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->GetPublicKey(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }
  return response;
}

CryptoKeysRange KmsClient::ListCryptoKeys(
    const kms_v1::ListCryptoKeysRequest& request) const {
  return CryptoKeysRange(
      request,
      [this](const kms_v1::ListCryptoKeysRequest& request)
          -> absl::StatusOr<kms_v1::ListCryptoKeysResponse> {
        grpc::ClientContext ctx;
        AddContextSettings(&ctx, "parent", request.parent());

        kms_v1::ListCryptoKeysResponse response;
        absl::Status rpc_result =
            ToStatus(kms_stub_->ListCryptoKeys(&ctx, request, &response));
        if (!rpc_result.ok()) {
          return DecorateStatus(rpc_result);
        }
        return response;
      },
      [](kms_v1::ListCryptoKeysResponse response)
          -> std::vector<kms_v1::CryptoKey> {
        std::vector<kms_v1::CryptoKey> result(response.crypto_keys_size());
        auto& keys = *response.mutable_crypto_keys();
        std::move(keys.begin(), keys.end(), result.begin());
        return result;
      });
}

CryptoKeyVersionsRange KmsClient::ListCryptoKeyVersions(
    const kms_v1::ListCryptoKeyVersionsRequest& request) const {
  return CryptoKeyVersionsRange(
      request,
      [this](const kms_v1::ListCryptoKeyVersionsRequest& request)
          -> absl::StatusOr<kms_v1::ListCryptoKeyVersionsResponse> {
        grpc::ClientContext ctx;
        AddContextSettings(&ctx, "parent", request.parent());

        kms_v1::ListCryptoKeyVersionsResponse response;
        absl::Status rpc_result = ToStatus(
            kms_stub_->ListCryptoKeyVersions(&ctx, request, &response));
        if (!rpc_result.ok()) {
          return DecorateStatus(rpc_result);
        }
        return response;
      },
      [](kms_v1::ListCryptoKeyVersionsResponse response)
          -> std::vector<kms_v1::CryptoKeyVersion> {
        std::vector<kms_v1::CryptoKeyVersion> result(
            response.crypto_key_versions_size());
        auto& versions = *response.mutable_crypto_key_versions();
        std::move(versions.begin(), versions.end(), result.begin());
        return result;
      });
}

absl::StatusOr<kms_v1::GenerateRandomBytesResponse>
KmsClient::GenerateRandomBytes(
    const kms_v1::GenerateRandomBytesRequest& request) const {
  grpc::ClientContext ctx;
  AddContextSettings(&ctx, "location", request.location());

  kms_v1::GenerateRandomBytesResponse response;
  absl::Status rpc_result =
      ToStatus(kms_stub_->GenerateRandomBytes(&ctx, request, &response));
  if (!rpc_result.ok()) {
    return DecorateStatus(rpc_result);
  }
  return response;
}

absl::Status KmsClient::WaitForGeneration(kms_v1::CryptoKeyVersion& ckv,
                                          absl::Time deadline) const {
  // The time for newly generated HSM keys to flip to enabled in (real) KMS
  // varies from 10-40ish milliseconds depending on key type.
  constexpr absl::Duration kMinDelay = absl::Milliseconds(20);
  constexpr absl::Duration kMaxDelay = absl::Seconds(1);

  int tries = 0;
  while (ckv.state() == kms_v1::CryptoKeyVersion::PENDING_GENERATION) {
    absl::SleepFor(ComputeBackoff(kMinDelay, kMaxDelay, tries++));

    grpc::ClientContext ctx;
    AddContextSettings(&ctx, "name", ckv.name(), deadline);

    kms_v1::GetCryptoKeyVersionRequest req;
    req.set_name(ckv.name());
    absl::Status rpc_result =
        ToStatus(kms_stub_->GetCryptoKeyVersion(&ctx, req, &ckv));
    if (!rpc_result.ok()) {
      return DecorateStatus(rpc_result);
    }
  }
  return absl::OkStatus();
}

}  // namespace cloud_kms
