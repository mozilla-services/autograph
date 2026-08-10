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

#include "common/test/resource_helpers.h"

#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "absl/time/clock.h"
#include "common/openssl.h"
#include "fakekms/cpp/fakekms.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms {

// TODO(b/270419822): Clean up these using statements once crypto_utils has
// been moved to common.
using ::cloud_kms::kmsp11::RandBytes;

kms_v1::KeyRing CreateKeyRingOrDie(kms_v1::KeyManagementService::Stub* kms_stub,
                                   std::string_view location_name,
                                   std::string_view key_ring_id,
                                   const kms_v1::KeyRing& key_ring) {
  kms_v1::CreateKeyRingRequest req;
  req.set_parent(std::string(location_name));
  req.set_key_ring_id(std::string(key_ring_id));
  *req.mutable_key_ring() = key_ring;

  kms_v1::KeyRing kr;
  grpc::ClientContext ctx;

  CHECK_OK(kms_stub->CreateKeyRing(&ctx, req, &kr));
  return kr;
}

kms_v1::CryptoKey CreateCryptoKeyOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    std::string_view key_ring_name, std::string_view crypto_key_id,
    const kms_v1::CryptoKey& crypto_key, bool skip_initial_version_creation) {
  kms_v1::CreateCryptoKeyRequest req;
  req.set_parent(std::string(key_ring_name));
  req.set_crypto_key_id(std::string(crypto_key_id));
  *req.mutable_crypto_key() = crypto_key;
  req.set_skip_initial_version_creation(skip_initial_version_creation);

  kms_v1::CryptoKey ck;
  grpc::ClientContext ctx;

  CHECK_OK(kms_stub->CreateCryptoKey(&ctx, req, &ck));
  return ck;
}

kms_v1::CryptoKeyVersion CreateCryptoKeyVersionOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    std::string_view crypto_key_name,
    const kms_v1::CryptoKeyVersion& crypto_key_version) {
  kms_v1::CreateCryptoKeyVersionRequest req;
  req.set_parent(std::string(crypto_key_name));
  *req.mutable_crypto_key_version() = crypto_key_version;

  kms_v1::CryptoKeyVersion ckv;
  grpc::ClientContext ctx;

  CHECK_OK(kms_stub->CreateCryptoKeyVersion(&ctx, req, &ckv));
  return ckv;
}

kms_v1::CryptoKey GetCryptoKeyOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    std::string_view crypto_key_name) {
  kms_v1::GetCryptoKeyRequest req;
  req.set_name(std::string(crypto_key_name));

  kms_v1::CryptoKey ck;
  grpc::ClientContext ctx;

  CHECK_OK(kms_stub->GetCryptoKey(&ctx, req, &ck));
  return ck;
}

kms_v1::CryptoKeyVersion GetCryptoKeyVersionOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    std::string_view crypto_key_version_name) {
  kms_v1::GetCryptoKeyVersionRequest req;
  req.set_name(std::string(crypto_key_version_name));

  kms_v1::CryptoKeyVersion ckv;
  grpc::ClientContext ctx;

  CHECK_OK(kms_stub->GetCryptoKeyVersion(&ctx, req, &ckv));
  return ckv;
}

kms_v1::CryptoKeyVersion WaitForEnablement(
    kms_v1::KeyManagementService::Stub* kms_stub,
    const kms_v1::CryptoKeyVersion& crypto_key_version,
    absl::Duration poll_interval) {
  kms_v1::CryptoKeyVersion ckv = crypto_key_version;
  while (ckv.state() !=
         kms_v1::CryptoKeyVersion_CryptoKeyVersionState_ENABLED) {
    absl::SleepFor(poll_interval);
    kms_v1::GetCryptoKeyVersionRequest req;
    req.set_name(ckv.name());

    grpc::ClientContext ctx;
    CHECK_OK(kms_stub->GetCryptoKeyVersion(&ctx, req, &ckv));
  }
  return ckv;
}

kms_v1::CryptoKeyVersion UpdateCryptoKeyVersionOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    const kms_v1::CryptoKeyVersion& crypto_key_version,
    const google::protobuf::FieldMask& update_mask) {
  kms_v1::UpdateCryptoKeyVersionRequest req;
  *req.mutable_crypto_key_version() = crypto_key_version;
  *req.mutable_update_mask() = update_mask;

  kms_v1::CryptoKeyVersion ckv;
  grpc::ClientContext ctx;

  CHECK_OK(kms_stub->UpdateCryptoKeyVersion(&ctx, req, &ckv));
  return ckv;
}

kms_v1::PublicKey GetPublicKeyOrDie(
    kms_v1::KeyManagementService::Stub* kms_stub,
    const kms_v1::CryptoKeyVersion& crypto_key_version) {
  kms_v1::GetPublicKeyRequest req;
  req.set_name(crypto_key_version.name());

  kms_v1::PublicKey pub;
  grpc::ClientContext ctx;

  CHECK_OK(kms_stub->GetPublicKey(&ctx, req, &pub));
  return pub;
}

std::string RandomId(std::string_view prefix) {
  return absl::StrFormat("%s-%s", prefix,
                         absl::BytesToHexString(RandBytes(12)));
}

}  // namespace cloud_kms
