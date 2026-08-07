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

#include "kmsp11/object_loader.h"

#include "common/status_macros.h"
#include "glog/logging.h"
#include "kmsp11/algorithm_details.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {
namespace {

std::string EnumNameOrValue(std::string name, int value) {
  return name.empty() ? std::to_string(value) : name;
}

}  // namespace

bool ObjectLoader::IsLoadable(const kms_v1::CryptoKey& key) {
  switch (key.purpose()) {
    case kms_v1::CryptoKey::ASYMMETRIC_DECRYPT:
    case kms_v1::CryptoKey::ASYMMETRIC_SIGN:
    case kms_v1::CryptoKey::MAC:
    case kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT:
      break;
    default:
      LOG(INFO) << "INFO: key " << key.name()
                << " is not loadable due to unsupported purpose "
                << EnumNameOrValue(
                       kms_v1::CryptoKey::CryptoKeyPurpose_Name(key.purpose()),
                       key.purpose());
      return false;
  }

  if (key.version_template().protection_level() !=
          kms_v1::ProtectionLevel::HSM &&
      key.version_template().protection_level() !=
          kms_v1::ProtectionLevel::SOFTWARE &&
      key.version_template().protection_level() !=
          kms_v1::ProtectionLevel::HSM_SINGLE_TENANT) {
    LOG(INFO) << "INFO: key " << key.name()
              << " is not loadable due to unsupported protection level "
              << EnumNameOrValue(kms_v1::ProtectionLevel_Name(
                                     key.version_template().protection_level()),
                                 key.version_template().protection_level());
    return false;
  }

  if (key.version_template().protection_level() ==
          kms_v1::ProtectionLevel::SOFTWARE &&
      !allow_software_keys_) {
    LOG(INFO) << "INFO: key " << key.name()
              << " is not loadable because it has protection level = "
                 "SOFTWARE but only keys with protection level = HSM are "
                 "allowed. If you want to be able to use software keys, use "
                 "allow_software_keys in the configuration.";
    return false;
  }
  return true;
}

bool ObjectLoader::IsLoadable(const kms_v1::CryptoKeyVersion& ckv) {
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

Key* ObjectLoader::Cache::Get(std::string_view ckv_name) {
  auto it = keys_.find(ckv_name);
  if (it == keys_.end()) {
    return nullptr;
  }

  return it->second.get();
}

Key* ObjectLoader::Cache::Store(const kms_v1::CryptoKeyVersion& ckv,
                                std::string_view public_key_der,
                                std::string_view certificate_der) {
  keys_[ckv.name()] = std::make_unique<Key>();
  Key* key = keys_[ckv.name()].get();

  *key->mutable_crypto_key_version() = ckv;
  key->set_public_key_handle(NewHandle());
  key->set_private_key_handle(NewHandle());
  key->set_public_key_der(std::string(public_key_der));

  if (!certificate_der.empty()) {
    key->mutable_certificate()->set_x509_der(std::string(certificate_der));
    key->mutable_certificate()->set_handle(NewHandle());
  }

  return key;
}

Key* ObjectLoader::Cache::StoreSecretKey(const kms_v1::CryptoKeyVersion& ckv) {
  keys_[ckv.name()] = std::make_unique<Key>();
  Key* key = keys_[ckv.name()].get();

  *key->mutable_crypto_key_version() = ckv;
  key->set_secret_key_handle(NewHandle());

  return key;
}

void ObjectLoader::Cache::EvictUnused(const ObjectStoreState& state) {
  absl::flat_hash_set<std::string> items_to_retain;
  for (const Key& key : state.keys()) {
    items_to_retain.insert(key.crypto_key_version().name());
  }

  auto it = keys_.begin();
  while (it != keys_.end()) {
    if (items_to_retain.contains(it->first)) {
      it++;
      continue;
    }

    if (it->second->public_key_handle() != CK_INVALID_HANDLE) {
      allocated_handles_.erase(it->second->public_key_handle());
    }
    if (it->second->private_key_handle() != CK_INVALID_HANDLE) {
      allocated_handles_.erase(it->second->private_key_handle());
    }
    if (it->second->has_certificate()) {
      allocated_handles_.erase(it->second->certificate().handle());
    }
    if (it->second->secret_key_handle() != CK_INVALID_HANDLE) {
      allocated_handles_.erase(it->second->secret_key_handle());
    }
    keys_.erase(it++);
  }
}

CK_OBJECT_HANDLE ObjectLoader::Cache::NewHandle() {
  CK_OBJECT_HANDLE handle;
  do {
    handle = RandomHandle();
  } while (allocated_handles_.contains(handle));
  allocated_handles_.insert(handle);
  return handle;
}

absl::StatusOr<std::unique_ptr<ObjectLoader>> ObjectLoader::New(
    std::string_view key_ring_name,
    absl::Span<const std::string* const> pem_user_certs, bool generate_certs,
    bool allow_software_keys) {
  absl::flat_hash_map<std::string, std::string> user_certs;
  for (const std::string* const pem_cert : pem_user_certs) {
    ASSIGN_OR_RETURN(bssl::UniquePtr<X509> parsed_cert,
                     ParseX509CertificatePem(*pem_cert));
    bssl::UniquePtr<EVP_PKEY> public_key(X509_get_pubkey(parsed_cert.get()));
    if (!public_key) {
      return NewInternalError(
          absl::StrCat("failed to retrieve X.509 certificate's public key: ",
                       SslErrorToString()),
          SOURCE_LOCATION);
    }
    ASSIGN_OR_RETURN(std::string der_public_key,
                     MarshalX509PublicKeyDer(public_key.get()));
    ASSIGN_OR_RETURN(user_certs[der_public_key],
                     MarshalX509CertificateDer(parsed_cert.get()));
  }

  std::unique_ptr<CertAuthority> cert_authority;
  if (generate_certs) {
    ASSIGN_OR_RETURN(cert_authority, CertAuthority::New());
  }

  return absl::WrapUnique(new ObjectLoader(key_ring_name, user_certs,
                                           std::move(cert_authority),
                                           allow_software_keys));
}

absl::StatusOr<ObjectStoreState> ObjectLoader::BuildState(
    const KmsClient& client) {
  // In the initial implementation of Provider::LoopRefresh, there is no danger
  // of overlapping calls to BuildState. That said, holding the mutex for the
  // duration of BuildState seems like a pretty cheap way to guard against an
  // unintentional change that causes BuildState calls to overlap.
  absl::MutexLock lock(&cache_mutex_);
  ObjectStoreState result;

  kms_v1::ListCryptoKeysRequest req;
  req.set_parent(key_ring_name_);
  CryptoKeysRange keys = client.ListCryptoKeys(req);

  for (CryptoKeysRange::iterator it = keys.begin(); it != keys.end(); it++) {
    ASSIGN_OR_RETURN(kms_v1::CryptoKey key, *it);
    if (!IsLoadable(key)) {
      continue;
    }

    kms_v1::ListCryptoKeyVersionsRequest req;
    req.set_parent(key.name());
    CryptoKeyVersionsRange v = client.ListCryptoKeyVersions(req);

    for (CryptoKeyVersionsRange::iterator it = v.begin(); it != v.end(); it++) {
      ASSIGN_OR_RETURN(kms_v1::CryptoKeyVersion ckv, *it);
      if (!IsLoadable(ckv)) {
        continue;
      }

      Key* cached_key = cache_.Get(ckv.name());
      if (cached_key) {
        *result.add_keys() = *cached_key;
        continue;
      }

      if (key.purpose() == kms_v1::CryptoKey::MAC ||
          key.purpose() == kms_v1::CryptoKey::RAW_ENCRYPT_DECRYPT) {
        *result.add_keys() = *cache_.StoreSecretKey(ckv);
      } else {
        kms_v1::GetPublicKeyRequest pub_req;
        pub_req.set_name(ckv.name());

        ASSIGN_OR_RETURN(kms_v1::PublicKey pub_resp,
                         client.GetPublicKey(pub_req));
        ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> pub,
                         ParseX509PublicKeyPem(pub_resp.pem()));
        ASSIGN_OR_RETURN(std::string public_key_der,
                         MarshalX509PublicKeyDer(pub.get()));

        std::string cert_der;
        if (auto it = user_certs_.find(public_key_der);
            it != user_certs_.end()) {
          cert_der = it->second;
        } else if (cert_authority_) {
          ASSIGN_OR_RETURN(bssl::UniquePtr<X509> cert,
                           cert_authority_->GenerateCert(ckv, pub.get()));
          ASSIGN_OR_RETURN(cert_der, MarshalX509CertificateDer(cert.get()));
        }

        *result.add_keys() = *cache_.Store(ckv, public_key_der, cert_der);
      }
    }
  }

  // Compute the unused user certificates by copying all of them, then removing
  // the ones that were actually used.
  absl::flat_hash_set<std::string> unused_user_certs;
  for (const auto& [spki, cert] : user_certs_) {
    unused_user_certs.emplace(cert);
  }
  for (const Key& key : result.keys()) {
    unused_user_certs.erase(key.certificate().x509_der());
  }
  if (unused_user_certs.size() > 0) {
    LOG(INFO) << "INFO: one or more provided certificates could not be matched "
                 "to a KMS key.";
  }

  cache_.EvictUnused(result);
  return result;
}

}  // namespace cloud_kms::kmsp11
