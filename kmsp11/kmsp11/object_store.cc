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

#include "kmsp11/object_store.h"

#include "common/status_macros.h"
#include "kmsp11/util/crypto_utils.h"
#include "kmsp11/util/errors.h"

namespace cloud_kms::kmsp11 {
namespace {

// Cryptoki defines CK_OBJECT_HANDLE (and CK_ULONG) as simply `unsigned long`,
// whose size is platform-dependent. Ensure that proto's uint64 is large enough
// to hold such a value on any platform we're compiling on.
static_assert(
    sizeof(CK_OBJECT_HANDLE) <= sizeof(google::protobuf::uint64),
    "object handles must fit in proto uint64 for proto compatibility");

using ObjectStoreEntry = ObjectStoreMap::value_type;

absl::StatusOr<std::vector<ObjectStoreEntry>> ParseStoreEntries(
    const ObjectStoreState& state) {
  std::vector<ObjectStoreEntry> entries;
  for (const Key& item : state.keys()) {
    if (item.secret_key_handle() == 0 && item.private_key_handle() == 0) {
      return absl::InvalidArgumentError(
          "both secret_key_handle and private_key_handle are unset, cannot "
          "determine if key is symmetric or asymmetric");
    }
    if (item.secret_key_handle() != 0) {
      ASSIGN_OR_RETURN(Object key,
                       Object::NewSecretKey(item.crypto_key_version()));

      entries.emplace_back(item.secret_key_handle(),
                           std::make_shared<Object>(std::move(key)));
      continue;
    }
    ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> public_key,
                     ParseX509PublicKeyDer(item.public_key_der()));
    ASSIGN_OR_RETURN(
        KeyPair keypair,
        Object::NewKeyPair(item.crypto_key_version(), public_key.get()));

    if (item.public_key_handle() == 0) {
      return absl::InvalidArgumentError("public_key_handle is unset");
    }
    entries.emplace_back(
        item.public_key_handle(),
        std::make_shared<Object>(std::move(keypair.public_key)));

    if (item.private_key_handle() == 0) {
      return absl::InvalidArgumentError("private_key_handle is unset");
    }
    entries.emplace_back(
        item.private_key_handle(),
        std::make_shared<Object>(std::move(keypair.private_key)));

    if (item.has_certificate()) {
      if (item.certificate().handle() == 0) {
        return absl::InvalidArgumentError("certificate_handle is unset");
      }
      ASSIGN_OR_RETURN(
          bssl::UniquePtr<X509> x509,
          ParseX509CertificateDer(item.certificate().x509_der()));
      ASSIGN_OR_RETURN(
          Object cert,
          Object::NewCertificate(item.crypto_key_version(), x509.get()));
      entries.emplace_back(item.certificate().handle(),
                           std::make_shared<Object>(std::move(cert)));
    }
  }
  return entries;
}

// A comparison function for ObjectStore entries that sorts by KMS key name,
// followed by object class.
bool EntryCompare(const ObjectStoreEntry& e1, const ObjectStoreEntry& e2) {
  int name_cmp = e1.second->kms_key_name().compare(e2.second->kms_key_name());
  if (name_cmp == 0) {
    return e1.second->object_class() < e2.second->object_class();
  }
  return name_cmp < 0;
}

}  // namespace

absl::StatusOr<std::unique_ptr<ObjectStore>> ObjectStore::New(
    const ObjectStoreState& state) {
  absl::StatusOr<std::vector<ObjectStoreEntry>> entries =
      ParseStoreEntries(state);
  if (!entries.ok()) {
    return NewInvalidArgumentError(
        absl::StrCat("failure building ObjectStore: ",
                     entries.status().message()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  std::unique_ptr<ObjectStore> store = absl::WrapUnique(
      new ObjectStore(ObjectStoreMap(entries->begin(), entries->end())));
  if (store->entries_.size() != entries->size()) {
    return NewInvalidArgumentError(
        absl::StrFormat("duplicate handle detected: "
                        "store.entries_.size()=%d; entries.size()=%d",
                        store->entries_.size(), entries->size()),
        CKR_DEVICE_ERROR, SOURCE_LOCATION);
  }

  return std::move(store);
}

absl::StatusOr<std::shared_ptr<Object>> ObjectStore::GetObject(
    CK_OBJECT_HANDLE handle) const {
  ObjectStoreMap::const_iterator it = entries_.find(handle);
  if (it == entries_.end()) {
    return HandleNotFoundError(handle, CKR_OBJECT_HANDLE_INVALID,
                               SOURCE_LOCATION);
  }

  return it->second;
}

absl::StatusOr<std::shared_ptr<Object>> ObjectStore::GetKey(
    CK_OBJECT_HANDLE handle) const {
  ObjectStoreMap::const_iterator it = entries_.find(handle);
  if (it == entries_.end()) {
    return HandleNotFoundError(handle, CKR_KEY_HANDLE_INVALID, SOURCE_LOCATION);
  }

  switch (it->second->object_class()) {
    case CKO_PRIVATE_KEY:
    case CKO_PUBLIC_KEY:
    case CKO_SECRET_KEY:
      return it->second;
    default:
      return HandleNotFoundError(handle, CKR_KEY_HANDLE_INVALID,
                                 SOURCE_LOCATION);
  }
}

std::vector<CK_OBJECT_HANDLE> ObjectStore::Find(
    std::function<bool(const Object&)> predicate) const {
  std::vector<std::reference_wrapper<const ObjectStoreEntry>> matches;
  for (const ObjectStoreEntry& entry : entries_) {
    if (predicate(*entry.second)) {
      matches.push_back(entry);
    }
  }

  std::sort(matches.begin(), matches.end(), &EntryCompare);

  std::vector<CK_OBJECT_HANDLE> handles(matches.size());
  for (size_t i = 0; i < matches.size(); i++) {
    handles[i] = matches[i].get().first;
  }
  return handles;
}

absl::StatusOr<CK_OBJECT_HANDLE> ObjectStore::FindSingle(
    std::function<bool(const Object&)> predicate) const {
  std::optional<CK_OBJECT_HANDLE> match;
  for (const auto& [handle, object] : entries_) {
    if (predicate(*object)) {
      if (match.has_value()) {
        return absl::FailedPreconditionError("multiple matches found");
      }
      match = handle;
    }
  }
  if (!match.has_value()) {
    return absl::NotFoundError("no match found");
  }
  return *match;
}

}  // namespace cloud_kms::kmsp11
