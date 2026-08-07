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

#include "kmsp11/test/resource_helpers.h"

#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "absl/time/clock.h"
#include "common/openssl.h"
#include "common/test/runfiles.h"
#include "fakekms/cpp/fakekms.h"
#include "kmsp11/main/bridge.h"
#include "kmsp11/util/crypto_utils.h"

namespace cloud_kms::kmsp11 {

absl::StatusOr<KeyPair> NewMockKeyPair(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    std::string_view public_key_runfile) {
  kms_v1::CryptoKeyVersion ckv;
  ckv.set_name(
      "projects/foo/locations/bar/keyRings/baz/cryptoKeys/qux/"
      "cryptoKeyVersions/1");
  ckv.set_algorithm(algorithm);
  ckv.set_state(kms_v1::CryptoKeyVersion::ENABLED);

  ASSIGN_OR_RETURN(std::string pub_pem, LoadTestRunfile(public_key_runfile));
  ASSIGN_OR_RETURN(bssl::UniquePtr<EVP_PKEY> pub,
                   ParseX509PublicKeyPem(pub_pem));
  return Object::NewKeyPair(ckv, pub.get());
}

absl::StatusOr<Object> NewMockSecretKey(
    kms_v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  kms_v1::CryptoKeyVersion ckv;
  ckv.set_name(
      "projects/foo/locations/bar/keyRings/baz/cryptoKeys/qux/"
      "cryptoKeyVersions/1");
  ckv.set_algorithm(algorithm);
  ckv.set_state(kms_v1::CryptoKeyVersion::ENABLED);

  return Object::NewSecretKey(ckv);
}

absl::StatusOr<bssl::UniquePtr<EVP_PKEY>> GetEVPPublicKey(
    fakekms::Server* fake_server, kms_v1::CryptoKeyVersion ckv) {
  auto client = fake_server->NewClient();
  kms_v1::PublicKey pub_proto = GetPublicKeyOrDie(client.get(), ckv);
  return ParseX509PublicKeyPem(pub_proto.pem());
}

absl::StatusOr<CK_OBJECT_HANDLE> GetObjectHandle(CK_SESSION_HANDLE session,
                                                 kms_v1::CryptoKeyVersion ckv,
                                                 CK_OBJECT_CLASS object_class) {
  CK_ATTRIBUTE attr_template[2] = {
      {CKA_ID, const_cast<char*>(ckv.name().data()), ckv.name().size()},
      {CKA_CLASS, &object_class, sizeof(object_class)},
  };
  CK_ULONG found_count;

  CK_OBJECT_HANDLE key;
  RETURN_IF_ERROR(FindObjectsInit(session, attr_template, 2));
  RETURN_IF_ERROR(FindObjects(session, &key, 1, &found_count));
  if (found_count != 1) {
    return absl::InvalidArgumentError(
        "Number of found keys should be exactly one!");
  }
  RETURN_IF_ERROR(FindObjectsFinal(session));
  return key;
}

absl::StatusOr<CK_OBJECT_HANDLE> GetPrivateKeyObjectHandle(
    CK_SESSION_HANDLE session, kms_v1::CryptoKeyVersion ckv) {
  return GetObjectHandle(session, ckv, CKO_PRIVATE_KEY);
}

absl::StatusOr<CK_OBJECT_HANDLE> GetPublicKeyObjectHandle(
    CK_SESSION_HANDLE session, kms_v1::CryptoKeyVersion ckv) {
  return GetObjectHandle(session, ckv, CKO_PUBLIC_KEY);
}

absl::StatusOr<CK_OBJECT_HANDLE> GetSecretKeyObjectHandle(
    CK_SESSION_HANDLE session, kms_v1::CryptoKeyVersion ckv) {
  return GetObjectHandle(session, ckv, CKO_SECRET_KEY);
}

}  // namespace cloud_kms::kmsp11
