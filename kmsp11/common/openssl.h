/*
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMON_OPENSSL_H_
#define COMMON_OPENSSL_H_

#include "openssl/bio.h"       // IWYU pragma: export
#include "openssl/bn.h"        // IWYU pragma: export
#include "openssl/conf.h"      // IWYU pragma: export
#include "openssl/crypto.h"    // IWYU pragma: export
#include "openssl/ec.h"        // IWYU pragma: export
#include "openssl/ecdsa.h"     // IWYU pragma: export
#include "openssl/err.h"       // IWYU pragma: export
#include "openssl/evp.h"       // IWYU pragma: export
#include "openssl/pem.h"       // IWYU pragma: export
#include "openssl/rand.h"      // IWYU pragma: export
#include "openssl/rsa.h"       // IWYU pragma: export
#include "openssl/x509.h"      // IWYU pragma: export
#include "openssl/x509_vfy.h"  // IWYU pragma: export
#include "openssl/x509v3.h"    // IWYU pragma: export

#ifdef OPENSSL_IS_BORINGSSL
#define BSSL_CONST const

#else  // OPENSSL_IS_BORINGSSL

#define BSSL_CONST

#include <memory>

extern "C" {
#include "openssl/libcrypto-compat.h"
}

// bssl::UniquePtr implementation cribbed from
// https://github.com/google/boringssl/blob/49f0329110a1d93a5febc2bceceedc655d995420/include/openssl/base.h#L510

#define MAKE_DELETER(type, deleter)              \
  template <>                                    \
  struct Deleter<type> {                         \
    void operator()(type* ptr) { deleter(ptr); } \
  };

namespace bssl {

template <typename T, typename Enable = void>
struct Deleter {};

template <typename T>
using UniquePtr = std::unique_ptr<T, Deleter<T> >;

MAKE_DELETER(ASN1_OBJECT, ASN1_OBJECT_free);
MAKE_DELETER(ASN1_TIME, ASN1_TIME_free);
MAKE_DELETER(BIGNUM, BN_free);
MAKE_DELETER(BIO, BIO_free);
MAKE_DELETER(BN_CTX, BN_CTX_free);
MAKE_DELETER(CONF, NCONF_free);
MAKE_DELETER(EC_GROUP, EC_GROUP_free);
MAKE_DELETER(EC_KEY, EC_KEY_free);
MAKE_DELETER(EC_POINT, EC_POINT_free);
MAKE_DELETER(ECDSA_SIG, ECDSA_SIG_free);
MAKE_DELETER(EVP_MD_CTX, EVP_MD_CTX_free);
MAKE_DELETER(EVP_PKEY, EVP_PKEY_free);
MAKE_DELETER(EVP_PKEY_CTX, EVP_PKEY_CTX_free);
MAKE_DELETER(RSA, RSA_free);
MAKE_DELETER(X509, X509_free);
MAKE_DELETER(X509_EXTENSION, X509_EXTENSION_free);
MAKE_DELETER(X509_SIG, X509_SIG_free);
MAKE_DELETER(X509_STORE, X509_STORE_free);
MAKE_DELETER(X509_STORE_CTX, X509_STORE_CTX_free);

}  // namespace bssl

// A hook for version-specific initialization required for OpenSSL.
// BoringSSL contains a function called CRYPTO_library_init() that
// does nothing.
void CRYPTO_library_init();

// A handful of functions that we use are unavailable in older OpenSSL
// versions; add our own implementations.
#if OPENSSL_VERSION_NUMBER < 0x10100000L

#define OpenSSL_version SSLeay_version
#define OPENSSL_VERSION SSLEAY_VERSION
#define ASN1_STRING_get0_data ASN1_STRING_data

EC_KEY* EVP_PKEY_get0_EC_KEY(EVP_PKEY* pkey);

const ASN1_TIME* X509_get0_notAfter(const X509* x);
const ASN1_TIME* X509_get0_notBefore(const X509* x);

void X509_SIG_get0(const X509_SIG* sig, const X509_ALGOR** out_alg,
                   const ASN1_OCTET_STRING** out_digest);

void X509_SIG_getm(X509_SIG* sig, X509_ALGOR** out_alg,
                   ASN1_OCTET_STRING** out_digest);

#endif  // OPENSSL_VERSION_NUMBER
#endif  // OPENSSL_IS_BORINGSSL

namespace cloud_kms {

static const bool kCryptoLibraryInitialized = [] {
  CRYPTO_library_init();
  return true;
}();

}  // namespace cloud_kms

#endif  // COMMON_OPENSSL_H_
