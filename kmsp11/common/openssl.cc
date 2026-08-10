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

#include "common/openssl.h"

#if !defined(OPENSSL_IS_BORINGSSL)
#if OPENSSL_VERSION_NUMBER < 0x10100000L

void X509_SIG_get0(const X509_SIG* sig, const X509_ALGOR** out_alg,
                   const ASN1_OCTET_STRING** out_digest) {
  if (out_alg != nullptr) {
    *out_alg = sig->algor;
  }
  if (out_digest != nullptr) {
    *out_digest = sig->digest;
  }
}

void X509_SIG_getm(X509_SIG* sig, X509_ALGOR** out_alg,
                   ASN1_OCTET_STRING** out_digest) {
  if (out_alg != nullptr) {
    *out_alg = sig->algor;
  }
  if (out_digest != nullptr) {
    *out_digest = sig->digest;
  }
}

EC_KEY* EVP_PKEY_get0_EC_KEY(EVP_PKEY* pkey) {
  if (pkey->type != EVP_PKEY_EC) {
    return nullptr;
  }
  return pkey->pkey.ec;
}

const ASN1_TIME* X509_get0_notBefore(const X509* x) {
  return x->cert_info->validity->notBefore;
}

const ASN1_TIME* X509_get0_notAfter(const X509* x) {
  return x->cert_info->validity->notAfter;
}

void CRYPTO_library_init() {
  // https://www.openssl.org/docs/man1.0.2/man3/OPENSSL_config.html
  OPENSSL_config(nullptr);
  // https://www.openssl.org/docs/man1.0.2/man3/ERR_load_crypto_strings.html
  ERR_load_crypto_strings();
}

#else  // OPENSSL_VERSION_NUMBER

void CRYPTO_library_init() {
  // https://www.openssl.org/docs/man1.1.0/man3/OPENSSL_init_crypto.html
  OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nullptr);
}

#endif  // OPENSSL_VERSION_NUMBER
#endif  // OPENSSL_IS_BORINGSSL
