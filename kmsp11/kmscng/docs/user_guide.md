# CNG Provider for Cloud KMS User Guide

## Table of Contents

1.  [Getting started](#getting-started)
2.  [Authentication and authorization](#authentication-and-authorization)
3.  [Configuration](#configuration)
4.  [Functions](#functions)
5.  [Cryptographic operations](#cryptographic-operations)
    1.  [ECDSA signing](#ecdsa-signing)
    2.  [RSA signing](#rsa-signing)
6.  [Limitations](#limitations)
7.  [FAQs](#faqs)

## Getting started

This provider gives access to Google Cloud HSM through the Microsoft CNG API.
Official Google-built releases of this provider are covered by the
[Google Cloud Platform Terms of Service][gcp-service-terms].

If you are upgrading from a previous version of the provider, be sure to check
the [change log](../../CHANGELOG.md) for changes that might affect your usage.

Please refer to the [FAQs section](#faqs) to troubleshoot installation or usage
issues.

### Windows system requirements

The provider is built and tested on Windows Server (semi-annual channel), on the
amd64 architecture. The library is designed to be compatible with Windows Server
2012 R2, Windows 8.1 (x64), and all subsequent server and x64 desktop releases.

On Windows versions prior to Windows 10, the provider requires the
preinstallation of the Visual C++ 2022 x64 Redistributable package (14.34 or
higher), which can be downloaded [here][msvc-redistributable].

### Downloading and verifying the provider

The provider is available for download in [GitHub Releases][releases].

After you've downloaded the installer, you can check the downloaded .msi file
for integrity by verifying the build signature against the preview release
public signing key.

Save this key on your filesystem, for example, in a file named
`cng-release-signing-key.pem`:

```
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEtfLbXkHUVc9oUPTNyaEK3hIwmuGRoTtd
6zDhwqjJuYaMwNd1aaFQLMawTwZgR0Xn27ymVWtqJHBe0FU9BPIQ+SFmKw+9jSwu
/FuqbJnLmTnWMJ1jRCtyHNZawvv2wbiB
-----END PUBLIC KEY-----
```

You can then verify the provider signature using OpenSSL:

```sh
openssl dgst -sha384 -verify cng-release-signing-key.pem \
  -signature kmscng.msi.sig kmscng.msi
```

## Authentication and Authorization

The provider authenticates to GCP using service account credentials. You can
[use an existing service][gcp-authn-prod] account associated with a GCE instance
or GKE node, or you can follow the
[Getting Started with Authentication][gcp-authn-getting-started] guide to create
a service account for use with the provider.

In order to use the provider at all, you must grant the account a role or roles
with the following IAM permissions:

*   `cloudkms.cryptoKeyVersions.viewPublicKey` for all asymmetric keys that will
    be loaded with the provider.
*   `cloudkms.cryptoKeyVersions.useToSign` for all asymmetric keys that will be
    used for signing.

You can learn more about
[managing access to Cloud KMS resources][kms-permissions-and-roles].

## Configuration

If your application uses `NCryptEnumKeys` calls, you will need to have a YAML
configuration file in order to locate Cloud KMS resources. The YAML must at a
minimum contain a single Cloud KMS CryptoKeyVersion.

Your provider configuration should be stored in `C:\Windows\KMSCNG\config.yaml`.

### Sample configuration file

```yaml
---
resources:
  - crypto_key_version: "projects/my-project/locations/us/keyRings/key-ring/cryptoKeys/my-key/cryptoKeyVersions/1"
  - crypto_key_version: "projects/my-project/locations/us/keyRings/other-key-ring/cryptoKeys/other-key/cryptoKeyVersions/2"
```

### Configuration reference

Item Name             | Type   | Required | Default | Description
--------------------- | ------ | -------- | ------- | -----------
resources             | list   | Yes      | None    | A list of crypto_key_version entries, see field below.
crypto_key_version    | string | Yes      | None    | The full name of the KMS key version that will be made accessible.

## Functions

The provider conforms to the
[NCRYPT_KEY_STORAGE_FUNCTION_TABLE][cng-key-storage-function-table], but only
implements a subset of the functions defined by that interface.

Function                                                   | Status | Notes
---------------------------------------------------------- | ------ | -----
[`NCryptCreatePersistedKey`][NCryptCreatePersistedKey]     | ❌     |
[`NCryptDecrypt`][NCryptDecrypt]                           | ❌     |
[`NCryptDeleteKey`][NCryptDeleteKey]                       | ❌     |
[`NCryptDeriveKey`][NCryptDeriveKey]                       | ❌     |
[`NCryptEncrypt`][NCryptEncrypt]                           | ❌     |
[`NCryptEnumAlgorithms`][NCryptEnumAlgorithms]             | ✅     |
[`NCryptEnumKeys`][NCryptEnumKeys]                         | ✅     |
[`NCryptExportKey`][NCryptExportKey]                       | ⚠️     | Only supports public key export, since Cloud KMS private keys cannot be exported.
[`NCryptFinalizeKey`][NCryptFinalizeKey]                   | ❌     |
[`NCryptFreeBuffer`][NCryptFreeBuffer]                     | ✅     |
[`NCryptFreeObject`][NCryptFreeObject]                     | ✅     |
[`NCryptGetProperty`][NCryptGetProperty]                   | ✅     |
[`NCryptImportKey`][NCryptImportKey]                       | ❌     |
[`NCryptIsAlgSupported`][NCryptIsAlgSupported]             | ✅     |
[`NCryptNotifyChangeKey`][NCryptNotifyChangeKey]           | ❌     |
[`NCryptOpenKey`][NCryptOpenKey]                           | ✅     |
[`NCryptOpenStorageProvider`][NCryptOpenStorageProvider]   | ✅     |
[`NCryptSecretAgreement`][NCryptSecretAgreement]           | ❌     |
[`NCryptSetProperty`][NCryptSetProperty]                   | ⚠️     | Only supports setting provider properties, not key properties.
[`NCryptSignHash`][NCryptSignHash]                         | ✅     |
[`NCryptVerifySignature`][NCryptVerifySignature]           | ❌     |

## Cryptographic Operations

### ECDSA Signing

The provider may be used for ECDSA signing. The expected input for a signing
operation is a message digest of the appropriate length for the Cloud KMS
algorithm.

Compatibility                | Compatible With
---------------------------- | ---------------
CNG Function                 | [`NCryptSignHash`][NCryptSignHash]
CNG Algorithm ID             | `BCRYPT_ECDSA_P256_ALGORITHM`, `BCRYPT_ECDSA_P384_ALGORITHM`
Cloud KMS Algorithm          | [`EC_SIGN_P256_SHA256`][kms-ec-algorithms], [`EC_SIGN_P384_SHA384`][kms-ec-algorithms]

### RSA Signing

The provider may be used for RSA signing. The expected input for a signing
operation is a message digest of the appropriate length for the Cloud KMS
algorithm.

Compatibility                | Compatible With
---------------------------- | ---------------
CNG Function                 | [`NCryptSignHash`][NCryptSignHash]
CNG Algorithm ID             | `BCRYPT_RSA_ALGORITHM`
Cloud KMS Algorithm          | [`RSA_SIGN_PKCS1_2048_SHA256`][kms-rsa-algorithms], [`RSA_SIGN_PKCS1_3072_SHA256`][kms-rsa-algorithms], [`RSA_SIGN_PKCS1_4096_SHA256`][kms-rsa-algorithms], [`RSA_SIGN_PKCS1_4096_SHA512`][kms-rsa-algorithms]

## Limitations

### Key purpose and protection level

To use the provider to act on a CryptoKeyVersion, the CryptoKeyVersion must meet
these characteristics:

*   The purpose for the CryptoKey is `ASYMMETRIC_SIGN`.
*   The protection level for the CryptoKeyVersion is `HSM`.
*   The algorithm for the CryptoKeyVersion is `EC_SIGN_P256_SHA256`,
    `EC_SIGN_P384_SHA384`, `RSA_SIGN_PKCS1_2048_SHA256`,
    `RSA_SIGN_PKCS1_3072_SHA256`, `RSA_SIGN_PKCS1_4096_SHA256` or `RSA_SIGN_PKCS1_4096_SHA512`.

The CNG provider returns an error when trying to load keys that don't conform to
these requirements.

## FAQs

### Issues during installation

If you see this error during the installation, Visual C++ is likely not installed
on your system:
```
There is a problem with this Windows Installer package. A DLL required for this
install to complete could not be run. Contact your support personnel or package
vendor.
```

The provider requires the preinstallation of the Visual C++ 2022 x64
Redistributable package (14.34 or higher), which can be downloaded
[here][msvc-redistributable].

### gRPC Could not get default PEM root certs

Sample error:
```
W0000 00:00:1687369894.825370    1892 logging.cc:39] [external/com_github_grpc_grpc/src/core/lib/security/security_connector/ssl_utils.cc:606]: load_file: UNKNOWN:Failed to load file {filename:"/usr/share/grpc/roots.pem", created_time:"2023-06-21T17:51:34.8251349+00:00", children:[UNKNOWN:No such file or directory [...]]}
W0000 00:00:1687369894.826457    1892 logging.cc:39] [external/com_github_grpc_grpc/src/core/lib/security/security_connector/ssl/ssl_security_connector.cc:425]: Could not get default pem root certs.
```

If you see this error, it's likely because gRPC requires an environment variable
to find the root of trust for SSL. You can download the missing file and set the
environment variable with:
```
@powershell -NoProfile -ExecutionPolicy unrestricted -Command ^
    (new-object System.Net.WebClient).Downloadfile( ^
        'https://pki.google.com/roots.pem', 'roots.pem')
set GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=%cd%\roots.pem
```

NOTE: the snippet above downloads the roots.pem file to your current directory,
and sets the environment variable to point to that location.

[cng-key-storage-function-table]: https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
[gcp-authn-getting-started]: https://cloud.google.com/docs/authentication/getting-started
[gcp-authn-prod]: https://cloud.google.com/docs/authentication/production
[gcp-service-terms]: https://cloud.google.com/terms/service-terms#1
[kms-ec-algorithms]: https://cloud.google.com/kms/docs/algorithms#elliptic_curve_signing_algorithms
[kms-rsa-algorithms]: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
[kms-permissions-and-roles]: https://cloud.google.com/kms/docs/reference/permissions-and-roles
[kms-rsa-sign-algorithms]: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
[msvc-redistributable]: https://aka.ms/vs/17/release/vc_redist.x64.exe
[releases]: https://github.com/GoogleCloudPlatform/kms-integrations/releases
[NCryptCreatePersistedKey]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptcreatepersistedkey
[NCryptDecrypt]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptdecrypt
[NCryptDeleteKey]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptdeletekey
[NCryptDeriveKey]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptderivekey
[NCryptEncrypt]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptencrypt
[NCryptEnumAlgorithms]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptenumalgorithms
[NCryptEnumKeys]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptenumkeys
[NCryptExportKey]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptexportkey
[NCryptFinalizeKey]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptfinalizekey
[NCryptFreeBuffer]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptfreebuffer
[NCryptFreeObject]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptfreeobject
[NCryptGetProperty]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptgetproperty
[NCryptImportKey]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptimportkey
[NCryptIsAlgSupported]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptisalgsupported
[NCryptNotifyChangeKey]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptnotifychangekey
[NCryptOpenKey]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptopenkey
[NCryptOpenStorageProvider]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptopenstorageprovider
[NCryptSecretAgreement]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptsecretagreement
[NCryptSetProperty]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptsetproperty
[NCryptSignHash]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptsignhash
[NCryptVerifySignature]: https://learn.microsoft.com/en-us/windows/desktop/api/Ncrypt/nf-ncrypt-ncryptverifysignature
