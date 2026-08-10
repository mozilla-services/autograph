# PKCS #11 Library for Cloud KMS User Guide

## Table of Contents

1.  [Getting started](#getting-started)
2.  [Authentication and authorization](#authentication-and-authorization)
3.  [Configuration](#configuration)
4.  [Functions](#functions)
5.  [Cryptographic operations](#cryptographic-operations)
    1.  [Elliptic curve keypair generation](#elliptic-curve-keypair-generation)
    2.  [ECDSA signing and verification](#ecdsa-signing-and-verification)
    3.  [RSA keypair generation](#rsa-keypair-generation)
    4.  [RSA-OAEP encryption and decryption](#rsa-oaep-encryption-and-decryption)
    5.  [RSA-PKCS1 signing and verification](#rsa-pkcs1-signing-and-verification)
    6.  [RSA-PSS signing and verification](#rsa-pss-signing-and-verification)
6.  [Limitations](#limitations)

## Getting started

This library provides access to Google Cloud HSM through the industry standard
PKCS #11 API. Official Google-built releases of this library are covered by the
[Google Cloud Platform Terms of Service][gcp-service-terms].

If you are upgrading from a previous version of the library, be sure to check
the [change log](../../CHANGELOG.md) for changes that might affect your usage.

### Linux system requirements

The library is built and tested on Ubuntu 16.04 LTS Linux, on the amd64
architecture. The shared object file `libkmsp11.so` is compatible with any Linux
distribution that contains glibc version 2.17 or greater. You do not need to
compile the library yourself, and it does not require an installation routine.

### Windows system requirements

The library is built and tested on Windows Server (semi-annual channel), on the
amd64 architecture. The library is designed to be compatible with Windows Server
2012 R2, Windows 8.1 (x64), and all subsequent server and x64 desktop releases.

On Windows versions prior to Windows 10, the library requires the
preinstallation of the Visual C++ 2022 x64 Redistributable package (14.34 or
higher), which can be downloaded [here][msvc-redistributable].

### Downloading and verifying the library

The library is available for download in [GitHub Releases][releases].

After you've downloaded the library, you can check the downloaded library for
integrity by verifying the build signature against the preview release public
signing key.

Save this key on your filesystem, for example, in a file named
`pkcs11-release-signing-key.pem`:

```
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEtfLbXkHUVc9oUPTNyaEK3hIwmuGRoTtd
6zDhwqjJuYaMwNd1aaFQLMawTwZgR0Xn27ymVWtqJHBe0FU9BPIQ+SFmKw+9jSwu
/FuqbJnLmTnWMJ1jRCtyHNZawvv2wbiB
-----END PUBLIC KEY-----
```

You can then verify the library signature using OpenSSL:

```sh
openssl dgst -sha384 -verify pkcs11-release-signing-key.pem \
  -signature libkmsp11.so.sig libkmsp11.so
```

## Authentication and Authorization

The library authenticates to GCP using service account credentials. You can
[use an existing service][gcp-authn-prod] account associated with a GCE instance
or GKE node, or you can follow the
[Getting Started with Authentication][gcp-authn-getting-started] guide to create
a service account for use with the library.

In order to use the library at all, you must grant the account a role or roles
with the following IAM permissions:

*   `cloudkms.cryptoKeys.list` on all configured KeyRings.
*   `cloudkms.cryptoKeyVersions.list` on all CryptoKeys in each configured
    KeyRing.
*   `cloudkms.cryptoKeyVersions.viewPublicKey` for all asymmetric keys contained
    within all configured KeyRings.
*   `cloudkms.cryptoKeyVersions.useToDecrypt` or
    `cloudkms.cryptoKeyVersions.useToSign` for any keys to be used for
    decryption or signing.
*   `cloudkms.cryptoKeys.create` if you intend to create keys.
*   `cloudkms.cryptoKeyVersions.destroy` if you intend to destroy keys

You can learn more about
[managing access to Cloud KMS resources][kms-permissions-and-roles].

## Configuration

The library requires a YAML configuration file in order to locate Cloud KMS
resources. The YAML must at a minimum configure a single PKCS #11 token. Most
configuration items are optional.

You can provide a library configuration file in either of the following ways:

*   By providing a null-terminated C string containing the path to the library
    configuration file in the field `pInitArgs->pReserved` during your call to
    `C_Initialize`.
*   By setting the environment variable `KMS_PKCS11_CONFIG` to the path to a
    configuration file.

You must set the permissions on the configuration file so that it is writable
only by the file owner.

### Sample configuration file

```yaml
---
tokens:
  - key_ring: "projects/my-project/locations/us/keyRings/my-key-ring"
    label: "my key ring"
  - key_ring: "projects/my-project/locations/us/keyRings/second-ring"
log_directory: "/var/log/kmsp11"
```

### Global configuration

Item Name             | Type   | Required | Default | Description
--------------------- | ------ | -------- | ------- | -----------
tokens                | list   | Yes      | None    | A list of [token configuration items](#per-token-configuration), as specified in the next section. The tokens will be assigned to increasing slot numbers in the order they are defined, starting with 0.
refresh_interval_secs | int    | No       | 0       | The interval (in seconds) between attempts to update the key change in this library with the latest state from Cloud KMS. A value of 0 means never refresh.
rpc_timeout_secs      | int    | No       | 30      | The timeout (in seconds) for RPCs made to Cloud KMS.
log_directory         | string | No       | None    | A directory where application logs should be written. If unspecified, application logs will be written to standard error rather than to the filesystem.
log_filename_suffix   | string | No       | None    | A suffix that will be appended to application log file names.
generate_certs        | bool   | No       | false   | Whether to generate certificates at runtime for asymmetric KMS keys. The certificates are regenerated each time the library is intiailized, and they do not chain to a public root of trust. They are intended to provide compatibility with the [Sun PKCS #11 JCA Provider][java-p11-guide] which requires that all private keys have an associated certificate. Other use is discouraged.
require_fips_mode     | bool   | No       | false   | Whether to enable an initialization time check that requires that BoringSSL or OpenSSL have been built in FIPS mode, and that FIPS self checks pass.
skip_fork_handlers    | bool   | No       | false   | Whether to skip fork handlers registration, for applications that don't need the PKCS#11 library to work in the child process.
allow_software_keys   | bool   | No       | false   | Whether the library may be used to act on crypto key versions with protection level = `SOFTWARE`.

#### Experimental global configuration options

Item Name                              | Type | Required | Default | Description
-------------------------------------- | ---- | -------- | ------- | -----------
experimental_create_multiple_versions  | bool | No       | false   | Enables an experiment that allows multiple versions of a CryptoKey to be created.

### Per token configuration

Item Name | Type            | Required | Default | Description
--------- | --------------- | -------- | ------- | -----------
key_ring  | string          | Yes      | None    | The full name of the KMS key ring whose keys will be made accessible.
label     | string          | No       | Empty   | The label to use for this token's `CK_TOKEN_INFO` structure. Setting a value here may help an application disambiguate tokens at runtime.
certs     | list of strings | No       | Empty   | Exposes the provided PEM X.509 certificate(s) alongside any KMS keys they match.

## Functions

The library conforms to the
[PKCS #11 Extended Provider Profile][p11-extended-provider-profile], and
implements all of the functions defined by that profile. In addition, the
library supports single-part Encryption, Decryption, Signing, and Verification
for the asymmetric key types supported in Cloud KMS.

Function                                         | Status | Notes
------------------------------------------------ | ------ | -----
[`C_Initialize`][C_Initialize]                   | ✅      | Library initialization requires a [configuration file](#configuration). If `pInitArgs` is specified, then the flag `CKF_OS_LOCKING_OK` must be set, and the flag `CKF_LIBRARY_CANT_CREATE_OS_THREADS` must not be set. If `pInitArgs` is not specified, the library assumes that it may use mutexes and create threads.
[`C_Finalize`][C_Finalize]                       | ✅      |
[`C_GetInfo`][C_GetInfo]                         | ✅      |
[`C_GetFunctionList`][C_GetFunctionList]         | ✅      |
[`C_GetSlotList`][C_GetSlotList]                 | ✅      |
[`C_GetSlotInfo`][C_GetSlotInfo]                 | ✅      |
[`C_GetTokenInfo`][C_GetTokenInfo]               | ✅      |
[`C_WaitForSlotEvent`][C_WaitForSlotEvent]       | ❌      |
[`C_GetMechanismList`][C_GetMechanismList]       | ✅      |
[`C_GetMechanismInfo`][C_GetMechanismInfo]       | ✅      |
[`C_InitToken`][C_InitToken]                     | ❌      |
[`C_InitPIN`][C_InitPIN]                         | ❌      |
[`C_SetPIN`][C_SetPIN]                           | ❌      |
[`C_OpenSession`][C_OpenSession]                 | ✅      | The flag `CKF_SERIAL_SESSION` must be supplied. The library does not make callbacks, so the arguments `pApplication` and `Notify` are ignored.
[`C_CloseSession`][C_CloseSession]               | ✅      |
[`C_CloseAllSessions`][C_CloseAllSessions]       | ✅      |
[`C_GetSessionInfo`][C_GetSessionInfo]           | ✅      |
[`C_GetOperationState`][C_GetOperationState]     | ❌      |
[`C_SetOperationState`][C_SetOperationState]     | ❌      |
[`C_Login`][C_Login]                             | ✅      | Login is not required, and is implemented only to provide compatibility with clients that expect to log in. Login is only permitted for the user role (`CKU_USER`). Any supplied PIN is ignored.
[`C_Logout`][C_Logout]                           | ✅      |
[`C_CreateObject`][C_CreateObject]               | ❌      |
[`C_CopyObject`][C_CopyObject]                   | ❌      |
[`C_DestroyObject`][C_DestroyObject]             | ✅      |
[`C_GetObjectSize`][C_GetObjectSize]             | ❌      |
[`C_GetAttributeValue`][C_GetAttributeValue]     | ✅      |
[`C_SetAttributeValue`][C_SetAttributeValue]     | ❌      |
[`C_FindObjectsInit`][C_FindObjectsInit]         | ✅      |
[`C_FindObjects`][C_FindObjects]                 | ✅      |
[`C_FindObjectsFinal`][C_FindObjectsFinal]       | ✅      |
[`C_EncryptInit`][C_EncryptInit]                 | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which encryption algorithms are supported.
[`C_Encrypt`][C_Encrypt]                         | ✅      |
[`C_EncryptUpdate`][C_EncryptUpdate]             | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which encryption algorithms support multi-part encryption. See [other notes](#other-notes) for additional insights.
[`C_EncryptFinal`][C_EncryptFinal]               | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which encryption algorithms support multi-part encryption. See [other notes](#other-notes) for additional insights.
[`C_DecryptInit`][C_DecryptInit]                 | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which decryption algorithms are supported.
[`C_Decrypt`][C_Decrypt]                         | ✅      |
[`C_DecryptUpdate`][C_DecryptUpdate]             | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which decryption algorithms support multi-part decryption. See [other notes](#other-notes) for additional insights.
[`C_DecryptFinal`][C_DecryptFinal]               | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which decryption algorithms support multi-part decryption. See [other notes](#other-notes) for additional insights.
[`C_DigestInit`][C_DigestInit]                   | ❌      |
[`C_Digest`][C_Digest]                           | ❌      |
[`C_DigestUpdate`][C_DigestUpdate]               | ❌      |
[`C_DigestKey`][C_DigestKey]                     | ❌      |
[`C_DigestFinal`][C_DigestFinal]                 | ❌      |
[`C_SignInit`][C_SignInit]                       | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which signing algorithms are supported.
[`C_Sign`][C_Sign]                               | ✅      |
[`C_SignUpdate`][C_SignUpdate]                   | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which signing algorithms support  multi-part signing. See [other notes](#other-notes) for additional insights.
[`C_SignFinal`][C_SignFinal]                     | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which signing algorithms support  multi-part signing. See [other notes](#other-notes) for additional insights.
[`C_SignRecoverInit`][C_SignRecoverInit]         | ❌      |
[`C_SignRecover`][C_SignRecover]                 | ❌      |
[`C_VerifyInit`][C_VerifyInit]                   | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which verification algorithms are supported.
[`C_Verify`][C_Verify]                           | ✅      |
[`C_VerifyUpdate`][C_VerifyUpdate]               | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which signing algorithms support  multi-part verification. See [other notes](#other-notes) for additional insights.
[`C_VerifyFinal`][C_VerifyFinal]                 | ✅      | Consult the [cryptographic operations](#cryptographic-operations) documentation for details on which signing algorithms support  multi-part verification. See [other notes](#other-notes) for additional insights.
[`C_VerifyRecoverInit`][C_VerifyRecoverInit]     | ❌      |
[`C_VerifyRecover`][C_VerifyRecover]             | ❌      |
[`C_DigestEncryptUpdate`][C_DigestEncryptUpdate] | ❌      |
[`C_DecryptDigestUpdate`][C_DecryptDigestUpdate] | ❌      |
[`C_SignEncryptUpdate`][C_SignEncryptUpdate]     | ❌      |
[`C_DecryptVerifyUpdate`][C_DecryptVerifyUpdate] | ❌      |
[`C_GenerateKey`][C_GenerateKey]                 | ✅      | When using this function, the template must specify the attributes `CKA_LABEL` and `CKA_KMS_ALGORITHM` (required). The template may also optionally specify the attribute `CKA_KMS_PROTECTION_LEVEL`. If protection level `HSM_SINGLE_TENANT` is specified, `CKA_KMS_CRYPTO_KEY_BACKEND` must also be specified. No other attributes are supported. This function creates a Cloud KMS CryptoKey with `HSM` protection level (unless otherwise specified in the `CKA_KMS_PROTECTION_LEVEL` attribute) and a first version. This mechanism cannot be used to create additional versions in an existing CryptoKey, unless the `experimental_create_multiple_versions` option is enabled.
[`C_GenerateKeyPair`][C_GenerateKeyPair]         | ✅      | When using this function, a public key template must not be specified. The private key template must specify the attributes `CKA_LABEL` and `CKA_KMS_ALGORITHM` (required). The template may also optionally specify the attribute `CKA_KMS_PROTECTION_LEVEL`. If protection level `HSM_SINGLE_TENANT` is specified, `CKA_KMS_CRYPTO_KEY_BACKEND` must also be specified. No other attributes are supported. This function creates a Cloud KMS CryptoKey with `HSM` protection level (unless otherwise specified in the `CKA_KMS_PROTECTION_LEVEL` attribute) and a first version. This mechanism cannot be used to create additional versions in an existing CryptoKey, unless the `experimental_create_multiple_versions` option is enabled.
[`C_WrapKey`][C_WrapKey]                         | ❌      |
[`C_UnwrapKey`][C_UnwrapKey]                     | ❌      |
[`C_DeriveKey`][C_DeriveKey]                     | ❌      |
[`C_SeedRandom`][C_SeedRandom]                   | ❌      |
[`C_GenerateRandom`][C_GenerateRandom]           | ✅      | Retrieves between 8 and 1024 bytes of randomness from Cloud HSM.
[`C_GetFunctionStatus`][C_GetFunctionStatus]     | ❌      |
[`C_CancelFunction`][C_CancelFunction]           | ❌      |

## Cryptographic Operations

### Elliptic Curve Keypair Generation

The library may be used to create new elliptic curve keypairs. See the
[function notes](#functions) for `C_GenerateKeyPair` for invocation
requirements.

Compatibility                 | Compatible With
----------------------------- | ---------------
PKCS #11 Function             | [`C_GenerateKeyPair`][C_GenerateKeyPair]
PKCS #11 Mechanism            | [`CKM_EC_KEY_PAIR_GEN`][CKM_EC_KEY_PAIR_GEN]
PKCS #11 Mechanism Parameters | None
Cloud KMS Algorithm           | [`EC_SIGN_P256_SHA256`][kms-ec-algorithms], [`EC_SIGN_P384_SHA384`][kms-ec-algorithms]

### ECDSA Signing and Verification

The library may be used for ECDSA signing and verification. The expected input
for a signing or verification operation varies by mechanism, and is either a
message digest of the appropriate length for the Cloud KMS algorithm, or plain
input data.

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_Sign`][C_Sign], [`C_Verify`][C_Verify]
PKCS #11 Mechanism           | [`CKM_ECDSA`][CKM_ECDSA], `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`
PKCS #11 Mechanism Parameter | None
Cloud KMS Algorithm          | [`EC_SIGN_P256_SHA256`][kms-ec-algorithms], [`EC_SIGN_P384_SHA384`][kms-ec-algorithms]

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_SignUpdate`][C_SignUpdate], [`C_SignFinal`][C_SignFinal], [`C_VerifyUpdate`][C_VerifyUpdate], [`C_VerifyFinal`][C_VerifyFinal]
PKCS #11 Mechanism           | `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`
PKCS #11 Mechanism Parameter | None
Cloud KMS Algorithm          | [`EC_SIGN_P256_SHA256`][kms-ec-algorithms], [`EC_SIGN_P384_SHA384`][kms-ec-algorithms]

### RSA Keypair Generation

The library may be used to create new elliptic curve keypairs. See the
[function notes](#functions) for `C_GenerateKeyPair` for invocation
requirements.

Compatibility                 | Compatible With
----------------------------- | ---------------
PKCS #11 Function             | [`C_GenerateKeyPair`][C_GenerateKeyPair]
PKCS #11 Mechanism            | [`CKM_RSA_PKCS_KEY_PAIR_GEN`][CKM_RSA_PKCS_KEY_PAIR_GEN]
PKCS #11 Mechanism Parameters | None
Cloud KMS Algorithm           | [`RSA_DECRYPT_OAEP_2048_SHA256`][kms-asymmetric-encrypt-algorithms], [`RSA_DECRYPT_OAEP_3072_SHA256`][kms-asymmetric-encrypt-algorithms], [`RSA_DECRYPT_OAEP_4096_SHA256`][kms-asymmetric-encrypt-algorithms], [`RSA_DECRYPT_OAEP_4096_SHA512`][kms-asymmetric-encrypt-algorithms], [`RSA_SIGN_PKCS1_2048_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PKCS1_3072_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PKCS1_4096_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PKCS1_4096_SHA512`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_2048_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_3072_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_4096_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_4096_SHA512`][kms-rsa-sign-algorithms], [`RSA_SIGN_RAW_PKCS1_2048`][kms-rsa-sign-algorithms], [`RSA_SIGN_RAW_PKCS1_3072`][kms-rsa-sign-algorithms], [`RSA_SIGN_RAW_PKCS1_4096`][kms-rsa-sign-algorithms]

### RSA-OAEP Encryption and Decryption

The library may be used for RSAES-OAEP encryption or decryption.

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_Encrypt`][C_Encrypt], [`C_Decrypt`][C_Decrypt]
PKCS #11 Mechanism           | [`CKM_RSA_PKCS_OAEP`][CKM_RSA_PKCS_OAEP]
PKCS #11 Mechanism Parameter | [`CK_RSA_PKCS_OAEP_PARAMS`][CK_RSA_PKCS_OAEP_PARAMS]
Cloud KMS Algorithm          | [`RSA_DECRYPT_OAEP_2048_SHA256`][kms-asymmetric-encrypt-algorithms], [`RSA_DECRYPT_OAEP_3072_SHA256`][kms-asymmetric-encrypt-algorithms], [`RSA_DECRYPT_OAEP_4096_SHA256`][kms-asymmetric-encrypt-algorithms], [`RSA_DECRYPT_OAEP_4096_SHA512`][kms-asymmetric-encrypt-algorithms]

### RSA-PKCS1 Signing and Verification

The library may be used for RSASSA-PKCS1 single-part or multi-part signing and
verification.

For Cloud KMS keys with an algorithm name that includes a digest type, the
expected input for a signing or verification operation varies by mechanism and
is either a PKCS #1 DigestInfo with the appropriate digest algorithm, or plain
input data. For Cloud KMS keys without a digest type ("Raw PKCS#1" keys),
arbitrary input is accepted.

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_Sign`][C_Sign], [`C_Verify`][C_Verify]
PKCS #11 Mechanism           | [`CKM_RSA_PKCS`][CKM_RSA_PKCS], `CKM_RSA_PKCS_SHA256`, `CKM_RSA_PKCS_SHA512`
PKCS #11 Mechanism Parameter | None
Cloud KMS Algorithm          | [`RSA_SIGN_PKCS1_2048_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PKCS1_3072_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PKCS1_4096_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PKCS1_4096_SHA512`][kms-rsa-sign-algorithms], [`RSA_SIGN_RAW_PKCS1_2048`][kms-rsa-sign-algorithms], [`RSA_SIGN_RAW_PKCS1_3072`][kms-rsa-sign-algorithms], [`RSA_SIGN_RAW_PKCS1_4096`][kms-rsa-sign-algorithms]

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_SignUpdate`][C_SignUpdate], [`C_SignFinal`][C_SignFinal], [`C_VerifyUpdate`][C_VerifyUpdate], [`C_VerifyFinal`][C_VerifyFinal]
PKCS #11 Mechanism           | `CKM_RSA_PKCS_SHA256`, `CKM_RSA_PKCS_SHA512`
PKCS #11 Mechanism Parameter | None
Cloud KMS Algorithm          | [`RSA_SIGN_PKCS1_2048_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PKCS1_3072_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PKCS1_4096_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PKCS1_4096_SHA512`][kms-rsa-sign-algorithms], [`RSA_SIGN_RAW_PKCS1_2048`][kms-rsa-sign-algorithms], [`RSA_SIGN_RAW_PKCS1_3072`][kms-rsa-sign-algorithms], [`RSA_SIGN_RAW_PKCS1_4096`][kms-rsa-sign-algorithms]

### RSA-PSS Signing and Verification

The library may be used for RSASSA-PSS single-part or multi-part signing and
verification. The expected input for a signing or verification operation varies
by mechanism and is either a message digest of the appropriate length for the
Cloud KMS algorithm, or plain input data.

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_Sign`][C_Sign], [`C_Verify`][C_Verify]
PKCS #11 Mechanism           | [`CKM_RSA_PKCS_PSS`][CKM_RSA_PKCS_PSS]
PKCS #11 Mechanism Parameter | [`CK_RSA_PKCS_PSS_PARAMS`][CK_RSA_PKCS_PSS_PARAMS]
Cloud KMS Algorithm          | [`RSA_SIGN_PSS_2048_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_3072_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_4096_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_4096_SHA512`][kms-rsa-sign-algorithms]

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_SignUpdate`][C_SignUpdate], [`C_SignFinal`][C_SignFinal], [`C_VerifyUpdate`][C_VerifyUpdate], [`C_VerifyFinal`][C_VerifyFinal]
PKCS #11 Mechanism           | `CKM_RSA_PKCS_PSS_SHA256`, `CKM_RSA_PKCS_PSS_SHA512`
PKCS #11 Mechanism Parameter | [`CK_RSA_PKCS_PSS_PARAMS`][CK_RSA_PKCS_PSS_PARAMS]
Cloud KMS Algorithm          | [`RSA_SIGN_PSS_2048_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_3072_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_4096_SHA256`][kms-rsa-sign-algorithms], [`RSA_SIGN_PSS_4096_SHA512`][kms-rsa-sign-algorithms]

### Generic Secret Key Generation

The library may be used to create new generic secret keys (symmetric keys). See
the [function notes](#functions) for `C_GenerateKey` for invocation
requirements.

Compatibility                 | Compatible With
----------------------------- | ---------------
PKCS #11 Function             | [`C_GenerateKey`][C_GenerateKey]
PKCS #11 Mechanism            | [`CKM_GENERIC_SECRET_KEY_GEN`][CKM_GENERIC_SECRET_KEY_GEN], [`CKM_AES_KEY_GEN`][CKM_AES_KEY_GEN]
PKCS #11 Mechanism Parameters | None
Cloud KMS Algorithm           | `AES_128_GCM`, `AES_256_GCM`, `AES_128_CTR`, `AES_256_CTR`, `AES_128_CBC`, `AES_256_CBC`, [`HMAC_SHA1`][kms-mac-algorithms], [`HMAC_SHA224`][kms-mac-algorithms], [`HMAC_SHA256`][kms-mac-algorithms], [`HMAC_SHA384`][kms-mac-algorithms], [`HMAC_SHA512`][kms-mac-algorithms]

### AES-CBC Encryption and Decryption

The library may be used for AES encryption or decryption.

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_Encrypt`][C_Encrypt], [`C_EncryptUpdate`][C_EncryptUpdate], [`C_EncryptFinal`][C_EncryptFinal], [`C_Decrypt`][C_Decrypt], [`C_DecryptUpdate`][C_DecryptUpdate], [`C_DecryptFinal`][C_DecryptFinal]
PKCS #11 Mechanism           | [`CKM_AES_CBC`][CKM_AES_CBC], [`CKM_AES_CBC_PAD`][CKM_AES_CBC_PAD]
PKCS #11 Mechanism Parameter | CK_BYTE (initialization vector)
Cloud KMS Algorithm          | `AES_128_CBC`, `AES_256_CBC`

### AES-CTR Encryption and Decryption

The library may be used for AES encryption or decryption.

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_Encrypt`][C_Encrypt], [`C_EncryptUpdate`][C_EncryptUpdate], [`C_EncryptFinal`][C_EncryptFinal], [`C_Decrypt`][C_Decrypt], [`C_DecryptUpdate`][C_DecryptUpdate], [`C_DecryptFinal`][C_DecryptFinal]
PKCS #11 Mechanism           | [`CKM_AES_CTR`][CKM_AES_CTR]
PKCS #11 Mechanism Parameter | [`CK_AES_CTR_PARAMS`][CK_AES_CTR_PARAMS]
Cloud KMS Algorithm          | `AES_128_CTR`, `AES_256_CTR`

### AES-GCM Encryption and Decryption

The library may be used for AES encryption or decryption.

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_Encrypt`][C_Encrypt], [`C_EncryptUpdate`][C_EncryptUpdate], [`C_EncryptFinal`][C_EncryptFinal], [`C_Decrypt`][C_Decrypt], [`C_DecryptUpdate`][C_DecryptUpdate], [`C_DecryptFinal`][C_DecryptFinal]
PKCS #11 Mechanism           | `CKM_CLOUDKMS_AES_GCM`
PKCS #11 Mechanism Parameter | [`CK_GCM_PARAMS`][CK_GCM_PARAMS]
Cloud KMS Algorithm          | `AES_128_GCM`, `AES_256_GCM`

### MAC Signing and Verification

The library may be used for MAC single-part or multi-part signing and
verification. The expected input for a signing or verification is plain input
data.

Compatibility                | Compatible With
---------------------------- | ---------------
PKCS #11 Functions           | [`C_Sign`][C_Sign], [`C_SignUpdate`][C_SignUpdate], [`C_SignFinal`][C_SignFinal], [`C_Verify`][C_Verify], [`C_VerifyUpdate`][C_VerifyUpdate], [`C_VerifyFinal`][C_VerifyFinal]
PKCS #11 Mechanism           | [`CKM_SHA1_HMAC`][CKM_SHA1_HMAC], [`CKM_SHA224_HMAC`][CKM_SHA224_HMAC], [`CKM_SHA256_HMAC`][CKM_SHA256_HMAC], [`CKM_SHA384_HMAC`][CKM_SHA384_HMAC], [`CKM_SHA512_HMAC`][CKM_SHA512_HMAC]
PKCS #11 Mechanism Parameter | None
Cloud KMS Algorithm           | [`HMAC_SHA1`][kms-mac-algorithms], [`HMAC_SHA224`][kms-mac-algorithms], [`HMAC_SHA256`][kms-mac-algorithms], [`HMAC_SHA384`][kms-mac-algorithms], [`HMAC_SHA512`][kms-mac-algorithms]

## Limitations

### Key purpose, protection level, and state

To use the library to act on a CryptoKeyVersion, the CryptoKeyVersion must meet
these characteristics:

*   The purpose for the CryptoKey is `ASYMMETRIC_SIGN`, `ASYMMETRIC_DECRYPT`,
    `RAW_ENCRYPT_DECRYPT`, or `MAC`.
*   The protection level for the CryptoKeyVersion is `HSM` or
    `HSM_SINGLE_TENANT`. The protection level for the CryptoKeyVersion may also
    be `SOFTWARE` if the YAML configuration file contains
    `allow_software_keys: true`.
*   The CryptoKeyVersion is in state `ENABLED`.

The PKCS #11 library ignores keys that don't conform to these requirements.

### Caching

At library initialization time, the library uses KMS RPC calls to read the
entire contents of each configured key ring. Those contents are cached in
memory, so that subsequent calls like `C_FindObjects` do not require network
access. The cache is periodically refreshed if the configuration option
`refresh_interval_secs` is set to a non-zero value.

This means that:

*   You should expect initialization time (that is, the amount of time it takes
    for `C_Initialize` to complete) to increase with the number of keys that
    exist in your configured KeyRings.
*   Keys that are created or modified after the library is initialized will be
    stale if `refresh_interval_secs` is unspecified, or else will take up to
    that amount of time to become up-to-date in the library.

## Other notes

Keys can be located with the `CKA_LABEL` attribute (`pkcs11:object` in openssl
commands), which is the Cloud KMS CryptoKey identifier, or with the `CKA_ID`
attribute (`pkcs11:id` in openssl commands), which is the full Cloud KMS
CryptoKeyVersion name. As an example, a key might have a `CKA_ID` of
`projects/some_project/locations/some_location/keyRings/some_keyring/cryptoKeys/some_ck/cryptoKeyVersions/1`
and a `CKA_LABEL` of `some_ck`.  Some tools including `pkcs11-tool` hex-encode
`CKA_ID` attribute values, so they seem different at first.

Note that the OpenSC libp11 engine used by OpenSSL has a 100-character limit on
the PKCS#11 `CKA_ID`s that can be passed as input. For our library, this means
that you won't be able to pass a specific CryptoKeyVersion to OpenSSL if the
resource name is longer than 100 characters. See
https://github.com/OpenSC/libp11/issues/531. As a workaround, use short KeyRing
and CryptoKey names, or use `CKA_LABEL` instead.

For multi-part crypto operations, the library caches input data and parameters
in memory (up to a max buffer, depending on the specific crypto operation and
algorithm), before sending the request to Cloud KMS. This is required for these
operations to fit in the current APIs exposed by Cloud KMS.

[gcp-authn-getting-started]: https://cloud.google.com/docs/authentication/getting-started
[gcp-authn-prod]: https://cloud.google.com/docs/authentication/production
[gcp-service-terms]: https://cloud.google.com/terms/service-terms#1
[java-p11-guide]: https://docs.oracle.com/javase/8/docs/technotes/guides/security/p11guide.html
[kms-asymmetric-encrypt-algorithms]: https://cloud.google.com/kms/docs/algorithms#asymmetric_encryption_algorithms
[kms-ec-algorithms]: https://cloud.google.com/kms/docs/algorithms#elliptic_curve_signing_algorithms
[kms-mac-algorithms]: https://cloud.google.com/kms/docs/algorithms#mac_signing_algorithms
[kms-permissions-and-roles]: https://cloud.google.com/kms/docs/reference/permissions-and-roles
[kms-rsa-sign-algorithms]: https://cloud.google.com/kms/docs/algorithms#rsa_signing_algorithms
[msvc-redistributable]: https://aka.ms/vs/16/release/vc_redist.x64.exe
[p11-extended-provider-profile]: http://docs.oasis-open.org/pkcs11/pkcs11-profiles/v2.40/os/pkcs11-profiles-v2.40-os.html#_Toc416960554
[releases]: https://github.com/GoogleCloudPlatform/kms-integrations/releases
[C_Initialize]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024102
[C_Finalize]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc383864872
[C_GetInfo]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057897
[C_GetFunctionList]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057898
[C_GetSlotList]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024105
[C_GetSlotInfo]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024106
[C_GetTokenInfo]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024107
[C_WaitForSlotEvent]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc405794722
[C_GetMechanismList]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc405794723
[C_GetMechanismInfo]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024109
[C_InitToken]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024110
[C_InitPIN]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024111
[C_SetPIN]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024112
[C_OpenSession]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc235002337
[C_CloseSession]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024115
[C_CloseAllSessions]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024116
[C_GetSessionInfo]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024117
[C_GetOperationState]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057913
[C_SetOperationState]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057914
[C_Login]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057915
[C_Logout]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024119
[C_CreateObject]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024121
[C_CopyObject]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024122
[C_DestroyObject]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024123
[C_GetObjectSize]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024124
[C_GetAttributeValue]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024125
[C_SetAttributeValue]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024126
[C_FindObjectsInit]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323205460
[C_FindObjects]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323205461
[C_FindObjectsFinal]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057926
[C_EncryptInit]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#encryptinit
[C_Encrypt]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024130
[C_EncryptUpdate]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024131
[C_EncryptFinal]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024132
[C_DecryptInit]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057933
[C_Decrypt]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024134
[C_DecryptUpdate]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057935
[C_DecryptFinal]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024136
[C_DigestInit]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024138
[C_Digest]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024139
[C_DigestUpdate]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024140
[C_DigestKey]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057941
[C_DigestFinal]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057942
[C_SignInit]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024143
[C_Sign]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024144
[C_SignUpdate]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024145
[C_SignFinal]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024146
[C_SignRecoverInit]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024147
[C_SignRecover]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024148
[C_VerifyInit]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024149
[C_Verify]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024150
[C_VerifyUpdate]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024151
[C_VerifyFinal]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024152
[C_VerifyRecoverInit]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024153
[C_VerifyRecover]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024154
[C_DigestEncryptUpdate]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057958
[C_DecryptDigestUpdate]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057959
[C_SignEncryptUpdate]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057960
[C_DecryptVerifyUpdate]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc385057961
[C_GenerateKey]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024156
[C_GenerateKeyPair]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024157
[C_WrapKey]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024158
[C_UnwrapKey]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024159
[C_DeriveKey]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024160
[C_SeedRandom]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323610925
[C_GenerateRandom]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024163
[C_GetFunctionStatus]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024165
[C_CancelFunction]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/pkcs11-base-v2.40-errata01-os-complete.html#_Toc323024166
[CK_AES_CTR_PARAMS]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc228894707
[CK_GCM_PARAMS]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228894714
[CK_RSA_PKCS_OAEP_PARAMS]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228807161
[CK_RSA_PKCS_PSS_PARAMS]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228807164
[CKM_AES_CTR]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc228894705
[CKM_AES_CBC]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc228894699
[CKM_AES_CBC_PAD]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc228894700
[CKM_AES_KEY_GEN]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894697
[CKM_EC_KEY_PAIR_GEN]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228894664
[CKM_ECDSA]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc441850452
[CKM_GENERIC_SECRET_KEY_GEN]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894689
[CKM_RSA_PKCS]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228894635
[CKM_RSA_PKCS_KEY_PAIR_GEN]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228894633
[CKM_RSA_PKCS_OAEP]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228894637
[CKM_RSA_PKCS_PSS]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/errata01/os/pkcs11-curr-v2.40-errata01-os-complete.html#_Toc228894639
[CKM_SHA1_HMAC]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894748
[CKM_SHA224_HMAC]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894754
[CKM_SHA256_HMAC]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894760
[CKM_SHA384_HMAC]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894766
[CKM_SHA512_HMAC]: http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/pkcs11-curr-v2.40-cs01.html#_Toc228894772
