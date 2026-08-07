# Release Notes

## Table of Contents

1.  [PKCS#11 Library](#pkcs-11-cloud-kms-library)
2.  [CNG Provider](#cng-provider-for-cloud-kms)

## PKCS #11 Cloud KMS Library

### PKCS#11 v1.9

The following changes are included in the v1.9 (December 2025) release:

*   Add support for Single-tenant Cloud HSM key loading.
*   Add support for Single-tenant Cloud HSM key creation by specifying the
    `CKA_KMS_PROTECTION_LEVEL` and `CKA_CRYPTO_KEY_BACKEND` attributes. See the
    [user guide][user-guide] to learn more.
*   Fix a bug related to the random serial number used for auto-generation of
    x.509 certificates.

### PKCS#11 v1.8

The following changes are included in the v1.8 (October 2025) release:

*   Add GCE credentials configuration option.
*   Bug fix: Fix potential undefined behavior in FindOp::Next.

### PKCS#11 v1.7

The following changes are included in the v1.7 (May 2025) release:

*   Add retries at library initialization to reduce transient failures.
*   Dependency updates.

### PKCS#11 v1.6

The following changes are included in the v1.6 (July 2024) release:

*   Add support for software key creation by specifying the
    `CKA_KMS_PROTECTION_LEVEL` attribute. See the [user guide][user-guide] to
    learn more.
*   Updated deps:
    *   glog => v0.7.1

### PKCS#11 v1.5

The following changes are included in the v1.5 (May 2024) release:

*   Add support for software keys. See the user guide to learn more about the
    new `allow_software_keys` configuration flag.

### PKCS#11 v1.4

The following changes are included in the v1.4 (April 2024) release:

*   Add support for symmetric AES key creation.

### PKCS#11 v1.3

The following changes are included in the v1.3 (November 2023) release:

*   Promote HMAC and raw symmetric AES encryption/decryption experimental
    features to fully supported. This includes dropping the related experimental
    configuration flags (`experimental_allow_mac_keys` and
    `experimental_allow_raw_encryption_keys`), please remove them from your
    config if used.
*   Add configuration flag to skip fork handlers registration, for applications
    that don't need the library to work in the child process.
*   Add configuration item to provide X.509 certificates that will be exposed by
    the library when matched with a KMS key.
*   Several internal dependencies were updated.

### PKCS#11 v1.2

The following changes are included in the v1.2 (April 2023) release:

*   Add support for digesting mechanisms that can sign over raw data instead of
    precomputed digests. See [mechanism.cc][mechanisms] for the full list.
*   Add support for multi-part signing functions (`C_{Sign|Verify}Update`, and
    `C_{Sign|Verify}Final`). See the [user guide][user-guide] for more details
    about these functions.
*   Add support for `C_GenerateRandom`, see the [user guide][user-guide] for
    more details.
*   Add experimental support for interoperable AES symmetric encryption
    mechanisms, such as `CKM_AES_CTR`, and the related functions (eg.
    `C_Encrypt`, `C_Decrypt`, etc). See the [user guide][user-guide] for the
    full list of mechanisms and functions. This feature is currently in private
    preview and can only be accessed by allowlisted preview customers. If you
    are interested, please fill out
    [this form](https://forms.gle/z8qpV5wkG9gtVCof8).
*   Add experimental support for HMAC symmetric signing mechanisms, such as
    `CKM_SHA256_HMAC`. Some of these algorithms are in public preview but can be
    accessed without restrictions. See [mechanism.cc][mechanisms] for the full
    list of mechanisms.
*   Add integrity verification checks for crypto operations performed through
    the library.
*   Support case #1 of
    [`C_Initialize`](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc385057894)
*   Several internal dependencies were updated.

### PKCS#11 v1.1

The following changes are included in the v1.1 (March 2022) release:

*   The value for `CKA_EC_POINT` was corrected.
*   The configuration option `experimental_generate_certs` is now fully
    supported, and has been renamed to `generate_certs`.
*   Google now supplies a version of the library where the included BoringSSL
    has been built in FIPS mode.
*   The configuration option `experimental_require_fips_mode` is now fully
    supported, and has been renamed to `require_fips_mode`.
*   For `CK_RSA_PKCS_OAEP_PARAMS.source`, the value `0` is treated as meaning
    "no label" for compatibility purposes.
*   The library must now be built with Bazel v4.2.1.
*   Several internal dependencies were updated.

### PKCS#11 v1.0

Initial release of the library.

## CNG Provider for Cloud KMS

### CNG v1.3

The following changes are included in the v1.3 (October 2025) release:

*   Add support for `RSA_SIGN_PKCS1_4096_SHA512`.

### CNG v1.2

The following changes are included in the v1.2 (May 2025) release:

*   Add support for `RSA_SIGN_PKCS1_2048_SHA256` and
    `RSA_SIGN_PKCS1_3072_SHA256`.

### CNG v1.1

The following changes are included in the v1.1 (April 2024) release:

*   Add support for `RSA_SIGN_PKCS1_4096_SHA256`.

### CNG v1.0

Initial GA release of the provider.

### CNG v0.9

Second public preview release of the library. The following changes are included
in the v0.9 release:

*   Add support for `EC_SIGN_P384_SHA384`.
*   Add a gRPC patch to support Windows default system roots loading.

### CNG v0.8

Initial public preview release of the library.

[mechanisms]: kmsp11/mechanism.cc
[user-guide]: kmsp11/docs/user_guide.md
