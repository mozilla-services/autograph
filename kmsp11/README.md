# Cloud KMS Integrations

This repository contains clients that integrate Cloud KMS with standard
cryptographic APIs. Presently, this includes the library for PKCS #11, and the
CNG provider.

For                          | Go To
---------------------------- | -----
Detailed Product Information | [cloud.google.com/kms](https://cloud.google.com/kms)
Feedback                     | cloudkms-feedback@google.com

## Cloud KMS Library for PKCS #11

The `libkmsp11` library exposes cryptographic and key management capabilities
from Google Cloud KMS using the
[PKCS #11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
C API. Sources for this library are contained in the `kmsp11/` directory in this
repository.

Popular uses for the PKCS #11 library include:

* Creating signatures, certificates, or certificate signing requests at the
  command line. [Learn more](kmsp11/docs/openssl_setup.md).
* Serving TLS web sessions backed by Cloud HSM keys.
  [Learn more](kmsp11/docs/apache_ssl_setup.md).
* Migrating an existing application that uses the PKCS #11 API to the cloud.

If you are migrating an existing application that uses the PKCS #11 API to the
cloud, you will need to point your application to the new library. In many
cases, this is as simple as changing a configuration option, as most
applications that use the PKCS #11 API do so by loading a provider's library
dynamically. We provide [a sample](kmsp11/sample/sample.c) of how you might do
this if you are writing a new application.

You can learn more about the PKCS #11 library in the
[user guide](kmsp11/docs/user_guide.md).

## Cloud KMS CNG Provider

The CNG provider exposes cryptographic and key management capabilities
from Google Cloud KMS using the
[CNG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal) API.
Sources for this library are contained in the `kmscng/` directory in this
repository.

Popular uses for the CNG provider include:

* Signing Windows artifacts using Windows SignTool.
  [Learn more](https://cloud.google.com/kms/docs/reference/cng-signtool).
* Migrating an existing application that uses the CNG API to the cloud.

You can learn more about the CNG provider in the
[user guide](kmscng/docs/user_guide.md).

## General Information

Binary distributions of the libraries are available as Github releases. These
binaries built and distributed by Google are covered by the
[GCP Terms of Service](https://cloud.google.com/terms), and support is available
from [Google Cloud support](https://cloud.google.com/support-hub).

We recommend that you use a binary distribution of these libraries rather than
building from source.  Support for a library that you build yourself from source
is on a best-effort basis, via GitHub issues. Further information about
build configurations is available in [BUILDING](BUILDING.md).
