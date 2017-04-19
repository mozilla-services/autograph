XPI Signing
===========

.. sectnum::
.. contents:: Table of Contents

XPI are zip files that contain Firefox extensions and addons. XPI signing uses
the `JAR Signing`_ format to produce PKCS7 signatures protecting the integrity
of addons.

.. _`JAR Signing`: http://download.java.net/jdk7/archive/b125/docs/technotes/tools/solaris/jarsigner.html

A full description of how addon signing is implemented in Firefox can be found
`on the Mozilla wiki`_. This readme focuses on the autograph implementation.

.. _`on the Mozilla wiki`: https://wiki.mozilla.org/Add-ons/Extension_Signing

Configuration
-------------

The XPI signer in Autograph supports four types of addons. A signer is
configured to issue signature for a given type using the `category` parameter in
the autograph configuration:

* Regular addons use category `add-on` 
* Mozilla Extensions use category `extension`
* Mozilla Components (aka. System Addons) `system add-on`
* Hotfixes `hotfix`

When configuring a signer, the private key and signed certificate must be
provided. The certificate must be issued by either the production or staging
roots of the Firefox AMO PKI (refer to internal documentation to issue those, as
they require access to private HSMs).

.. code:: yaml

	signers:
    - id: webextensions-rsa
      type: xpi
      category: add-on
      certificate: |
          -----BEGIN CERTIFICATE-----
          MIIH0zCCBbugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBvDELMAkGA1UEBhMCVVMx
		  ...
          -----END CERTIFICATE-----
      privatekey: |
          -----BEGIN PRIVATE KEY-----
          MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQDHV+bKFLr1p5FR
		  ...
          -----END PRIVATE KEY-----

Signature requests
------------------

This signer only supports the `/sign/data` endpoint. The `input` field of the
JSON signing requests must contain the base64 of a `mozilla.sf` signature file,
as described in `Extension Signing Algorithm`_. The signer issues a PKCS7
signature on the `mozilla.sf` file and returns it in the JSON response.

.. _`Extension Signing Algorithm`: https://wiki.mozilla.org/Add-ons/Extension_Signing#Algorithm

In addition to the input data, this signer also needs to receive the ID of the
addon being signed in the options of the signing request. This ID must be
decided client side, and is generally a string that looks like an email address,
but can also be the hexadecimal of a sha256 hash if said string is longer than
64 characters. The Autograph XPI signer doesn't care about the content of the
string, and uses it as received when generating the end-entity signing cert.

.. code:: json

	[
		{
			"input": "Y2FyaWJvdW1hdXJpY2UK",
			"options": {
				"id": "myaddon@allizom.org",
			},
			"keyid": "some_xpi_signer"
		}
	]
