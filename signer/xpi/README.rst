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

The type of this signer is **xpi**.

The XPI signer in Autograph supports four types of addons. A signer is
configured to issue signatures for a given type using the `mode` parameter in
the autograph configuration:

* Regular addons use mode `add-on`
* Mozilla Extensions use mode `extension`
* Mozilla Components (aka. System Addons) use mode `system add-on`
* Hotfixes use mode `hotfix`

Each signer must have a type, a mode and the certificate and private key of
an intermediate CA issued by either the staging or root PKIs of AMO (refer to
internal documentation to issue those, as they require access to private HSMs).

When a signature is requested, autograph will generate a private key and issue
an end-entity certificate specifically for the signature request. The certificate
is signed by the configured intermediate CA. The private key is thrown away
right after the signature is issued.

.. code:: yaml

	signers:
    - id: webextensions-rsa
      type: xpi
      mode: add-on
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

Signature Request
-----------------

Supports the `/sign/data` and `/sign/file` endpoints for data and file signing respectively. Both use the same request format:

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

Where options includes the following fields:

* `id` is the **required** ID of the addon to sign for both data and
  file signing. It must be decided client side, and is generally a
  string that looks like an email address, but when longer than 64
  characters can be the hexadecimal encoding of a sha256 hash. This
  signer doesn't care about the content of the string, and uses it as
  received when generating the end-entity signing cert.


The `/sign/file` endpoint takes a whole XPI encoded in base64. As
described in `Extension Signing Algorithm`_, it:

* unzips the XPI
* hashes each file to generate the manifest file `manifest.mf`
* hashes the manifest to generate the signature file `mozilla.sf`
* generates an RSA end entity cert from the signer's intermediate
* uses the generated cert to sign the signature file and create a PKCS7 detached signature `mozilla.rsa`
* adds the generated manifest, signature, and detached signature files to the XPI `META-INF/`
* repacks and returns the ZIP/XPI

The `/sign/data` endpoint only generates the end entity cert and signs
the signature file. It must contain the base64 encoding of a
`mozilla.sf` signature file in the `input` field and returns the PKCS7
detached signature `mozilla.sf`. The caller is then responsible for
repacking the ZIP.

.. _`Extension Signing Algorithm`: https://wiki.mozilla.org/Add-ons/Extension_Signing#Algorithm

Signature Response
------------------

Data Signing
~~~~~~~~~~~~

XPI signatures are binary files encoded using the PKCS7 format and stored in the
file called **mozilla.rsa** in the META-INF folder of XPI archives.

Autograph returns the base64 representation of the mozilla.rsa file in its
signature responses. Clients must decode the base64 from the autograph response
and write it to a `mozilla.rsa` file.

.. code:: json

	[
	  {
		"ref": "z4cfx4x6qymxsj9hiqbuqvn7",
		"type": "xpi",
		"signer_id": "webextensions-rsa",
		"public_key": "",
		"signature": "MIIRUQYJKoZIhvcNAQcCoIIRQjCCET4CAQExCTAHBgUr..."
	  }
	]

Note that the **public_key** field is empty in signature responses because PKCS7
files already contain the public certificate of the end-entity that issued the
signature.

File Signing
~~~~~~~~~~~~

Like the data signing except the signed XPI is returned in the
`signed_file` field. Clients must decode the base64 from the autograph
response and write it to a `signed_addon.xpi` file.

.. code:: json

	[
	  {
		"ref": "z4cfx4x6qymxsj9hiqbuqvn7",
		"type": "xpi",
		"signer_id": "webextensions-rsa",
		"public_key": "",
		"signed_file": "MIIRUQYJKoZIhvcNAQcCoIIRQjCCET4CAQExCTAHBgUr..."
	  }
	]
