APK Signing
===========

.. sectnum::
.. contents:: Table of Contents

APK is Android's application packaging format. It's basically a ZIP file that
follows the `JAR Signing`_ specification, and stores a manifest of all file checksums
that gets signed by a private RSA key.

.. _`JAR Signing`: http://download.java.net/jdk7/archive/b125/docs/technotes/tools/solaris/jarsigner.html

Android supports another signing mechanisms that puts a signature in the
metadata of the zip file, but this isn't supported by autograph at this time.


Configuration
-------------

To generate a key and certificate using the standard `keytool` approach, use the
following command:

.. code:: bash

    keytool -keystore testkeystore.jks -genkey -alias testapp -keysize 2048 -keyalg RSA -validity 10000 -keypass password1 -storepass password1

This will create a file called `testkeystore.jks` that contains both the private
RSA key and the public certificate. To export these in PEM format and load them
into the Autograph configuration, we first need to export the keystore into
PKCS12, then extract the private key from the PKCS12 file, as follows:

.. code:: bash

    # export the keystore into pkcs12
    keytool -importkeystore -srckeystore testkeystore.jks -destkeystore testkeystore.p12 -deststoretype PKCS12 -srcalias testapp -deststorepass password1 -destkeypass password1

    # export the private key from the pkcs12 file into PEM
    openssl pkcs12 -in testkeystore.p12  -nodes -nocerts -out key.pem

    # export the public certificate from the keystore into PEM
    keytool -exportcert -keystore testkeystore.jks -alias testapp|openssl x509 -inform der -text

You can then place the certificate and private key in `autograph.yaml`:

.. code:: yaml

	signers:
    - id: some-android-app
      type: apk
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

Signature request
-----------------

This signer supports both `/sign/data/` and `/sign/file` endpoints.

Both endpoints take an **optional** string representing a supported
PKCS7 digest algorithm (`"SHA1"` or `"SHA256"`). Both endpoints
support this option. It defaults to SHA256 for null and the empty `""`
string.

The `/sign/data` endpoint only does the signing step. It takes a
jarsigner signature file as input and returns a PKCS7 detached
signature. The caller is then responsible for repacking the APK. It
uses the request format:

.. code:: json

	[
		{
			"input": "Y2FyaWJvdW1hdXJpY2UK",
			"options": {
				"pkcs7_digest": "SHA1"
			},
			"keyid": "some-android-app"
		}
	]


The `/sign/file` endpoint takes a whole APK encoded in base64. It will
unzip the apk, generate the manifests, sign and align the output
zip. It uses the same request format with an optional param `zip` that
defaults to `"all"` for DEFLATE compressing all files in the APK. It
can also be `"passthrough"` to preserve the compression of the input
APK (e.g. for `mmap`ed media files) in which case the caller is
responsible for zip-aligning APK after submitting it:

.. code:: json

	[
		{
			"input": "Y2FyaWJvdW1hdXJpY2UK",
			"keyid": "some-android-app",
			"options": {
				"zip": "all"
				"pkcs7_digest": "SHA256"
			}
		}
	]



Signature response
------------------

Data Signing
~~~~~~~~~~~~

The response to a data signing request contains the base64 of the PKCS7 detached
signature in the `signature` field of the JSON response. You should decode this
base64 and write it to a file called `META-INF/SIGNATURE.RSA` in the APK.

.. code:: json

	[
	  {
	    "ref": "7khgpu4gcfdv30w8joqxjy1cc",
	    "type": "apk",
	    "signer_id": "testapp-android",
	    "signature": "MIIGPQYJKoZIhvcN..."
	  }
	]


The response to a file signing request contains the base64 of the signed and
aligned APK in the `signed_file` field of the json response. You should base64
decode that field and write the output as a file.

.. code:: json

	[
	  {
	    "ref": "7khgpu4gcfdv30w8joqxjy1cc",
	    "type": "apk",
	    "signer_id": "testapp-android",
	    "signed_file": "MIIGPQYJKoZIhvcN..."
	  }
	]

Verifying signatures
--------------------

The android SDK has a tool called `apksigner` that can verify both signature
versions, as well as the zip alignment.

.. code:: bash

	$ /opt/android-sdk/build-tools/27.0.3/apksigner verify -v test.apk

	Verifies
	Verified using v1 scheme (JAR signing): true
	Verified using v2 scheme (APK Signature Scheme v2): false
	Number of signers: 1
