=============
API Endpoints
=============

.. sectnum::
.. contents:: Table of Contents

Authorization: All API calls require a
`hawk <https://github.com/hueniverse/hawk>`_ Authorization header with payload
signature enabled. Example code for can be found in the `tools` directory.

/sign/data
----------

Request
~~~~~~~

Request a signature on raw data. The data to sign is passed in the request body
using the JSON format described below.

When requesting the signature of raw data, autograph will determine which hash
function to use based on the key type (eg. p384 with sha384). The caller can
also force a specific hash algorithm with the `hashwith` parameter.

The request body is an array of signature requests, to allow for batching signature
of multiple inputs into a single API request.

example:

.. code:: bash

	POST /sign/data
	Host: autograph.example.net
	Content-type: application/json
	Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="
	
	[
	    {
	        "input": "c29tZSB2ZXJ5IGxvbmcgaW5wdXQgdGhhdCBkb2VzIG5vdCBjb250YWluIGFueXRoaW5nIGludGVyZXN0aW5nIG90aGVyIHRoYW4gdGFraW5nIHNwYWNlCg=="
	    },
	    {
	        "input": "c2lnbl9tZQo=",
	        "template": "content-signature",
	        "hashwith": "sha384",
	        "keyid": "123456"
	    }
	]

Body format:
The request body is a json array where each entry of the array is an object to sign. The parameters are:

* template: tells Autograph to template the input data using custom logic. This
  is used to add or change the input data prior to hash and signing it. If set
  to "content-signature", the header `Content-Signature:\x00` is prepended to
  the input data prior to signing.

* hashwith: the algorithm to hash the input data with prior to signing. If
  omitted, autograph will select the appropriate hash algorithm to use based on
  the private key (sha256 for P-256, sha384 for P-384, sha512 as a fallback).

* input: base64 encoded data to sign

* keyid: allows the caller to specify a key to sign the data with. This
  parameter is optional, and Autograph will pick a key based on the caller's
  permission if omitted.

* signature_encoding: by default, signatures returned by autograph use a R||S
  string format encoded with base64_urlsafe. The R||S format simply concatenates
  the two integer value that compose an ECDSA signature into one big number
  (for p384, each value is 48 bytes long, so the total is 96 bytes). This format
  avoid relying on ASN.1 parser to read the signatures, but can make it difficult
  to verify signatures without custom code. The base64_urlsafe encoding format
  strips base64 padding and replaces characters  `+` and `/` with `-` and `_`
  respectively.
  The R||S base64_urlsafe format complies with the
  `Content-Signature <https://github.com/martinthomson/content-signature/>`_ protocol,
  and is needed to verify signatures in Firefox. But, if needed, autograph can
  return signatures in other formats:

	-  `rs_base64url` is the default format and returns the signature in R||S
		format with base64 url safe encoding.

	- `rs_base64` returns the signature in R||S format with regular base64 encoding
		instead of base64_urlsafe.

	- `der_base64` returns the signature in DER ASN.1 format, encoded with
		regular base64. This format is useful to verify signatures with OpenSSL or
		other libraries.

	- `der_base64url` is similar to the previous one but uses base64 urlsafe.

Response
~~~~~~~~

A successful request return a `201 Created` with a response body containing
signature elements encoded in JSON. The ordering of the response array is
identical to the request array, such that signing request 1 maps to signing
response 1, etc...

.. code:: json

	[
	    {
	        "ref": "20e5t7zv0jh6n1cts4opu4vsup",
	        "signer_id": "appkey1",
	        "signature": "MS8ZXMzr9YVttwuHgZ_SxlPogZKm_mYO6SsEiqupBeu01ELO_xP6huN4bXBn-ZH1ZJkbgBeVQ_QKd8wW9_ggJxDaPpQ3COFcpW_SdHaiEOLBcKt_SrKmLVIWHE3wc3lV",
	        "signature_encoding": "rs_base64url",
	        "hash_algorithm": "sha384",
	        "public_key": "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEu+HCTEht2Y5U3IwWZeaR54pqAsQDPly934y8tBb0rXEKslpDGnJgGNzKjOGMb8gTb+SfiSTwJLJGFaJkM5N//C2vg9lELo+l7kXkyiYnvBKaVb618DAI4Usuc7Lqu/4C",
	        "x5u": "https://bucket.example.net/appkey2.pem",
	        "content-signature": "x5u=https://bucket.example.net/appkey2.pem; p384ecdsa=MS8ZXMzr9YVttwuHgZ_SxlPogZKm_mYO6SsEiqupBeu01ELO_xP6huN4bXBn-ZH1ZJkbgBeVQ_QKd8wW9_ggJxDaPpQ3COFcpW_SdHaiEOLBcKt_SrKmLVIWHE3wc3lV"
	    }
	]

Each signature response contains the following fields:

* `ref` is a random string that acts as a reference number for logging and
  tracking.

* `signer_id` is ID of the signer in configuration.

* `signature` is the ECDSA signature of the input data submitting in the
  signing request.

* `signature_encoding` is the encoding format of the `signature`. If none
  was specified in the signature request, `rs_base64url` is used.

* `hash_algorithm` is the SHA function used to sign the input data. If
  none was specificed in the signature request, autograph assumed the
  input data was hashed prior to requesting signature, and this value is empty.

* `public_key` is the DER encoded public key that maps to the signing key
  used to generate the signature. This value can be used by clients to verify
  signatures. The DER format is supported by OpenSSL and most libraries.

* `x5u` is the URL to the certificate chain that can be used to verify the
  signature. This value is returned when the signing key maps to a public
  certificate which is part of a PKI. In such environments, the X5U value
  will point to a file that contains PEM encoded certificates. The signing
  certificate will be first, followed by any intermediate. The Root CA that
  represents that base of the chain is not included in the X5U URL, and must
  be trusted by applications through other means (like a local truststore).

* `content-signature` is the raw HTTP header of the Content-Signature protocol.
  This value is only returned if the signature requested a `content-signature`
  template to be applied to the data. It should not be interpreted by client
  applications, but passed unmodified to verifying libraries, such as the Content
  Verifier in Firefox.

/sign/hash
----------

Request
~~~~~~~

Request a signature on a hash. The hash is provided as a base64 encoded bytes
array, and is not manipulated at all by autograph before signing. You must
ensure that data is templated prior to hashing it and calling autograph.

This endpoint always returns a `content-signature` with every response.

example:

.. code:: bash

	POST /sign/hash
	Host: autograph.example.net
	Content-type: application/json
	Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="
	
	[
	    {
	        "input": "y0hdfsN8tHlCG82JLywb4d2U+VGWWry8dzwIC3Hk6j32mryUHxUel9SWM5TWkk0d"
	    },
	    {
	        "input": "Z4hdf5N8tHlwG82JLywb4X2U+VGWWry4dzwIC3vk6j32mryUHxUel9SWk5Trff8f",
	        "keyid": "123456"
	    }
	]


Body format:
The request body is a json array where each entry of the array is an object to sign. The parameters are:

* input: base64 encoded hash to sign

* keyid: see `/sign/data`

* signature_encoding: see `/sign/data`

Response
~~~~~~~~

See `/sign/data`, the response format is identical.

/sign/xpi
---------

Request an signature S/MIME detached signature of an addon signature file,
either using the signer's private key or using a key/cert generated for the
operation when `make_ephemeral_cert` is `true`.

Request
~~~~~~~

The endpoint accepts a multipart POST request with two parameters:

* `addon_id` is the unique identifier of the addon

* `file` is the signature file of the addon (eg. mozilla.sf)

* `make_ephemeral_cert` is a boolean that indicates whether a signing
  certificate should be created to sign the file with. If set to true,
  Autograph generates an ephemeral signing certificate and an ephemeral
  private key, signs the certificate with the configured signer's private
  key (here acting as an intermediate), and uses the ephemeral private key
  to sign the signature file.
  The ephemeral certificate is returned in the detached signature, alongside
  the intermediate. The ephemeral private key is thrown away.
  For most addons, `make_ephemeral_cert` should be true because it's the
  standard way to sign. Some addons, like hotfixes or system addons, use
  predefine keys instead of ephemeral ones and thus should leave
  `make_ephemeral_cert` to false.

Response
~~~~~~~~

A successful request return a `201 Created` with a response body containing
an S/MIME detached signature encoded with Base 64.

/__monitor__
------------

This is a special endpoint designed to monitor the status of all signers without
granting signing privileged to a monitoring client. It requires a special user
named `monitor` that can request a signature of the string `AUTOGRAPH MONITORING`
by all active signers.

Request
~~~~~~~

The endpoint accepts a GET request without query parameter or request body. The
`Hawk` authorization of the user named `monitor` is required.

.. code:: bash

	GET /__monitor__

	Host: autograph.example.net
	Content-type: application/json
	Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="

Response
~~~~~~~~

See `/sign/data`, the response format is identical.
For each signer, two responses are returned: one with Content-Signature
templating applied to the input data, and one without.

The monitoring client should verify the signature returned with each response.
If X5U values are provided, the monitoring client should verify that certificate
chains are hosted at those locations, and that certificate are not too close to
their expiration date.

/__heartbeat__ and /__lbheartbeat__
-----------------------------------

Heartbeating endpoints designed to answer load balancers with a 200 OK.

.. code:: bash

	HTTP/1.1 200 OK
	Date: Fri, 05 Aug 2016 20:19:54 GMT
	Content-Length: 4
	Content-Type: text/plain; charset=utf-8

	ohai


/__version__
------------

Returns metadata about the autograph version.

.. code:: bash

	HTTP/1.1 200 OK
	Date: Fri, 05 Aug 2016 20:20:54 GMT
	Content-Length: 209
	Content-Type: text/plain; charset=utf-8

	{
	"source": "https://go.mozilla.org/autograph",
	"version": "20160512.0-19fbb91",
	"commit": "19fbb910e2bd81cdd71fba2d1a297852a3ca17e8",
	"build": "https://travis-ci.org/mozilla-services/autograph"
	}
