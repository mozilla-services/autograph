Content Signature
=================

.. sectnum::
.. contents:: Table of Contents

Rationale
---------

As we rapidly increase the number of services that send configuration data to
Firefox agents, we also increase the probability of a service being
compromised to serve fraudulent data to our users. Content Signature implements
a signing protocol to protect the information sent from backend services to Firefox
user-agents.

Content signature adds a layer to TLS and certificate pinning. 
As we grow our service infrastructure, the risk of a vulnerability on our public 
endpoints increases, and an attacker could exploit a vulnerability to serve bad 
data from trusted sites directly. TLS with certificate pinning prevents bad actors
from creating fraudulent Firefox services, but does not reduce the impact a break-in
would have on our users. Content signature provides this extra layer.

Finally, content signature helps us use Content Delivery Networks (CDN) without
worrying that a compromise would end-up serving bad data to our users.
Signing content at the source reduces pressure on the infrastructure
and allows us to rely on vendors without worrying about data integrity.

For more information, refer to Julien Vehent's presentation linked below:

.. image:: https://img.youtube.com/vi/b2kPo8YdLTw/0.jpg
   :target: https://www.youtube.com/watch?v=b2kPo8YdLTw

Signature
---------

Content signatures are computed on data and served to Firefox either via a HTTP
response header or through a separate signature field in the data being transported.

Content signature have three main components: a signature mode (**mode**), an
ecdsa signature encoded with Base64 URL (**signature**) and the URL to a chain
of certificates that link to a trusted root (**x5u**). The example below shows
the JSON representation of a content signature:

.. code:: json

	{
	  "mode": "p384ecdsa",
	  "signature": "gZimwQAsuCj_JcgxrIjw1wzON8WYN9YKp3I5I9NmOgnGLOJJwHDxjOA2QEnzN7bXBGWFgn8HJ7fGRYxBy1SHiDMiF8VX7V49KkanO9MO-RRN1AyC9xmghuEcF4ndhQaI",
      "x5u": "https://foo.example.com/chains/certificates.pem"
	}

* **mode** is a suite of algorithms used to issue the signature. Autograph uses three
  modes:

  * **p384ecdsa** is the default used by firefox. It calculates signatures on the P-384
    NIST curve and uses SHA2-384 for hashes.

  * **p256ecdsa** uses the P-256 NIST curve and SHA256 for hashes

  * **p521ecdsa** uses the P-521 NIST curve and SHA512 for hashes

* **signature** contains the base64_url of the signature, computed using an elliptic
  curve and a hash algorithm that depends on the mode. The signature is issued by
  the private key of the end-entity cert referenced in the X5U. The decoded base64
  contains a binary string that is a DL/ECSSA representation of the R and S values
  (IEEE Std 1363-2000). This format concatenates R and S into a single value. To
  retrieve R and S, split the decoded base64 in the middle, and take R on the left
  and S on the right.

* **x5u** contains the location of the chain of trust that issued the signature.
  This file contains at least two certificates encoded in PEM format, where the
  first certificate is the end-entity that issued the signature, and the last
  certificate is the root of the PKI. Firefox is configured to only accept
  signatures from the internal PKI shared with AMO. This is controlled via the
  `security.content.signature.root_hash` preference, where the value is the
  hexadecimal of the sha256 of the DER of the root certificate.

When Firefox verifies a content signature, it first retrieves the X5U and checks
the signature validity using the end-entity certificate, the signature, and the
content being protected. Firefox then verifies the chain of trust of the
end-entity links to a root cert with a hash matching the one in Firefox.
Finally, to prevent application A from signing content for application B,
Firefox verifies the subject alternate name of the end-entity certificate
matches the one it expects. This is hardcoded for each component that uses
content signature. Onecrl, for example, uses the namespace
`onecrl.content-signature.mozilla.org` and only end-entity certificates that
have this subject alternate name can issue signatures for the OneCRL service.

Configuration
-------------

The type of this signer is **contentsignature**.

Configuring an Autograph signer to issue content signature requires providing
the private ECDSA key and the X5U value to be used in signatures.

 Each signer is composed of an identifier and an ECDSA private key on the P-384
 NIST curve. To generate a key pair with openssl, use:

.. code:: bash

	$ openssl ecparam -name secp384r1 -genkey
	-----BEGIN EC PARAMETERS-----
	BgUrgQQAIg==
	-----END EC PARAMETERS-----
	-----BEGIN EC PRIVATE KEY-----
	MIGkAgEBBDAGajHPaAY9gliN0RzSlByVXZa4jyruijtIFXmuSPHlZxLegbiqGmJh
	NCdu65eF4UagBwYFK4EEACKhZANiAAQDN4noWrHubA8gsigJM/AwY1yO1NmjuKnc
	3ZT32OE2/nk9UMsIYE8LwGEMikGXAUd3XVkJh6wJybVekcjz9khNDAos/EnoiJ96
	ZosSXJrWEeyFmlp8GvDlOoZqd7xpW08=
	-----END EC PRIVATE KEY-----


The output from OpenSSL must be copied under the `privatekey` section of the
signer, as follows:

.. code:: yaml

	signers:
    - id: appkey1
      type: contentsignature
      privatekey: |
          -----BEGIN EC PARAMETERS-----
          BgUrgQQAIg==
          -----END EC PARAMETERS-----
          -----BEGIN EC PRIVATE KEY-----
          MIGkAgEBBDART/nn3fKlhyENdc2u3klbvRJ5+odP0kWzt9p+v5hDyggbtVA4M1Mb
          fL9KoaiAAv2gBwYFK4EEACKhZANiAATugz97A6HPqq0fJCGom9PdKJ58Y9aobARQ
          BkZWS5IjC+15Uqt3yOcCMdjIJpikiD1WjXRaeFe+b3ovcoBs4ToLK7d8y0qFlkgx
          /5Cp6z37rpp781N4haUOIauM14P4KUw=
          -----END EC PRIVATE KEY-----


Based on the `privatekey`, autograph will return the corresponding `publickey`
in the JSON responses. If you're using a PKI and want to verify signatures with
a X.509 certificate, you can generate this certificate based on the private key,
store it someplace, and tell autograph to return its location in the `x5u`
value.

.. code:: bash

	# first make a CSR based on the private key
	$ openssl req -new -key /tmp/autograph-dev.key -out /tmp/autograph-dev.csr

	# then self sign the CSR
	$ openssl x509 -req -days 365 -in /tmp/autograph-dev.csr -signkey /tmp/autograph-dev.key -out /tmp/autograph-dev.crt

Store the CRT on `http://example.net/certs/autograph-dev.crt` and set the x5u value in `autograph.yaml`.

.. code:: yaml

	signers:
	- id: appkey2
	  x5u: "http://example.net/certs/autograph-dev.crt"
      type: contentsignature
      privatekey: |
          -----BEGIN EC PARAMETERS-----
		  .....

Signature requests
------------------

This signer support both the `/sign/data` and `/sign/hash` endpoints. When
signing data, the base64 of the data being signed must be passed in the `input`
field of the JSON signing request. When signing hashes, the `input` field must
contain the base64 of the hash being signed.

.. code:: json

	[
		{
			"input": "Y2FyaWJvdW1hdXJpY2UK",
			"keyid": "some_content_signer"
		}
	]

This signer doesn't support any option.
