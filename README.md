# Autograph
Autograph is a cryptographic signature service that implements
[Content-Signature](https://github.com/martinthomson/content-signature/)
and other signing methods.

[![Build Status](https://travis-ci.org/mozilla-services/autograph.svg?branch=master)](https://travis-ci.org/mozilla-services/autograph)
[![Coverage Status](https://coveralls.io/repos/github/mozilla-services/autograph/badge.svg?branch=master)](https://coveralls.io/github/mozilla-services/autograph?branch=master)

## Installation

If you don't yet have a GOPATH, export one:
```bash
$ export GOPATH=$HOME/go
$ mkdir $GOPATH
```

Then download and build autograph:
```bash
$ go get go.mozilla.org/autograph
```

The resulting binary will be placed in `$GOPATH/bin/autograph`. To run autograph with the example conf, do:
```bash
$ cd $GOPATH/src/go.mozilla.org/autograph
$ $GOPATH/bin/autograph -c autograph.yaml
```

Example clients are in the `tools` directory. You can install the Go one like this:
```bash
$ go get go.mozilla.org/autograph/tools/autograph-client
$ $GOPATH/bin/autograph-client -u alice -p fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu -t http://localhost:8000/sign/data -r '[{"input": "Y2FyaWJvdW1hdXJpY2UK"}]'
2016/08/23 17:25:55 signature 0 pass
```

## Rationale

As we rapidly increase the number of services that send configuration data to
Firefox agents, we also increase the probability of a service being
compromised to serve fraudulent data to our users. Autograph implements a way
to sign the information sent from backend services to Firefox user-agents, and
protect them from a service compromise.

Digital signature adds an extra layer to the ones already provided by TLS and
certificates pinning. As we grow our service infrastructure, the risk of a
vulnerability on our public endpoints increases, and an attacker could exploit
a vulnerability to serve bad data from trusted sites directly. TLS with
certificate pinning prevents bad actors from creating fraudulent Firefox
services, but does not reduce the impact a break-in would have on our users.
Digital signature provides this extra layer.

Finally, digital signature helps us use Content Delivery Network without
worrying that a CDN compromise would end-up serving bad data to our users.
Signing at the source reduces the pressure off of the infrastructure and
allows us to rely on vendors without worrying about data integrity.

## Architecture

### Signing

Autograph exposes a REST API that services can query to request signature of
their data. Autograph knows which key should be used to sign the data of a
service based on the service's authentication token. Access control and rate
limiting are performed at that layer as well.

![signing.png](docs/statics/Autograph signing.png)

### Certificate issuance and renewal

Autograph signs data using ECDSA keys. The autograph public certs are signed
by intermediate certs stored in HSMs, themselves signed by a Root CA stored
offline. The Root CA is trusted in NSS, but for specific purposes only (eg. not
signing website certs). Upon verification of a signature issued by Autograph,
Firefox clients verify the full chain of trust against the root CAs, like any
other PKI.

![signing.png](docs/statics/Autograph issuance.png)

Accessing the RootCA requires multiple people and a key ceremony, so we only do
it every couple of years to reissue intermediate certificates. The
intermediates are kept safely in HSMs where their private keys cannot be
exported or stolen.

Every month-or-so, the autograph signers are refreshed with new certificates
valid for only short period of time. Upon refresh, autograph calls the HSMs
API with a CSR to obtain signed certificates. Those certificates are then
stored in a public location when Firefox agents can retrieve them to verify
signatures.

The full sequence from Root CA key ceremony to Firefox clients verifying
signatures is described in the diagram below.

![pkisequence](docs/statics/ContentSignaturePKI.png)

## API

Authorization: All API calls require a
[hawk](https://github.com/hueniverse/hawk) Authorization header with payload
signature enabled. Example code for can be found in the `tools` directory.

### /sign/data

#### Request

Request a signature on raw data. The data to sign is passed in the request body
using the JSON format described below.

When requesting the signature of raw data, autograph will determine which hash
function to use based on the key type (eg. p384 with sha384). The caller can
also force a specific hash algorithm with the `hashwith` parameter.

The request body is an array of signature requests, to allow for batching signature
of multiple inputs into a single API request.

example:
```bash
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
```

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
  [Content-Signature](https://github.com/martinthomson/content-signature/) protocol,
  and is needed to verify signatures in Firefox. But, if needed, autograph can
  return signatures in other formats:
   * `rs_base64url` is the default format and returns the signature in R||S
     format with base64 url safe encoding.
   * `rs_base64` returns the signature in R||S format with regular base64 encoding
     instead of base64_urlsafe.
   * `der_base64` returns the signature in DER ASN.1 format, encoded with
     regular base64. This format is useful to verify signatures with OpenSSL or
     other libraries.
   * `der_base64url` is similar to the previous one but uses base64 urlsafe.

#### Response

A successful request return a `201 Created` with a response body containing
signature elements encoded in JSON. The ordering of the response array is
identical to the request array, such that signing request 1 maps to signing
response 1, etc...

```json
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
```
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

### /sign/hash

#### Request

Request a signature on a hash. The hash is provided as a base64 encoded bytes
array, and is not manipulated at all by autograph before signing. You must
ensure that data is templated prior to hashing it and calling autograph.

This endpoint always returns a `content-signature` with every response.

example:
```bash
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
```

Body format:
The request body is a json array where each entry of the array is an object to sign. The parameters are:

* input: base64 encoded hash to sign

* keyid: see `/sign/data`

* signature_encoding: see `/sign/data`

#### Response

See `/sign/data`, the response format is identical.


### /__monitor__

This is a special endpoint designed to monitor the status of all signers without
granting signing privileged to a monitoring client. It requires a special user
named `monitor` that can request a signature of the string `AUTOGRAPH MONITORING`
by all active signers.

#### Request

The endpoint accepts a GET request without query parameter or request body. The
`Hawk` authorization of the user named `monitor` is required.

```bash
GET /__monitor__

Host: autograph.example.net
Content-type: application/json
Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="
```

#### Response

See `/sign/data`, the response format is identical.
For each signer, two responses are returned: one with Content-Signature
templating applied to the input data, and one without.

The monitoring client should verify the signature returned with each response.
If X5U values are provided, the monitoring client should verify that certificate
chains are hosted at those locations, and that certificate are not too close to
their expiration date.

### /__heartbeat__ and /__lbheartbeat__

Heartbeating endpoints designed to answer load balancers with a 200 OK.

```bash
HTTP/1.1 200 OK
Date: Fri, 05 Aug 2016 20:19:54 GMT
Content-Length: 4
Content-Type: text/plain; charset=utf-8

ohai
```

### /__version__

Returns metadata about the autograph version.
```bash
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
```

## Configuration

The configuration lives in `autograph.yaml` and is expected in
`/etc/autograph/autograph.yaml` (use flag `-c` to provide an alternate
location).

### Listener

Define an address and port for the API to listen on:
```yaml
server:
    listen: "192.168.1.28:8000"
```

### Signers
Then configure the signers. Each signer is composed of an identifier
and an ECDSA private key (any curve [supported by
Go](https://godoc.org/crypto/elliptic) works).

To generate a key pair with openssl, use:
```bash
$ openssl ecparam -out /tmp/autograph-dev.key -name secp384r1 -genkey

$ openssl ec -in /tmp/autograph-dev.key -text
-----BEGIN EC PARAMETERS-----
BgUrgQQAIg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDC32Lv42JlmEnaPHe+UG6wtrG39vHZAQtvUPTPgJP8Bflfsy0T30Q/5
AMXvh0EgFbigBwYFK4EEACKhZANiAAS74cJMSG3ZjlTcjBZl5pHnimoCxAM+XL3f
jLy0FvStcQqyWkMacmAY3MqM4YxvyBNv5J+JJPAkskYVomQzk3/8La+D2UQuj6Xu
ReTKJie8EppVvrXwMAjhSy5zsuq7/gI=
-----END EC PRIVATE KEY-----
```

Take the base64 keys from the `BEGIN EC PRIVATE KEY` to `END EC PRIVATE KEY`
blocks and add them to the configuration file as a single line.
```yaml
signers:
    - id: appkey2
      privatekey: "MIGkAgEBBDC32Lv42JlmEnaPHe+UG6wtrG39vHZAQtvUPTPgJP8Bflfsy0T30Q/5AMXvh0EgFbigBwYFK4EEACKhZANiAAS74cJMSG3ZjlTcjBZl5pHnimoCxAM+XL3fjLy0FvStcQqyWkMacmAY3MqM4YxvyBNv5J+JJPAkskYVomQzk3/8La+D2UQuj6XuReTKJie8EppVvrXwMAjhSy5zsuq7/gI="
```

Based on the `privatekey`, autograph will return the corresponding `publickey`
in the JSON responses. If you're using a PKI and want to verify signatures with
a X.509 certificate, you can generate this certificate based on the private key,
store it someplace, and tell autograph to return its location in the `x5u`
value.

```bash
# first make a CSR based on the private key
$ openssl req -new -key /tmp/autograph-dev.key -out /tmp/autograph-dev.csr

# then self sign the CSR
$ openssl x509 -req -days 365 -in /tmp/autograph-dev.csr -signkey /tmp/autograph-dev.key -out /tmp/autograph-dev.crt
```

Store the CRT on `http://example.net/certs/autograph-dev.crt` and set the x5u value in `autograph.yaml`.
```yaml
signers:
    - id: appkey2
      privatekey: "MIGkAgEBBDC32Lv42JlmEnaPHe+....."
      x5u: "http://example.net/certs/autograph-dev.crt"
```

### Authorizations

Authorizations map an arbitrary username and key to a list of signers. The
key does not need to be generated in any special way, but you can use the tool
in `tools/maketoken/main.go` to obtain a random 256bits string:
```bash
$ go run tools/maketoken/main.go
256bits random token: xsdxco7uy0pn1ei004pdkl4ex1krdu6z6o1rl1dweooo7t7tk0
```

Then add it to the configuration as follows:
```yaml
authorizations:
    - id: alice
      key: fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu
      signers:
          - appkey1
          - appkey2
    - id: bob
      key: 9vh6bhlc10y63ow2k4zke7k0c3l9hpr8mo96p92jmbfqngs9e7d
      signers:
          - appkey2
```

The configuration above allows `alice` to request signatures from both `appkey1`
and `appkey2`, while `bob` is only allowed to request signatures from `appkey2`.

Note that, when a user is allowed to sign with more than one signer, and no
specific signer key id is provided in the signing request, autograph will use
the first signer in the list. For example, if alice requests a signature without
providing a key id, the private key from `appkey1` will be used to sign her
request.

### Build and running

Build the autograph binary using make:
```bash
$ make
```

The binary is located in `$GOPATH/bin/autograph` and can be started with the
configuration file:
```bash
$ $GOPATH/bin/autograph -c autograph.yaml 
{"Timestamp":1453721399358695130,"Type":"app.log","Logger":"Autograph","Hostname":"gator1","EnvVersion":"2.0","Pid":17287,"Fields":{"msg":"main.go:74: Starting Autograph API on localhost:8000"}}
```

You can test that the API is alive by querying its heartbeat URL:
```bash
$ curl localhost:8000/__heartbeat__
ohai
```

## Test Key/Cert
For dev and testing purposes, the private key `appkey1` can be used with the
following self-signed certificate:
```
-----BEGIN CERTIFICATE-----
MIICjjCCAhUCCQC92fl+HNcL+zAKBggqhkjOPQQDAjCBsDELMAkGA1UEBhMCVVMx
EzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDU1vdW50YWluIFZpZXcxHDAa
BgNVBAoTE01vemlsbGEgQ29ycG9yYXRpb24xFzAVBgNVBAsTDkNsb3VkIFNlcnZp
Y2VzMRYwFAYDVQQDEw1BdXRvZ3JhcGggRGV2MSUwIwYJKoZIhvcNAQkBFhZob3N0
bWFzdGVyQG1vemlsbGEuY29tMB4XDTE2MDIwNjAwMDYwMloXDTI2MDIwMzAwMDYw
MlowgbAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1Nb3VudGFpbiBWaWV3MRwwGgYDVQQKExNNb3ppbGxhIENvcnBvcmF0aW9uMRcw
FQYDVQQLEw5DbG91ZCBTZXJ2aWNlczEWMBQGA1UEAxMNQXV0b2dyYXBoIERldjEl
MCMGCSqGSIb3DQEJARYWaG9zdG1hc3RlckBtb3ppbGxhLmNvbTB2MBAGByqGSM49
AgEGBSuBBAAiA2IABOJNxZhu3RaDrd07s5e+mm00bSvLG/6/4mwknlSmvekW6zl9
nIrHM/00/MH6gWEv/HDeMzHtfn+8EZpDawlKI2UdWSpmDNgXolDjJTKKpNju/rsL
J9Q8DUEmD+fE5L2bejAKBggqhkjOPQQDAgNnADBkAjARjtum9oq77JL9fhZ46Q1S
vxT5RAdzQRp9/l3OqnUP+kK42tRk05c9UGDFXLLVH/4CMH/ZmcpvtM0sCjeAWzGs
gnw91z0443965WZmaeBKpbinxB1PpnNMCnPhd9J/Hz40+Q==
-----END CERTIFICATE-----
```
