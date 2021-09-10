# API Endpoints

Authorization: All API calls require a
[hawk](https://github.com/mozilla/hawk) Authorization header with
payload signature enabled. Example code can be found in the `tools`
directory.

## /sign/data

### Request

Request a signature on raw data. The data to sign is passed in the
request body using the JSON format described below.

The request body is an array of signature requests, to allow for
batching signatures into a single API request. The parameters are:

-   **input**: base64 encoded data to sign
-   **keyid**: allows the caller to specify a key to sign the data with.
    This parameter is optional, and Autograph will pick a key based on
    the caller\'s permission if omitted.
-   **options**: a JSON object used to pass signer-specific options in
    the request. Refer to the documentation of each signer to find out
    which options they accept.

example:

``` bash
POST /sign/data
Host: autograph.example.net
Content-type: application/json
Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="

[
    {
      "input": "c29tZSB2ZXJ5IGxvbmcgaW5wdXQgdGhhdCBkb2VzIG5vdCBjb250YWluIGFueXRoaW5nIGludGVyZXN0aW5nIG90aGVyIHRoYW4gdGFraW5nIHNwYWNlCg=="
    },
    {
      "input": "U2lnbmF0dXJlLVZlcnNpb246IDEuMApNRDUtRGlnZXN0LU1hbmlmZXN0OiBoWmt4TjVhUW5PMTNhUGl3U3B4amlRPT0KU0hBMS1EaWdlc3QtTWFuaWZlc3Q6IGQxV09kTCsyUXVzeW1LYXBpTHB3bnhBd2Rjcz0KCg==",
      "keyid": "webextensions-rsa",
      "options": {
        "id": "sample-mozilla-extension@tests.mozilla.org"
      }
    }
]
```

### Response

A successful request return a `201 Created` with a response
body containing signature elements encoded in JSON. The ordering of the
response array is identical to the request array, such that signing
request 0 maps to signing response 0, etc.

Below is an example signing response for a content-signature request:

``` json
[
  {
    "ref": "1p21kj11od4no13o1xepn22mkc",
    "type": "contentsignature",
    "mode": "p384ecdsa",
    "signer_id": "appkey1",
    "public_key": "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7oM/ewOhz6qtHyQhqJvT3SiefGPWqGwEUAZGVkuSIwvteVKrd8jnAjHYyCaYpIg9Vo10WnhXvm96L3KAbOE6Cyu3fMtKhZZIMf+Qqes9+66ae/NTeIWlDiGrjNeD+ClM",
    "signature": "Niffk674SNKzQaq23z2sv7xkU_IEgrPc8_tEFGw0bYXlNJDpAPe7hEaipyg-wY10_XUzkoRphtYVIAa70Hw22EkWfSGAdzosEYyxsDai52PG088KqasP_nd_byiiqIAz",
    "x5u": "https://foo.example.com/chains/certificates.pem"
  }
]
```

Each signature response contains the following fields:

-   `ref` is a random string that acts as a reference number
    for logging and tracking.
-   `type` is the type of signer that issued the signature
-   `signer_id` is ID of the signer in configuration.
-   `public_key` is the DER encoded public key that maps to
    the signing key used to generate the signature. This value can be
    used by clients to verify signatures. The DER format is supported by
    OpenSSL and most libraries.
-   `signature` is the signature encoded in the proper
    format. Each signer uses a different format, so refer to their
    documentation for more information.

## /sign/file

### Request

Request for a signature on signed files. This can be useful to add hash
manifests to files and reduce the number of round trips for file formats
requiring multiple signatures. The files to sign are passed in the
request body using the JSON format described below.

The request body is an array of signature requests, to allow for
batching signatures into a single API request. The parameters are:

-   **input**: a base64 encoded file to sign
-   **keyid**: allows the caller to specify a key to sign the data with.
    This parameter is optional, and Autograph will pick a key based on
    the caller\'s permission if omitted.
-   **options**: a JSON object used to pass signer-specific options in
    the request. Refer to the documentation of each signer to find out
    which options they accept.

example:

``` bash
POST /sign/file
Host: autograph.example.net
Content-type: application/json
Authorization: Hawk id="alice", mac="756lSgQEYLoc6V0Uv2wS8pRg/h+4WFUVKWQynCFvY8Y=", ts="1524487134", nonce="MrpGL35q", hash="9m3WhtGQDuHermi5fDYBGJlOqNeK5B3nk0lKreZ+YSw=", ext="933126753"

[
    {
      "input":"UEsDBBQACAAIAAAAAAAAAAAAAAAAAAAAAAATAAAAQW5kcm9pZE1hbmlmZXN0LnhtbKSYS2ybx7XHf0PqbVmW4...BwAACigAAAAA",
    },
    {
      "input":"UEsDBBQACAAIAAAAAAAAAAAAAAAAAAAAAAATAAAAQW5kcm9pZE1hbmlmZXN0LnhtbKSYS2ybx7XHf0PqbVmW4...BwAACigAAAAA",
      "keyid":"testapp-android",
      "options":null
    }
]
```

### Response

A successful request return a `201 Created` with a response
body containing all signed files encoded in JSON. The ordering of the
response array is identical to the request array, such that signing
request 0 maps to signing response 0, etc.

The response format is the same as `/sign/data` except
instead of the `signature` field autograph returns the
field:

-   `signed_file` is the base64 encoded signed file data.
    Each signer uses a different format, so refer to their documentation
    for more information.

## /sign/hash

### Request

Request a signature on a hash. The hash is provided as a base64 encoded
bytes array, and is not manipulated at all by autograph before signing.
You must ensure that data is templated prior to hashing it and calling
autograph.

example:

``` bash
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

Body format: The request body is a json array where each entry of the
array is an object to sign. The parameters are:

-   input: base64 encoded hash to sign
-   keyid: see `/sign/data`
-   options: see `/sign/data`

### Response

See `/sign/data`, the response format is identical.

### Response

A successful request return a `201 Created` with a response
body containing an S/MIME detached signature encoded with Base 64.

## /\_\_monitor\_\_

This is a special endpoint designed to monitor the status of all signers
without granting signing privileges to a monitoring client. It requires
a special user named `monitor` that can request a signature
of the string `AUTOGRAPH MONITORING` by all active signers.

### Request

The endpoint accepts a GET request without query parameter or request
body. The `Hawk` authorization of the user named
`monitor` is required.

``` bash
GET /__monitor__

Host: autograph.example.net
Content-type: application/json
Authorization: Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="
```

### Response

One signing response per active signer is returned. The format follows
the standard signing response format described in
`/sign/data`.

The monitoring client should verify the signature returned with each
response. If X5U values are provided, the monitoring client should
verify that certificate chains are hosted at those locations, and that
certificate are not too close to their expiration date.

## /\_\_heartbeat\_\_ and /\_\_lbheartbeat\_\_

Heartbeating endpoints designed to answer load balancers with a 200 OK.

``` bash
HTTP/1.1 200 OK
Date: Fri, 05 Aug 2016 20:19:54 GMT
Content-Length: 4
Content-Type: text/plain; charset=utf-8

ohai
```

## /\_\_version\_\_

Returns metadata about the autograph version.

``` bash
HTTP/1.1 200 OK
Date: Fri, 05 Aug 2016 20:20:54 GMT
Content-Length: 209
Content-Type: text/plain; charset=utf-8

{
"source": "https://github.com/mozilla-services/autograph",
"version": "20160512.0-19fbb91",
"commit": "19fbb910e2bd81cdd71fba2d1a297852a3ca17e8",
"build": "https://travis-ci.org/mozilla-services/autograph"
}
```
