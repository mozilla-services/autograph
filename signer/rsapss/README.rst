RSA-PSS Signing
===============

.. sectnum::
.. contents:: Table of Contents

This signer implements RSA-PSS signing for Widevine and possibly other
signature types in the future. It accepts 20-byte SHA1 hashes on
`/sign/hash` and data to be hashed on `/sign/data`. Both endpoints
return base64-encoded RSA-PSS signatures of the hashed data using
`rsa.PSSSaltLengthEqualsHash` padding.

Example Usage:

.. code:: bash

    # request a signature using the autograph client
    $ go run client.go -D -wa $(echo hi | sha1sum -b | cut -d ' ' -f 1 | xxd -r -p | base64) \
      -k dummyrsapss -o signed-hash.out -ko /tmp/testkey.pub

Configuration
-------------

Requires PEM encoded public and private RSA keys.

NB: if the publickey does not match the private key the monitor will
break.

For example:

.. code:: yaml

    signers:
    - id: some-rsapss-rsa-key
      type: rsapss
      privatekey: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAtEM/Vdfd4Vl9wmeVdCYuWYnQl0Zc9RW5hLE4hFA+c277qanE
        ...
        TDd4Me4PP+sTZeJ3RKvArDiMzEncDeMGZZnd4dBdi3LjzCNGTANAGw==
        -----END RSA PRIVATE KEY-----
      publickey: |
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtEM/Vdfd4Vl9wmeVdCYu
        ...
        mwIDAQAB
        -----END PUBLIC KEY-----

Signature response
------------------

Returns base64-encoded public key (DER) and signature (hex). The
public key is from the config.

.. code:: json

    [
      {
        "ref": "29cfra8jxug9r3mzjapmlbjlp5",
        "type": "rsapss",
        "mode": "",
        "signer_id": "dummy-rsapss",
        "public_key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtEM/Vdfd4Vl9wmeVdCYuWYnQl0Zc9RW5hLE4hFA+c277qanE8XCK+ap/c5so87XngLLfacB3zZhGxIOut/4SlEBOAUmVNCfnTO+YkRk3A8OyJ4XNqdn+/ov78ZbssGf+0zws2BcwZYwhtuTvro3yi62FQ7T1TpT5VjljH7sHW/iZnS/RKiY4DwqAN799gkB+Gwovtroabh2w5OX0P+PYyUbJLFQeo5uiAQ8cAXTlHqCkj11GYgU4ttVDuFGotKRyaRn1F+yKxE4LQcAULx7s0KzvS35mNU+MoywLWjy9a4TcjK0nq+BjspKX4UkNwVstvH18hQWun7E+dxTi59cRmwIDAQAB",
        "signature": "S81qc/poBLToOIXVd8eOS6/CxXdhdsM/0Uz0q4cJWdmSKf9Iv8Eboz94xfuMgl81ybtPrEWDuZRLgY1qr4GxhShwa1Yb7rBtGxyJlseYfstnf24T7B6s4aeW3Zo5lfF2SCONbI0hLSHHyFzPPsnCHxvA2Ji5F+vDeBLpSrXhFn+mn14AGhz6smtU4k/iLPrfhocvBGscZv+7h7PI0vPs3MEckVZeSP8i0CkK4ev1QV88wrIa8estHCbiT4STu5zBHYb0LkkowEyCMW0KrQu5M2HO8yL4SSK9LHNR4WOS8BxBvKIXjmG5bjcH+g0gEK0RFSuJ3sLCNoRETGhRykufJA=="
      }
    ]
