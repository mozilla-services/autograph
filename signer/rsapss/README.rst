RSA-PSS Signing
===============

**THIS SIGNER IS DEPRECATED, USE THE `genericrsa` SIGNER INSTEAD**

.. sectnum::
.. contents:: Table of Contents

This signer implements RSA-PSS signing for Widevine and possibly other
signature types in the future. It accepts 20-byte SHA1 hashes on
`/sign/hash` and data to be hashed on `/sign/data`. Both endpoints
return base64-encoded RSA-PSS signatures of the hashed data using
`rsa.PSSSaltLengthEqualsHash` padding.

Example Usage:

.. code:: bash

    # hash your input data into a separate file
    $ echo foo | sha1sum -b | cut -d ' ' -f 1 | xxd -r -p > /tmp/inputhash.bin

    # request a signature using the autograph client
    $ go run client.go -D -wa $(cat /tmp/inputhash.bin | base64) \
      -k dummyrsapss -o /tmp/sig.bin -ko /tmp/pub.key

    # format /tmp/pub.key to PEM (fold lines to 64 and add header and footer)
    $ (echo '-----BEGIN PUBLIC KEY-----'; cat /tmp/pub.key |fold -w 64; echo;echo '-----END PUBLIC KEY-----') > /tmp/pub.pem

    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtEM/Vdfd4Vl9wmeVdCYu
    WYnQl0Zc9RW5hLE4hFA+c277qanE8XCK+ap/c5so87XngLLfacB3zZhGxIOut/4S
    lEBOAUmVNCfnTO+YkRk3A8OyJ4XNqdn+/ov78ZbssGf+0zws2BcwZYwhtuTvro3y
    i62FQ7T1TpT5VjljH7sHW/iZnS/RKiY4DwqAN799gkB+Gwovtroabh2w5OX0P+PY
    yUbJLFQeo5uiAQ8cAXTlHqCkj11GYgU4ttVDuFGotKRyaRn1F+yKxE4LQcAULx7s
    0KzvS35mNU+MoywLWjy9a4TcjK0nq+BjspKX4UkNwVstvH18hQWun7E+dxTi59cR
    mwIDAQAB
    -----END PUBLIC KEY-----

    # verify the signature with openssl
    $ openssl pkeyutl -verify \
    -in /tmp/inputhash.bin \
    -sigfile /tmp/sig.bin \
    -inkey /tmp/pub.pem -pubin -keyform PEM \
    -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1 -pkeyopt digest:sha1

    Signature Verified Successfully

Configuration
-------------

Requires PEM encoded public and private RSA keys.

NB: if the publickey does not match the private key the monitor will
break.

For example:

.. code:: yaml

    signers:
    - id: some-rsa-key
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
