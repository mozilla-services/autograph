Widevine Signing
================

.. sectnum::
.. contents:: Table of Contents

This signer implements Widevine signing. It accepts 20-byte SHA1
hashes on `/sign/hash` and data to be hashed on `/sign/data`. Both
endpoints return base64-encoded RSA PSS signatures of the hashed data.

Example Usage:

.. code:: bash

    # request a signature using the autograph client
    $ go run client.go -D -wa $(echo hi | sha1sum -b | cut -d ' ' -f 1 | xxd -r -p | base64) \
      -k dummywidevine -o signed-hash.out -ko /tmp/testkey.pub

Configuration
-------------

Requires PEM encoded public and private RSA keys.

NB: if the publickey does not match the private key the monitor will
break.

For example:

.. code:: yaml

    signers:
    - id: some-widevine-rsa-key
      type: widevine
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

Returns base64-encoded public key and signature. The public key is
from the config.

.. code:: json

    [
      {
        "ref": "1rvr84djhxxg11mmyk4imt9ekv",
        "type": "widevine",
	"mode": "",
        "signer_id": "some-widevine-rsa-key",
        "public_key": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0RU0vVmRmZDRWbDl3bWVWZENZdQpXWW5RbDBaYzlSVzVoTEU0aEZBK2MyNzdxYW5FOFhDSythcC9jNXNvODdYbmdMTGZhY0IzelpoR3hJT3V0LzRTCmxFQk9BVW1WTkNmblRPK1lrUmszQThPeUo0WE5xZG4rL292NzhaYnNzR2YrMHp3czJCY3daWXdodHVUdnJvM3kKaTYyRlE3VDFUcFQ1Vmpsakg3c0hXL2lablMvUktpWTREd3FBTjc5OWdrQitHd292dHJvYWJoMnc1T1gwUCtQWQp5VWJKTEZRZW81dWlBUThjQVhUbEhxQ2tqMTFHWWdVNHR0VkR1RkdvdEtSeWFSbjFGK3lLeEU0TFFjQVVMeDdzCjBLenZTMzVtTlUrTW95d0xXank5YTRUY2pLMG5xK0Jqc3BLWDRVa053VnN0dkgxOGhRV3VuN0UrZHhUaTU5Y1IKbXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==",
        "signature": "oOYuyidOjDC/Y7ADLGJM6L9NkJxpvX32OoLQpWulUT+oxETNj81VwRiF+FxXL8ds0Mc6ZMxtMqGbTw9PDVu0svt3Kp7ifdmNecyIuRKGF7dxSWQlbSrgJF+yF7GzaAyy/HybxOr6cjFrU7mY60019bnqqM77sWZMeox+LbdaHWefDYbityzNBcf11qHIN3edxvaVsIFm91AR6yWxlhCpcy2agX5IWsOjzV6kCyD2smuRp+QUH+ABjHkWP6DSYeV34T++fiH0Fh4/A8WQrQhwolxf0DBOihlEceMdVtHzi/ovIU+LidWM3PgxEBlM8c2Gnh5jJYN47Z4bGUxm+swLfA=="
      }
    ]
