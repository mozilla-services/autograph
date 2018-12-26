PGP Signing with GPG2
=====================

.. sectnum::
.. contents:: Table of Contents

This signer implements the Pretty Good Privacy signature format. It
accepts data on the `/sign/data` interface and returns armored
detached signatures like the `pgp` signer.

Unlike the `pgp` signer `gpg2` supports loading private keys with
passphrases exported with the `unsupported and non-standard gnu-dummy
S2K algorithm`_ and signing with subkeys. However, it does require
that a gpg2 version > 2.1 be installed.

.. _`unsupported and non-standard gnu-dummy S2K algorithm`: https://github.com/golang/go/issues/13605


Example Usage:

.. code:: bash

    # request a signature using the autograph client
    $ go run client.go -d $(base64 /tmp/pgpinput.txt) -k pgpsubkey \
      -o /tmp/testsig.pgp -ko /tmp/testkey.asc

    # import the public key returned by autograph into a temp keyring
    $ gpg --no-default-keyring --keyring /tmp/testkeyring.pgp \
      --secret-keyring /tmp/testsecring.gpg --import /tmp/testkey.asc

    # verify the signature using the temp keyring
    $ gpg --no-default-keyring --keyring /tmp/testkeyring.pgp \
      --secret-keyring /tmp/testsecring.gpg \
      --verify /tmp/testsig.pgp /tmp/pgpinput.txt


Configuration
-------------

Add a signer to `autograph.yaml` with the following **required** fields

1. a PGP public key (e.g. a key exported with `gpg --armor --export $KEYID`)
2. a PGP private key (e.g. a subkey exported with `gpg --armor --export-secret-subkeys $SUBKEYID`)
3. a KeyID or fingerprint specifying which private key sign with (e.g. `$SUBKEYID` from the above export)
4. a passphrase to unlock the private key

For example:

.. code:: yaml

    signers:
    - id: some-pgp-key
      type: gpg2
      keyid: 0xE09F6B4F9E6FDCCB
      passphrase: abcdef123
      privatekey: |
        -----BEGIN PGP PRIVATE KEY BLOCK-----

        lQOYBFuW9xABCACzCLYHwgGba7hi+lwhD/Hr5qqpg+UuN+88NclYgLWyl1nPpx2D
        ...
        HQASoA7mirON
        =vJUu
        -----END PGP PRIVATE KEY BLOCK-----
      publickey: |
        -----BEGIN PGP PUBLIC KEY BLOCK-----
	...
        =459B
        -----END PGP PUBLIC KEY BLOCK-----

Signature request
-----------------

This signer only supports the `/sign/data/` endpoint.

.. code:: json

    [
        {
            "input": "Y2FyaWJvdW1hdXJpY2UK",
            "keyid": "pgpsubkey"
        }
    ]

Signature response
------------------

The response to a data signing request contains a PGP armored detached
signature in its raw form with newlines preserved but wrapped on a single line
due to JSON marshalling. You can write it out to a file to recover the standard
armored signature that gnupg expects.

.. code:: json

    [
      {
        "ref": "7khgpu4gcfdv30w8joqxjy1cc",
        "type": "pgp",
        "signer_id": "some-pgp-key",
        "public_key":"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxsBNBFuW9xABCACzCLYHwg...",
        "signature":"-----BEGIN PGP SIGNATURE-----\n\nwsBcBAABCAAQBQJbt3KqCRDdCl2Z...."
      }
    ]
