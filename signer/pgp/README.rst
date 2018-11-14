PGP Signing
===========

.. sectnum::
.. contents:: Table of Contents

This signer implements the Pretty Good Privacy signature format. It accepts data
on the `/sign/data` interface and returns armored detached signatures.

Example:

.. code:: bash

    # request a signature using the autograph client
    $ go run client.go -d $(base64 /tmp/pgpinput.txt) -k randompgp \
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

Place a PGP Private Key in `autograph.yaml`:

.. code:: yaml

    signers:
    - id: some-pgp-key
      type: pgp
      privatekey: |
        -----BEGIN PGP PRIVATE KEY BLOCK-----

        lQOYBFuW9xABCACzCLYHwgGba7hi+lwhD/Hr5qqpg+UuN+88NclYgLWyl1nPpx2D
        ...
        HQASoA7mirON
        =vJUu
        -----END PGP PRIVATE KEY BLOCK-----

Signature request
-----------------

This signer only supports the `/sign/data/` endpoint.

.. code:: json

    [
        {
            "input": "Y2FyaWJvdW1hdXJpY2UK",
            "keyid": "some-pgp-key"
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
