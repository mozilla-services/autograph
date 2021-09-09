# PGP Signing with GPG2

This signer implements the Pretty Good Privacy signature format. It
accepts data on the [/sign/data]{.title-ref} interface and returns
armored detached signatures like the [pgp]{.title-ref} signer.

**Try the \`pgp\` signer first since it keeps private keys in memory,
which is more secure.**

Only use the this signer if the [pgp]{.title-ref} signer doesn\'t
understand your key format and you need to load private keys with
passphrases exported with the [unsupported and non-standard gnu-dummy
S2K algorithm](https://github.com/golang/go/issues/13605) and sign with
a subkey. Also prefer the [pgp]{.title-ref} signer, since this signer 1)
requires a the gpg2 binary with version \>2.1, 2) writes private keys to
keyrings on disk, and 3) shells out to the [gpg2]{.title-ref} binary.

Example Usage:

``` bash
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
```

# Configuration

Add a signer to [autograph.yaml]{.title-ref} with the following
**required** fields

1.  a PGP public key (e.g. a key exported with [gpg \--armor \--export
    \$KEYID]{.title-ref})
2.  a PGP private key (e.g. a subkey exported with [gpg \--armor
    \--export-secret-subkeys \$SUBKEYID]{.title-ref})
3.  a KeyID or fingerprint specifying which private key sign with (e.g.
    [\$SUBKEYID]{.title-ref} from the above export or from [gpg
    \--list-keys \--with-subkey-fingerprint]{.title-ref})
4.  a passphrase to unlock the private key

For example:

``` yaml
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
```

# Signature request

This signer only supports the [/sign/data/]{.title-ref} endpoint.

``` json
[
    {
        "input": "Y2FyaWJvdW1hdXJpY2UK",
        "keyid": "pgpsubkey"
    }
]
```

# Signature response

The response to a data signing request contains a PGP armored detached
signature in its raw form with newlines preserved but wrapped on a
single line due to JSON marshalling. You can write it out to a file to
recover the standard armored signature that gnupg expects.

``` json
[
  {
    "ref": "7khgpu4gcfdv30w8joqxjy1cc",
    "type": "pgp",
    "signer_id": "some-pgp-key",
    "public_key":"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxsBNBFuW9xABCACzCLYHwg...",
    "signature":"-----BEGIN PGP SIGNATURE-----\n\nwsBcBAABCAAQBQJbt3KqCRDdCl2Z...."
  }
]
```
