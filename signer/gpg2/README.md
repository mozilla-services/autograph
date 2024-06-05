# PGP Signing with GPG2

This signer implements the Pretty Good Privacy signature format and
Debian GPG signing using `debsign`.

When configured in `gpg2` mode it accepts data on the `/sign/data`
interface and returns armored detached signatures.

In `debsign` mode it accepts files on the `/sign/files` interface and
returns the clearsigned files.

Example Usage:

``` bash
# request a signature using the autograph client
$ go run client.go -d $(base64 /tmp/pgpinput.txt) -k pgpsubkey \
  -o /tmp/testsig.pgp -ko /tmp/testkey.asc

# import the public key returned by autograph into a temp keyring
$ gpg --no-default-keyring --keyring /tmp/testkeyring.pgp \
  --import /tmp/testkey.asc

# verify the signature using the temp keyring
$ gpg --no-default-keyring --keyring /tmp/testkeyring.pgp \
  --verify /tmp/testsig.pgp /tmp/pgpinput.txt
```

## Configuration

Add a signer to `autograph.yaml` with the following
**required** fields

1.  a PGP public key (e.g. a key exported with `gpg --armor --export
    $KEYID`)
2.  a PGP private key (e.g. a subkey exported with `gpg --armor
    --export-secret-subkeys $SUBKEYID`)
3.  a KeyID or fingerprint specifying which private key sign with
    (e.g. `$SUBKEYID` from the above export or from `gpg --list-keys
    --with-subkey-fingerprint`)
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

The **optional** field `mode` it can be either `gpg2` or
`debsign`. When empty or missing it defaults to `gpg2` and should use
the full key fingerprint in the `keyid` field. For example:

```yaml
- id: some-pgp-key
  type: gpg2
  mode: debsign
  keyid: A2910E4FBEA076009BCDE536DD0A5D99AAAB1F1A
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

## Signature request

This signer only supports the `/sign/data/` endpoint in `gpg2` mode:

``` json
[
    {
        "input": "Y2FyaWJvdW1hdXJpY2UK",
        "keyid": "pgpsubkey"
    }
]
```

This signer only supports the `/sign/files/` endpoint in `debsign` mode:

``` json
[
    {
        "input": "",
        "keyid": "pgpsubkey-debsign",
        "signed_files": [
          {
            "name": "sphinx_1.7.2-1.dsc",
            "content": "LS0tLS1CRUdJTiBQR1AgU0lHTkVEIE1FU1NBR0UtLS0tLQpIYXNoOiBTS..."
          },
          {
            "name": "sphinx_1.7.2-1_amd64.buildinfo",
            "content": "LS0tLS1CRUdJTiBQR1AgU0lHTkVEIE1FU1NBR0UtLS0tLQpIYXNoOiBTS..."
          }
        ]
    }
]
```

## Signature response

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

In `debsign` mode responses are at the field `signed_files`:

```json
[
  {
    "ref": "boxfa5qavzf11p6zme2pd74tn",
    "type": "gpg2",
    "mode": "debsign",
    "signer_id": "pgpsubkey-debsign",
    "public_key": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBFwaoDMBEAC0FVHFLTVYFSr8ZpCWOKyF+Xrpcr032pOr3p3rBH6Ld9ZTpaLS...",
    "signed_files": [
      {
        "name": "sphinx_1.7.2-1.dsc",
        "content": "LS0tLS1CRUdJTiBQR1AgU0lHTkVEIE1FU1NBR0UtLS0tLQpIYXNoOiBTS..."
      },
      {
        "name": "sphinx_1.7.2-1_amd64.buildinfo",
        "content": "LS0tLS1CRUdJTiBQR1AgU0lHTkVEIE1FU1NBR0UtLS0tLQpIYXNoOiBTS..."
      }
    ]
  }
]
```
