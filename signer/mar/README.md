---
title: MAR Signing
---

::: sectnum
:::

::: contents
Table of Contents
:::

MAR is Firefox\'s update file format. For a full description, see
[go.mozilla.org/mar](https://godoc.org/go.mozilla.org/mar).

# Configuration

The only thing needed to configure a MAR signer is a private key, either
RSA or ECDSA P256/P384.

``` yaml
signers:
- id: testmar
  type: mar
  privatekey: |
      -----BEGIN PRIVATE KEY-----
      MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQDHV+bKFLr1p5FR
      ...
      -----END PRIVATE KEY-----
```

# Signature request

This signer supports [/sign/hash]{.title-ref}, [/sign/data]{.title-ref}
and [/sign/file]{.title-ref} endpoints. They all use the same request
format:

``` json
[
    {
        "input": "Y2FyaWJvdW1hdXJpY2UK",
        "keyid": "testmar"
    }
]
```

The [/sign/file]{.title-ref} endpoint takes a whole MAR encoded in
base64. It will parse the mar, sign it and return the signed file.

The [/sign/data]{.title-ref} and [/sign/hash]{.title-ref} endpoint only
does the signing step. They takes a MAR block already prepared for
signature, calculate its digest (if [/sign/data]{.title-ref}) and return
the signature bytes to be inserted in the signature field. Because the
signer needs to know which algorithm to use for signature, the signature
algorithm can be specified in the signing request options. The
acceptable value of the [sigalg]{.title-ref} field can be found in [the
constants of the MAR
package](https://godoc.org/go.mozilla.org/mar#pkg-constants).

``` json
[
    {
        "input": "Y2FyaWJvdW1hdXJpY2UK",
        "keyid": "testmar",
        "options": {
            "sigalg": 1
        }
    }
]
```

# Signature response

## Data & Hash Signing

The response to a data or hash signing request contains the base64 of
the signature in the [signature]{.title-ref} field of the JSON response.
You should decode this base64 and insert it into the MAR\'s signature
entry.

``` json
[
  {
    "ref": "7khgpu4gcfdv30w8joqxjy1cc",
    "type": "mar",
    "signer_id": "testmar",
    "signature": "MIIGPQYJKoZIhvcN..."
  }
]
```

## File Signing

The response to a file signing request contains the base64 of the signed
MAR in the [signed_file]{.title-ref} field of the json response. You
should base64 decode that field and write the output as a file.

``` json
[
  {
    "ref": "7khgpu4gcfdv30w8joqxjy1cc",
    "type": "mar",
    "signer_id": "testmar",
    "signed_file": "MIIGPQYJKoZIhvcN..."
  }
]
```

# Verifying signatures

Firefox has a [signmar]{.title-ref} tool that can be used to verify MAR
signatures. Refer to [MAR Signing and
Verification](https://wiki.mozilla.org/Software_Update:MAR_Signing_and_Verification)
for more details.
