# Content Signature

## Rationale

As we rapidly increase the number of services that send configuration
data to Firefox agents, we also increase the probability of a service
being compromised to serve fraudulent data to our users. Content
Signature implements a signing protocol to protect the information sent
from backend services to Firefox user-agents.

Content signature adds a layer to TLS and certificate pinning. As we
grow our service infrastructure, the risk of a vulnerability on our
public endpoints increases, and an attacker could exploit a
vulnerability to serve bad data from trusted sites directly. TLS with
certificate pinning prevents bad actors from creating fraudulent Firefox
services, but does not reduce the impact a break-in would have on our
users. Content signature provides this extra layer.

Finally, content signature helps us use Content Delivery Networks (CDN)
without worrying that a compromise would end-up serving bad data to our
users. Signing content at the source reduces pressure on the
infrastructure and allows us to rely on vendors without worrying about
data integrity.

For more information, refer to Julien Vehent\'s presentation linked
below:

[![image](https://img.youtube.com/vi/b2kPo8YdLTw/0.jpg)](https://www.youtube.com/watch?v=b2kPo8YdLTw)

## Signature

Content signatures are computed on data and served to Firefox either via
a HTTP response header or through a separate signature field in the data
being transported.

Content signature have three main components: a signature mode
(**mode**), an ecdsa signature encoded with Base64 URL (**signature**)
and the URL to a chain of certificates that link to a trusted root
(**x5u**). The example below shows the JSON representation of a content
signature:

``` json
{
  "mode": "p384ecdsa",
  "signature": "gZimwQAsuCj_JcgxrIjw1wzON8WYN9YKp3I5I9NmOgnGLOJJwHDxjOA2QEnzN7bXBGWFgn8HJ7fGRYxBy1SHiDMiF8VX7V49KkanO9MO-RRN1AyC9xmghuEcF4ndhQaI",
  "x5u": "https://foo.example.com/chains/certificates.pem"
}
```

-   **mode** is a suite of algorithms used to issue the signature. Two
    modes are supported:
    -   **p384ecdsa** is the default used by firefox. It calculates
        signatures on the P-384 NIST curve and uses SHA2-384 for hashes.
    -   **p256ecdsa** uses the P-256 NIST curve and SHA256 for hashes
-   **signature** contains the base64_url of the signature, computed
    using an elliptic curve and a hash algorithm that depends on the
    mode. The signature is issued by the private key of the end-entity
    cert referenced in the X5U. The decoded base64 contains a binary
    string that is a DL/ECSSA representation of the R and S values (IEEE
    Std 1363-2000). This format concatenates R and S into a single
    value. To retrieve R and S, split the decoded base64 in the middle,
    and take R on the left and S on the right.
-   **x5u** contains the location of the chain of trust that issued the
    signature. In practice, this file usually contains three
    certificates: the end-entity that issues the content signature, the
    intermediate issuer and the root of the Firefox private PKI. Firefox
    is configured to only accept signatures from the private PKI, as
    controlled via the
    [security.content.signature.root_hash]{.title-ref} preference, where
    the value is the hexadecimal of the sha256 of the DER of the root
    certificate.

When Firefox verifies a content signature, it first retrieves the X5U
and checks the signature validity using the end-entity certificate, the
signature, and the content being protected. Firefox then verifies the
chain of trust of the end-entity links to a root cert with a hash
matching the one in Firefox. Finally, to prevent application A from
signing content for application B, Firefox verifies the subject
alternate name of the end-entity certificate matches the one it expects.
This is hardcoded for each component that uses content signature.
Normandy, for example, uses the namespace
[normandy.content-signature.mozilla.org]{.title-ref} and only end-entity
certificates that have this subject alternate name can issue signatures
for the Normandy service.

## Configuration

The type of this signer is **contentsignaturepki**.

Unlike the original **contentsignature** signer which was entirely
manual, this signer automates the generation of end-entity certificates
at runtime, and uploads chains to a pre-determined location (typically
an S3 bucket).

To achieve this, it makes use of a Postgres database which must be
configured in the main autograph configuration file (refer to
*docs/configuration.md* for details). The database allows multiple
autograph instances in a cluster to collaborate in creating only one
end-entity at a time. Without a database, Autograph will also create new
end-entity certificates at startup because it has no way of knowing if
one already exists.

This signer needs a PKI that has been previously initialized (ideally in
an HSM but it will also work with local keys). You can make a PKI using
the *genpki* tool under *tools/*.

When initialized (when autograph starts), it will looks into the
database for an end-entity that is currently valid (using the *validity*
parameter) or create one if none is found. The end-entity public cert
will be valid for *validity*+\*clockskewtolerance\* amount of time. This
is done to accomodate clients that may have bad clocks. The standard is
to use a validity of 30 days and another 30 days ahead and after the
validity period for tolerance, effectively creating certificates that
are valid for 90 days (30d of clock skew in the past, 30 days of
validity, 30 days of clock skew in the future).

Once the end-entity created, it is concatenated to the public
certificate of the intermediate and root of the PKI, then uploaded to
*chainuploadlocation*, and retrieved from *x5u* (these two locations may
actually be different when we upload to an S3 bucket but download from a
CDN).

If this entire procedure succeeds, the signer is initialized with the
end-entity and starts processing requests.

``` yaml
signers:
- id: normandy
  type: contentsignaturepki

  # rotate certs every 29.5 days, a lunar month
  validity: 708h

  # give +/- 30d of validity room for clients with bad clocks
  clockskewtolerance: 10m

  # upload cert chains to this location (file:// is really just for local dev)
  chainuploadlocation: file:///tmp/chains/
  # when using S3, make sure the relevant AWS credentials are set in the
  # environment that autograph runs in
  #chainuploadlocation: s3://net-mozaws-dev-content-signature/chains/

  # x5u is the path to the public dir where chains are stored. This MUST end
  # with a trailing slash because filenames will be appended to it.
  # x5u: https://s3.amazonaws.com/net-mozaws-dev-content-signature/chains/
  x5u: file:///tmp/chains/

  # label of the intermediate's private key in the HSM
  issuerprivkey: csinter1550858489

  # public certificate of the intermediate
  issuercert: |
    -----BEGIN CERTIFICATE-----
    MIICXDCCAeKgAwIBAgIIFYXBlGIHbWAwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
    VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
    EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUwODU4NDg5MB4XDTE4MTIyMTE4
    MDEyOVoXDTI5MDIyMjE4MDEyOVowYDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
    MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRowGAYD
    VQQDExFjc2ludGVyMTU1MDg1ODQ4OTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLW8
    5oxfe3iBBaw/tvb/DrBfzCL3i3fHxngkahC2LASsEfUhKPQEwE88pOyREcAjCXCo
    FSrv34Cx7H9FiItOpu837Z5d+Qax1tWHJg2qrNTm3A5VL0F14RbHbc665H0WQaNq
    MGgwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA8GA1UdEwEB
    /wQFMAMBAf8wMAYDVR0eAQH/BCYwJKAiMCCCHi5jb250ZW50LXNpZ25hdHVyZS5t
    b3ppbGxhLm9yZzAKBggqhkjOPQQDAwNoADBlAjAyFx5dWkW1CMmAAatNH3tlFMuv
    UqjZk9QGiisGU7LGpsEs2GFK4k7Qs1fFNVVzHicCMQCX5GfEa/zBc7fJL+IP+XIZ
    AhaDpVhf9tReXSzilurgSy4u4gAE6nwdUFezm9iOsFg=
    -----END CERTIFICATE-----

  # public certificate of the root CA
  cacert: |
    -----BEGIN CERTIFICATE-----
    MIICKDCCAa+gAwIBAgIIFYXBlGCX7CAwCgYIKoZIzj0EAwMwXzELMAkGA1UEBhMC
    VVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQK
    EwdNb3ppbGxhMRkwFwYDVQQDExBjc3Jvb3QxNTUwODU4NDg5MB4XDTE4MTIyMDE4
    MDEyOVoXDTQ5MDIyMjE4MDEyOVowXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNB
    MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKEwdNb3ppbGxhMRkwFwYD
    VQQDExBjc3Jvb3QxNTUwODU4NDg5MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEVtXP
    Dx+XtUydct/YtvcOZDtndtLGu5kQtelIOS9TNISxbFbeJpa2dwuDQ+fvQ1Q1WNMY
    BHiOgWIoTKc+387yp6uijDxZBXAppIWUsMamdHKDiAyVHzFXpAiaXp69+Gvzozgw
    NjAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDwYDVR0TAQH/
    BAUwAwEB/zAKBggqhkjOPQQDAwNnADBkAjAuO8xbda+w4dq8iATflp4H5/0ubUcr
    9F24ABbpLdWtoMfyBJWeWPO61Qn0W+dNmqoCMHwSYgZMDvZK+uy9nqIyf+1h2eA4
    2OqlM2hZQeI/FpHm2ZevdMYcyqmQD0uBE1DTcg==
    -----END CERTIFICATE-----
```

## Signature requests

This signer support both the [/sign/data]{.title-ref} and
[/sign/hash]{.title-ref} endpoints. When signing data, the base64 of the
data being signed must be passed in the [input]{.title-ref} field of the
JSON signing request. When signing hashes, the [input]{.title-ref} field
must contain the base64 of the hash being signed.

``` json
[
    {
        "input": "Y2FyaWJvdW1hdXJpY2UK",
        "keyid": "some_content_signer"
    }
]
```

This signer doesn\'t support any option.
