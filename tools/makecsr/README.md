# makecsr

This is a small helper used to generate a PEM-encoded CSR from a private key
hosted in our HSMs. It's used particularly to issue the CS and AMO intermediates
used by autograph. See our private hsm repo for how we've invoked it.

Note: nearly all of the CSRs attributes can be overridden at signing time, so
this is not a complete picture (esp. of the name constraints). From SAN to
signature algorithm. But we include those out of a desire to be as explicit as
we can be, at the cost of perhaps confusing ourselves about all the places those
attributes must be specified.

If you're invoking in GCP, be sure to set the `KMS_PKCS11_CONFIG` env var to the
YAML config file that the libkmsp11 library requires.

This code also requires a crypto11 JSON configuration file at whereever the
`-cryptoConfig` arg says (the default is `./crypto11-config.json`).

For AWS, that file will look something like:

```json
{
  "Path": "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",
  "TokenLabel": "cavium",
  "Pin": "$CRYPTO_USER:$PASSWORD"
}
```

For GCP, that file will look something like:

```json
{
  "Path": "/path/to/libkmsp11.so",
  "TokenLabel": "gcp"
}
```

You will additionally need to be logged into gcloud locally (`gcloud auth login
--update-adc`). And you'll need a kmsp11 yml configuration file created and
specified in the `KMS_PKCS11_CONFIG` environment variable. This will look
something like:

```yaml
tokens:
  - key_ring: projects/autograph/locations/us-west-2/keyRings/autograph-keyring
  - label: gcp
```

Note that the `label` must match between the two configuration files.

For more information, see
https://mana.mozilla.org/wiki/pages/viewpage.action?pageId=87365053
