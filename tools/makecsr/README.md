# makecsr

This is a small helper used to generate a PEM-encoded CSR from a private key
hosted in our HSMs. It's used particularly to issue the CS and AMO intermediates
used by autograph. See our private hsm repo for how we've invoked it.

Note: nearly all of the CSRs attributes can be overridden at signing time, so
this is not a complete picture of what will be signed. But we include attributes
like subject alternative names and signature algorithm out of a desire to be as
explicit as we can be. This comes at the cost of perhaps confusing ourselves
about all the places those attributes must be specified.

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
    label: gcp
```

Note that the `label` must match between the two configuration files.

For more information, see
https://mana.mozilla.org/wiki/pages/viewpage.action?pageId=87365053

### Putting it all together, practical GCP example
Using this with GCP, you should have:

1. A read only libkmsp11-config.yaml file like this
```
tokens:
  - key_ring: projects/my-project/locations/global/keyRings/my-key-ring
    label: gcp-token
# Note: This file should be read-only. You can do `chmod -w libkmsp11-config.yaml` after you create it.
```

2. A crypto11-config.json file like this
```
{
  "Path": "/app/libkmsp11.so",
  "TokenLabel": "gcp-autograph-token"
}
```

3. Be authenticated with GCP. Ex: `gcloud auth login --update-adc`

4. Have the latest autograph docker image pulled down. `docker pull mozilla:autograph/latest`

5. Run the docker container in interactive mode with those configs your gcloud credentials mounted.
```
docker run -it --rm --user 0:0 \
    -e "KMS_PKCS11_CONFIG=/mnt/libkmsp11-config.yaml" \
    -e GOOGLE_APPLICATION_CREDENTIALS="/app/.config/gcloud/application_default_credentials.json" \
    --mount type=bind,source="${HOME}/.config/gcloud,target=/app/.config/gcloud" \
    -v "${PWD}/libkmsp11-config.yaml:/mnt/libkmsp11-config.yaml:ro" \
    -v "${PWD}/crypto11-config.json:/mnt/crypto11-config.json" \
    "mozilla/autograph:latest" /bin/bash
```

6. Run the makecsr command with the options you want.
```
makecsr -cn "My Corporation" \
    -dnsName "my.domain.name.foo" 
    -l "my-key-label-from-kms" 
    -ou "Engineering Operations" 
    -sigAlg "SHA256WithRSA" 
    -crypto11Config "/mnt/crypto11-config.json"
```
