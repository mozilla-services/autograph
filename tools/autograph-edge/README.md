Autograph edge
==============

This is an AWS Lambda function that provides a public endpoint to autograph,
without exposing the entire service to the internet. It only supports XPI and
APK signing, and provides fine grained access control to only give clients the
ability to sign a given apk or xpi.

Use `make` to create a zip file you can deploy as a Go Lambda in AWS, then
enable an API Gateway to front the function with an open endpoint. Any client
with a valid authorization token can then send files to the endpoint for
signature.

The file must be base64 encoded prior to sending (because lambda) and their
output must be base64 decoded, as follows:


```bash
base64 -w 0 test.apk > /tmp/b64apk.txt

curl -X POST -H "Authorization: dd095f88adbf7bdfa18b06e23e83896107df969f7415830028fa2c1ccf9fd"
-d @/tmp/b64apk.txt -o /tmp/b64signedapk.txt
https://x5i5l9jk3g.execute-api.us-east-1.amazonaws.com/dev/autograph-edge-dev-20180330

base64 -d /tmp/b64signedapk.txt > signed.apk

/opt/android-sdk/build-tools/27.0.3/apksigner verify -v signed.apk
```

Configuration
-------------


The yaml file `autograph-edge.yaml` the location of the autograph server in
`url` and a list of authorizations.

```yaml
authorizations:
    - token: c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547
      addonid: myaddon@allizom.org
      user: alice
      key: fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu
      signer: extensions-ecdsa
```

Each authorization has a `token` that clients send in their `Authorization` HTTP
headers.

The authorization also has a `user`, `key` and `signer` that are used to call
autograph (therefore these configuration items must come from the autograph
config).

If the authorization is for an add-on, it must also contain an `addonid`, which
is the ID of the add-on being signed. The sample configuration file in this
repository can get you started.

Note that the token must be longer than 60 characters. You should use `openssl
rand -hex 32` to generate it.
