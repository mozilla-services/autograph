Autograph Monitor
=================

A small tool that queries Autograph's monitoring endpoint `__monitor__` and
verifies each signature returned to make sure the service is operating
correctly.

Monitor runs standalone or as a lambda function.

Three environment variables are required:

* AUTOGRAPH_URL is the address of the autograph endpoint
* AUTOGRAPH_KEY is the monitoring API key
* AUTOGRAPH_ENV optionally sets the root of the firefox pki to a pre-defined value
    depending on the environment monitor is running in.
    Acceptable values are "stage" and "prod".
    When unset, this will use a default value for local development.

With these env vars set, running monitor is as easy as:

```bash
AUTOGRAPH_URL=http://localhost:8000/ \
AUTOGRAPH_KEY=19zd4w3xirb5syjgdx8atq6g91m03bdsmzjifs2oddivswlu9qs \
./autograph-monitor

2019/04/09 09:41:13 Retrieving monitoring data from http://localhost:8000/
2019/04/09 09:41:13 Verifying content signature from signer "appkey1"
2019/04/09 09:41:13 Response 0 from signer "appkey1" passes verification
2019/04/09 09:41:13 Verifying content signature from signer "appkey2"
2019/04/09 09:41:13 Response 1 from signer "appkey2" passes verification
2019/04/09 09:41:13 Verifying content signature pki from signer "normandy"
2019/04/09 09:41:13 Response 2 from signer "normandy" passes verification
2019/04/09 09:41:13 Verifying content signature pki from signer "remote-settings"
2019/04/09 09:41:13 Response 3 from signer "remote-settings" passes verification
2019/04/09 09:41:13 Verifying XPI signature from signer "webextensions-rsa"
2019/04/09 09:41:13 Response 4 from signer "webextensions-rsa" passes verification
2019/04/09 09:41:13 Verifying XPI signature from signer "extensions-ecdsa"
2019/04/09 09:41:13 Response 5 from signer "extensions-ecdsa" passes verification
2019/04/09 09:41:13 Verifying APK signature from signer "testapp-android"
2019/04/09 09:41:13 Response 6 from signer "testapp-android" passes verification
2019/04/09 09:41:13 Verifying APK signature from signer "apk_cert_with_dsa_sha1"
2019/04/09 09:41:13 Response 7 from signer "apk_cert_with_dsa_sha1" passes verification
2019/04/09 09:41:13 Verifying APK signature from signer "legacy_apk_with_rsa"
2019/04/09 09:41:13 Response 8 from signer "legacy_apk_with_rsa" passes verification
2019/04/09 09:41:13 Verifying APK signature from signer "apk_cert_with_ecdsa_sha256"
2019/04/09 09:41:13 Response 9 from signer "apk_cert_with_ecdsa_sha256" passes verification
2019/04/09 09:41:13 Verifying MAR signature from signer "testmar"
2019/04/09 09:41:13 Response 10 from signer "testmar" passes verification
2019/04/09 09:41:13 Verifying MAR signature from signer "testmarecdsa"
2019/04/09 09:41:13 Response 11 from signer "testmarecdsa" passes verification
2019/04/09 09:41:13 Skipping verification of PGP signature from signer "randompgp"
2019/04/09 09:41:13 Skipping verification of PGP signature from signer "pgpsubkey"
2019/04/09 09:41:13 Verifying RSA-PSS signature from signer "dummyrsapss"
2019/04/09 09:41:13 Response 14 from signer "dummyrsapss" passes verification
2019/04/09 09:41:13 All signature responses passed, monitoring OK
```
