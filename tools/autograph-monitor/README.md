Autograph Monitor
=================

A small tool that queries Autograph's monitoring endpoint `__monitor__` and
verifies each signature returned to make sure the service is operating
correctly.

Monitor runs as a standalone app or container.

It accepts two required environment variables:

* `AUTOGRAPH_URL` the address of the autograph endpoint
* `AUTOGRAPH_KEY` the monitoring API key

And additional optional environment variables:

* `AUTOGRAPH_ENV` sets the root of the Firefox PKI to a pre-defined
  value depending on the environment monitor is running in.
  Acceptable values are "stage" and "prod".  When unset, this will use
  a default value for local development. The variables it uses can be
  found in `constants.go`.

* `AUTOGRAPH_ROOT_HASH` sets the root hash monitor to verify addon and
  content signature against (as used in
  `run-monitor-with-root-hash.sh`).

* `AUTOGRAPH_PD_ROUTING_KEY` is an integration key for the pagerduty
  events v2 API. When present the monitor will trigger and resolve
  alerts for warnings like a content signature certificate expiring in
  30 days.

When the upstream app is down monitor requests will time out after 30 seconds.

An example run looks like:

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
