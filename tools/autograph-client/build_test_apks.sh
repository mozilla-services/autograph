#!/usr/bin/env sh

set -e

# CI script to fetch and check autograph and its go client can sign APKs

FENNEC_NIGHTLY_URL=https://archive.mozilla.org/pub/mobile/nightly/2018/10/2018-10-01-10-01-42-mozilla-central-android-api-16/fennec-64.0a1.multi.android-arm.apk
FENNEC_BETA_URL=https://archive.mozilla.org/pub/mobile/releases/64.0b9/android-api-16/en-US/fennec-64.0b9.en-US.android-arm.apk
ALIGNED_URL=https://raw.githubusercontent.com/mozilla-services/autograph/master/signer/apk/aligned-two-files.apk

wget -t 5 $FENNEC_NIGHTLY_URL $FENNEC_BETA_URL $ALIGNED_URL

HAWK_USER=${HAWK_USER:-alice}
HAWK_SECRET=${HAWK_SECRET:-fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu}

# Sign Fennec Nightly
go run client.go -u $HAWK_USER -p $HAWK_SECRET -f fennec-64.0a1.multi.android-arm.apk -o fennec-64.0a1.multi.android-arm.resigned.apk -k apk_cert_with_dsa_sha1 -pk7digest sha1

# Sign Fennec Beta
go run client.go -u $HAWK_USER -p $HAWK_SECRET -f fennec-64.0b9.en-US.android-arm.apk -o fennec-64.0b9.en-US.android-arm.resigned.apk -k legacy_apk_with_rsa -pk7digest sha1

# Sign with ECDSA
go run client.go -u $HAWK_USER -p $HAWK_SECRET -f aligned-two-files.apk -o aligned-two-files.ecdsa.resigned.apk -k apk_cert_with_ecdsa_sha256

# Sign with RSA
go run client.go -u $HAWK_USER -p $HAWK_SECRET -f aligned-two-files.apk -o aligned-two-files.rsa.resigned.apk -k testapp-android

tar cvzf resigned-apks.tgz *.resigned.apk
