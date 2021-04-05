#!/usr/bin/env sh

set -e

# CI script to fetch and check the autograph go client can sign APKs
# optionally verifies the APKs when env var VERIFY=1

FENNEC_NIGHTLY_URL=https://archive.mozilla.org/pub/mobile/nightly/2018/10/2018-10-01-10-01-42-mozilla-central-android-api-16/fennec-64.0a1.multi.android-arm.apk
FENNEC_BETA_URL=https://archive.mozilla.org/pub/mobile/releases/64.0b9/android-api-16/en-US/fennec-64.0b9.en-US.android-arm.apk
FOCUS_LATEST_URL=https://archive.mozilla.org/pub/android/focus/latest/Focus-arm.apk

wget -t 5 $FENNEC_NIGHTLY_URL $FENNEC_BETA_URL $FOCUS_LATEST_URL

HAWK_USER=${HAWK_USER:-alice}
HAWK_SECRET=${HAWK_SECRET:-fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu}
TARGET=${TARGET:-'http://127.0.0.1:8000'}

# Sign Fennec Beta
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f fennec-64.0b9.en-US.android-arm.apk -o fennec-legacy-sha1.resigned.apk -k legacy_apk_with_rsa -pk7digest sha1

# Sign with ECDSA
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f Focus-arm.apk -o focus-ecdsa.resigned.apk -k apk_cert_with_ecdsa_sha256

# Sign with RSA
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f Focus-arm.apk -o focus-rsa.resigned.apk -k testapp-android

# Sign Aligned APK with ECDSA
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f ../../signer/apk2/aligned-two-files.apk -o aligned-two-files.ecdsa.resigned.apk -k apk_cert_with_ecdsa_sha256

# Sign Aligned APK with RSA
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f ../../signer/apk2/aligned-two-files.apk -o aligned-two-files.rsa.resigned.apk -k testapp-android-legacy

VERIFY=${VERIFY:-"0"}
if [ "$VERIFY" = "1" ]; then
    # NB: need to be running as root
    apt update -qq
    apt install -y openjdk-11-jre android-sdk-build-tools apksigner
    for apk in $(ls *.resigned.apk); do
        echo "verifying ${apk}"
        java -jar /usr/bin/apksigner verify --verbose $apk
    done
fi
