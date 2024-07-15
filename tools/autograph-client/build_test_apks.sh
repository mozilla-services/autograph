#!/usr/bin/env sh

set -e

# CI script to fetch and check the autograph go client can sign APKs
# optionally verifies the APKs when env var VERIFY=1

FENNEC_NIGHTLY_URL=https://archive.mozilla.org/pub/mobile/nightly/2018/10/2018-10-01-10-01-42-mozilla-central-android-api-16/fennec-64.0a1.multi.android-arm.apk
FENNEC_BETA_URL=https://archive.mozilla.org/pub/mobile/releases/64.0b9/android-api-16/en-US/fennec-64.0b9.en-US.android-arm.apk
FOCUS_LATEST_URL=https://archive.mozilla.org/pub/android/focus/latest/Focus-arm.apk

curl --retry 5 $FENNEC_NIGHTLY_URL -o fennec-nightly.apk
curl --retry 5 $FENNEC_BETA_URL -o fennec-beta.apk
curl --retry 5 $FOCUS_LATEST_URL -o focus-latest.apk

HAWK_USER=${HAWK_USER:-alice}
HAWK_SECRET=${HAWK_SECRET:-fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu}
TARGET=${TARGET:-'http://127.0.0.1:8000'}

# Sign Fennec Beta
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f fennec-beta.apk -o fennec-legacy-sha1.resigned.apk -k legacy_apk_with_rsa -pk7digest sha1 &

# Sign with ECDSA
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f focus-latest.apk -o focus-ecdsa.v2.resigned.apk -k apk_cert_with_ecdsa_sha256 &

# Sign with RSA
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f focus-latest.apk -o focus-rsa.v2.resigned.apk -k testapp-android &

# Sign Aligned APK with ECDSA
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f ../../signer/apk2/aligned-two-files.apk -o aligned-two-files.ecdsa.v2.signed.apk -k apk_cert_with_ecdsa_sha256 &

# Sign Aligned APK with RSA
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f ../../signer/apk2/aligned-two-files.apk -o aligned-two-files.rsa.signed.apk -k testapp-android-legacy &

# Sign aligned APK with v3 sigs using RSA and ECDSA keys
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f ../../signer/apk2/aligned-two-files.apk -o aligned-two-files.rsa.v2.v3.signed.apk -k testapp-android-v3 &
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f ../../signer/apk2/aligned-two-files.apk -o aligned-two-files.ecdsa.v2.v3.signed.apk -k apk_cert_with_ecdsa_sha256_v3 &

# Resign v2 sigs with v3 sigs using RSA and ECDSA keys
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f focus-rsa.v2.resigned.apk -o focus-rsa.v2.v3.resigned.apk -k testapp-android-v3 &
go run client.go -t $TARGET -u $HAWK_USER -p $HAWK_SECRET -f focus-ecdsa.v2.resigned.apk -o focus-ecdsa.v2.v3.resigned.apk -k apk_cert_with_ecdsa_sha256_v3 &

# Wait for all the signing to be done
wait

VERIFY=${VERIFY:-"0"}
if [ "$VERIFY" = "1" ]; then
    for apk in $(ls *.resigned.apk *.signed.apk); do
        echo "verifying ${apk}"
        java -jar /usr/share/java/apksigner.jar verify --verbose "$apk" | grep -v WARNING
    done

    for apk in $(ls *.v2*.resigned.apk *.v2*.signed.apk); do
        echo "verifying v2 signature for ${apk}"
        java -jar /usr/share/java/apksigner.jar verify --verbose "$apk" | grep -v WARNING | grep 'Verified using v2 scheme (APK Signature Scheme v2): true'

	# if only v2 verify it doesn't have a v3 signature too
	echo "$apk" | grep -v ".v3" && echo "verifying ${apk} does not have a v3 signature" && java -jar /usr/share/java/apksigner.jar verify --verbose "$apk" | grep -v WARNING | grep 'Verified using v3 scheme (APK Signature Scheme v3): false'
    done

    for apk in $(ls *.v3*.resigned.apk *.v3*.signed.apk); do
        echo "verifying v3 signature for ${apk}"
	java -jar /usr/share/java/apksigner.jar verify --verbose "$apk" | grep -v WARNING | grep 'Verified using v3 scheme (APK Signature Scheme v3): true'
    done
fi
