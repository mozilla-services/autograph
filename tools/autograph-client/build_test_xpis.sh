#!/usr/bin/env bash

set -e

# produces signed XPIs with various params for testing using the
# autograph go client
#
# usage run autograph with a give config then invoke like:
#
# CONFIG=stage SIGNER_ID=webextensions_rsa HAWK_USER=amo HAWK_SECRET=redacted_hawk_secret CN="jid1-Kt2kYYgi32zPuw@jetpack" TRUST_ROOTS=roots.pem ./build_test_xpi.sh tomato-clock.zip
#
INPUT_FILE=$1

TARGET=${TARGET:-'http://127.0.0.1:8000'}

PROJECT_SHORTHASH=$(curl -s "${TARGET}/__version__" | jq -r '.commit' | head -c8)
OUTPUT_BASENAME=autograph-$PROJECT_SHORTHASH-$CONFIG-$(basename $INPUT_FILE '.zip')-PKCS7

HAWK_USER=${HAWK_USER:-alice}
HAWK_SECRET=${HAWK_SECRET:-fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu}
CN=${CN:-testaddon@allizom}
VERIFICATION_TIME=${VERIFICATION_TIME:-""}

if [[ "$VERIFICATION_TIME" = "" ]]; then
    COMMON_ARGS="-t $TARGET -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -k $SIGNER_ID -r $TRUST_ROOTS"
else
    COMMON_ARGS="-t $TARGET -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -k $SIGNER_ID -r $TRUST_ROOTS -vt $VERIFICATION_TIME"
fi

VERIFY=${VERIFY:-"1"}
if [ "$VERIFY" = "0" ]; then
    COMMON_ARGS="$COMMON_ARGS -noverify"
fi

# only PKCS7 SHA1
go run client.go $COMMON_ARGS -pk7digest sha1 -o ${OUTPUT_BASENAME}-SHA1.zip

# PKCS7 SHA1 with COSE ES256
go run client.go $COMMON_ARGS -pk7digest sha1 -o ${OUTPUT_BASENAME}-SHA1-ES256.zip -c ES256

# PKCS7 SHA1 with COSE ES512
go run client.go $COMMON_ARGS -pk7digest sha1 -o ${OUTPUT_BASENAME}-SHA1-ES256.zip -c ES512

# PKCS7 SHA1 with COSE PS256
go run client.go $COMMON_ARGS -pk7digest sha1 -o ${OUTPUT_BASENAME}-SHA1-PS256.zip -c PS256

# PKCS7 SHA1 with COSE ES256 ES384 ES512 (multiple recognized)
go run client.go $COMMON_ARGS -pk7digest sha1 -o ${OUTPUT_BASENAME}-SHA1-ES256-ES384-ES512.zip -c ES256 -c ES384 -c ES512

# PKCS7 SHA1 with COSE ES256 PS256 (multiple one Fx recognizes ES256 and another unrecognized PS256)
go run client.go $COMMON_ARGS -pk7digest sha1  -o ${OUTPUT_BASENAME}-SHA1-ES256-PS256.zip -c ES256 -c PS256


# only PKCS7 SHA256
go run client.go $COMMON_ARGS -pk7digest sha256 -o ${OUTPUT_BASENAME}-SHA256.zip

# PKCS7 SHA256 with COSE ES256
go run client.go $COMMON_ARGS -pk7digest sha256 -o ${OUTPUT_BASENAME}-SHA256-ES256.zip -c ES256

# PKCS7 SHA256 with COSE ES512
go run client.go $COMMON_ARGS -pk7digest sha256 -o ${OUTPUT_BASENAME}-SHA256-ES256.zip -c ES512

# PKCS7 SHA256 with COSE PS256
go run client.go $COMMON_ARGS -pk7digest sha256 -o ${OUTPUT_BASENAME}-SHA256-PS256.zip -c PS256

# PKCS7 SHA256 with COSE ES256 ES384 ES512 (multiple recognized)
go run client.go $COMMON_ARGS -pk7digest sha256 -o ${OUTPUT_BASENAME}-SHA256-ES256-ES384-ES512.zip -c ES256 -c ES384 -c ES512

# PKCS7 SHA256 with COSE ES256 PS256 (multiple one Fx recognizes ES256 and another unrecognized PS256)
go run client.go $COMMON_ARGS -pk7digest sha256 -o ${OUTPUT_BASENAME}-SHA256-ES256-PS256.zip -c ES256 -c PS256

tar cvzf ${OUTPUT_BASENAME}.tgz ${OUTPUT_BASENAME}*.zip
