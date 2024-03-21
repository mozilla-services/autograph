#!/usr/bin/env bash

set -eu

# produces signed XPIs with various params for testing using the
# autograph go client
#
# usage run autograph with a give config then invoke like:
#
# CONFIG=stage SIGNER_ID=webextensions_rsa HAWK_USER=amo HAWK_SECRET=redacted_hawk_secret CN="jid1-Kt2kYYgi32zPuw@jetpack" TRUST_ROOTS=roots.pem ./build_test_xpi.sh tomato-clock.zip
#
INPUT_FILE=$1

OUTPUT_BASENAME=autograph-$(git rev-parse --short HEAD)-${CONFIG:-x}-$(basename $INPUT_FILE '.zip')-PKCS7

HAWK_USER=${HAWK_USER:-alice}
HAWK_SECRET=${HAWK_SECRET:-fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu}
CN=${CN:-testaddon@allizom}
VERIFICATION_TIME=${VERIFICATION_TIME:-""}

TARGET=${TARGET:-'http://127.0.0.1:8000'}

# build up common args, skipping things that aren't defined 
COMMON_ARGS=" -f ${INPUT_FILE}"
[[ -n ${TARGET:-} ]]              && COMMON_ARGS+=" -t ${TARGET}"
[[ -n ${HAWK_USER:-} ]]           && COMMON_ARGS+=" -u ${HAWK_USER}"
[[ -n ${HAWK_SECRET:-} ]]         && COMMON_ARGS+=" -p ${HAWK_SECRET}"
[[ -n ${CN:-} ]]                  && COMMON_ARGS+=" -cn ${CN}"
[[ -n ${SIGNER_ID:-} ]]           && COMMON_ARGS+=" -k ${SIGNER_ID}"
[[ -n ${TRUST_ROOTS:-} ]]         && COMMON_ARGS+=" -r ${TRUST_ROOTS}"
[[ -n ${VERIFICATION_TIME:-} ]]   && COMMON_ARGS+=" -vt ${VERIFICATION_TIME}"


# TODO should throw error if VERIFICATION_TIME doesn't match VERIFY
VERIFY=${VERIFY:-"1"}
if [ "$VERIFY" = "0" ]; then
    COMMON_ARGS="$COMMON_ARGS -noverify"
fi
#COMMON_ARGS+=" -D"      # debug
echo "using common args: '${COMMON_ARGS}'"

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
