#!/usr/bin/env sh

# produces signed XPIs with various params for testing using the
# autograph go client
#
# usage run autograph with a give config then invoke like:
#
# CONFIG=stage HAWK_USER=amo HAWK_SECRET=redacted_hawk_secret CN="jid1-Kt2kYYgi32zPuw@jetpack" ./build_test_xpi.sh tomato-clock.zip
#
INPUT_FILE=$1

OUTPUT_BASENAME=autograph-$(git rev-parse --short HEAD)-$CONFIG-$(basename $INPUT_FILE '.zip')-PKCS7

# only PKCS7 signature
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -k webextensions_rsa -o ${OUTPUT_BASENAME}.zip

# PKCS7 with COSE ES256
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -k webextensions_rsa -o ${OUTPUT_BASENAME}-ES256.zip -c ES256

# PKCS7 with COSE ES256 ES384 (multiple)
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -k webextensions_rsa -o ${OUTPUT_BASENAME}-ES256-ES384.zip -c ES256 -c ES384

# PKCS7 with COSE ES256 PS256 (i.e. unrecognized COSE alg)
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -k webextensions_rsa -o ${OUTPUT_BASENAME}-ES256-PS256.zip -c ES256 -c PS256
