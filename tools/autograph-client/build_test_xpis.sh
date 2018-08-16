#!/usr/bin/env sh

# produces signed XPIs with various params for testing using the
# autograph go client
#
# usage run autograph with a give config then invoke like:
#
# CONFIG=stage SIGNER_ID=webextensions_rsa HAWK_USER=amo HAWK_SECRET=redacted_hawk_secret CN="jid1-Kt2kYYgi32zPuw@jetpack" ./build_test_xpi.sh tomato-clock.zip
#
INPUT_FILE=$1

OUTPUT_BASENAME=autograph-$(git rev-parse --short HEAD)-$CONFIG-$(basename $INPUT_FILE '.zip')-PKCS7

# only PKCS7 SHA1
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha1 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA1.zip

# PKCS7 SHA1 with COSE ES256
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha1 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA1-ES256.zip -c ES256

# PKCS7 SHA1 with COSE ES512
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha1 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA1-ES256.zip -c ES512

# PKCS7 SHA1 with COSE PS256
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha1 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA1-PS256.zip -c PS256

# PKCS7 SHA1 with COSE ES256 ES384 ES512 (multiple recognized)
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha1 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA1-ES256-ES384-ES512.zip -c ES256 -c ES384 -c ES512

# PKCS7 SHA1 with COSE ES256 PS256 (multiple one Fx recognizes ES256 and another unrecognized PS256)
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha1 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA1-ES256-PS256.zip -c ES256 -c PS256


# only PKCS7 SHA256
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha256 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA256.zip

# PKCS7 SHA256 with COSE ES256
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha256 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA256-ES256.zip -c ES256

# PKCS7 SHA256 with COSE ES512
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha256 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA256-ES256.zip -c ES512

# PKCS7 SHA256 with COSE PS256
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha256 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA256-PS256.zip -c PS256

# PKCS7 SHA256 with COSE ES256 ES384 ES512 (multiple recognized)
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha256 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA256-ES256-ES384-ES512.zip -c ES256 -c ES384 -c ES512

# PKCS7 SHA256 with COSE ES256 PS256 (multiple one Fx recognizes ES256 and another unrecognized PS256)
go run client.go -f $INPUT_FILE -u $HAWK_USER -p $HAWK_SECRET -cn $CN -pk7digest sha256 -k $SIGNER_ID -o ${OUTPUT_BASENAME}-SHA256-ES256-PS256.zip -c ES256 -c PS256

tar cvzf ${OUTPUT_BASENAME}.tgz ${OUTPUT_BASENAME}*.zip
