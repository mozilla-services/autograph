#!/usr/bin/env sh

set -e

# CI script to check default webextensions signers sign a test webext
# fixture with various signature options autograph

AUTOGRAPH_URL=${AUTOGRAPH_URL:?}
SIGNER_ID_PREFIX=${SIGNER_ID_PREFIX:-""}


SIGNER_ID=${SIGNER_ID_PREFIX}webextensions-rsa \
	 TRUST_ROOTS=dev-webext-rsa-root.pem \
	 TARGET="$AUTOGRAPH_URL" \
	 CONFIG=${SIGNER_ID_PREFIX}webextensions-rsa \
         ./build_test_xpis.sh /app/src/autograph/signer/xpi/test/fixtures/ublock_origin-1.33.2-an+fx.xpi

SIGNER_ID=${SIGNER_ID_PREFIX}extensions-ecdsa \
	 TRUST_ROOTS=dev-ext-ecdsa-root.pem \
	 TARGET="$AUTOGRAPH_URL" \
	 CONFIG=${SIGNER_ID_PREFIX}extensions-ecdsa \
	 ./build_test_xpis.sh /app/src/autograph/signer/xpi/test/fixtures/ublock_origin-1.33.2-an+fx.xpi

SIGNER_ID=${SIGNER_ID_PREFIX}extensions-ecdsa-expired-chain \
	 TRUST_ROOTS=dev-ext-ecdsa-expired-root.pem \
	 TARGET="$AUTOGRAPH_URL" \
	 CONFIG=${SIGNER_ID_PREFIX}extensions-ecdsa-expired-chain \
	 VERIFICATION_TIME="2020-01-01T01:01:01Z" \
	 ./build_test_xpis.sh /app/src/autograph/signer/xpi/test/fixtures/ublock_origin-1.33.2-an+fx.xpi
