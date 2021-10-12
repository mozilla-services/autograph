#!/usr/bin/env sh

set -e


AUTOGRAPH_URL=${AUTOGRAPH_URL:?}

SIGNER_ID=randompgp \
	 TARGET="$AUTOGRAPH_URL" \
	 VERIFY=1 \
         ./build_test_gpg.sh

SIGNER_ID=pgpsubkey \
	 TARGET="$AUTOGRAPH_URL" \
	 VERIFY=1 \
         ./build_test_gpg.sh

SIGNER_ID=randompgp-debsign \
	 TARGET="$AUTOGRAPH_URL" \
	 VERIFY=1 \
         ./build_test_gpg.sh /app/src/autograph/signer/gpg2/test/fixtures/sphinx_*

SIGNER_ID=pgpsubkey-debsign \
	 TARGET="$AUTOGRAPH_URL" \
	 VERIFY=1 \
         ./build_test_gpg.sh /app/src/autograph/signer/gpg2/test/fixtures/sphinx_*
