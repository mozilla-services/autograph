#!/usr/bin/env sh

set -e

# CI script to fetch a test XPI and check default webextensions
# signers can sign it with various signature options
# autograph and its go client can sign APKs

XPI_URL=${XPI_URL:-"https://addons.mozilla.org/firefox/downloads/file/935711/pomodoro_clock-1.1.1-an+fx-windows.xpi"}
AUTOGRAPH_URL=${AUTOGRAPH_URL:?}
SIGNER_ID_PREFIX=${SIGNER_ID_PREFIX:-""}

# TODO: local file support e.g. recognize and don't try to fetch file:// urls
wget -t 5 $XPI_URL

SIGNER_ID=${SIGNER_ID_PREFIX}webextensions-rsa \
	 TRUST_ROOTS=dev-webext-rsa-root.pem \
	 TARGET="$AUTOGRAPH_URL" \
         ./build_test_xpis.sh pomodoro_clock-1.1.1-an+fx-windows.xpi

SIGNER_ID=${SIGNER_ID_PREFIX}extensions-ecdsa \
	 TRUST_ROOTS=dev-ext-ecdsa-root.pem \
	 TARGET="$AUTOGRAPH_URL" \
	 ./build_test_xpis.sh pomodoro_clock-1.1.1-an+fx-windows.xpi
