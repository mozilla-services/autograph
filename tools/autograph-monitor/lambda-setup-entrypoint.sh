#!/bin/bash

set -e
set -o pipefail

# Wait for the heartbeat
HEARTBEAT=$(curl --silent \
                 --connect-timeout 5 \
                 --max-time 10 \
                 --retry-connrefused \
                 --retry 5 \
                 --retry-delay 5 \
                 --retry-max-time 60 \
                 "${AUTOGRAPH_URL}/__heartbeat__")
RETCODE=$?
if [ $RETCODE -ne 0 ]; then
    echo "Failed to reach autograph heartbeat" >&2
    exit $RETCODE
fi

# Fetch the normandy root hash
export AUTOGRAPH_ROOT_HASH=$(autograph-client -t "$AUTOGRAPH_URL" -listconfig normandy | \
      jq -r '.cacert' | openssl x509 -outform der | openssl dgst -sha256 -hex | \
      awk '{print $2}' | tr '[:lower:]' '[:upper:]')

echo "Autograph instance: $AUTOGRAPH_URL"
echo "Got Root hash: $AUTOGRAPH_ROOT_HASH"
echo "Starting lambda: $@"
/usr/local/bin/aws-lambda-rie "$@"
