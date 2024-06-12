#!/bin/bash

set -e
set -o pipefail

# Fetch the normandy root hash
export AUTOGRAPH_ROOT_HASH=$(autograph-client -t "$AUTOGRAPH_URL" -listconfig normandy | \
      jq -r '.cacert' | openssl x509 -outform der | openssl dgst -sha256 -hex | \
      awk '{print $2}' | tr '[:lower:]' '[:upper:]')

echo "Autograph instance: $AUTOGRAPH_URL"
echo "Got Root hash: $AUTOGRAPH_ROOT_HASH"
echo "Starting lambda: $@"
/usr/local/bin/aws-lambda-rie "$@"
