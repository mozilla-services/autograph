#!/bin/bash
[ -z "$2" ] && echo "$0 <config> <signer_id>" && echo "returns the SHA256 of the CACERT" && exit 1
[ ! -r "$1" ] && echo "configuration file '$1' not found" && exit 1

yqcmd=(yq -r -c ".signers | (map(select(.id | contains (\"$2\")))) | .[] .cacert")

ROOT_HASH=$("${yqcmd[@]}" "$1" | \
      openssl x509 -outform der | \
      openssl dgst -sha256 -hex | \
      awk '{print $2}' | tr '[:lower:]' '[:upper:]')
echo "Calling monitor with root hash $ROOT_HASH"
AUTOGRAPH_ROOT_HASH=$ROOT_HASH /go/bin/autograph-monitor
