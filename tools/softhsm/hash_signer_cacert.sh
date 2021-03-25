#!/bin/bash

# Print the SHA256 hash of the contentsignature pki cacert in an autograph config file with the given name
#
# requires:
#
# awk, jq, and openssl commands
# the python yq command
#
# usage:
#
# ./hash_signer_cacert.sh ../../softhsm/autograph.softhsm.yaml normandy
# EB1D805F4566F38EADC4BF826400F3DC263E2A328A1B597F69D832FF993D00AB
#
[ -z "$2" ] && echo "$0 <config> <signer_id>" && echo "returns the SHA256 of the CACERT" && exit 1
[ ! -r "$1" ] && echo "configuration file '$1' not found" && exit 1

yqcmd=(yq -r -c ".signers | (map(select(.id | contains (\"$2\")))) | .[] .cacert")

ROOT_HASH=$("${yqcmd[@]}" "$1" | \
      openssl x509 -outform der | \
      openssl dgst -sha256 -hex | \
      awk '{print $2}' | tr '[:lower:]' '[:upper:]')
echo "$ROOT_HASH"
