#!/usr/bin/env bash

set -e

CLOUDHSM_PIN="${CLOUDHSM_PIN:?}"
CLOUDHSM_ROLE="${CLOUDHSM_ROLE:?}"

# read key labels from stdin
# search for EC public and private keys matching the label
# write a CSV of label,handle to stdout where the handle can be an empty string
#
# Requires env vars (use set_cloudhsm_env_vars to set them):
#
# CLOUDHSM_PIN
# CLOUDHSM_ROLE

while IFS= read -r keylabel; do
    pubkey_handles=$(/opt/cloudhsm/bin/cloudhsm-cli key list --filter attr.label="${keylabel}" | jq '.data.matched_keys[]["key-reference"]')

    for handle in ${pubkey_handles}; do
        echo "${keylabel},${handle}"
    done
done
