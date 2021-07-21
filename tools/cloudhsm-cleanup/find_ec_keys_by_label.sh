#!/usr/bin/env bash

set -e

CLOUDHSM_USER=${CLOUDHSM_USER:?}
CLOUDHSM_PASSWORD=${CLOUDHSM_PASSWORD:?}
CLOUDHSM_USER_TYPE=${CLOUDHSM_USER_TYPE:-"CU"}

# read key labels from stdin
# search for EC public and private keys matching the label
# write a CSV of label,handle to stdout where the handle can be an empty string
#
# Requires env vars (use set_cloudhsm_env_vars to set them):
#
# CLOUDHSM_USER
# CLOUDHSM_PASSWORD
#
# Accepts the optional env vars:
#
# CLOUDHSM_USER_TYPE
#

TMP=$(mktemp)

while IFS= read -r keylabel; do
    # truncate the tempfile
    true > "$TMP"

    # echo "checking for public EC keys with label: ${keylabel}" >&2;
    # -t 3 searches for EC key types
    # -c 2 searches for public keys (3 for private keys)
    #
    # https://docs.aws.amazon.com/cloudhsm/latest/userguide/key_mgmt_util-findKey.html
    /opt/cloudhsm/bin/key_mgmt_util singlecmd loginHSM -u "$CLOUDHSM_USER_TYPE" -s "$CLOUDHSM_USER" -p "$CLOUDHSM_PASSWORD" findKey -c 2 -t 3 -l "$keylabel" > "$TMP"
    grep -E "Total number of keys present: 1\s*$" "$TMP" > /dev/null || echo "INFO: public key not found for $keylabel it may have already been deleted" >&2;
    # cut uses a tab delimiter by default
    pubkey_handle=$(tr -d '\n' < "$TMP" | grep -o 'Handles of matching keys:\s*\([0-9]*\)' | cut -f 2)
    # echo "found public EC key handle ${pubkey_handle} for label: ${keylabel}" >&2;

    # truncate the tempfile
    true > "$TMP"

    # echo "checking for private EC keys with label: ${keylabel}" >&2;
    /opt/cloudhsm/bin/key_mgmt_util singlecmd loginHSM -u "$CLOUDHSM_USER_TYPE" -s "$CLOUDHSM_USER" -p "$CLOUDHSM_PASSWORD" findKey -c 3 -t 3 -l "$keylabel" > "$TMP"
    grep -E "Total number of keys present: 1$" "$TMP" > /dev/null || echo "INFO: private key not found for $keylabel it may have already been deleted" >&2;
    # cut uses a tab delimiter by default
    privkey_handle=$(tr -d '\n' < "$TMP" | grep -o 'Handles of matching keys:\s*\([0-9]*\)' | cut -f 2)
    # echo "found private EC key handle ${privkey_handle} for label: ${keylabel}" >&2;

    # write non-empty handles to stdout
    if [[ ! "" = "$pubkey_handle" ]]; then
	echo "${keylabel},${pubkey_handle}"
    fi
    if [[ ! "" = "$privkey_handle" ]]; then
	echo "${keylabel},${privkey_handle}"
    fi
done
rm "$TMP"
echo "INFO: success finished searching for EC keys with the provided labels" >&2;
