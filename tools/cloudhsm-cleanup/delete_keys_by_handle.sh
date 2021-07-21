#!/usr/bin/env bash

set -e

CLOUDHSM_USER=${CLOUDHSM_USER:?}
CLOUDHSM_PASSWORD=${CLOUDHSM_PASSWORD:?}
CLOUDHSM_USER_TYPE=${CLOUDHSM_USER_TYPE:-"CU"}
DRY_RUN=${DRY_RUN:-"1"}

# read CSV lines of key label,handle from stdin
# check stdin label matches key handle label attr
# delete keys
#
# Defaults to printing keys to delete in dry run mode (set DRY_RUN=0 to delete keys)
#
# Requires env vars (use set_cloudhsm_env_vars to set them):
#
# CLOUDHSM_USER
# CLOUDHSM_PASSWORD
#
# Accepts the optional env vars:
#
# CLOUDHSM_USER_TYPE
# DRY_RUN
#
TMP=$(mktemp)

keys_seen=0
while IFS= read -r keyline; do
    # truncate the tempfile
    true > "$TMP"
    echo

    keylabel=$(echo "$keyline" | cut -d ',' -f 1)
    keyhandle=$(echo "$keyline" | cut -d ',' -f 2)
    echo "got label ${keylabel} and handle ${keyhandle}" >&2;

    # get the key label for the handle
    #
    # 3 is OBJ_ATTR_LABEL
    # https://docs.aws.amazon.com/cloudhsm/latest/userguide/key-attribute-table.html
    #
    /opt/cloudhsm/bin/key_mgmt_util singlecmd loginHSM -u "$CLOUDHSM_USER_TYPE" -s "$CLOUDHSM_USER" -p "$CLOUDHSM_PASSWORD" getAttribute -o "$keyhandle" -a 3 -out "$TMP" > /dev/null
    keylabelattr="$(tail -n 1 "$TMP")"
    echo "${keyhandle}"  >&2;

    if [[ ! "$keylabel" = "$keylabelattr" ]]; then
	echo "Aborting! provided key label ${keylabel} does not match label ${keylabelattr} for handle ${keyhandle}" >&2;
	exit 1
    else
	echo "provided key label ${keylabel} matches label ${keylabelattr} for handle ${keyhandle}" >&2;
    fi

    if [[ "$DRY_RUN" = "0" ]]; then
	echo "deleting: ${keyhandle} for label ${keylabel}"
	/opt/cloudhsm/bin/key_mgmt_util singlecmd loginHSM -u "$CLOUDHSM_USER_TYPE" -s "$CLOUDHSM_USER" -p "$CLOUDHSM_PASSWORD" deleteKey -k "$keyhandle"
    else
	echo "would delete: ${keyhandle} for label ${keylabel}"
    fi
    ((keys_seen+=1))
done
rm "$TMP"

if [[ "$DRY_RUN" = "0" ]]; then
    echo "success! deleted: ${keys_seen} keys" >&2;
else
    echo "success! would delete: ${keys_seen} keys" >&2;
fi
