#!/usr/bin/env bash

set -e

CLOUDHSM_PIN="${CLOUDHSM_PIN:?}"
CLOUDHSM_ROLE="${CLOUDHSM_ROLE:?}"
DRY_RUN=${DRY_RUN:-"1"}

# Reads input lines of `keylabels` from stdin. And then deletes the private and
# public keys for that label.
#
# Defaults to printing keys to delete in dry run mode (set DRY_RUN=0 to delete
# keys)
#
# Requires env vars (use set_cloudhsm_env_vars to set them):
#
# CLOUDHSM_PIN CLOUDHSM_ROLE
#
# Accepts the optional env vars:
#
# DRY_RUN
#

while IFS= read -r keylabel; do
    # There are two keys with the same label, the private-key and the public-key
    # key delete expects to only delete a single key per run, so we separate these calls

    echo "Keys to delete: --filter attr.label=\"${keylabel}\""
    /opt/cloudhsm/bin/cloudhsm-cli key list --filter attr.label="${keylabel}" --filter attr.class="private-key"
    /opt/cloudhsm/bin/cloudhsm-cli key list --filter attr.label="${keylabel}" --filter attr.class="public-key"

    if [[ "$DRY_RUN" != "1" ]]; then
        # It's okay if we fail to delete a key, because that usually means we've deleted it already
        /opt/cloudhsm/bin/cloudhsm-cli key delete --filter attr.label="${keylabel}" --filter attr.class="private-key" || true
        /opt/cloudhsm/bin/cloudhsm-cli key delete --filter attr.label="${keylabel}" --filter attr.class="public-key" || true
    fi
done
