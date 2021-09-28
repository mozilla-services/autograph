#!/usr/bin/env bash

set -e
set -o pipefail

# test script to check default gpg2 signers sign and verify test data
# or debsign files
#
# when no args are provided it signs fixed test data (gpg2 signer
# should be in gpg2 mode)
# when a list of debsign files is provided it signs them in debsign mode

HAWK_USER=${HAWK_USER:-alice}
HAWK_SECRET=${HAWK_SECRET:-fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu}
TARGET=${TARGET:-'http://127.0.0.1:8000'}
SIGNER_ID=${SIGNER_ID:?}
VERIFY=${VERIFY:-"0"}

DEBSIGN_FILES=( "$@" )

test_dir=$(mktemp -d --suffix "$SIGNER_ID")

if [ "$#" -eq 0 ]; then
    echo "testing signing data with signer: ${SIGNER_ID} in ${test_dir}"

    echo 'hello' | base64 > "${test_dir}/pgpinput.txt"

    go run client.go -t "$TARGET" -u "$HAWK_USER" -p "$HAWK_SECRET" -k "$SIGNER_ID" -d "$(cat "${test_dir}"/pgpinput.txt)" -o "${test_dir}/testsig.pgp" -ko "${test_dir}/testkey.asc"

    if [ "$VERIFY" = "1" ]; then
	# import the public key returned by autograph into a temp keyring
	gpg --no-options --homedir "${test_dir}" --no-default-keyring --keyring "${test_dir}/testkeyring.pgp" --secret-keyring "${test_dir}/testsecring.gpg" --import "${test_dir}/testkey.asc"

	# verify the signature using the temp keyring
	echo "running: gpg --no-options --homedir \"${test_dir}\" --no-default-keyring --keyring \"${test_dir}/testkeyring.pgp\" --verify \"${test_dir}/testsig.pgp\" <(base64 -d \"${test_dir}/pgpinput.txt\")"
	gpg --no-options --homedir "${test_dir}" --no-default-keyring --keyring "${test_dir}/testkeyring.pgp" --verify "${test_dir}/testsig.pgp" <(base64 -d "${test_dir}/pgpinput.txt")
    fi
else
    echo "testing signing files " "${DEBSIGN_FILES[@]}" " with signer: ${SIGNER_ID} in ${test_dir}"
    cd "$test_dir"
    autograph-client -t "$TARGET" -u "$HAWK_USER" -p "$HAWK_SECRET" -k "$SIGNER_ID" -ko "${test_dir}/testkey.asc" -outfilesprefix signed_ "${DEBSIGN_FILES[@]}"

    if [ "$VERIFY" = "1" ]; then
	# import the public key returned by autograph into a temp keyring
	gpg --no-options --homedir "${test_dir}" --no-default-keyring --keyring "${test_dir}/testkeyring.pgp" --secret-keyring "${test_dir}/testsecring.gpg" --import "${test_dir}/testkey.asc"

	# verify the signature using the temp keyring
	for signed in signed_*; do
            echo "verifying gpg2 clearsign signature for ${signed}"
	    echo "running: gpg --no-options --homedir \"${test_dir}\" --no-default-keyring --keyring \"${test_dir}/testkeyring.pgp\" --verify \"$signed\""
	    gpg --no-options --homedir "${test_dir}" --no-default-keyring --keyring "${test_dir}/testkeyring.pgp" --verify "$signed"
	done
    fi
    cd "$OLDPWD"
fi
