#! /usr/bin/env bash

# Get official firefox signing keys
# stolen from https://github.com/mozilla/build-mar/blob/master/get_mozilla_keys.sh
set -e

SHA1_REV="58402b43c9e1e22d8a9976ee9a7e4ffeee1bbbf2"
SHA384_REV="92f6879a8f9fc7e727d7c281c9fa9f538cb96cb5"

function get_key() {
    filename=$1
    name=$2
    rev=${3-default}
    url="https://hg.mozilla.org/mozilla-central/raw-file/${rev}/toolkit/mozapps/update/updater/${filename}"
    echo "// From $url"
    echo -n "\"$name\": \`"
    curl -s $url | openssl x509 -inform DER -pubkey -noout | head -c -1
    echo '`,'
}

(
echo "package mar"
echo
echo "// FirefoxReleasePublicKeys contains a map of PEM encoded public keys used to verify"
echo "// signatures on MAR files. This map is automatically generated, do not edit it by hand!"
echo "var FirefoxReleasePublicKeys = map[string]string{"
get_key "release_primary.der" "release1_sha384" $SHA384_REV
echo
get_key "release_secondary.der" "release2_sha384" $SHA384_REV
echo
get_key "release_primary.der" "release1_sha1" $SHA1_REV
echo
get_key "release_secondary.der" "release2_sha1" $SHA1_REV
echo

get_key "nightly_aurora_level3_primary.der" "nightly1_sha384" $SHA384_REV
echo
get_key "nightly_aurora_level3_secondary.der" "nightly2_sha384" $SHA384_REV
echo
get_key "nightly_aurora_level3_primary.der" "nightly1_sha1" $SHA1_REV
echo
get_key "nightly_aurora_level3_secondary.der" "nightly2_sha1" $SHA1_REV
echo

get_key "dep1.der" "dep1_sha384" $SHA384_REV
echo
get_key "dep2.der" "dep2_sha384" $SHA384_REV
echo
get_key "dep1.der" "dep1_sha1" $SHA1_REV
echo
get_key "dep2.der" "dep2_sha1" $SHA1_REV
echo "}"
) > firefoxkeys.go
gofmt -w firefoxkeys.go
