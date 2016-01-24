#!/bin/bash

set -e

cd "$(dirname "$0")"
RELEASE=0
VERSION="$(date +%Y%m%d).$RELEASE"
if REV=$(git rev-parse --short HEAD); then
    VERSION="${VERSION}-${REV}"
fi

cat > version.go <<HERE
package main

const version = "${VERSION}"
HERE
