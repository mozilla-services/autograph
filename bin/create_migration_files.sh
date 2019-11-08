#!/bin/bash

# create migration sql files with the name of the first arg
#
# requires make install-migrate

set -e
set -o pipefail

migrate create -ext sql -format unix -dir database/migrations/ "$1"
# TODO: add filename header
