#!/bin/bash

set -e
set -o pipefail

# stop everything currently running
docker compose down -v

# wipe DB state from previous runs
docker compose stop db
docker compose rm -f db

# start db and app servers
docker compose up -d --force-recreate db app app-hsm
docker compose build monitor-lambda-emulator monitor-hsm-lambda-emulator

echo "waiting for autograph-app to start"
while test "true" != "$(docker inspect -f {{.State.Running}} autograph-app)"; do
  echo -n "."
  sleep 1 # wait before checking again
done
echo "waiting for autograph-app-hsm to start"
while test "true" != "$(docker inspect -f {{.State.Running}} autograph-app-hsm)"; do
  echo -n "."
  sleep 1 # wait before checking again
done

# fetch the updated root hash from the app-hsm service
docker cp autograph-app-hsm:/tmp/normandy_dev_root_hash.txt .
APP_HSM_NORMANDY_ROOT_HASH=$(grep '[0-9A-F]' normandy_dev_root_hash.txt | tr -d '\r\n')

# start the monitor lambda emulators
echo "checking autograph monitors"
docker compose run \
	       --rm \
	       -e AUTOGRAPH_URL=http://app:8000/ \
	       --entrypoint /usr/local/bin/lambda-selftest-entrypoint.sh \
	       monitor-lambda-emulator /go/bin/autograph-monitor

echo "FIXME hsm monitor"
docker compose run \
	       --rm \
	       -e AUTOGRAPH_URL=http://autograph-app-hsm:8001/ \
	       -e AUTOGRAPH_ROOT_HASH=$APP_HSM_NORMANDY_ROOT_HASH \
	       --entrypoint /usr/local/bin/lambda-selftest-entrypoint.sh \
	       monitor-hsm-lambda-emulator /go/bin/autograph-monitor

echo "checking read-only API"
# user bob doesn't exist in the softhsm config
docker compose run \
	       --rm \
	       --user 0 \
	       -e CHECK_BOB=1 \
	       -e AUTOGRAPH_URL=http://app:8000 \
	       --workdir /app/src/autograph/tools/autograph-client \
	       --entrypoint ./integration_test_api.sh \
	       app
docker compose run \
	       --rm \
	       --user 0 \
	       -e AUTOGRAPH_URL=http://app-hsm:8001 \
	       --workdir /app/src/autograph/tools/autograph-client \
	       --entrypoint ./integration_test_api.sh \
	       app-hsm

echo "checking gpg signing"
docker compose run \
	       --rm \
	       --user 0 \
	       -e AUTOGRAPH_URL=http://app:8000 \
	       --workdir /app/src/autograph/tools/autograph-client \
	       --entrypoint ./integration_test_gpg2_signer.sh \
	       app
# TODO(GH-785): add HSM support for GPG signing keys and test here

echo "checking XPI signing"
docker compose run \
	       --rm \
	       --user 0 \
	       -e AUTOGRAPH_URL=http://app:8000 \
	       --workdir /app/src/autograph/tools/autograph-client \
	       --entrypoint ./integration_test_xpis.sh \
	       app
docker compose run \
	       --rm \
	       --user 0 \
	       -e AUTOGRAPH_URL=http://app-hsm:8001 \
	       -e SIGNER_ID_PREFIX="hsm-" \
	       --workdir /app/src/autograph/tools/autograph-client \
	       --entrypoint ./integration_test_xpis.sh \
	       app-hsm

echo "checking APK signing"
docker compose run \
	       --rm \
	       --user 0 \
	       -e TARGET=http://app:8000 \
	       -e VERIFY=1 \
	       --workdir /app/src/autograph/tools/autograph-client \
	       --entrypoint ./build_test_apks.sh \
	       app
# TODO(GH-381): add HSM support for APK signing keys and test here
