#!/bin/bash

set -e
set -o pipefail

# stop everything currently running
docker-compose down -v

# wipe DB state from previous runs
docker-compose stop db
docker-compose rm -f db

# start db and servers
docker-compose up -d --force-recreate db app app-hsm

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

echo "checking monitoring"
docker-compose run \
	       --rm \
               -e AUTOGRAPH_KEY=19zd4w3xirb5syjgdx8atq6g91m03bdsmzjifs2oddivswlu9qs \
               monitor
docker-compose run \
	       --rm \
               -e AUTOGRAPH_KEY=19zd4w3xirb5syjgdx8atq6g91m03bdsmzjifs2oddivswlu9qs \
               monitor-hsm

echo "checking XPI signing"
docker-compose run \
	       --rm \
	       --user 0 \
	       -e AUTOGRAPH_URL=http://app:8000 \
	       --workdir /app/src/autograph/tools/autograph-client \
	       --entrypoint ./integration_test_xpis.sh \
	       app
docker-compose run \
	       --rm \
	       --user 0 \
	       -e AUTOGRAPH_URL=http://app-hsm:8001 \
	       -e SIGNER_ID_PREFIX="hsm-" \
	       --workdir /app/src/autograph/tools/autograph-client \
	       --entrypoint ./integration_test_xpis.sh \
	       app-hsm

echo "checking APK signing"
docker-compose run \
	       --rm \
	       --user 0 \
	       -e TARGET=http://app:8000 \
               -e VERIFY=1 \
	       --workdir /app/src/autograph/tools/autograph-client \
	       --entrypoint ./build_test_apks.sh \
	       app
# TODO: add HSM support for APK signing keys and test here
