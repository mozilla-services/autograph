#!/usr/bin/env bash

set -e

# CI script to check the /auths/:auth_id/keyids endpoint

AUTOGRAPH_URL=${AUTOGRAPH_URL:?}
CHECK_BOB=${CHECK_BOB:-"0"}

# check alice has access to normandy
go run client.go -t "$AUTOGRAPH_URL" -listkeyids -u alice | grep normandy

if [ "$CHECK_BOB" = "1" ]; then
    # but bob doesn't
    go run client.go -t "$AUTOGRAPH_URL" -listkeyids -u bob -p 9vh6bhlc10y63ow2k4zke7k0c3l9hpr8mo96p92jmbfqngs9e7d | grep -v normandy
    # bob should only have access to appkey2
    go run client.go -t "$AUTOGRAPH_URL" -listkeyids -u bob -p 9vh6bhlc10y63ow2k4zke7k0c3l9hpr8mo96p92jmbfqngs9e7d | grep appkey2
fi

# invalid user and auth should return a 401 error
go run client.go -t "$AUTOGRAPH_URL" -listkeyids -u nobody 2>&1 | grep 401
