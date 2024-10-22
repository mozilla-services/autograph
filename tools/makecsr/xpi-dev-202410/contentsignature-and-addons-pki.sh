#!/bin/bash

set -e
docker run \
        -e "KMS_PKCS11_CONFIG=/app/src/autograph/tools/makecsr/xpi-dev-202410/libkmsp11-config.yaml" \
        -e GOOGLE_APPLICATION_CREDENTIALS="/app/.config/gcloud/application_default_credentials.json" \
        --mount type=bind,source="${HOME}/.config/gcloud,target=/app/.config/gcloud" \
        "mozilla/autograph:latest" makecsr \
        -crypto11Config /app/src/autograph/tools/makecsr/xpi-dev-202410/crypto11-config.json \
        -l "addons-intermediate-202410-dev" \
        -cn "Mozilla Autograph Dev Addons" \
        -ou "Mozilla Dev Signing Service" \
        -dnsName "addons.signing.dev.mozilla.org" \
        -sigAlg "SHA256WithRSA" > addons-intermediate-202410-dev.csr

docker run --rm \
        -e "KMS_PKCS11_CONFIG=/mnt/libkmsp11-config.yaml" \
        -e GOOGLE_APPLICATION_CREDENTIALS="/app/.config/gcloud/application_default_credentials.json" \
        -e PKCS11_MODULE_PATH="/app/libkmsp11.so" \
        --mount type=bind,source="${HOME}/.config/gcloud,target=/app/.config/gcloud" \
        -v "${PWD}/content-signature-and-addons-root-202410-dev.crt:/app/content-signature-and-addons-root-202410-dev.crt" \
        -v "${PWD}/libkmsp11-config.yaml:/mnt/libkmsp11-config.yaml" \
        -v "${PWD}/openssl_sign.cnf:/mnt/openssl_sign.cnf" \
        -v "${PWD}:/out" \
        -v "${PWD}/addons-intermediate-202410-dev.csr:/app/addons-intermediate-202410-dev.csr" \
        "mozilla/autograph:latest" openssl ca \
        -startdate 20241022000000Z \
        -enddate 21010519000000Z \
        -cert content-signature-and-addons-root-202410-dev.crt\
        -keyfile pkcs11:object=content-signature-and-addons-root-202410-dev \
        -policy policy_match \
        -extensions amo_intermediate_ca \
        -config "/mnt/openssl_sign.cnf" \
        -in addons-intermediate-202410-dev.csr \
        -out /out/addons-intermediate-202410-dev.crt \
        -create_serial \
        -notext \
        -engine pkcs11 \
        -keyform engine \
        -batch
