#!/bin/bash

set -e

CERT_NAME="content-signature-ecdsa-intermediate-202410-dev"
SIG_ALG="ECDSAWithSHA384"
OPENSSL_MSG_DGST="sha256"
COMMON_NAME="Mozilla Autograph Dev Content Signature"
DNS_NAME="contentsignature.signing.dev.mozilla.org"


docker run --rm --user 0:0 \
        -e "KMS_PKCS11_CONFIG=/mnt/libkmsp11-config.yaml" \
        -e GOOGLE_APPLICATION_CREDENTIALS="/app/.config/gcloud/application_default_credentials.json" \
        --mount type=bind,source="${HOME}/.config/gcloud,target=/app/.config/gcloud,readonly" \
        --mount type=bind,source="${PWD}/libkmsp11-config.yaml,target=/mnt/libkmsp11-config.yaml,readonly" \
        -v "${PWD}/crypto11-config.json:/mnt/crypto11-config.json" \
        "mozilla/autograph:latest" makecsr \
        -crypto11Config /mnt/crypto11-config.json \
        -l "${CERT_NAME}" \
        -cn "${COMMON_NAME}" \
        -ou "Mozilla Dev Signing Service" \
        -dnsName "${DNS_NAME}" \
        -sigAlg "${SIG_ALG}" > ${CERT_NAME}.csr

docker run --rm --user 0:0 \
        -e "KMS_PKCS11_CONFIG=/mnt/libkmsp11-config.yaml" \
        -e GOOGLE_APPLICATION_CREDENTIALS="/app/.config/gcloud/application_default_credentials.json" \
        -e PKCS11_MODULE_PATH="/app/libkmsp11.so" \
        --mount type=bind,source="${HOME}/.config/gcloud,target=/app/.config/gcloud" \
        -v "${PWD}/content-signature-and-addons-root-202410-dev.crt:/app/content-signature-and-addons-root-202410-dev.crt" \
        -v "${PWD}/libkmsp11-config.yaml:/mnt/libkmsp11-config.yaml" \
        -v "${PWD}/openssl_sign.cnf:/mnt/openssl_sign.cnf" \
        -v "${PWD}:/out" \
        -v "${PWD}/${CERT_NAME}.csr:/app/${CERT_NAME}.csr" \
        "mozilla/autograph:latest" openssl ca \
        -startdate 20241022000000Z \
        -enddate 21010519000000Z \
        -cert content-signature-and-addons-root-202410-dev.crt\
        -keyfile pkcs11:object=content-signature-and-addons-root-202410-dev \
        -policy policy_match \
        -extensions amo_intermediate_ca \
        -config "/mnt/openssl_sign.cnf" \
        -in ${CERT_NAME}.csr \
        -out /out/${CERT_NAME}.crt \
        -create_serial \
        -notext \
        -engine pkcs11 \
        -keyform engine \
        -batch \
        -md "${OPENSSL_MSG_DGST}"
