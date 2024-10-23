#!/bin/bash

set -e

# params
CERT_NAME="content-signature-ecdsa-intermediate-202410-dev"
SIG_ALG="ECDSAWithSHA384"
OPENSSL_MSG_DGST="sha256"
COMMON_NAME="Mozilla Autograph Dev Content Signature"
DNS_NAME="contentsignature.signing.dev.mozilla.org"
ROOT_CERT_NAME="content-signature-and-addons-root-202410-dev"

# Check for active gcloud account and login if we're not already authenticated
active_gcloud_account=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)")
if [ -z "$active_gcloud_account" ]; then
    echo "No active gcloud account found. Running gcloud auth login..."
    gcloud auth login --update-adc
fi

if [[ "$(uname)" == "Linux" ]]; then
    # if this is writable in linux, we get an error from the libkmsp11 library
    chmod -w libkmsp11-config.yaml
fi

docker run -u $(id -u ${USER}):$(id -g ${USER}) \
        -e "KMS_PKCS11_CONFIG=/mnt/libkmsp11-config.yaml" \
        -e GOOGLE_APPLICATION_CREDENTIALS="/app/.config/gcloud/application_default_credentials.json" \
        --mount type=bind,source="${HOME}/.config/gcloud,target=/app/.config/gcloud,readonly" \
        -v "${PWD}/:/mnt" \
        "mozilla/autograph:latest" makecsr \
        -crypto11Config /mnt/crypto11-config.json \
        -l "${CERT_NAME}" \
        -cn "${COMMON_NAME}" \
        -ou "Mozilla Dev Signing Service" \
        -dnsName "${DNS_NAME}" \
        -sigAlg "${SIG_ALG}" > ${CERT_NAME}.csr && \

docker run -u $(id -u ${USER}):$(id -g ${USER}) \
        -e "KMS_PKCS11_CONFIG=/mnt/libkmsp11-config.yaml" \
        -e GOOGLE_APPLICATION_CREDENTIALS="/app/.config/gcloud/application_default_credentials.json" \
        -e PKCS11_MODULE_PATH="/app/libkmsp11.so" \
        --mount type=bind,source="${HOME}/.config/gcloud,target=/app/.config/gcloud" \
        -v "${PWD}/:/mnt" \
        "mozilla/autograph:latest" openssl ca \
        -startdate 20241022000000Z \
        -enddate 21010519000000Z \
        -cert /mnt/${ROOT_CERT_NAME}.crt \
        -keyfile pkcs11:object=${ROOT_CERT_NAME} \
        -policy policy_match \
        -extensions amo_intermediate_ca \
        -config "/mnt/openssl_sign.cnf" \
        -in /mnt/${CERT_NAME}.csr \
        -out /mnt/${CERT_NAME}.crt \
        -create_serial \
        -notext \
        -engine pkcs11 \
        -keyform engine \
        -batch \
        -md "${OPENSSL_MSG_DGST}"

if [[ "$(uname)" == "Linux" ]]; then
    # make it writable again
    chmod +w libkmsp11-config.yaml
fi
