docker run \
        -e "KMS_PKCS11_CONFIG=/app/src/autograph/tools/makecsr/xpi-dev-202410/libkmsp11-config.yaml" \
        -e GOOGLE_APPLICATION_CREDENTIALS="/app/.config/gcloud/application_default_credentials.json" \
        --mount type=bind,source="${HOME}/.config/gcloud,target=/app/.config/gcloud" \
        -v
        "mozilla/autograph:latest" openssl ca \
        -startdate 20241022000000Z \
        -enddate 21010519000000Z \
        -selfsign \
        -keyfile content-signature-and-addons-root-202410-dev \
        -policy policy_match \
        -extensions content_signature_and_addons_root_ca \
        -config "openssl.cnf" \
        -in content-signature-and-addons-root-202410-dev.csr \
        -out content-signature-and-addons-root-202410-dev.crt \
        -notext \
        -engine pkcs11 \
        -keyform engine \
        -batch