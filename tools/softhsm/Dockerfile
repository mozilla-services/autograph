FROM autograph-app

USER root
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install jq yq softhsm2 gettext postgresql-client && \
    apt-get clean

# copy the config
ADD soft-hsm-schema.sql /app/
ADD autograph.softhsm-service.yaml /app/
ADD soft-hsm-schema.sql /app/

# give app access to dev db root cert
ADD db-root.crt /opt/db-root.crt
RUN chgrp -vR app /opt
RUN chmod -vR 0444 /opt/db-root.crt

# Setup SoftHSM
RUN mkdir -p /var/lib/softhsm/tokens && \
      softhsm2-util --init-token --slot 0 --label test --pin 0000 --so-pin 0000

# load dev keys
ADD webextensions-rsa.pem /app/src/autograph/tools/softhsm/
ADD extensions-ecdsa-pk8.pem /app/src/autograph/tools/softhsm/

# Import a key pair from the given path. The file must be in PKCS#8-format. Use with --slot or --token or --serial, --file-pin, --label, --id, --no-public-key, and --pxin.
RUN softhsm2-util --token test --pin 0000 --so-pin 0000 --label webextrsa4096 --id deadbeef --import /app/src/autograph/tools/softhsm/webextensions-rsa.pem
RUN softhsm2-util --token test --pin 0000 --so-pin 0000 --label ext-ecdsa-p384 --id 12345678 --import /app/src/autograph/tools/softhsm/extensions-ecdsa-pk8.pem
RUN softhsm2-util --token test --pin 0000 --so-pin 0000 --label ext-ecdsa-p384-2 --id 11111111 --import /app/src/autograph/tools/softhsm/extensions-ecdsa-2-pk8.pem

# genkeys
RUN cd /app/src/autograph/tools/softhsm/ && go run ./genkeys/genkeys.go

# make a pki in softhsm
# then update the config
# then write the generated config and new root hash to /tmp
# we expect /tmp was mounted for exports to the monitor-hsm service
RUN cd /app/src/autograph/tools/genpki/ && \
      go run genpki.go > /app/genpki.out
RUN cd /app
RUN NORMANDY_IS_PRIV_KEY="$(grep 'inter key name' /app/genpki.out | awk '{print $4}')" \
      NORMANDY_IS_CERT="$(cat $(grep 'inter cert path' /app/genpki.out | awk '{print $4}'))" \
      NORMANDY_CA_CERT="$(cat $(grep 'root cert path' /app/genpki.out | awk '{print $4}'))" \
      KINTO_IS_PRIV_KEY="$(grep 'inter key name' /app/genpki.out | awk '{print $4}')" \
      KINTO_IS_CERT="$(cat $(grep 'inter cert path' /app/genpki.out | awk '{print $4}'))" \
      KINTO_CA_CERT="$(cat $(grep 'root cert path' /app/genpki.out | awk '{print $4}'))" \
      envsubst < soft-hsm-schema.sql > soft-hsm-schema-merged.sql

CMD PGPASSWORD=$(yq -r '.database.password' /app/autograph-service.yaml) \
      psql -h $(yq -r '.database.host' /app/autograph-service.yaml | cut -d ":" -f 1) \
      -p $(yq -r '.database.host' /app/autograph-service.yaml | cut -d ":" -f 2) \
      -U $(yq -r '.database.user' /app/autograph-service.yaml) \
      -d $(yq -r '.database.name' /app/autograph-service.yaml) \
      -a -f soft-hsm-schema-merged.sql && \
      /go/bin/autograph -c /app/autograph.softhsm-service.yaml
