ARG GO_VERSION=1.22

#------------------------------------------------------------------------------
# Base Debian Image
#------------------------------------------------------------------------------
FROM debian:bookworm as base
ARG GO_VERSION

ENV DEBIAN_FRONTEND='noninteractive' \
    PATH="${PATH}:/usr/lib/go-${GO_VERSION}/bin:/go/bin" \
    GOPATH='/go'

## Enable bookworm-backports
RUN echo "deb http://deb.debian.org/debian/ bookworm-backports main" > /etc/apt/sources.list.d/bookworm-backports.list
RUN echo "deb-src http://deb.debian.org/debian/ bookworm-backports main" >> /etc/apt/sources.list.d/bookworm-backports.list

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install --no-install-recommends \
        libltdl-dev \
        gpg \
        libncurses5 \
        devscripts \
        apksigner \
        golang-${GO_VERSION} \
        gcc \
        g++ \
        libc6-dev \
        pkg-config \
        curl \
        jq

# Cleanup after package installation
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

#------------------------------------------------------------------------------
# Build Stage
#------------------------------------------------------------------------------
FROM base as builder

ADD . /app/src/autograph

RUN cd /app/src/autograph && go install .
RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .
RUN cd /app/src/autograph/tools/autograph-client && go build -o /go/bin/autograph-client .

#------------------------------------------------------------------------------
# Deployment Stage
#------------------------------------------------------------------------------
FROM base
EXPOSE 8000

# fetch the RDS CA bundles
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions
RUN curl -o /usr/local/share/old-rds-ca-bundle.pem https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem && \
      curl -o /usr/local/share/new-rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem && \
      cat /usr/local/share/old-rds-ca-bundle.pem /usr/local/share/new-rds-ca-bundle.pem > /usr/local/share/rds-combined-ca-bundle.pem

# Copy compiled appliation from the builder.
ADD . /app/src/autograph
ADD autograph.yaml /app
ADD version.json /app
COPY --from=builder /go/bin /go/bin/

# Setup the worker and entrypoint.
RUN useradd --uid 10001 --home-dir /app --shell /sbin/nologin app
USER app
WORKDIR /app
CMD /go/bin/autograph

#------------------------------------------------------------------------------
# With SoftHSM set up for testing
#------------------------------------------------------------------------------
FROM base as autograph-app-softhsm

RUN apt-get update && \
      apt-get -y upgrade && \
      apt-get -y install jq yq softhsm2 python3 python3-ruamel.yaml && \
      apt-get clean

# copy the config
ADD tools/softhsm/autograph.softhsm.yaml /app/

# give app access to dev db root cert
ADD tools/softhsm/db-root.crt /opt/db-root.crt
RUN chgrp -vR app /opt
RUN chmod -vR 0444 /opt/db-root.crt

# Setup SoftHSM
RUN mkdir -p /var/lib/softhsm/tokens && \
      softhsm2-util --init-token --slot 0 --label test --pin 0000 --so-pin 0000

# load dev keys
ADD tools/softhsm/webextensions-rsa.pem /app/src/autograph/tools/softhsm/
ADD tools/softhsm/extensions-ecdsa-pk8.pem /app/src/autograph/tools/softhsm/

# Import a key pair from the given path. The file must be in PKCS#8-format. Use with --slot or --token or --serial, --file-pin, --label, --id, --no-public-key, and --pxin.
RUN softhsm2-util --token test --pin 0000 --so-pin 0000 --label webextrsa4096 --id deadbeef --import /app/src/autograph/tools/softhsm/webextensions-rsa.pem
RUN softhsm2-util --token test --pin 0000 --so-pin 0000 --label ext-ecdsa-p384 --id 12345678 --import /app/src/autograph/tools/softhsm/extensions-ecdsa-pk8.pem
RUN softhsm2-util --token test --pin 0000 --so-pin 0000 --label ext-ecdsa-p384-2 --id 11111111 --import /app/src/autograph/tools/softhsm/extensions-ecdsa-2-pk8.pem

# genkeys
RUN cd /app/src/autograph/tools/softhsm/ && go run genkeys.go

# make a pki in softhsm
# then update the config
# then write the generated config and new root hash to /tmp
# we expect /tmp was mounted for exports to the monitor-hsm service
RUN cd /app/src/autograph/tools/genpki/ && \
      go run genpki.go > /app/genpki.out && \
      cd /app/src/autograph/tools/configurator && \
      python3 configurator.py -c /app/autograph.softhsm.yaml -i -s normandy \
      -p issuerprivkey -v "$(grep 'inter key name' /app/genpki.out | awk '{print $4}')" && \
      python3 configurator.py -c /app/autograph.softhsm.yaml -i -s normandy \
      -p issuercert -v "$(grep 'inter cert path' /app/genpki.out | awk '{print $4}')" && \
      python3 configurator.py -c /app/autograph.softhsm.yaml -i -s normandy \
      -p cacert -v "$(grep 'root cert path' /app/genpki.out | awk '{print $4}')" && \
      python3 configurator.py -c /app/autograph.softhsm.yaml -i -s kinto \
      -p issuerprivkey -v "$(grep 'inter key name' /app/genpki.out | awk '{print $4}')" && \
      python3 configurator.py -c /app/autograph.softhsm.yaml -i -s kinto \
      -p issuercert -v "$(grep 'inter cert path' /app/genpki.out | awk '{print $4}')" && \
      python3 configurator.py -c /app/autograph.softhsm.yaml -i -s kinto \
      -p cacert -v "$(grep 'root cert path' /app/genpki.out | awk '{print $4}')" && \
      cp /app/autograph.softhsm.yaml /tmp/ && \
      /bin/bash /app/src/autograph/tools/softhsm/hash_signer_cacert.sh /app/autograph.softhsm.yaml normandy > /tmp/normandy_dev_root_hash.txt && \
      cat /tmp/normandy_dev_root_hash.txt

CMD /go/bin/autograph -c /app/autograph.softhsm.yaml

#------------------------------------------------------------------------------
# Lambda emulator
#------------------------------------------------------------------------------
FROM base as autograph-lambda-emulator

USER root

RUN curl -Lo /usr/local/bin/aws-lambda-rie \
    https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie \
    && \
    chmod +x /usr/local/bin/aws-lambda-rie

COPY tools/autograph-monitor/lambda-selftest-entrypoint.sh /usr/local/bin/lambda-selftest-entrypoint.sh

USER app
ENTRYPOINT ["/usr/local/bin/aws-lambda-rie"]
CMD ["/go/bin/autograph-monitor"]