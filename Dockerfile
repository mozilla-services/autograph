ARG GO_VERSION=1.22
ARG LIBKMSP11_VERSION=1.6

#------------------------------------------------------------------------------
# Base Debian Image
#------------------------------------------------------------------------------
FROM --platform=linux/amd64 debian:bookworm as base
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
        jq \
        libengine-pkcs11-openssl

# Cleanup after package installation
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

#------------------------------------------------------------------------------
# Pre-build dependency caching
#------------------------------------------------------------------------------
FROM base as prebuild
ARG LIBKMSP11_VERSION

COPY google-pkcs12-release-signing-key.pem /app/src/autograph/

# Download and verify the Google KMS library
RUN cd /tmp && curl -L https://github.com/GoogleCloudPlatform/kms-integrations/releases/download/pkcs11-v${LIBKMSP11_VERSION}/libkmsp11-${LIBKMSP11_VERSION}-linux-amd64.tar.gz | tar -zx --strip-components=1
RUN openssl dgst -sha384 -verify /app/src/autograph/google-pkcs12-release-signing-key.pem -signature /tmp/libkmsp11.so.sig /tmp/libkmsp11.so

# fetch the RDS CA bundles
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions
RUN curl -o /usr/local/share/old-rds-ca-bundle.pem https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem && \
      curl -o /usr/local/share/new-rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem && \
      cat /usr/local/share/old-rds-ca-bundle.pem /usr/local/share/new-rds-ca-bundle.pem > /usr/local/share/rds-combined-ca-bundle.pem

#------------------------------------------------------------------------------
# Build Stage
#------------------------------------------------------------------------------
FROM prebuild as builder

ADD . /app/src/autograph
RUN cd /app/src/autograph && go install .
RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .
RUN cd /app/src/autograph/tools/autograph-client && go build -o /go/bin/autograph-client .
RUN cd /app/src/autograph/tools/makecsr && go build -o /go/bin/makecsr .

#------------------------------------------------------------------------------
# Deployment Stage
#------------------------------------------------------------------------------
FROM prebuild
EXPOSE 8000

# Copy compiled appliation from the builder.
ADD . /app/src/autograph
ADD autograph.yaml /app
ADD version.json /app
COPY --from=builder /go/bin /go/bin/

# Copy Google KMS library from the builder.
COPY --from=builder /tmp/libkmsp11.so /app

# Setup the worker and entrypoint.
RUN useradd --uid 10001 --home-dir /app --shell /sbin/nologin app
USER app
WORKDIR /app
CMD /go/bin/autograph

