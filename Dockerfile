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

#
# Development Stage
#
FROM base as development

ENV PATH="$PATH:/usr/lib/go-${GO_VERSION}/bin:/go/bin"
ENV FOO='bar'
ENV GOPATH='/go'

# fetch the RDS CA bundles
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions
RUN curl -o /usr/local/share/old-rds-ca-bundle.pem https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem && \
      curl -o /usr/local/share/new-rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem && \
      cat /usr/local/share/old-rds-ca-bundle.pem /usr/local/share/new-rds-ca-bundle.pem > /usr/local/share/rds-combined-ca-bundle.pem

CMD [ "/bin/bash"]
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

