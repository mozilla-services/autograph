#------------------------------------------------------------------------------
# Build Stage
#------------------------------------------------------------------------------
FROM debian:bookworm as builder

ENV DEBIAN_FRONTEND='noninteractive' \
    PATH="${PATH}:/go/bin" \
    GOPATH='/go'

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install \
        libltdl-dev \
        gpg libncurses5 \
        devscripts \
        apksigner \
        golang \
        build-essential

ADD . /app/src/autograph

RUN cd /app/src/autograph && go install .
RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .
RUN cd /app/src/autograph/tools/autograph-client && go build -o /go/bin/autograph-client .

#------------------------------------------------------------------------------
# Deployment Stage
#------------------------------------------------------------------------------
FROM debian:bookworm
EXPOSE 8000

ENV DEBIAN_FRONTEND='noninteractive' \
    PATH="${PATH}:/go/bin" \
    GOPATH='/go'

# Install required packages
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install --no-install-recommends \
        libltdl-dev \
        gpg \
        libncurses5 \
        devscripts \
        apksigner \
        golang \
        build-essential \
        curl \
        jq

# Cleanup after package installation
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/*

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
