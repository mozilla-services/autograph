ARG LIBKMSP11_VERSION=1.6

#------------------------------------------------------------------------------
# Base Debian Image
#------------------------------------------------------------------------------
FROM golang:1.26.6-trixie AS base
ARG TARGETARCH
ENV DEBIAN_FRONTEND='noninteractive'

## Enable trixie-backports
RUN echo "deb http://deb.debian.org/debian/ trixie-backports main" > /etc/apt/sources.list.d/trixie-backports.list
RUN echo "deb-src http://deb.debian.org/debian/ trixie-backports main" >> /etc/apt/sources.list.d/trixie-backports.list

RUN apt update && \
      apt -y upgrade && \
      apt -y install --no-install-recommends \
        libltdl-dev \
        gpg \
        libncurses6 \
        devscripts \
        apksigner \
        rpm \
        gcc \
        g++ \
        libc6-dev \
        pkg-config \
        curl \
        jq \
        libengine-pkcs11-openssl

# Cleanup after package installation
RUN apt clean && rm -rf /var/lib/apt/lists/*

#------------------------------------------------------------------------------
# Pre-build dependency caching
#------------------------------------------------------------------------------
FROM base AS prebuild
ARG TARGETARCH

## install bazelisk for building libkmsp11
RUN wget https://github.com/bazelbuild/bazelisk/releases/download/v1.29.0/bazelisk-${TARGETARCH}.deb
RUN dpkg -i bazelisk-${TARGETARCH}.deb
RUN rm bazelisk-${TARGETARCH}.deb

COPY google-pkcs12-release-signing-key.pem /app/src/autograph/

# Build the Google KMS library
RUN echo "Building Google KMS library for ${TARGETARCH}."
ADD ./kmsp11 /tmp/kmsp11
WORKDIR /tmp/kmsp11
RUN bazel build //kmsp11/main:libkmsp11.so
RUN mv $(find / -type f -name "libkmsp11.so") ./

#------------------------------------------------------------------------------
# Build Stage
#------------------------------------------------------------------------------
FROM prebuild AS builder

ADD . /app/src/autograph
RUN cd /app/src/autograph && go install .
RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .
RUN cd /app/src/autograph/tools/autograph-client && go build -o /go/bin/autograph-client .
RUN cd /app/src/autograph/tools/makecsr && go build -o /go/bin/makecsr .

#------------------------------------------------------------------------------
# Deployment Stage
#------------------------------------------------------------------------------
FROM base
EXPOSE 8000
EXPOSE 2112

# Copy compiled appliation from the builder.
ADD . /app/src/autograph
ADD autograph.yaml /app
ADD version.json /app
COPY --from=builder /go/bin /go/bin/

# Copy Google KMS library from the builder.
COPY --from=builder /tmp/kmsp11/libkmsp11.so /app

# Setup the worker and entrypoint.
RUN useradd --uid 10001 --home-dir /app --shell /sbin/nologin app
USER app
WORKDIR /app
CMD ["/go/bin/autograph"]
