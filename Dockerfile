ARG LIBKMSP11_VERSION=1.6

#------------------------------------------------------------------------------
# rcodesign build stage (Apple code signing tool)
#------------------------------------------------------------------------------
# The apple signer shells out to rcodesign (github.com/indygreg/apple-platform-rs).
# PKCS#11/HSM signing exists only on the upstream main branch — no released
# version (0.29.0 is newest) or prebuilt binary includes it — so we build from a
# pinned commit with the pkcs11 feature. It's built here and copied into the
# final image so the runtime image carries no Rust toolchain. Revisit (switch to
# a pinned release/prebuilt) once upstream ships a release with PKCS#11.
#
# We also apply a local patch (signer/apple/rcodesign-pkcs11-init.patch): rcodesign
# initializes the PKCS#11 library more than once per process (certificate
# resolution + signing) and never calls C_Finalize, and the cryptoki crate has no
# finalize-on-drop — so a spec-compliant module (e.g. SoftHSM) rejects the second
# C_Initialize with CKR_CRYPTOKI_ALREADY_INITIALIZED and signing fails. The patch
# makes a redundant C_Initialize benign. This is present on upstream main too;
# drop the patch once fixed upstream.
FROM rust:1-bookworm AS rcodesign-builder
ARG RCODESIGN_GIT=https://github.com/indygreg/apple-platform-rs
ARG RCODESIGN_REV=607b3c1d952b06c0affa12106f9d6bad2ffbc44a
RUN apt-get update && apt-get -y install --no-install-recommends cmake git && rm -rf /var/lib/apt/lists/*
COPY signer/apple/rcodesign-pkcs11-init.patch /tmp/rcodesign-pkcs11-init.patch
RUN git clone ${RCODESIGN_GIT} /tmp/rcodesign && \
    cd /tmp/rcodesign && \
    git checkout ${RCODESIGN_REV} && \
    git apply /tmp/rcodesign-pkcs11-init.patch && \
    cargo install --path apple-codesign --features pkcs11 --locked --root /out && \
    /out/bin/rcodesign --version

#------------------------------------------------------------------------------
# Base Debian Image
#------------------------------------------------------------------------------
FROM golang:1.26.3-trixie AS base
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
        libengine-pkcs11-openssl \
        softhsm2

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

# Copy rcodesign (built with the pkcs11 feature) used by the apple signer.
COPY --from=rcodesign-builder /out/bin/rcodesign /usr/local/bin/rcodesign
RUN rcodesign --version

# Setup the worker and entrypoint.
RUN useradd --uid 10001 --home-dir /app --shell /sbin/nologin app
USER app
WORKDIR /app
CMD ["/go/bin/autograph"]
