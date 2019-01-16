FROM app:build
MAINTAINER Mozilla

USER root
RUN apt update && \
    apt -y upgrade && \
    apt -y install softhsm2 && \
    apt-get clean

# Setup SoftHSM
RUN mkdir -p /var/lib/softhsm/tokens && \
    softhsm2-util --init-token --slot 0 --label test --pin 0000 --so-pin 0000

# genkeys then cleanup go dirs so this volume doesn't conflict
RUN cd /go/src/go.mozilla.org/autograph/ && \
    go run tools/softhsm/genkeys.go && \
    rm -rf /go/
