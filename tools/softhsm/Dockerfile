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

# load dev keys
ADD webextensions-rsa.pem /go/src/go.mozilla.org/autograph/tools/softhsm/

# Import a key pair from the given path. The file must be in PKCS#8-format. Use with --slot or --token or --serial, --file-pin, --label, --id, --no-public-key, and --pxin.
RUN softhsm2-util --token test --pin 0000 --so-pin 0000 --label webextrsa4096 --id deadbeef --import /go/src/go.mozilla.org/autograph/tools/softhsm/webextensions-rsa.pem

# genkeys
RUN cd /go/src/go.mozilla.org/autograph/ && \
    go run tools/softhsm/genkeys.go

RUN cp /go/src/go.mozilla.org/autograph/autograph.softhsm.yaml /app/autograph.softhsm.yaml

CMD /go/bin/autograph -c /app/autograph.softhsm.yaml
