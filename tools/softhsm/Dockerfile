FROM autograph-app

USER root
RUN apt update && \
      apt -y upgrade && \
      apt -y install softhsm2 python3 python3-ruamel.yaml && \
      apt-get clean

# copy the config
ADD autograph.softhsm.yaml /app/

# give app access to dev db root cert
ADD db-root.crt /opt/db-root.crt
RUN chgrp -vR app /opt
RUN chmod -vR 0444 /opt/db-root.crt

# Setup SoftHSM
RUN mkdir -p /var/lib/softhsm/tokens && \
      softhsm2-util --init-token --slot 0 --label test --pin 0000 --so-pin 0000

# load dev keys
ADD webextensions-rsa.pem /go/src/go.mozilla.org/autograph/tools/softhsm/
ADD extensions-ecdsa-pk8.pem /go/src/go.mozilla.org/autograph/tools/softhsm/

# Import a key pair from the given path. The file must be in PKCS#8-format. Use with --slot or --token or --serial, --file-pin, --label, --id, --no-public-key, and --pxin.
RUN softhsm2-util --token test --pin 0000 --so-pin 0000 --label webextrsa4096 --id deadbeef --import /go/src/go.mozilla.org/autograph/tools/softhsm/webextensions-rsa.pem
RUN softhsm2-util --token test --pin 0000 --so-pin 0000 --label ext-ecdsa-p384 --id 12345678 --import /go/src/go.mozilla.org/autograph/tools/softhsm/extensions-ecdsa-pk8.pem

# genkeys
RUN cd /go/src/go.mozilla.org/autograph/tools/softhsm/ && go run genkeys.go

# make a pki in softhsm then update the config
RUN cd /go/src/go.mozilla.org/autograph/tools/genpki/ && \
      go run genpki.go > /app/genpki.out && \
      cd /go/src/go.mozilla.org/autograph/tools/configurator && \
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
      -p cacert -v "$(grep 'root cert path' /app/genpki.out | awk '{print $4}')"

RUN curl -o /app/wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh && \
      chmod +x /app/wait-for-it.sh

# in docker-compose, the monitor job will mount /tmp to get the generated config
RUN cp /app/autograph.softhsm.yaml /tmp/

CMD /go/bin/autograph -c /app/autograph.softhsm.yaml
