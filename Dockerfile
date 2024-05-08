FROM golang:1.16.10-buster as builder
ENV GODEBUG=x509ignoreCN=0

COPY . /app/src/autograph
COPY autograph.yaml version.json /app/

RUN cd /app/src/autograph && go install .
RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .
RUN cd /app/src/autograph/tools/autograph-client && go build -o /go/bin/autograph-client .

FROM golang:1.16.10-buster
ENV GODEBUG=x509ignoreCN=0

RUN addgroup --gid 10001 app \
      && \
      adduser --gid 10001 --uid 10001 \
      --home /app --shell /sbin/nologin \
      --disabled-password app \
      && \
      echo 'deb http://archive.debian.org/debian buster-backports main' > /etc/apt/sources.list.d/buster-backports.list && \
      apt update && \
      apt -y upgrade && \
      apt -y install --no-install-recommends libltdl-dev gpg libncurses5 devscripts && \
      apt -y install --no-install-recommends -t buster-backports apksigner && \
      apt-get clean && \
      rm -rf /var/lib/apt/lists/*

# fetch the RDS CA bundles
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions
RUN curl -o /usr/local/share/old-rds-ca-bundle.pem https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem && \
      curl -o /usr/local/share/new-rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem && \
      cat /usr/local/share/old-rds-ca-bundle.pem /usr/local/share/new-rds-ca-bundle.pem > /usr/local/share/rds-combined-ca-bundle.pem


USER app
WORKDIR /app

COPY . ./src/autograph
COPY autograph.yaml version.json ./
COPY --chown=app:app --from=builder /go/bin /go/bin/
EXPOSE 8000
CMD /go/bin/autograph
