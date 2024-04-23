FROM debian:bookworm
EXPOSE 8000

ENV DEBIAN_FRONTEND='noninteractive' \
    PATH="${PATH}:/go/bin" \
    GOPATH='/go'

RUN useradd --uid 10001 --home-dir /app \
        --shell /sbin/nologin app

RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install libltdl-dev gpg libncurses5 devscripts apksigner golang && \
    apt-get clean

# fetch the RDS CA bundles
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions
RUN curl -o /usr/local/share/old-rds-ca-bundle.pem https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem && \
      curl -o /usr/local/share/new-rds-ca-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem && \
      cat /usr/local/share/old-rds-ca-bundle.pem /usr/local/share/new-rds-ca-bundle.pem > /usr/local/share/rds-combined-ca-bundle.pem

ADD . /app/src/autograph
ADD autograph.yaml /app
ADD version.json /app

RUN cd /app/src/autograph && go install .

RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .
RUN cd /app/src/autograph/tools/autograph-client && go build -o /go/bin/autograph-client .

USER app
WORKDIR /app
CMD /go/bin/autograph
