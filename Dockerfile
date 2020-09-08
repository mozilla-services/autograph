FROM golang:1.15.1-buster
EXPOSE 8000

ENV GODEBUG=x509ignoreCN=0

RUN addgroup --gid 10001 app \
      && \
      adduser --gid 10001 --uid 10001 \
      --home /app --shell /sbin/nologin \
      --disabled-password app \
      && \
      apt update && \
      apt -y upgrade && \
      apt -y install libltdl-dev gpg libncurses5 apksigner && \
      apt-get clean

# fetch the RDS CA bundle
# https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_PostgreSQL.html#PostgreSQL.Concepts.General.SSL
RUN curl -o /usr/local/share/rds-combined-ca-bundle.pem https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem

ADD . /app/src/autograph
ADD autograph.yaml /app
ADD version.json /app

RUN cd /app/src/autograph && go install go.mozilla.org/autograph

USER app
WORKDIR /app
CMD /go/bin/autograph
