FROM golang:1.11
MAINTAINER Mozilla
EXPOSE 8000

ENV GO111MODULE on

RUN addgroup --gid 10001 app && \

    adduser --gid 10001 --uid 10001 \
    --home /app --shell /sbin/nologin \
    --disabled-password app && \

    apt update && \
    apt -y upgrade && \
    apt -y install libltdl-dev && \
    apt-get clean

ADD . /go/src/go.mozilla.org/autograph
ADD autograph.yaml /app
ADD version.json /app

RUN cd /go/src/go.mozilla.org/autograph && go install .

USER app
WORKDIR /app
CMD /go/bin/autograph
