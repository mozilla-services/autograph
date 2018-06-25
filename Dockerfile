FROM golang:1.10
MAINTAINER Mozilla
EXPOSE 8000

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

RUN go install go.mozilla.org/autograph

USER app
WORKDIR /app
CMD /go/bin/autograph
