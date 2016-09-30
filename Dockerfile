FROM golang:1.7
MAINTAINER Mozilla
EXPOSE 8000

RUN addgroup --gid 10001 app
RUN adduser --gid 10001 --uid 10001 \
    --home /app --shell /sbin/nologin \
    --disabled-password app

RUN apt update
RUN apt -y upgrade

ADD . /go/src/go.mozilla.org/autograph
ADD autograph.yaml /app
ADD version.json /app

RUN go install go.mozilla.org/autograph

WORKDIR /app
CMD /go/bin/autograph
