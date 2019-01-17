FROM app:build
MAINTAINER Mozilla

RUN go build -o /go/bin/autograph-monitor /go/src/go.mozilla.org/autograph/tools/autograph-monitor/*.go

ADD monitor.autograph.yaml /app

USER app
CMD /go/bin/autograph-monitor
