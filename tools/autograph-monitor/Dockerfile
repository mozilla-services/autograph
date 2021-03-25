FROM autograph-app

USER root

RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .

USER app

CMD /go/bin/autograph-monitor
