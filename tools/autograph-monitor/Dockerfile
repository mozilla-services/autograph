FROM autograph-app
MAINTAINER Mozilla

USER root
RUN apt update && \
      apt -y upgrade && \
      apt -y install softhsm2 python3 python3-pip jq && \
      apt-get clean && \
      python3 -m pip install yq

RUN go build -o /go/bin/autograph-monitor /go/src/go.mozilla.org/autograph/tools/autograph-monitor/*.go

RUN curl -o /app/wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh && \
      chmod +x /app/wait-for-it.sh

ADD run-monitor-with-root-hash.sh /app
RUN chmod +x /app/run-monitor-with-root-hash.sh

USER app

CMD /app/run-monitor-with-root-hash.sh
