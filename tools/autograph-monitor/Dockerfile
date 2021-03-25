FROM autograph-app

USER root
RUN apt update && \
      apt -y upgrade && \
      apt -y install softhsm2 python3 python3-pip jq && \
      apt-get clean && \
      python3 -m pip install yq

RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .

ADD run-monitor-with-root-hash.sh /app
RUN chmod +x /app/run-monitor-with-root-hash.sh

USER app

CMD /app/run-monitor-with-root-hash.sh
