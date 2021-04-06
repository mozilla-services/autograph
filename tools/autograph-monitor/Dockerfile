FROM autograph-app as build

USER root
RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .

# copy artifacts to a clean image
FROM debian:buster

COPY --from=build /go/bin/autograph-monitor /usr/bin/autograph-monitor

RUN addgroup --gid 10001 app \
      && \
      adduser --gid 10001 --uid 10001 \
      --home /app --shell /sbin/nologin \
      --disabled-password app \
      && \
      echo 'deb http://deb.debian.org/debian buster-backports main' > /etc/apt/sources.list.d/buster-backports.list && \
      apt update && \
      apt -y upgrade && \
      apt -y install gpg && \
      apt -y install -t buster-backports apksigner && \
      apt-get clean

USER app
CMD ["/usr/bin/autograph-monitor"]
