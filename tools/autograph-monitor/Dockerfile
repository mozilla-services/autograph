FROM autograph-app as build

USER root
RUN cd /app/src/autograph/tools/autograph-monitor && go build -o /go/bin/autograph-monitor .

# copy artifacts to a clean image
FROM debian:buster

COPY --from=build /go/bin/autograph-monitor /usr/bin/autograph-monitor
COPY --from=build /app/src/autograph/bin/wait-for-it.sh /usr/bin/wait-for-it.sh

RUN addgroup --gid 10001 app \
      && \
      adduser --gid 10001 --uid 10001 \
      --home /app --shell /sbin/nologin \
      --disabled-password app \
      && \
      apt update && \
      apt -y upgrade && \
      apt -y install gpg apksigner && \
      apt-get clean

USER app
CMD ["/usr/bin/autograph-monitor"]
