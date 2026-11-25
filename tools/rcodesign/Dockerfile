FROM rust:1.100-trixie as builder
ENV DEBIAN_FRONTEND='noninteractive'

## Enable trixie-backports
RUN echo "deb http://deb.debian.org/debian/ trixie-backports main" > /etc/apt/sources.list.d/trixie-backports.list
RUN echo "deb-src http://deb.debian.org/debian/ trixie-backports main" >> /etc/apt/sources.list.d/trixie-backports.list

RUN apt update && apt upgrade -y

WORKDIR /app
ADD . /app
RUN cargo build --release


FROM debian:trixie
ARG TARGETARCH=amd64
EXPOSE 8000

WORKDIR /app
RUN useradd --uid 10001 --home-dir /app --shell /sbin/nologin app
USER app
COPY --from=builder /app/target/release/rcodesign-api /app
ADD rcodesign-${TARGETARCH} rcodesign-cli
ADD src/test_files /app
CMD ["/app/rcodesign-api"]
