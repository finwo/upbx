ARG VERSION=latest

FROM debian:stable AS builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev bash curl tar gzip ca-certificates

RUN mkdir -p /build

WORKDIR /build

RUN curl -fsSL https://github.com/finwo/dep/raw/main/dist/dep -o /usr/bin/dep && \
    chmod +x /usr/bin/dep

COPY package.ini /build/package.ini

WORKDIR /build

RUN dep repository add finwo https://github.com/finwo/dep-repository/archive/refs/heads/main.tar.gz && \
    dep repository update && \
    dep install

COPY Makefile /build/Makefile
COPY src /build/src
COPY LICENSE.md /build/LICENSE.md

RUN make clean && make upbx

FROM busybox:latest

ARG TARGETARCH

COPY --from=builder /build/upbx /usr/bin/upbx

COPY entrypoint.sh /etc/rc.local
RUN chmod +x /etc/rc.local

ENTRYPOINT ["/bin/ash", "/etc/rc.local"]
