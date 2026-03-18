ARG VERSION=latest

FROM debian:stable AS builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev bash curl tar gzip ca-certificates

RUN mkdir -p /build

WORKDIR /build

#RUN curl -fsSL https://github.com/finwo/dep/releases/download/stable/dep-linux-x64 -o /usr/bin/dep && \
RUN curl -fsSL https://github.com/finwo/dep/releases/download/stable/dep-linux-arm64 -o /usr/bin/dep && \
    chmod +x /usr/bin/dep

COPY .dep /build/.dep

WORKDIR /build

RUN dep install

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
