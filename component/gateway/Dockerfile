FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH
RUN ARCH=$(echo "$TARGETARCH" | sed 's/amd64/x64/') \
    && curl -fsSL "https://github.com/finwo/dep/releases/download/edge/dep-linux-${ARCH}" \
       -o /usr/local/bin/dep \
    && chmod +x /usr/local/bin/dep

WORKDIR /src
COPY . .
RUN dep install
RUN make upbx-gw

FROM debian:bookworm-slim
COPY --from=build /src/upbx-gw /usr/local/bin/upbx-gw
EXPOSE 5060/udp
ENTRYPOINT ["upbx-gw", "daemon", "-c", "/etc/upbx-gw.conf"]
