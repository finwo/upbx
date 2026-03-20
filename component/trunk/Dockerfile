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
RUN make upbx-trk

FROM debian:bookworm-slim
COPY --from=build /src/upbx-trk /usr/local/bin/upbx-trk
EXPOSE 5062/udp
ENTRYPOINT ["upbx-trk", "daemon", "-c", "/etc/upbx-trk.conf"]
