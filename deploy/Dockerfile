# Builds the server, the dashboard, and downloadable agent binaries into one small image.
FROM node:24-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json web/.npmrc ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM rust:1-alpine AS server
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p rmm-server

# Agents offered by the "Enroll agents" dialog. Linux is a static musl binary, so it runs on
# any distro; Windows is cross-compiled with mingw.
#
# Self-update (optional): RMM_UPDATE_PUBKEY builds the release public key into the agents,
# and an `update_key` build secret (the hex key from `rmm-sign keygen`) signs them, writing
# `<binary>.update.json` next to each. Without the secret the agents are unsigned and the
# server won't offer them as updates. RMM_AGENT_VERSION overrides the crate version.
FROM rust:1-alpine AS agents
ARG RMM_UPDATE_PUBKEY=
ARG RMM_AGENT_VERSION=
RUN apk add --no-cache musl-dev mingw-w64-gcc && rustup target add x86_64-pc-windows-gnu
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=secret,id=update_key \
    cargo build --release -p rmm-agent -p rmm-sign \
 && cargo build --release -p rmm-agent --target x86_64-pc-windows-gnu \
 && mkdir /out \
 && cp target/release/rmm-agent /out/rmm-agent-linux-x86_64 \
 && cp target/x86_64-pc-windows-gnu/release/rmm-agent.exe /out/rmm-agent-windows-x86_64.exe \
 && if [ -s /run/secrets/update_key ]; then \
        v="$(target/release/rmm-agent --version | cut -d' ' -f2)" \
     && target/release/rmm-sign sign --key /run/secrets/update_key --platform linux-x86_64 --version "$v" /out/rmm-agent-linux-x86_64 \
     && target/release/rmm-sign sign --key /run/secrets/update_key --platform windows-x86_64 --version "$v" /out/rmm-agent-windows-x86_64.exe; \
    else echo "no update_key secret: agents are not signed for self-update"; fi

FROM alpine:3
RUN adduser -D -H rmm
COPY --from=server /src/target/release/rmm-server /usr/local/bin/rmm-server
COPY --from=web /web/build /srv/web
COPY --from=agents /out /srv/agents
# Ticket attachments and raw email (unless RMM_S3_BUCKET is set). Mount a volume here; owned
# by rmm so a fresh named volume inherits that.
RUN mkdir -p /srv/data/storage && chown -R rmm /srv/data
ENV RMM_WEB_DIR=/srv/web RMM_AGENT_DIR=/srv/agents RMM_STORAGE_DIR=/srv/data/storage RMM_BIND=0.0.0.0:8080
USER rmm
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["rmm-server"]
CMD ["serve"]
