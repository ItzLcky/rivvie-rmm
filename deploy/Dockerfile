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
FROM rust:1-alpine AS agents
RUN apk add --no-cache musl-dev mingw-w64-gcc && rustup target add x86_64-pc-windows-gnu
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p rmm-agent \
 && cargo build --release -p rmm-agent --target x86_64-pc-windows-gnu \
 && mkdir /out \
 && cp target/release/rmm-agent /out/rmm-agent-linux-x86_64 \
 && cp target/x86_64-pc-windows-gnu/release/rmm-agent.exe /out/rmm-agent-windows-x86_64.exe

FROM alpine:3
RUN adduser -D -H rmm
COPY --from=server /src/target/release/rmm-server /usr/local/bin/rmm-server
COPY --from=web /web/build /srv/web
COPY --from=agents /out /srv/agents
ENV RMM_WEB_DIR=/srv/web RMM_AGENT_DIR=/srv/agents RMM_BIND=0.0.0.0:8080
USER rmm
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["rmm-server"]
CMD ["serve"]
