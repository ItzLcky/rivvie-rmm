# Builds the server and the dashboard into one small image.
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

FROM alpine:3
RUN adduser -D -H rmm
COPY --from=server /src/target/release/rmm-server /usr/local/bin/rmm-server
COPY --from=web /web/build /srv/web
ENV RMM_WEB_DIR=/srv/web RMM_BIND=0.0.0.0:8080
USER rmm
EXPOSE 8080
ENTRYPOINT ["rmm-server"]
CMD ["serve"]
