FROM node:22-bookworm-slim AS web-builder

WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web ./
RUN npm run build

FROM rust:1.94-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY src ./src
COPY migrations ./migrations
COPY --from=web-builder /build/web/dist ./web/dist
RUN cargo build --release --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /nonexistent --shell /usr/sbin/nologin chenxing

COPY --from=builder /build/target/release/chenxing-auth /usr/local/bin/chenxing-auth

RUN mkdir -p /var/lib/chenxing-auth/keys \
    && chown -R chenxing:chenxing /var/lib/chenxing-auth

USER chenxing
WORKDIR /var/lib/chenxing-auth
ENV APP_HOST=0.0.0.0 \
    APP_PORT=3000 \
    KEY_DIRECTORY=/var/lib/chenxing-auth/keys \
    COOKIE_SECURE=true

EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/chenxing-auth"]
