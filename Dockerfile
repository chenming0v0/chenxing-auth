FROM node:22-bookworm-slim AS web-builder

WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web ./
RUN npm run build

FROM rust:1.94-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY build.rs build_logic.rs ./
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

# The binary only embeds index.html; the hashed JS/CSS/font assets it references
# are served from disk. Ship them from the very same directory the builder stage
# embedded from, so the hashed filenames in index.html always resolve.
COPY --from=builder /build/web/dist /usr/local/share/chenxing-auth/web/dist

RUN mkdir -p /var/lib/chenxing-auth/keys \
    && chown -R chenxing:chenxing /var/lib/chenxing-auth

USER chenxing
WORKDIR /var/lib/chenxing-auth
# WORKDIR holds mutable state, so web/dist cannot be found relatively; point at
# the image path explicitly. Both production images use the same location.
ENV APP_HOST=0.0.0.0 \
    APP_PORT=3000 \
    KEY_DIRECTORY=/var/lib/chenxing-auth/keys \
    WEB_DIST_DIR=/usr/local/share/chenxing-auth/web/dist \
    COOKIE_SECURE=true

EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/chenxing-auth"]
