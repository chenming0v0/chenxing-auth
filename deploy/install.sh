#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' 'Docker is required. Install Docker Engine and the Compose plugin first.' >&2
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    printf '%s\n' 'Docker Compose v2 is required.' >&2
    exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
    printf '%s\n' 'curl is required for the deployment health check.' >&2
    exit 1
fi

if [[ -f .env ]]; then
    printf '%s\n' 'Using existing .env; secrets will not be replaced.'
else
    if ! command -v openssl >/dev/null 2>&1; then
        printf '%s\n' 'openssl is required to generate deployment secrets.' >&2
        exit 1
    fi

    APP_ISSUER="${CHENXING_ISSUER:-http://localhost:3000}"
    APP_PORT="${CHENXING_PORT:-3000}"
    POSTGRES_DB="${POSTGRES_DB:-chenxing_auth}"
    POSTGRES_USER="${POSTGRES_USER:-chenxing}"
    POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(openssl rand -hex 32)}"
    ADMIN_TOKEN="${ADMIN_TOKEN:-$(openssl rand -hex 32)}"
    AUTH_ENCRYPTION_KEY="${AUTH_ENCRYPTION_KEY:-$(openssl rand -base64 32)}"

    umask 077
    cat > .env <<EOF
APP_HOST=0.0.0.0
APP_PORT=${APP_PORT}
APP_ISSUER=${APP_ISSUER}
ADMIN_TOKEN=${ADMIN_TOKEN}
AUTH_ENCRYPTION_KEY=${AUTH_ENCRYPTION_KEY}
KEY_DIRECTORY=/var/lib/chenxing-auth/keys
KEY_ROTATION_GRACE_SECONDS=${KEY_ROTATION_GRACE_SECONDS:-604800}
COOKIE_SECURE=true
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
SESSION_TTL_SECONDS=${SESSION_TTL_SECONDS:-604800}
RUST_LOG=${RUST_LOG:-chenxing_auth=info,tower_http=info}
EOF
    printf '%s\n' 'Created .env with generated secrets. Keep this file private.'
fi

if ! docker compose --env-file .env -f docker-compose.prod.yml config >/dev/null; then
    printf '%s\n' 'The production Compose configuration is invalid. Check .env and try again.' >&2
    exit 1
fi

docker compose --env-file .env -f docker-compose.prod.yml up -d postgres redis
if ! docker compose --env-file .env -f docker-compose.prod.yml run --rm --build app migrate; then
    printf '%s\n' 'Database migration failed. This release uses a fresh unified SQLx baseline and does not roll old schemas forward automatically.' >&2
    printf '%s\n' 'Back up the database and follow the documented reset/migration procedure before retrying.' >&2
    exit 1
fi
docker compose --env-file .env -f docker-compose.prod.yml up -d --build app

HOST_PORT="$(docker compose --env-file .env -f docker-compose.prod.yml port app 3000 | awk -F: '{print $NF}')"
if [[ -z "$HOST_PORT" ]]; then
    printf '%s\n' 'Could not determine the published application port.' >&2
    exit 1
fi

for attempt in $(seq 1 30); do
    if curl --fail --silent "http://127.0.0.1:${HOST_PORT}/health" >/dev/null 2>&1; then
        printf '辰星认证中枢 is ready on port %s\n' "$HOST_PORT"
        exit 0
    fi
    sleep 2
done

docker compose --env-file .env -f docker-compose.prod.yml ps
docker compose --env-file .env -f docker-compose.prod.yml logs app
printf '%s\n' 'Deployment started but the health check did not become ready in time.' >&2
exit 1
