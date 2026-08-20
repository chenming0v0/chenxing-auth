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

secure_env_file() {
    if [[ -e .env || -L .env ]]; then
        if [[ -L .env ]]; then
            printf '%s\n' '.env must not be a symbolic link.' >&2
            exit 1
        fi
        if [[ ! -f .env ]]; then
            printf '%s\n' '.env must be a regular file.' >&2
            exit 1
        fi
        chmod 600 -- .env
    fi
}

read_env_value() {
    local key="$1"
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        if [[ "$line" == "${key}="* ]]; then
            printf '%s' "${line#*=}"
            return 0
        fi
    done < .env
    return 0
}

generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

ensure_env_value() {
    local key="$1" value="$2" temp
    if [[ -n "$(read_env_value "$key")" ]]; then
        return 0
    fi
    if ! grep -q "^${key}=" .env; then
        printf '\n%s=%s\n' "$key" "$value" >> .env
        return 0
    fi

    # Replace an existing empty assignment instead of appending a duplicate;
    # this keeps legacy .env files unambiguous on subsequent upgrades.
    temp="$(mktemp .env.tmp.XXXXXX)"
    awk -v key="$key" -v value="$value" '
        BEGIN { prefix = key "="; replaced = 0 }
        index($0, prefix) == 1 {
            if (!replaced) { print prefix value; replaced = 1 }
            next
        }
        { print }
        END { if (!replaced) print prefix value }
    ' .env > "$temp"
    chmod 600 "$temp"
    mv -f "$temp" .env
}

url_encode() {
    local value="$1" char encoded='' byte
    LC_ALL=C
    while [[ -n "$value" ]]; do
        char="${value:0:1}"
        value="${value:1}"
        if [[ "$char" =~ [a-zA-Z0-9.~_-] ]]; then
            encoded+="$char"
        else
            printf -v byte '%02X' "'${char}"
            encoded+="%${byte}"
        fi
    done
    printf '%s' "$encoded"
}

database_url() {
    local user="$1" password="$2" database="$3"
    printf 'postgres://%s:%s@postgres:5432/%s' \
        "$(url_encode "$user")" "$(url_encode "$password")" "$(url_encode "$database")"
}

set_env_value() {
    local key="$1" value="$2" temp
    temp="$(mktemp .env.tmp.XXXXXX)"
    awk -v key="$key" -v value="$value" '
        BEGIN { prefix = key "="; replaced = 0 }
        index($0, prefix) == 1 {
            if (!replaced) { print prefix value; replaced = 1 }
            next
        }
        { print }
        END { if (!replaced) print prefix value }
    ' .env > "$temp"
    chmod 600 "$temp"
    mv -f "$temp" .env
}

legacy_project_name() {
    local name
    name="$(basename -- "$ROOT_DIR")"
    name="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]+/-/g; s/^[^a-z0-9]+//; s/[^a-z0-9]+$//')"
    [[ -n "$name" ]] || name=chenxing-auth
    printf '%s' "$name"
}

resolve_legacy_project() {
    # fail closed: never guess a project and silently create empty volumes.
    local candidate volume project missing=0
    candidate="$(legacy_project_name)"
    for volume in chenxing-keys chenxing-postgres chenxing-redis; do
        if ! docker volume inspect "${candidate}_${volume}" >/dev/null 2>&1; then
            missing=1
            break
        fi
        project="$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}' "${candidate}_${volume}" 2>/dev/null || true)"
        if [[ "$project" != "$candidate" ]]; then
            missing=1
            break
        fi
    done
    if [[ "$missing" == 0 ]]; then
        printf '%s' "$candidate"
        return 0
    fi

    printf 'Cannot identify the legacy Compose project for %s. Existing volume candidates:\n' "$ROOT_DIR" >&2
    docker volume ls --format '{{.Name}}' \
        | while IFS= read -r volume; do
            project="$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}' "$volume" 2>/dev/null || true)"
            [[ -n "$project" ]] && printf '  %s (%s)\n' "$volume" "$project" >&2
        done
    printf '%s\n' 'Set COMPOSE_PROJECT_NAME in .env to the original project and retry; refusing to create new volumes.' >&2
    exit 1
}

validate_issuer() {
    if [[ -z "$APP_ISSUER" ]]; then
        EXPECTED_COOKIE_SECURE=true
        return 0
    fi
    if [[ "$APP_ISSUER" =~ ^https://[^/[:space:]?#@]+$ ]]; then
        EXPECTED_COOKIE_SECURE=true
        return 0
    fi
    if [[ "${CHENXING_ALLOW_LOOPBACK_HTTP:-false}" == "true" \
        && "$APP_ISSUER" =~ ^http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?$ ]]; then
        EXPECTED_COOKIE_SECURE=false
        return 0
    fi
    printf '%s\n' 'APP_ISSUER must be a public HTTPS URL; only explicitly enabled loopback HTTP is allowed.' >&2
    exit 1
}

secure_env_file
if [[ -e .env ]]; then
    printf '%s\n' 'Using existing .env; secrets will not be replaced.'
    # APP_ISSUER is read only for older deployments. New deployments configure
    # the runtime issuer through the Owner settings API after bootstrap.
    APP_ISSUER="$(read_env_value APP_ISSUER)"
    COOKIE_SECURE="$(read_env_value COOKIE_SECURE)"
    AUTH_ENCRYPTION_KEY="$(read_env_value AUTH_ENCRYPTION_KEY)"
    ensure_env_value REDIS_NAMESPACE legacy
    if [[ -z "$(read_env_value COMPOSE_PROJECT_NAME)" ]]; then
        legacy_project="$(resolve_legacy_project)" || exit 1
        ensure_env_value COMPOSE_PROJECT_NAME "$legacy_project"
    fi
    if [[ -n "$AUTH_ENCRYPTION_KEY" ]]; then
        ensure_env_value AUTH_ENCRYPTION_KEYS "kid=active:${AUTH_ENCRYPTION_KEY}"
    fi
else
    APP_ISSUER=""
    if ! command -v openssl >/dev/null 2>&1; then
        printf '%s\n' 'openssl is required to generate deployment secrets.' >&2
        exit 1
    fi

    APP_PORT="${CHENXING_PORT:-3000}"
    POSTGRES_DB="${POSTGRES_DB:-chenxing_auth}"
    POSTGRES_USER="${POSTGRES_USER:-chenxing}"
    POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(openssl rand -hex 32)}"
    POSTGRES_RUNTIME_USER="${POSTGRES_RUNTIME_USER:-chenxing_runtime}"
    POSTGRES_RUNTIME_PASSWORD="${POSTGRES_RUNTIME_PASSWORD:-$(generate_secret)}"
    ADMIN_TOKEN="${ADMIN_TOKEN:-$(openssl rand -hex 32)}"
    AUTH_ENCRYPTION_KEY="${AUTH_ENCRYPTION_KEY:-$(openssl rand -base64 32)}"
    REDIS_NAMESPACE="${REDIS_NAMESPACE:-cx-$(openssl rand -hex 16)}"
    COOKIE_SECURE="${COOKIE_SECURE:-true}"

    umask 077
    cat > .env <<EOF
COMPOSE_PROJECT_NAME=chenxing-auth
APP_HOST=0.0.0.0
APP_PORT=${APP_PORT}
ADMIN_TOKEN=${ADMIN_TOKEN}
AUTH_ENCRYPTION_KEY=${AUTH_ENCRYPTION_KEY}
AUTH_ENCRYPTION_KEYS=kid=active:${AUTH_ENCRYPTION_KEY}
AUTH_ENCRYPTION_ACTIVE_KID=active
KEY_DIRECTORY=/var/lib/chenxing-auth/keys
KEY_ROTATION_GRACE_SECONDS=${KEY_ROTATION_GRACE_SECONDS:-604800}
COOKIE_SECURE=${COOKIE_SECURE}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_RUNTIME_USER=${POSTGRES_RUNTIME_USER}
POSTGRES_RUNTIME_PASSWORD=${POSTGRES_RUNTIME_PASSWORD}
SESSION_TTL_SECONDS=${SESSION_TTL_SECONDS:-1209600}
REDIS_NAMESPACE=${REDIS_NAMESPACE}
AUDIT_ARCHIVE_ENABLED=${AUDIT_ARCHIVE_ENABLED:-false}
AUDIT_RETENTION_DAYS=${AUDIT_RETENTION_DAYS:-2555}
RUST_LOG=${RUST_LOG:-chenxing_auth=info,tower_http=info}
EOF
    chmod 600 -- .env
    printf '%s\n' 'Created .env with generated secrets. Keep this file private.'
fi

POSTGRES_DB="$(read_env_value POSTGRES_DB)"
POSTGRES_USER="$(read_env_value POSTGRES_USER)"
POSTGRES_PASSWORD="$(read_env_value POSTGRES_PASSWORD)"
POSTGRES_RUNTIME_USER="$(read_env_value POSTGRES_RUNTIME_USER)"
POSTGRES_RUNTIME_PASSWORD="$(read_env_value POSTGRES_RUNTIME_PASSWORD)"
if [[ -z "$POSTGRES_RUNTIME_USER" ]]; then
    POSTGRES_RUNTIME_USER="chenxing_runtime"
    ensure_env_value POSTGRES_RUNTIME_USER "$POSTGRES_RUNTIME_USER"
fi
if [[ -z "$POSTGRES_RUNTIME_PASSWORD" ]]; then
    POSTGRES_RUNTIME_PASSWORD="$(generate_secret)"
    ensure_env_value POSTGRES_RUNTIME_PASSWORD "$POSTGRES_RUNTIME_PASSWORD"
fi
[[ -n "$POSTGRES_DB" && -n "$POSTGRES_USER" && -n "$POSTGRES_PASSWORD" ]] || {
    printf '%s\n' '.env is missing PostgreSQL migration credentials.' >&2
    exit 1
}
set_env_value DATABASE_URL \
    "$(database_url "$POSTGRES_RUNTIME_USER" "$POSTGRES_RUNTIME_PASSWORD" "$POSTGRES_DB")"
set_env_value MIGRATION_DATABASE_URL \
    "$(database_url "$POSTGRES_USER" "$POSTGRES_PASSWORD" "$POSTGRES_DB")"

validate_issuer
if [[ -z "$COOKIE_SECURE" ]]; then
    COOKIE_SECURE="$EXPECTED_COOKIE_SECURE"
    ensure_env_value COOKIE_SECURE "$COOKIE_SECURE"
fi
if [[ -n "$APP_ISSUER" && "$COOKIE_SECURE" != "$EXPECTED_COOKIE_SECURE" ]]; then
    printf 'COOKIE_SECURE must be %s for issuer %s.\n' "$EXPECTED_COOKIE_SECURE" "$APP_ISSUER" >&2
    exit 1
fi

if ! docker compose --env-file .env -f docker-compose.prod.yml config >/dev/null; then
    printf '%s\n' 'The production Compose configuration is invalid. Check .env and try again.' >&2
    exit 1
fi

docker compose --env-file .env -f docker-compose.prod.yml up -d postgres redis
for attempt in $(seq 1 30); do
    if docker compose --env-file .env -f docker-compose.prod.yml \
        exec -T postgres pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
if ! docker compose --env-file .env -f docker-compose.prod.yml run --rm --build migrate; then
    printf '%s\n' 'Database migration failed. This release uses a fresh SQLx baseline and does not roll old schemas forward automatically.' >&2
    printf '%s\n' 'Back up the database and recreate the development database, or follow an approved production data migration procedure, before retrying.' >&2
    exit 1
fi
docker compose --env-file .env -f docker-compose.prod.yml up -d --build app

HOST_PORT="$(docker compose --env-file .env -f docker-compose.prod.yml port app 3000 | awk -F: '{print $NF}')"
if [[ -z "$HOST_PORT" ]]; then
    printf '%s\n' 'Could not determine the published application port.' >&2
    exit 1
fi

ready=false
for attempt in $(seq 1 30); do
    if curl --fail --silent --max-time 5 "http://127.0.0.1:${HOST_PORT}/health/ready" >/dev/null 2>&1; then
        printf '辰星认证中枢 is ready on port %s\n' "$HOST_PORT"
        ready=true
        break
    fi
    sleep 2
done

if [[ "$ready" != true ]]; then
    docker compose --env-file .env -f docker-compose.prod.yml ps
    docker compose --env-file .env -f docker-compose.prod.yml logs app
    printf '%s\n' 'Deployment started but the readiness check did not become ready in time.' >&2
    exit 1
fi

if [[ -n "$APP_ISSUER" ]]; then
    DISCOVERY_JSON="$(curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${HOST_PORT}/.well-known/openid-configuration")" || {
        printf '%s\n' 'Readiness succeeded but OpenID Connect discovery could not be fetched.' >&2
        exit 1
    }
    for marker in \
        "\"issuer\":\"${APP_ISSUER}\"" \
        "\"authorization_endpoint\":\"${APP_ISSUER}/oauth/authorize\"" \
        "\"token_endpoint\":\"${APP_ISSUER}/oauth/token\"" \
        "\"jwks_uri\":\"${APP_ISSUER}/.well-known/jwks.json\""; do
        if [[ "$DISCOVERY_JSON" != *"$marker"* ]]; then
            printf 'OpenID discovery does not match APP_ISSUER: %s\n' "$APP_ISSUER" >&2
            exit 1
        fi
    done
    printf '%s\n' 'OpenID Connect discovery matches the configured issuer.'
else
    printf '%s\n' 'No legacy APP_ISSUER was read; new deployments do not require that environment variable.'
    printf '%s\n' 'If PostgreSQL has no Issuer, the service is running in protected bootstrap mode: initialize the ID=1 Owner first, then set the fixed Issuer in Owner settings; it hot-reloads from PostgreSQL app_settings.'
fi
exit 0
