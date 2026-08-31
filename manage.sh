#!/usr/bin/env bash
set -Eeuo pipefail

DEFAULT_POSTGRES_IMAGE="postgres:16-alpine"
DEFAULT_REDIS_IMAGE="redis:7-alpine"
DEFAULT_PORT="3000"
RELEASE_REPOSITORY="${CHENXING_RELEASE_REPOSITORY:-chenming0v0/chenxing-auth}"
RELEASE_MANIFEST_NAME="chenxing-auth-release.env"
RELEASE_SCRIPT_NAME="chenxing-auth-manage.sh"
MANAGER_NAME="manage.sh"
DEBUG_MODE=false
MODE=deploy
PREPARE_ONLY=false
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
INSTALL_DIR="$(dirname -- "$SCRIPT_PATH")"
if [[ "${CHENXING_BOOTSTRAP_TEMP:-}" == 1 && -n "${CHENXING_INSTALL_DIR:-}" ]]; then
    # 升级时本脚本是从 .release.* 暂存目录里执行的已验证副本，安装目录不能由脚本
    # 自身位置推导，必须沿用原部署目录；否则 .env 和 compose.yml 会写进临时目录，
    # 升级会当成全新安装重新生成数据库密码与加密密钥，并把它们随暂存目录丢弃。
    INSTALL_DIR="${CHENXING_INSTALL_DIR}"
fi
RELEASE_VERSION="${CHENXING_RELEASE_VERSION:-}"
RELEASE_MANIFEST_FILE="${CHENXING_RELEASE_MANIFEST_FILE:-}"
RELEASE_FETCH_DIR=""
if [[ "${CHENXING_BOOTSTRAP_TEMP:-}" == 1 ]]; then
    RELEASE_FETCH_DIR="${CHENXING_RELEASE_FETCH_DIR:-}"
fi
RELEASE_MANIFEST_SHA256="${CHENXING_RELEASE_MANIFEST_SHA256:-}"
RELEASE_SCRIPT_SHA256="${CHENXING_SCRIPT_SHA256:-}"
RELEASE_IMAGE=""
RELEASE_IMAGE_DIGEST=""

stage() {
    printf '\n==> %s\n' "$1"
}

fail() {
    cleanup_release_artifacts || true
    printf '\n安装失败: %s\n' "$1" >&2
    exit 1
}

cleanup_release_artifacts() {
    if [[ "$RELEASE_FETCH_DIR" == "$INSTALL_DIR"/.release.* && -d "$RELEASE_FETCH_DIR" ]]; then
        rm -rf -- "$RELEASE_FETCH_DIR"
    fi
}

on_error() {
    local status=$?
    printf '\n安装在第 %s 行失败，退出码 %s。Docker 的错误输出已保留在上方。\n' \
        "${BASH_LINENO[0]:-unknown}" "$status" >&2
    if [[ "$DEBUG_MODE" == true && -f "${COMPOSE_FILE:-}" ]] && command_exists docker; then
        report_application_diagnostics || true
    fi
    cleanup_release_artifacts || true
    exit "$status"
}
trap on_error ERR

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

secure_env_file() {
    if [[ -e "$ENV_FILE" || -L "$ENV_FILE" ]]; then
        if [[ -L "$ENV_FILE" ]]; then
            fail ".env 不能是符号链接。"
        fi
        [[ -f "$ENV_FILE" ]] || fail ".env 必须是普通文件。"
        chmod 600 -- "$ENV_FILE"
    fi
}

install_manager() {
    local manager_file="$INSTALL_DIR/$MANAGER_NAME"
    if [[ "$SCRIPT_PATH" != "$manager_file" ]]; then
        install -m 700 -- "$SCRIPT_PATH" "$manager_file"
    else
        chmod 700 -- "$manager_file"
    fi
}

validate_release_version() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]
}

release_asset_url() {
    local version="$1" asset="$2"
    printf 'https://github.com/%s/releases/download/%s/%s' \
        "$RELEASE_REPOSITORY" "$version" "$asset"
}

download_release_asset() {
    local url="$1" output="$2"
    if command_exists curl; then
        if ! curl --fail --silent --show-error --location --retry 3 \
            --connect-timeout 10 -o "$output" "$url"; then
            fail "下载发布资产失败；现有部署未改变。"
        fi
    elif command_exists wget; then
        if ! wget --quiet --show-progress --tries=3 --timeout=10 \
            -O "$output" "$url"; then
            fail "下载发布资产失败；现有部署未改变。"
        fi
    else
        fail "升级需要 curl 或 wget。"
    fi
}

load_release_manifest() {
    local line key value
    declare -A values=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        [[ "$line" == *=* ]] || fail "发布清单格式无效。"
        key="${line%%=*}"
        value="${line#*=}"
        [[ "$key" =~ ^[a-z0-9_]+$ ]] || fail "发布清单字段名无效。"
        [[ -z "${values[$key]+present}" ]] || fail "发布清单包含重复字段：$key。"
        values["$key"]="$value"
    done < "$RELEASE_MANIFEST_FILE"

    for key in schema version image image_digest script script_sha256; do
        [[ -n "${values[$key]+present}" ]] || fail "发布清单缺少字段：$key。"
    done
    [[ "${values[schema]}" == 1 ]] || fail "不支持的发布清单版本。"
    [[ "${values[version]}" == "$RELEASE_VERSION" ]] || fail "发布清单版本与请求版本不一致。"
    [[ "${values[script]}" == "$RELEASE_SCRIPT_NAME" ]] || fail "发布清单脚本资产名称不受支持。"
    [[ "${values[image_digest]}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "发布清单中的镜像 digest 无效。"
    [[ "${values[script_sha256]}" =~ ^[0-9a-f]{64}$ ]] || fail "发布清单中的脚本摘要无效。"
    [[ "${values[image]}" == "ghcr.io/${RELEASE_REPOSITORY}:${RELEASE_VERSION}@${values[image_digest]}" ]] \
        || fail "发布清单中的镜像未绑定到同一版本。"

    RELEASE_IMAGE="${values[image]}"
    RELEASE_IMAGE_DIGEST="${values[image_digest]}"
    RELEASE_SCRIPT_SHA256="${values[script_sha256]}"
}

verify_release_asset_checksum() {
    local checksums_file="$1" asset="$2" actual expected
    expected="$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1; exit }' "$checksums_file")"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "SHA256SUMS 缺少发布资产：$asset。"
    actual="$(sha256sum "$RELEASE_FETCH_DIR/$asset" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || fail "发布资产摘要校验失败：$asset。"
    printf '%s' "$actual"
}

prepare_release_manifest() {
    command_exists sha256sum || fail "缺少 sha256sum，无法验证发布资产。"
    validate_release_version "$RELEASE_VERSION" || fail "发布版本必须是 vX.Y.Z 格式。"

    if [[ -z "$RELEASE_MANIFEST_FILE" ]]; then
        RELEASE_FETCH_DIR="$(mktemp -d "$INSTALL_DIR/.release.XXXXXX")"
        RELEASE_MANIFEST_FILE="$RELEASE_FETCH_DIR/$RELEASE_MANIFEST_NAME"
        download_release_asset \
            "$(release_asset_url "$RELEASE_VERSION" "$RELEASE_MANIFEST_NAME")" \
            "$RELEASE_MANIFEST_FILE"
        download_release_asset \
            "$(release_asset_url "$RELEASE_VERSION" SHA256SUMS)" \
            "$RELEASE_FETCH_DIR/SHA256SUMS"
        RELEASE_MANIFEST_SHA256="$(verify_release_asset_checksum "$RELEASE_FETCH_DIR/SHA256SUMS" "$RELEASE_MANIFEST_NAME")"
    else
        [[ -f "$RELEASE_MANIFEST_FILE" && ! -L "$RELEASE_MANIFEST_FILE" ]] \
            || fail "发布清单必须是普通文件。"
        RELEASE_MANIFEST_SHA256="$(sha256sum "$RELEASE_MANIFEST_FILE" | awk '{print $1}')"
    fi
    load_release_manifest
}

fetch_verified_manager() {
    local temp_file actual
    [[ -n "$RELEASE_FETCH_DIR" ]] || RELEASE_FETCH_DIR="$(mktemp -d "$INSTALL_DIR/.release.XXXXXX")"
    temp_file="$RELEASE_FETCH_DIR/$RELEASE_SCRIPT_NAME"
    download_release_asset \
        "$(release_asset_url "$RELEASE_VERSION" "$RELEASE_SCRIPT_NAME")" \
        "$temp_file"
    if [[ -f "$RELEASE_FETCH_DIR/SHA256SUMS" ]]; then
        verify_release_asset_checksum "$RELEASE_FETCH_DIR/SHA256SUMS" "$RELEASE_SCRIPT_NAME" >/dev/null
    fi
    actual="$(sha256sum "$temp_file" | awk '{print $1}')"
    [[ "$actual" == "$RELEASE_SCRIPT_SHA256" ]] || fail "升级脚本摘要与发布清单不一致。"
    bash -n "$temp_file" || fail "下载的升级脚本语法校验失败。"
    printf '%s' "$temp_file"
}

read_env_value() {
    local key="$1" line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        if [[ "$line" == "${key}="* ]]; then
            printf '%s' "${line#*=}"
            return 0
        fi
    done < "$ENV_FILE"
    return 0
}

env_has_key() {
    local key="$1" line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" == "${key}="* ]] && return 0
    done < "$ENV_FILE"
    return 1
}

append_env_default() {
    local key="$1" value="$2"
    if ! env_has_key "$key"; then
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

ensure_env_value() {
    local key="$1" value="$2" temp
    if ! env_has_key "$key"; then
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
        return 0
    fi
    [[ -n "$(read_env_value "$key")" ]] && return 0

    # Replace an existing empty assignment in place. Appending a duplicate
    # key leaves read_env_value seeing the stale empty value on upgrades.
    temp="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
    awk -v key="$key" -v value="$value" '
        BEGIN { prefix = key "="; replaced = 0 }
        index($0, prefix) == 1 {
            if (!replaced) { print prefix value; replaced = 1 }
            next
        }
        { print }
        END { if (!replaced) print prefix value }
    ' "$ENV_FILE" > "$temp"
    chmod 600 "$temp"
    mv -f "$temp" "$ENV_FILE"
}

valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 ))
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

set_env_value() {
    local key="$1" value="$2" temp
    temp="$(mktemp "${ENV_FILE}.tmp.XXXXXX")"
    awk -v key="$key" -v value="$value" '
        BEGIN { prefix = key "="; replaced = 0 }
        index($0, prefix) == 1 {
            if (!replaced) { print prefix value; replaced = 1 }
            next
        }
        { print }
        END { if (!replaced) print prefix value }
    ' "$ENV_FILE" > "$temp"
    chmod 600 "$temp"
    mv -f "$temp" "$ENV_FILE"
}

persist_release_lock() {
    set_env_value CHENXING_RELEASE_VERSION "$RELEASE_VERSION"
    set_env_value CHENXING_RELEASE_MANIFEST_SHA256 "$RELEASE_MANIFEST_SHA256"
    set_env_value CHENXING_SCRIPT_SHA256 "$RELEASE_SCRIPT_SHA256"
    set_env_value CHENXING_IMAGE "$RELEASE_IMAGE"
}

default_database_urls() {
    local runtime_user runtime_password migration_user migration_password database
    runtime_user="$(url_encode "$POSTGRES_RUNTIME_USER")"
    runtime_password="$(url_encode "$POSTGRES_RUNTIME_PASSWORD")"
    migration_user="$(url_encode "$POSTGRES_USER")"
    migration_password="$(url_encode "$POSTGRES_PASSWORD")"
    database="$(url_encode "$POSTGRES_DB")"
    DATABASE_URL="postgres://${runtime_user}:${runtime_password}@postgres:5432/${database}"
    MIGRATION_DATABASE_URL="postgres://${migration_user}:${migration_password}@postgres:5432/${database}"
}

generate_env() {
    local port="$1" auth_encryption_key
    auth_encryption_key="$(openssl rand -base64 32)"
    umask 077
    cat > "$ENV_FILE" <<EOF
COMPOSE_PROJECT_NAME=chenxing-auth
CHENXING_RELEASE_VERSION=${RELEASE_VERSION}
CHENXING_RELEASE_MANIFEST_SHA256=${RELEASE_MANIFEST_SHA256}
CHENXING_SCRIPT_SHA256=${RELEASE_SCRIPT_SHA256}
CHENXING_IMAGE=${CHENXING_IMAGE}
POSTGRES_IMAGE=${POSTGRES_IMAGE}
REDIS_IMAGE=${REDIS_IMAGE}
REDIS_NAMESPACE=cx-$(openssl rand -hex 16)
APP_HOST=0.0.0.0
APP_PORT=${port}
ADMIN_TOKEN=$(openssl rand -hex 32)
AUTH_ENCRYPTION_KEY=${auth_encryption_key}
AUTH_ENCRYPTION_KEYS=kid=active:${auth_encryption_key}
AUTH_ENCRYPTION_ACTIVE_KID=active
KEY_DIRECTORY=/var/lib/chenxing-auth/keys
KEY_ROTATION_GRACE_SECONDS=604800
KEY_ROTATION_SKEW_ALLOWANCE_SECONDS=3600
COOKIE_SECURE=true
POSTGRES_DB=chenxing_auth
POSTGRES_USER=chenxing
POSTGRES_PASSWORD=$(openssl rand -hex 32)
POSTGRES_RUNTIME_USER=chenxing_runtime
POSTGRES_RUNTIME_PASSWORD=$(openssl rand -hex 32)
SESSION_TTL_SECONDS=1209600
AUDIT_ARCHIVE_ENABLED=false
AUDIT_RETENTION_DAYS=2555
RUST_LOG=chenxing_auth=info,tower_http=info
EOF
    chmod 600 -- "$ENV_FILE"
}

write_compose() {
    local temp_file
    umask 022
    temp_file="$(mktemp "${COMPOSE_FILE}.tmp.XXXXXX")"
    trap 'rm -f -- "${temp_file:-}"' RETURN
    cat > "$temp_file" <<'YAML'
# Generated by the Chenxing remote installer. Persistent data lives in named volumes.
x-runtime-environment: &runtime-environment
  APP_HOST: 0.0.0.0
  APP_PORT: 3000
  APP_ISSUER: ${APP_ISSUER-}
  ADMIN_TOKEN: ${ADMIN_TOKEN-}
  AUTH_ENCRYPTION_KEY: ${AUTH_ENCRYPTION_KEY:?set AUTH_ENCRYPTION_KEY}
  AUTH_ENCRYPTION_KEYS: ${AUTH_ENCRYPTION_KEYS:-kid=active:${AUTH_ENCRYPTION_KEY}}
  AUTH_ENCRYPTION_ACTIVE_KID: ${AUTH_ENCRYPTION_ACTIVE_KID:-active}
  KEY_DIRECTORY: /var/lib/chenxing-auth/keys
  KEY_ROTATION_GRACE_SECONDS: ${KEY_ROTATION_GRACE_SECONDS:-604800}
  KEY_ROTATION_SKEW_ALLOWANCE_SECONDS: ${KEY_ROTATION_SKEW_ALLOWANCE_SECONDS:-3600}
  KEY_ACTIVATION_DELAY_SECONDS: ${KEY_ACTIVATION_DELAY_SECONDS:-65}
  COOKIE_SECURE: ${COOKIE_SECURE:-true}
  OAUTH_SESSION_HEADER_ENABLED: ${OAUTH_SESSION_HEADER_ENABLED:-false}
  SESSION_TOKEN_RESPONSE_ENABLED: ${SESSION_TOKEN_RESPONSE_ENABLED:-false}
  OAUTH_PROVIDER_LOOPBACK_ENABLED: ${OAUTH_PROVIDER_LOOPBACK_ENABLED:-false}
  WEB_DIST_DIR: /usr/local/share/chenxing-auth/web/dist
  SESSION_TTL_SECONDS: ${SESSION_TTL_SECONDS:-1209600}
  SESSION_IDLE_TIMEOUT_SECONDS: ${SESSION_IDLE_TIMEOUT_SECONDS:-1209600}
  SESSION_MAX_CONCURRENT_SESSIONS: ${SESSION_MAX_CONCURRENT_SESSIONS:-5}
  ACCESS_TOKEN_TTL_SECONDS: ${ACCESS_TOKEN_TTL_SECONDS:-3600}
  ID_TOKEN_TTL_SECONDS: ${ID_TOKEN_TTL_SECONDS:-3600}
  RUST_LOG: ${RUST_LOG:-chenxing_auth=info,tower_http=info}
  AUTH_LIMITER_FAILURE_POLICY: ${AUTH_LIMITER_FAILURE_POLICY:-fail-closed}
  AUTH_LIMITER_MISSING_SOURCE_IP: ${AUTH_LIMITER_MISSING_SOURCE_IP:-reject}
  TRUSTED_PROXIES: ${TRUSTED_PROXIES-}
  WEBAUTHN_RP_ID: ${WEBAUTHN_RP_ID-}
  WEBAUTHN_ORIGIN: ${WEBAUTHN_ORIGIN-}
  REQUEST_TIMEOUT_SECONDS: ${REQUEST_TIMEOUT_SECONDS:-30}
  HTTP_GRACEFUL_DRAIN_SECONDS: ${HTTP_GRACEFUL_DRAIN_SECONDS:-15}
  OAUTH_CLIENT_MAX_REDIRECT_URIS: ${OAUTH_CLIENT_MAX_REDIRECT_URIS:-10}
  OAUTH_CLIENT_MAX_REDIRECT_URI_LENGTH: ${OAUTH_CLIENT_MAX_REDIRECT_URI_LENGTH:-2048}
  OAUTH_CLIENT_MAX_SCOPES: ${OAUTH_CLIENT_MAX_SCOPES:-32}
  OAUTH_CLIENT_MAX_SCOPE_LENGTH: ${OAUTH_CLIENT_MAX_SCOPE_LENGTH:-64}
  OAUTH_CLIENT_ALLOWED_SCOPES: ${OAUTH_CLIENT_ALLOWED_SCOPES:-openid,profile,email}
  UNAUTHENTICATED_SOURCE_QPS: ${UNAUTHENTICATED_SOURCE_QPS:-30}
  AUTHORIZATION_CODE_TTL_SECONDS: ${AUTHORIZATION_CODE_TTL_SECONDS:-300}
  PENDING_REQUEST_TTL_SECONDS: ${PENDING_REQUEST_TTL_SECONDS:-600}
  MAX_PENDING_REQUESTS_PER_CLIENT: ${MAX_PENDING_REQUESTS_PER_CLIENT:-20}
  MAX_PENDING_REQUESTS_GLOBAL: ${MAX_PENDING_REQUESTS_GLOBAL:-1000}
  AUTH_FAILURE_WINDOW_SECONDS: ${AUTH_FAILURE_WINDOW_SECONDS:-900}
  ACCOUNT_FAILURE_LIMIT: ${ACCOUNT_FAILURE_LIMIT:-10}
  IP_FAILURE_LIMIT: ${IP_FAILURE_LIMIT:-30}
  TOTP_TICKET_FAILURE_LIMIT: ${TOTP_TICKET_FAILURE_LIMIT:-5}
  EXTERNAL_LOGIN_STATE_TTL_SECONDS: ${EXTERNAL_LOGIN_STATE_TTL_SECONDS:-600}
  EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS: ${EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS:-60}
  EXTERNAL_LOGIN_STATE_RATE_LIMIT: ${EXTERNAL_LOGIN_STATE_RATE_LIMIT:-30}
  EXTERNAL_LOGIN_STATE_MAX_PENDING: ${EXTERNAL_LOGIN_STATE_MAX_PENDING:-10000}
  DB_MAX_CONNECTIONS: ${DB_MAX_CONNECTIONS:-10}
  DB_ACQUIRE_TIMEOUT_SECONDS: ${DB_ACQUIRE_TIMEOUT_SECONDS:-5}
  DB_IDLE_TIMEOUT_SECONDS: ${DB_IDLE_TIMEOUT_SECONDS:-600}
  DB_MAX_LIFETIME_SECONDS: ${DB_MAX_LIFETIME_SECONDS:-1800}
  DB_STATEMENT_TIMEOUT_MS: ${DB_STATEMENT_TIMEOUT_MS:-5000}
  AUDIT_ARCHIVE_ENABLED: ${AUDIT_ARCHIVE_ENABLED:-false}
  AUDIT_RETENTION_DAYS: ${AUDIT_RETENTION_DAYS:-2555}
  AUDIT_ROLE_SEPARATION: ${AUDIT_ROLE_SEPARATION:-require}
  MIGRATION_MANAGE_RUNTIME_PASSWORD: ${MIGRATION_MANAGE_RUNTIME_PASSWORD:-true}
  DATABASE_URL: ${DATABASE_URL:?set DATABASE_URL}
  REDIS_URL: redis://redis:6379
  REDIS_NAMESPACE: ${REDIS_NAMESPACE:?set REDIS_NAMESPACE to a unique non-empty value}

services:
  app:
    image: ${CHENXING_IMAGE}
    restart: unless-stopped
    environment:
      <<: *runtime-environment
    ports:
      - "${APP_PORT}:3000"
    volumes:
      - chenxing-keys:/var/lib/chenxing-auth/keys
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      migrate:
        condition: service_completed_successfully
    healthcheck:
      test: ["CMD", "curl", "--fail", "http://127.0.0.1:3000/health/ready"]
      interval: 10s
      timeout: 5s
      retries: 12

  migrate:
    image: ${CHENXING_IMAGE}
    command: ["migrate"]
    environment:
      <<: *runtime-environment
      MIGRATION_DATABASE_URL: ${MIGRATION_DATABASE_URL:?set MIGRATION_DATABASE_URL}
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  postgres:
    image: ${POSTGRES_IMAGE}
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - chenxing-postgres:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 12

  redis:
    image: ${REDIS_IMAGE}
    restart: unless-stopped
    # Authorization-code consumption and Refresh Token tombstones/revocations are
    # authoritative here. A successful write must survive a process or host crash;
    # a truncated AOF must stop recovery instead of loading an older credential state.
    command:
      - redis-server
      - --appendonly
      - "yes"
      - --appendfsync
      - always
      - --no-appendfsync-on-rewrite
      - "no"
      - --aof-load-truncated
      - "no"
      - --aof-use-rdb-preamble
      - "yes"
      - --save
      - ""
      - --dir
      - /data
      - --appenddirname
      - appendonlydir
      - --appendfilename
      - appendonly.aof
    volumes:
      - chenxing-redis:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 12

volumes:
  chenxing-keys:
  chenxing-postgres:
  chenxing-redis:
YAML
    chmod 644 -- "$temp_file"
    mv -f -- "$temp_file" "$COMPOSE_FILE"
    trap - RETURN
}

compose() {
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

wait_for_postgres() {
    local attempt
    printf '等待 PostgreSQL 就绪'
    for attempt in $(seq 1 60); do
        if compose exec -T postgres pg_isready \
            -U "$POSTGRES_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; then
            printf ' 完成\n'
            return 0
        fi
        printf '.'
        sleep 2
    done
    printf '\n' >&2
    return 1
}

wait_for_application() {
    local attempt
    printf '等待辰星认证中枢就绪'
    for attempt in $(seq 1 60); do
        if compose exec -T app curl --fail --silent --max-time 5 \
            http://127.0.0.1:3000/health/ready >/dev/null 2>&1; then
            printf ' 完成\n'
            return 0
        fi
        printf '.'
        sleep 2
    done
    printf '\n' >&2
    return 1
}

report_application_diagnostics() {
    local app_container_id health_status

    printf '\nCompose 服务状态:\n' >&2
    compose ps >&2 || true

    printf '\n应用容器 health 状态:\n' >&2
    app_container_id="$(compose ps -q app 2>/dev/null || true)"
    if [[ -z "$app_container_id" ]]; then
        printf '%s\n' 'unavailable（未找到 app 容器）' >&2
    else
        health_status="$(
            docker inspect --format \
                '{{if .State.Health}}{{.State.Health.Status}}{{else}}unavailable{{end}}' \
                "$app_container_id" 2>/dev/null || true
        )"
        printf '%s\n' "${health_status:-unavailable}" >&2
    fi

    printf '\n应用日志:\n' >&2
    compose logs --no-color --tail=200 app >&2 || true
}

report_debug_context() {
    [[ "$DEBUG_MODE" == true ]] || return 0
    printf '\n调试信息（不包含 .env 和 Compose 展开配置）:\n' >&2
    printf '安装目录: %s\n' "$INSTALL_DIR" >&2
    printf 'Compose 文件: %s\n' "$COMPOSE_FILE" >&2
    printf '应用镜像: %s\n' "$CHENXING_IMAGE" >&2
    docker version --format 'Docker Server: {{.Server.Version}}' >&2 || true
    docker compose version >&2 || true
    compose ps -a >&2 || true
    compose images >&2 || true
    printf '\n最近容器日志（最多 200 行/服务）:\n' >&2
    compose logs --no-color --tail=200 app migrate postgres redis >&2 || true
}

IMAGE_OVERRIDE="${CHENXING_IMAGE:-}"
POSTGRES_IMAGE_OVERRIDE="${POSTGRES_IMAGE:-}"
REDIS_IMAGE_OVERRIDE="${REDIS_IMAGE:-}"
ENV_FILE="${INSTALL_DIR}/.env"
COMPOSE_FILE="${INSTALL_DIR}/compose.yml"

arguments=("$@")
argument_index=0
while (( argument_index < ${#arguments[@]} )); do
    argument="${arguments[$argument_index]}"
    case "$argument" in
        --debug)
            DEBUG_MODE=true
            ;;
        --apply)
            MODE=apply
            ;;
        --prepare-only)
            PREPARE_ONLY=true
            ;;
        --release-version)
            (( argument_index += 1 ))
            (( argument_index < ${#arguments[@]} )) || fail "--release-version 缺少版本值。"
            RELEASE_VERSION="${arguments[$argument_index]}"
            ;;
        --release-version=*)
            RELEASE_VERSION="${argument#*=}"
            ;;
        *)
            fail "未知参数：$argument。支持 --debug、--prepare-only 和 --release-version=vX.Y.Z。"
            ;;
    esac
    (( argument_index += 1 ))
done

if [[ "${CHENXING_BOOTSTRAP_TEMP:-}" == 1 ]]; then
    trap 'rm -f -- "${BASH_SOURCE[0]}"; cleanup_release_artifacts' EXIT
fi

if [[ "$MODE" == deploy && "$PREPARE_ONLY" == false && -f "$ENV_FILE" ]]; then
    MODE=upgrade
fi

command_exists openssl || fail "缺少 openssl，无法生成部署密钥。"

if [[ "$MODE" == upgrade ]]; then
    RELEASE_VERSION="${RELEASE_VERSION:-$(read_env_value CHENXING_RELEASE_VERSION)}"
    [[ -n "$RELEASE_VERSION" ]] || fail "升级必须显式指定 --release-version=vX.Y.Z；不会自动跟随可变 latest。"
    if [[ "${CHENXING_BOOTSTRAP_TEMP:-}" != 1 ]]; then
        prepare_release_manifest
        latest_manager="$(fetch_verified_manager)"
        upgrade_arguments=(--apply --release-version="$RELEASE_VERSION")
        [[ "$DEBUG_MODE" == true ]] && upgrade_arguments+=(--debug)
        CHENXING_BOOTSTRAP_TEMP=1 \
        CHENXING_INSTALL_DIR="$INSTALL_DIR" \
        CHENXING_RELEASE_MANIFEST_FILE="$RELEASE_MANIFEST_FILE" \
        CHENXING_RELEASE_FETCH_DIR="$RELEASE_FETCH_DIR" \
        CHENXING_RELEASE_MANIFEST_SHA256="$RELEASE_MANIFEST_SHA256" \
        CHENXING_SCRIPT_SHA256="$RELEASE_SCRIPT_SHA256" \
        exec bash "$latest_manager" "${upgrade_arguments[@]}"
    fi
fi

if [[ -z "$RELEASE_VERSION" ]]; then
    fail "首次部署必须显式指定 --release-version=vX.Y.Z；不会使用可变镜像标签。"
fi
prepare_release_manifest

if [[ -n "$IMAGE_OVERRIDE" && "$IMAGE_OVERRIDE" != "$RELEASE_IMAGE" ]]; then
    fail "CHENXING_IMAGE 必须与发布清单中的不可变镜像完全一致。"
fi
CHENXING_IMAGE="$RELEASE_IMAGE"
POSTGRES_IMAGE="${POSTGRES_IMAGE_OVERRIDE:-$DEFAULT_POSTGRES_IMAGE}"
REDIS_IMAGE="${REDIS_IMAGE_OVERRIDE:-$DEFAULT_REDIS_IMAGE}"

stage "准备安装目录"
mkdir -p "$INSTALL_DIR"
printf '安装目录: %s\n' "$INSTALL_DIR"
secure_env_file

if [[ -e "$ENV_FILE" ]]; then
    printf '检测到已有 .env，将保留数据库密码、Token 和加密密钥。\n'
    append_env_default COMPOSE_PROJECT_NAME chenxing-auth
    append_env_default POSTGRES_IMAGE "$DEFAULT_POSTGRES_IMAGE"
    append_env_default REDIS_IMAGE "$DEFAULT_REDIS_IMAGE"
    append_env_default REDIS_NAMESPACE legacy
    # Older installs predate the least-privileged runtime database role. Add
    # only missing/empty values; never replace credentials already in use.
    ensure_env_value POSTGRES_RUNTIME_USER chenxing_runtime
    ensure_env_value POSTGRES_RUNTIME_PASSWORD "$(openssl rand -hex 32)"
    AUTH_ENCRYPTION_KEY="$(read_env_value AUTH_ENCRYPTION_KEY)"
    if [[ -n "$AUTH_ENCRYPTION_KEY" ]]; then
        ensure_env_value AUTH_ENCRYPTION_KEYS "kid=active:${AUTH_ENCRYPTION_KEY}"
    fi
    chmod 600 -- "$ENV_FILE"
else
    port="${CHENXING_PORT:-}"
    if [[ -z "$port" && -t 0 ]]; then
        read -r -p "请输入对外端口 [${DEFAULT_PORT}]: " port
    fi
    port="${port:-$DEFAULT_PORT}"
    valid_port "$port" || fail "端口必须是 1 到 65535 之间的整数。"
    generate_env "$port"
    printf '已生成 .env，权限为 0600。\n'
fi

write_compose

CHENXING_IMAGE="$RELEASE_IMAGE"
POSTGRES_IMAGE="${POSTGRES_IMAGE_OVERRIDE:-$(read_env_value POSTGRES_IMAGE)}"
REDIS_IMAGE="${REDIS_IMAGE_OVERRIDE:-$(read_env_value REDIS_IMAGE)}"
export CHENXING_IMAGE POSTGRES_IMAGE REDIS_IMAGE
APP_PORT="$(read_env_value APP_PORT)"
APP_ISSUER="$(read_env_value APP_ISSUER)"
POSTGRES_DB="$(read_env_value POSTGRES_DB)"
POSTGRES_USER="$(read_env_value POSTGRES_USER)"
POSTGRES_PASSWORD="$(read_env_value POSTGRES_PASSWORD)"
POSTGRES_RUNTIME_USER="$(read_env_value POSTGRES_RUNTIME_USER)"
POSTGRES_RUNTIME_PASSWORD="$(read_env_value POSTGRES_RUNTIME_PASSWORD)"
AUTH_ENCRYPTION_KEY="$(read_env_value AUTH_ENCRYPTION_KEY)"
default_database_urls
set_env_value DATABASE_URL "$DATABASE_URL"
set_env_value MIGRATION_DATABASE_URL "$MIGRATION_DATABASE_URL"

valid_port "$APP_PORT" || fail ".env 中的 APP_PORT 无效。"
[[ -n "$CHENXING_IMAGE" && "$CHENXING_IMAGE" != *[[:space:]]* ]] || fail "辰星镜像名称无效。"
[[ -n "$POSTGRES_IMAGE" && "$POSTGRES_IMAGE" != *[[:space:]]* ]] || fail "PostgreSQL 镜像名称无效。"
[[ -n "$REDIS_IMAGE" && "$REDIS_IMAGE" != *[[:space:]]* ]] || fail "Redis 镜像名称无效。"
[[ -n "$POSTGRES_DB" && -n "$POSTGRES_USER" ]] || fail ".env 缺少 PostgreSQL 配置。"
if ! normalized_auth_key="$(
    printf '%s' "$AUTH_ENCRYPTION_KEY" \
        | openssl base64 -d -A 2>/dev/null \
        | openssl base64 -A
)"; then
    fail ".env 中的 AUTH_ENCRYPTION_KEY 不是有效 Base64。"
fi
[[ "$normalized_auth_key" == "$AUTH_ENCRYPTION_KEY" ]] \
    || fail ".env 中的 AUTH_ENCRYPTION_KEY 必须使用规范的标准 Base64 编码。"
decoded_key_bytes="$(printf '%s' "$AUTH_ENCRYPTION_KEY" | openssl base64 -d -A | wc -c)"
[[ "$decoded_key_bytes" -eq 32 ]] || fail ".env 中的 AUTH_ENCRYPTION_KEY 必须是 Base64 编码的 32 字节密钥。"

if [[ "$PREPARE_ONLY" == true ]]; then
    persist_release_lock
    install_manager
    printf '已生成 %s 和 %s。\n' "$ENV_FILE" "$COMPOSE_FILE"
    cleanup_release_artifacts
    exit 0
fi

command_exists docker || fail "缺少 Docker Engine，请先安装 Docker。"
docker compose version >/dev/null 2>&1 || fail "缺少 Docker Compose v2 插件。"
docker info >/dev/null 2>&1 || fail "无法连接 Docker daemon；请启动 Docker 或使用有权限的账号运行。"

stage "校验 Compose 配置"
compose config --quiet
printf 'Compose 配置有效。\n'
report_debug_context

stage "拉取辰星认证中枢镜像"
printf '镜像: %s\n' "$CHENXING_IMAGE"
docker pull "$CHENXING_IMAGE"

stage "拉取 PostgreSQL 镜像"
printf '镜像: %s\n' "$POSTGRES_IMAGE"
docker pull "$POSTGRES_IMAGE"

stage "拉取 Redis 镜像"
printf '镜像: %s\n' "$REDIS_IMAGE"
docker pull "$REDIS_IMAGE"

stage "启动 PostgreSQL 和 Redis"
compose up -d postgres redis
wait_for_postgres || fail "PostgreSQL 未能在规定时间内就绪。"

stage "执行数据库迁移"
if ! compose run --rm migrate; then
    report_debug_context
    fail "数据库迁移失败；应用未更新。请修复错误后重新运行 bash $INSTALL_DIR/$MANAGER_NAME。"
fi

stage "启动辰星认证中枢"
compose up -d app
if ! wait_for_application; then
    report_application_diagnostics
    fail "应用未能在规定时间内就绪。"
fi

persist_release_lock
cleanup_release_artifacts

stage "部署完成"
install_manager
compose ps
report_debug_context
cat <<EOF

访问地址: http://服务器地址:${APP_PORT}
安装目录: ${INSTALL_DIR}

新生成的 .env 不包含 APP_ISSUER。数据库尚未设置 Issuer 时，服务运行在保护模式：
健康检查和静态前端保持可用；不存在 Owner 时可公开初始化首个、固定为 ID=1 的 Owner，
该 Owner 可以登录并进入管理设置。注册、普通用户创建、管理员/Owner 创建保持关闭；
只有依赖正式 Issuer 的 OAuth/OIDC、Discovery、JWKS 和外部登录路由关闭。

请先完成首个 Owner 初始化，再由 Owner 在管理设置中写入固定的 HTTPS Issuer。
写入会保存到 PostgreSQL app_settings，并在当前进程热更新；不能从请求 Host 或代理头推导。
ADMIN_TOKEN 保留为管理 API 的恢复通道（为空时仍遵守管理 API 的禁用规则）。
管理员 Token 和全部随机密钥只保存在 ${ENV_FILE}，请备份并保持私密。
EOF
if [[ -n "$APP_ISSUER" ]]; then
    printf '%s\n' '检测到旧环境中的 APP_ISSUER；它仅按兼容规则在数据库没有 Issuer 时导入，数据库设置优先。'
fi
