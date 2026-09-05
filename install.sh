#!/usr/bin/env bash
set -Eeuo pipefail

# 辰星认证中枢 · 首次安装脚本（由 manage.sh 下载并移交，不建议手动直接运行）
#
# 职责：解析发布版本 → 生成全部密钥写入 .env → 校验 Compose → 拉镜像 →
# 启动依赖 → 数据库迁移 → 启动应用 → 健康检查。升级请运行 bash ./manage.sh。

DEFAULT_POSTGRES_IMAGE="postgres:16-alpine"
DEFAULT_REDIS_IMAGE="redis:7-alpine"
DEFAULT_PORT="3000"
RELEASE_REPOSITORY="${CHENXING_RELEASE_REPOSITORY:-chenming0v0/chenxing-auth}"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
INSTALL_DIR="$(dirname -- "$SCRIPT_PATH")"
ENV_FILE="$INSTALL_DIR/.env"
COMPOSE_FILE="$INSTALL_DIR/compose.yml"
RELEASE_VERSION="${CHENXING_RELEASE_VERSION:-}"
PREPARE_ONLY=false
DEBUG_MODE=false

stage() {
    printf '\n==> %s\n' "$1"
}

fail() {
    printf '\n安装失败: %s\n' "$1" >&2
    exit 1
}

on_error() {
    local status=$?
    printf '\n安装在第 %s 行失败，退出码 %s。Docker 的错误输出已保留在上方。\n' \
        "${BASH_LINENO[0]:-unknown}" "$status" >&2
    if [[ "$DEBUG_MODE" == true && -f "$COMPOSE_FILE" ]] && command_exists docker; then
        report_application_diagnostics || true
    fi
    exit "$status"
}
trap on_error ERR

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

http_get() {
    local url="$1" output="$2"
    if command_exists curl; then
        curl --fail --silent --show-error --location --retry 3 \
            --connect-timeout 10 -o "$output" "$url"
    elif command_exists wget; then
        wget --quiet --tries=3 --timeout=10 -O "$output" "$url"
    else
        return 1
    fi
}

valid_release_version() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]
}

# 版本自动解析：默认取 GitHub 最新 Release，用户不需要输入任何版本号。
# 需要固定或回滚时才用 CHENXING_RELEASE_VERSION=vX.Y.Z 覆盖。
resolve_release_version() {
    local api_response
    if [[ -n "$RELEASE_VERSION" ]]; then
        valid_release_version "$RELEASE_VERSION" \
            || fail "CHENXING_RELEASE_VERSION 必须是 vX.Y.Z 格式。"
        return 0
    fi
    api_response="$(mktemp)"
    if ! http_get "https://api.github.com/repos/${RELEASE_REPOSITORY}/releases/latest" "$api_response"; then
        rm -f -- "$api_response"
        fail "无法查询最新发布版本。请检查网络，或用 CHENXING_RELEASE_VERSION=vX.Y.Z bash ./manage.sh 指定版本。"
    fi
    RELEASE_VERSION="$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$api_response" \
        | head -n 1 | sed 's/.*"\(v[^"]*\)"$/\1/')"
    rm -f -- "$api_response"
    valid_release_version "$RELEASE_VERSION" \
        || fail "解析到的发布版本无效。请用 CHENXING_RELEASE_VERSION=vX.Y.Z bash ./manage.sh 指定版本。"
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

generate_env() {
    local port="$1" auth_encryption_key
    auth_encryption_key="$(openssl rand -base64 32)"
    umask 077
    cat > "$ENV_FILE" <<EOF
COMPOSE_PROJECT_NAME=chenxing-auth
CHENXING_RELEASE_VERSION=${RELEASE_VERSION}
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

write_database_urls() {
    local runtime_user runtime_password migration_user migration_password database
    runtime_user="$(url_encode "$(read_env_value POSTGRES_RUNTIME_USER)")"
    runtime_password="$(url_encode "$(read_env_value POSTGRES_RUNTIME_PASSWORD)")"
    migration_user="$(url_encode "$(read_env_value POSTGRES_USER)")"
    migration_password="$(url_encode "$(read_env_value POSTGRES_PASSWORD)")"
    database="$(url_encode "$(read_env_value POSTGRES_DB)")"
    set_env_value DATABASE_URL \
        "postgres://${runtime_user}:${runtime_password}@postgres:5432/${database}"
    set_env_value MIGRATION_DATABASE_URL \
        "postgres://${migration_user}:${migration_password}@postgres:5432/${database}"
}

compose() {
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

wait_for_postgres() {
    local attempt
    printf '等待 PostgreSQL 就绪'
    for attempt in $(seq 1 60); do
        if compose exec -T postgres pg_isready \
            -U "$(read_env_value POSTGRES_USER)" -d "$(read_env_value POSTGRES_DB)" >/dev/null 2>&1; then
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
    printf '\nCompose 服务状态:\n' >&2
    compose ps >&2 || true
    printf '\n应用日志（最近 200 行）:\n' >&2
    compose logs --no-color --tail=200 app >&2 || true
}

for argument in "$@"; do
    case "$argument" in
        --debug) DEBUG_MODE=true ;;
        --prepare-only) PREPARE_ONLY=true ;;
        *) fail "未知参数：$argument。支持 --debug 和 --prepare-only。" ;;
    esac
done

if [[ -e "$ENV_FILE" || -L "$ENV_FILE" ]]; then
    fail "检测到已有 .env：这是一个现有部署。升级请运行 bash $INSTALL_DIR/manage.sh。"
fi
[[ -f "$COMPOSE_FILE" ]] || fail "缺少 compose.yml。请通过 bash ./manage.sh 运行安装。"
command_exists openssl || fail "缺少 openssl，无法生成部署密钥。请先安装 openssl。"

stage "解析发布版本"
resolve_release_version
CHENXING_IMAGE="ghcr.io/${RELEASE_REPOSITORY}:${RELEASE_VERSION}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-$DEFAULT_POSTGRES_IMAGE}"
REDIS_IMAGE="${REDIS_IMAGE:-$DEFAULT_REDIS_IMAGE}"
printf '发布版本: %s\n镜像: %s\n' "$RELEASE_VERSION" "$CHENXING_IMAGE"

stage "生成部署配置"
port="${CHENXING_PORT:-}"
if [[ -z "$port" && -t 0 ]]; then
    read -r -p "请输入对外端口 [${DEFAULT_PORT}]: " port
fi
port="${port:-$DEFAULT_PORT}"
valid_port "$port" || fail "端口必须是 1 到 65535 之间的整数。"
generate_env "$port"
write_database_urls
printf '已生成 .env，权限为 0600。安装目录: %s\n' "$INSTALL_DIR"

if [[ "$PREPARE_ONLY" == true ]]; then
    printf '已生成 %s（--prepare-only，不启动容器）。\n' "$ENV_FILE"
    exit 0
fi

command_exists docker || fail "缺少 Docker Engine。请先安装 Docker：https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || fail "缺少 Docker Compose v2 插件。请安装 docker-compose-plugin。"
docker info >/dev/null 2>&1 || fail "无法连接 Docker daemon；请启动 Docker 或使用有权限的账号运行。"

stage "校验 Compose 配置"
compose config --quiet
printf 'Compose 配置有效。\n'

stage "拉取镜像"
docker pull "$CHENXING_IMAGE"
docker pull "$POSTGRES_IMAGE"
docker pull "$REDIS_IMAGE"

stage "启动 PostgreSQL 和 Redis"
compose up -d postgres redis
wait_for_postgres || fail "PostgreSQL 未能在规定时间内就绪。"

stage "执行数据库迁移"
if ! compose run --rm migrate; then
    report_application_diagnostics
    fail "数据库迁移失败；应用未启动。请修复错误后重新运行 bash $INSTALL_DIR/manage.sh。"
fi

stage "启动辰星认证中枢"
compose up -d app
if ! wait_for_application; then
    report_application_diagnostics
    fail "应用未能在规定时间内就绪。"
fi

stage "安装完成"
compose ps
cat <<EOF

访问地址: http://服务器地址:${port}
安装目录: ${INSTALL_DIR}
当前版本: ${RELEASE_VERSION}

首次打开站点会引导创建首个所有者（Owner）账号。在 Owner 于管理设置中写入本站的
固定 HTTPS Issuer 之前，服务运行在保护模式：健康检查和前端可用，注册与 OAuth/OIDC
相关路由保持关闭。Issuer 保存在 PostgreSQL app_settings 中，不能从请求 Host 或代理头推导。

升级：在本目录重新运行 bash ./manage.sh 即可（禁止手动 docker compose pull）。
管理员 Token 和全部随机密钥只保存在 ${ENV_FILE}，请备份并保持私密。
EOF
