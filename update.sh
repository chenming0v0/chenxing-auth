#!/usr/bin/env bash
set -Eeuo pipefail

# 辰星认证中枢 · 升级脚本（由 manage.sh 下载并移交，不建议手动直接运行）
#
# 职责：解析目标发布版本 → 补齐 .env 新增键（绝不覆盖已有值）→ 迁移先行 →
# 切换并检查新版本 → 成功后保存版本；切换失败则恢复旧应用，数据库迁移不反向执行。

DEFAULT_POSTGRES_IMAGE="postgres:16-alpine"
DEFAULT_REDIS_IMAGE="redis:7-alpine"
RELEASE_REPOSITORY="${CHENXING_RELEASE_REPOSITORY:-chenming0v0/chenxing-auth}"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
INSTALL_DIR="$(dirname -- "$SCRIPT_PATH")"
ENV_FILE="$INSTALL_DIR/.env"
COMPOSE_FILE="$INSTALL_DIR/compose.yml"
RELEASE_VERSION="${CHENXING_RELEASE_VERSION:-}"
DEBUG_MODE=false
COMPOSE_ENV_FILE="$ENV_FILE"
COMPOSE_IMAGE_OVERRIDE=''
TARGET_ENV_FILE=''
PREVIOUS_ENV_FILE=''
PREVIOUS_IMAGE_ID=''
APPLICATION_SWITCH_STARTED=false
PRESERVE_PREVIOUS_ENV=false
CANDIDATE_CONTAINER=''

stage() {
    printf '\n==> %s\n' "$1"
}

fail() {
    printf '\n升级失败: %s\n' "$1" >&2
    exit 1
}

on_error() {
    local status=$?
    printf '\n升级在第 %s 行失败，退出码 %s。Docker 的错误输出已保留在上方。\n' \
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

# 版本自动解析：默认升级到 GitHub 最新 Release。回滚或固定版本时用
# CHENXING_RELEASE_VERSION=vX.Y.Z bash ./manage.sh 重新运行同一命令。
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
        fail "无法查询最新发布版本。请检查网络，或用 CHENXING_RELEASE_VERSION=vX.Y.Z bash ./manage.sh 指定版本；现有部署未改变。"
    fi
    RELEASE_VERSION="$(grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' "$api_response" \
        | head -n 1 | sed 's/.*"\(v[^"]*\)"$/\1/')"
    rm -f -- "$api_response"
    valid_release_version "$RELEASE_VERSION" \
        || fail "解析到的发布版本无效。请用 CHENXING_RELEASE_VERSION=vX.Y.Z bash ./manage.sh 指定版本；现有部署未改变。"
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

set_env_value() {
    local key="$1" value="$2" file="${3:-$ENV_FILE}" temp
    temp="$(mktemp "${file}.tmp.XXXXXX")"
    awk -v key="$key" -v value="$value" '
        BEGIN { prefix = key "="; replaced = 0 }
        index($0, prefix) == 1 {
            if (!replaced) { print prefix value; replaced = 1 }
            next
        }
        { print }
        END { if (!replaced) print prefix value }
    ' "$file" > "$temp"
    chmod 600 "$temp"
    mv -f "$temp" "$file"
}

# 只在键缺失或为空时补默认值，永不替换用户已有值。
ensure_env_value() {
    local key="$1" value="$2"
    if ! env_has_key "$key"; then
        printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
        return 0
    fi
    [[ -n "$(read_env_value "$key")" ]] && return 0
    set_env_value "$key" "$value"
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

ensure_database_urls() {
    local runtime_user runtime_password migration_user migration_password database
    runtime_user="$(url_encode "$(read_env_value POSTGRES_RUNTIME_USER)")"
    runtime_password="$(url_encode "$(read_env_value POSTGRES_RUNTIME_PASSWORD)")"
    migration_user="$(url_encode "$(read_env_value POSTGRES_USER)")"
    migration_password="$(url_encode "$(read_env_value POSTGRES_PASSWORD)")"
    database="$(url_encode "$(read_env_value POSTGRES_DB)")"
    ensure_env_value DATABASE_URL \
        "postgres://${runtime_user}:${runtime_password}@postgres:5432/${database}"
    ensure_env_value MIGRATION_DATABASE_URL \
        "postgres://${migration_user}:${migration_password}@postgres:5432/${database}"
}

compose() {
    # Compose 插值优先吃已经 export 的进程环境，--env-file 盖不过。
    # 密钥只来自部署配置；回滚镜像覆盖仅取自脚本记录的本地镜像 ID。
    local -a isolated=(env -i)
    local name value
    for name in PATH HOME DOCKER_HOST DOCKER_TLS_VERIFY DOCKER_CERT_PATH \
        DOCKER_CONTEXT DOCKER_CONFIG XDG_RUNTIME_DIR; do
        value="${!name-}"
        if [[ -n "$value" ]]; then
            isolated+=("${name}=${value}")
        fi
    done
    if [[ -n "$COMPOSE_IMAGE_OVERRIDE" ]]; then
        isolated+=("CHENXING_IMAGE=${COMPOSE_IMAGE_OVERRIDE}")
    fi
    isolated+=(docker compose --env-file "$COMPOSE_ENV_FILE" -f "$COMPOSE_FILE")
    isolated+=("$@")
    "${isolated[@]}"
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

verify_candidate_application() {
    local attempt
    CANDIDATE_CONTAINER="chenxing-upgrade-$(openssl rand -hex 8)"
    # run 不发布 service ports，旧应用继续承接用户请求；候选使用同一网络、配置和密钥卷。
    if ! compose run -d --no-deps --name "$CANDIDATE_CONTAINER" app >/dev/null; then
        return 1
    fi
    printf '验证新版本候选容器'
    for attempt in $(seq 1 60); do
        if docker exec "$CANDIDATE_CONTAINER" curl --fail --silent --max-time 5 \
            http://127.0.0.1:3000/health/ready >/dev/null 2>&1; then
            printf ' 完成\n'
            docker stop --time 30 "$CANDIDATE_CONTAINER" >/dev/null || return 1
            docker container rm "$CANDIDATE_CONTAINER" >/dev/null || return 1
            CANDIDATE_CONTAINER=''
            return 0
        fi
        printf '.'
        sleep 2
    done
    printf '\n' >&2
    docker logs --tail=200 "$CANDIDATE_CONTAINER" >&2 || true
    return 1
}

prepare_upgrade_environment() {
    PREVIOUS_ENV_FILE="$(mktemp "${ENV_FILE}.previous.XXXXXX")"
    cp -- "$ENV_FILE" "$PREVIOUS_ENV_FILE"
    TARGET_ENV_FILE="$(mktemp "${ENV_FILE}.upgrade.XXXXXX")"
    cp -- "$ENV_FILE" "$TARGET_ENV_FILE"
    chmod 600 "$PREVIOUS_ENV_FILE" "$TARGET_ENV_FILE"
    set_env_value CHENXING_RELEASE_VERSION "$RELEASE_VERSION" "$TARGET_ENV_FILE"
    set_env_value CHENXING_IMAGE "$CHENXING_IMAGE" "$TARGET_ENV_FILE"
    COMPOSE_ENV_FILE="$TARGET_ENV_FILE"
}

record_previous_application() {
    local container_id previous_image
    container_id="$(compose ps --all --quiet app)"
    if [[ -n "$container_id" ]]; then
        PREVIOUS_IMAGE_ID="$(docker inspect --format '{{.Image}}' "$container_id")"
    else
        previous_image="$(read_env_value CHENXING_IMAGE)"
        [[ -n "$previous_image" ]] || fail "无法确定旧应用镜像，现有版本记录未改变。"
        if ! PREVIOUS_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$previous_image" 2>/dev/null)"; then
            # 首次安装中断后也会进入升级路径；先准备旧配置镜像，保证切换后仍可恢复。
            stage "准备可恢复的旧应用镜像"
            docker pull "$previous_image"
            PREVIOUS_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$previous_image")"
        fi
    fi
    [[ "$PREVIOUS_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] \
        || fail "无法记录可恢复的旧应用镜像，现有版本记录未改变。"
}

restore_previous_environment() {
    local restored
    restored="$(mktemp "${ENV_FILE}.restore.XXXXXX")" || return 1
    if cp -- "$PREVIOUS_ENV_FILE" "$restored" \
        && chmod 600 "$restored" \
        && mv -f -- "$restored" "$ENV_FILE"; then
        return 0
    fi
    rm -f -- "$restored" || true
    return 1
}

rollback_application() {
    local environment_restored=true
    stage "恢复旧版本应用"
    COMPOSE_ENV_FILE="$PREVIOUS_ENV_FILE"
    COMPOSE_IMAGE_OVERRIDE="$PREVIOUS_IMAGE_ID"
    if ! restore_previous_environment; then
        environment_restored=false
        PRESERVE_PREVIOUS_ENV=true
        printf '旧版本配置恢复失败，保留恢复副本：%s\n' "$PREVIOUS_ENV_FILE" >&2
    fi
    # 迁移已经完成；回滚只恢复应用，不重新执行迁移或改动基础服务。
    if ! compose up -d --no-deps --pull never app; then
        report_application_diagnostics
        printf '自动回滚失败：旧应用容器未能恢复。数据库迁移已保留，请处理上方 Docker 错误。\n' >&2
        return 1
    fi
    if ! wait_for_application; then
        report_application_diagnostics
        printf '自动回滚失败：旧应用未通过就绪检查。数据库迁移已保留，请处理上方应用错误。\n' >&2
        return 1
    fi
    if [[ "$environment_restored" != true ]]; then
        printf '旧应用已就绪，但版本配置恢复失败；自动回滚尚未完成。\n' >&2
        return 1
    fi
    printf '已恢复旧应用并通过就绪检查，.env 的旧版本和镜像记录已恢复。数据库迁移已保留。\n' >&2
}

finish_upgrade() {
    local status=$?
    trap - EXIT ERR INT TERM HUP
    if [[ "$APPLICATION_SWITCH_STARTED" == true ]]; then
        if ! rollback_application; then
            status=1
        fi
    fi
    if [[ -n "$CANDIDATE_CONTAINER" ]]; then
        docker stop --time 30 "$CANDIDATE_CONTAINER" >/dev/null 2>&1 || true
        docker container rm "$CANDIDATE_CONTAINER" >/dev/null 2>&1 || true
    fi
    [[ -z "$TARGET_ENV_FILE" ]] || rm -f -- "$TARGET_ENV_FILE" || true
    if [[ "$PRESERVE_PREVIOUS_ENV" != true && -n "$PREVIOUS_ENV_FILE" ]]; then
        rm -f -- "$PREVIOUS_ENV_FILE" || true
    fi
    exit "$status"
}

interrupt_upgrade() {
    printf '\n收到 %s，升级已中断。\n' "$1" >&2
    exit "$2"
}

trap finish_upgrade EXIT
trap 'interrupt_upgrade INT 130' INT
trap 'interrupt_upgrade TERM 143' TERM
trap 'interrupt_upgrade HUP 129' HUP

for argument in "$@"; do
    case "$argument" in
        --debug) DEBUG_MODE=true ;;
        *) fail "未知参数：$argument。支持 --debug。" ;;
    esac
done

[[ ! -L "$ENV_FILE" ]] || fail ".env 不能是符号链接。"
[[ -f "$ENV_FILE" ]] || fail "没有找到 .env：这不是一个现有部署。首次安装请运行 bash $INSTALL_DIR/manage.sh。"
[[ -f "$COMPOSE_FILE" ]] || fail "缺少 compose.yml。请通过 bash ./manage.sh 运行升级。"
chmod 600 -- "$ENV_FILE"
command_exists openssl || fail "缺少 openssl，无法补齐部署密钥。请先安装 openssl。"
command_exists docker || fail "缺少 Docker Engine。请先安装 Docker：https://docs.docker.com/engine/install/"
compose version >/dev/null 2>&1 || fail "缺少 Docker Compose v2 插件。请安装 docker-compose-plugin。"
docker info >/dev/null 2>&1 || fail "无法连接 Docker daemon；请启动 Docker 或使用有权限的账号运行。"

stage "解析发布版本"
resolve_release_version
CHENXING_IMAGE="ghcr.io/${RELEASE_REPOSITORY}:${RELEASE_VERSION}"
printf '当前版本: %s\n目标版本: %s\n镜像: %s\n' \
    "$(read_env_value CHENXING_RELEASE_VERSION)" "$RELEASE_VERSION" "$CHENXING_IMAGE"

stage "补齐 .env 新增配置（保留全部已有密钥）"
ensure_env_value COMPOSE_PROJECT_NAME chenxing-auth
ensure_env_value POSTGRES_IMAGE "$DEFAULT_POSTGRES_IMAGE"
ensure_env_value REDIS_IMAGE "$DEFAULT_REDIS_IMAGE"
ensure_env_value REDIS_NAMESPACE legacy
# 旧安装早于最小权限运行库角色；只补缺失/空值，绝不替换正在使用的凭据。
ensure_env_value POSTGRES_RUNTIME_USER chenxing_runtime
ensure_env_value POSTGRES_RUNTIME_PASSWORD "$(openssl rand -hex 32)"
auth_encryption_key="$(read_env_value AUTH_ENCRYPTION_KEY)"
if [[ -n "$auth_encryption_key" ]]; then
    ensure_env_value AUTH_ENCRYPTION_KEYS "kid=active:${auth_encryption_key}"
    ensure_env_value AUTH_ENCRYPTION_ACTIVE_KID active
fi
ensure_database_urls
prepare_upgrade_environment

stage "校验 Compose 配置"
compose config --quiet
printf 'Compose 配置有效。\n'
record_previous_application

stage "拉取镜像"
docker pull "$CHENXING_IMAGE"
docker pull "$(read_env_value POSTGRES_IMAGE)"
docker pull "$(read_env_value REDIS_IMAGE)"

stage "启动 PostgreSQL 和 Redis"
compose up -d postgres redis
wait_for_postgres || fail "PostgreSQL 未能在规定时间内就绪。"

stage "执行数据库迁移（迁移先行，失败不切换版本）"
if ! compose run --rm migrate; then
    report_application_diagnostics
    fail "数据库迁移失败；旧应用未切换，版本和镜像记录未改变。请修复错误后重新运行 bash $INSTALL_DIR/manage.sh。"
fi

stage "保持旧应用运行并验证新版本"
verify_candidate_application || fail "新版本候选容器未就绪，旧应用未切换，版本记录未改变。"

stage "切换到新版本"
APPLICATION_SWITCH_STARTED=true
if ! compose up -d --no-deps --pull never app; then
    report_application_diagnostics
    fail "新版本容器切换失败，将自动恢复旧应用。"
fi
if ! wait_for_application; then
    report_application_diagnostics
    fail "新版本未能在规定时间内就绪，将自动恢复旧应用。"
fi

stage "保存已就绪版本"
mv -f -- "$TARGET_ENV_FILE" "$ENV_FILE"
TARGET_ENV_FILE=''
APPLICATION_SWITCH_STARTED=false
COMPOSE_ENV_FILE="$ENV_FILE"

stage "升级完成"
compose ps || true
cat <<EOF

当前版本: ${RELEASE_VERSION}
安装目录: ${INSTALL_DIR}

下次升级：在本目录重新运行 bash ./manage.sh 即可。
回滚：CHENXING_RELEASE_VERSION=v旧版本 bash ./manage.sh。
禁止手动 docker compose pull && up -d，那会绕过数据库迁移。
EOF
