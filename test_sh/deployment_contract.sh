#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

assert_private_mode() {
    local file="$1" mode
    mode="$(stat -c '%a' "$file")"
    # NTFS mounted through MSYS does not preserve POSIX mode bits; the same
    # executable contract runs with real 0600 checks on Linux CI.
    if [[ "${OSTYPE:-}" != msys* && "${OSTYPE:-}" != cygwin* ]]; then
        [[ "$mode" == 600 ]]
    fi
}

expected_files='.env compose.yml install.sh manage.sh update.sh '

list_files() {
    find "$1" -maxdepth 1 -type f -printf '%f\n' | sort | tr '\n' ' '
}

# manage.sh 只做引导：每次运行重新下载 install.sh / update.sh / compose.yml。
# 用假 curl 把“下载”映射到本仓库文件，验证分发契约本身。
fake_bin="$WORK_DIR/fake-bin"
mkdir -p "$fake_bin"
cat > "$fake_bin/curl" <<FAKE_CURL
#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR='$ROOT_DIR'
FAKE_CURL
cat >> "$fake_bin/curl" <<'FAKE_CURL'
output=''
url=''
while (($#)); do
    case "$1" in
        -o) output="$2"; shift 2 ;;
        http*) url="$1"; shift ;;
        *) shift ;;
    esac
done
case "$url" in
    */deploy/compose.yml) cp "$ROOT_DIR/deploy/compose.yml" "$output" ;;
    */install.sh) cp "$ROOT_DIR/install.sh" "$output" ;;
    */update.sh) cp "$ROOT_DIR/update.sh" "$output" ;;
    *) echo "fake curl: unexpected url: $url" >&2; exit 1 ;;
esac
FAKE_CURL
chmod 755 "$fake_bin/curl"

# ---- 首次安装：无 .env 时 manage.sh 必须移交 install.sh，参数原样透传 ----
external_key='external-value-must-not-be-used'
export AUTH_ENCRYPTION_KEY="$external_key"
install_root="$WORK_DIR/install"
mkdir -p "$install_root"
cp "$ROOT_DIR/manage.sh" "$install_root/manage.sh"
release_version=v0.0.0
CHENXING_PORT=8080 CHENXING_RELEASE_VERSION="$release_version" \
    PATH="$fake_bin:$PATH" bash "$install_root/manage.sh" --prepare-only >/dev/null

env_file="$install_root/.env"
compose_file="$install_root/compose.yml"
[[ "$(list_files "$install_root")" == "$expected_files" ]]
assert_private_mode "$env_file"
actual_key="$(awk -F= '$1 == "AUTH_ENCRYPTION_KEY" { print substr($0, index($0, "=") + 1); exit }' "$env_file")"
ring="$(awk -F= '$1 == "AUTH_ENCRYPTION_KEYS" { print substr($0, index($0, "=") + 1); exit }' "$env_file")"
[[ -n "$actual_key" && "$actual_key" != "$external_key" ]]
[[ "$ring" == "kid=active:${actual_key}" ]]
grep -q "^CHENXING_RELEASE_VERSION=${release_version}$" "$env_file"
grep -q "^CHENXING_IMAGE=ghcr.io/chenming0v0/chenxing-auth:${release_version}$" "$env_file"
grep -q '^APP_PORT=8080$' "$env_file"
for key in POSTGRES_DB POSTGRES_USER POSTGRES_PASSWORD MIGRATION_DATABASE_URL; do
    grep -q "^${key}=." "$env_file"
done

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    unset AUTH_ENCRYPTION_KEY
    config="$(docker compose --env-file "$env_file" -f "$compose_file" config --format json)"
    python3 -c '
import json, sys
data = json.load(sys.stdin)
app = data["services"]["app"]
env = app["environment"]
port = app["ports"][0]
assert env["APP_HOST"] == "0.0.0.0"
assert str(env["APP_PORT"]) == "3000"
assert str(port["published"]) == "8080" and str(port["target"]) == "3000"
assert env.get("MIGRATION_DATABASE_URL") is None
assert env.get("POSTGRES_USER") is None and env.get("POSTGRES_PASSWORD") is None
assert app["depends_on"]["migrate"]["condition"] == "service_completed_successfully"
assert "migrate" in data["services"]
assert "chenxing" in str(data["services"]["migrate"]["environment"]["MIGRATION_DATABASE_URL"])
' <<< "$config"
fi

# ---- 升级：已有 .env 时 manage.sh 必须移交 update.sh，保留全部密钥，迁移先行 ----
upgrade_root="$WORK_DIR/upgrade"
mkdir -p "$upgrade_root"
cp "$ROOT_DIR/manage.sh" "$upgrade_root/manage.sh"
cp "$env_file" "$upgrade_root/.env"
upgrade_marker="$WORK_DIR/upgrade.marker"
: > "$upgrade_marker"
cat > "$fake_bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == compose ]]; then
    shift
    command_line="$*"
    case "$command_line" in
        *" run --rm migrate"*) printf '%s\n' migrate >> "${FAKE_DOCKER_MARKER:?}" ;;
        *" up -d app"*) printf '%s\n' up-app >> "${FAKE_DOCKER_MARKER:?}" ;;
    esac
    exit 0
fi
if [[ "${1:-}" == info || "${1:-}" == version || "${1:-}" == pull ]]; then exit 0; fi
exit 0
FAKE_DOCKER
chmod 755 "$fake_bin/docker"
FAKE_DOCKER_MARKER="$upgrade_marker" CHENXING_RELEASE_VERSION=v0.0.1 \
    PATH="$fake_bin:$PATH" bash "$upgrade_root/manage.sh" >/dev/null
[[ "$(list_files "$upgrade_root")" == "$expected_files" ]]
assert_private_mode "$upgrade_root/.env"
upgraded_key="$(awk -F= '$1 == "AUTH_ENCRYPTION_KEY" { print substr($0, index($0, "=") + 1); exit }' "$upgrade_root/.env")"
[[ "$upgraded_key" == "$actual_key" ]]
old_password="$(awk -F= '$1 == "POSTGRES_PASSWORD" { print substr($0, index($0, "=") + 1); exit }' "$env_file")"
new_password="$(awk -F= '$1 == "POSTGRES_PASSWORD" { print substr($0, index($0, "=") + 1); exit }' "$upgrade_root/.env")"
[[ "$new_password" == "$old_password" ]]
grep -q '^CHENXING_RELEASE_VERSION=v0.0.1$' "$upgrade_root/.env"
grep -q '^CHENXING_IMAGE=ghcr.io/chenming0v0/chenxing-auth:v0.0.1$' "$upgrade_root/.env"
[[ "$(tr '\n' ' ' < "$upgrade_marker")" == 'migrate up-app ' ]]
rm -f "$fake_bin/docker"

# Exercise the source installer upgrade path with a minimal temporary checkout.
# The fake Docker implementation records whether `up` was reached and reports
# legacy volume labels for the directory-derived project name.
source_root="$WORK_DIR/source-copy"
mkdir -p "$source_root/deploy"
cp "$ROOT_DIR/deploy/install.sh" "$source_root/deploy/install.sh"
cp "$ROOT_DIR/docker-compose.prod.yml" "$source_root/docker-compose.prod.yml"
src_fake_bin="$WORK_DIR/src-fake-bin"
mkdir -p "$src_fake_bin"
cat > "$src_fake_bin/docker" <<'FAKE_DOCKER'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == compose ]]; then
    shift
    command_line="$*"
    case "$command_line" in
        *" version"*) exit 0 ;;
        *" port app 3000"*) printf '%s\n' '0.0.0.0:8080' ;;
        *" exec -T postgres pg_isready"*) exit 0 ;;
        *)
            if [[ "$command_line" == *" run --rm --build migrate"* || "$command_line" == *" run --rm migrate"* ]]; then
                printf '%s\n' migrate >> "${FAKE_DOCKER_MARKER:?}"
            elif [[ "$command_line" == *" up "* ]]; then
                printf '%s\n' up >> "${FAKE_DOCKER_MARKER:?}"
            fi
            exit 0
            ;;
    esac
fi
if [[ "${1:-}" == volume && "${2:-}" == inspect ]]; then
    [[ "${FAKE_DOCKER_NO_VOLUMES:-0}" == 1 ]] && exit 1
    if [[ "${3:-}" == --format ]]; then
        printf '%s\n' "${FAKE_DOCKER_PROJECT:?}"
    else
        printf '%s\n' '{}'
    fi
    exit 0
fi
if [[ "${1:-}" == volume && "${2:-}" == ls ]]; then
    exit 0
fi
exit 0
FAKE_DOCKER
cat > "$src_fake_bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
exit 0
FAKE_CURL
chmod 755 "$src_fake_bin/docker" "$src_fake_bin/curl"

legacy_project="$(basename "$source_root" | tr '[:upper:]' '[:lower:]')"
cat > "$source_root/.env" <<EOF
APP_HOST=0.0.0.0
APP_PORT=3000
AUTH_ENCRYPTION_KEY=$(openssl rand -base64 32)
COOKIE_SECURE=true
POSTGRES_DB=chenxing_auth
POSTGRES_USER=chenxing
POSTGRES_PASSWORD=$(openssl rand -hex 32)
POSTGRES_RUNTIME_USER=chenxing_runtime
POSTGRES_RUNTIME_PASSWORD=runtime-password
REDIS_NAMESPACE=legacy
EOF
chmod 644 "$source_root/.env"
marker="$WORK_DIR/fake-docker.marker"
: > "$marker"
FAKE_DOCKER_MARKER="$marker" FAKE_DOCKER_PROJECT="$legacy_project" \
    PATH="$src_fake_bin:$PATH" bash -c 'hash -r; exec bash "$1"' _ "$source_root/deploy/install.sh" >/dev/null
assert_private_mode "$source_root/.env"
grep -q "^COMPOSE_PROJECT_NAME=${legacy_project}$" "$source_root/.env"
[[ "$(tr '\n' ' ' < "$marker")" == 'up migrate up ' ]]

moved_root="$WORK_DIR/moved-source"
mkdir -p "$moved_root/deploy"
cp "$ROOT_DIR/deploy/install.sh" "$moved_root/deploy/install.sh"
cp "$ROOT_DIR/docker-compose.prod.yml" "$moved_root/docker-compose.prod.yml"
cp "$source_root/.env" "$moved_root/.env"
sed -i 's/^COMPOSE_PROJECT_NAME=.*/COMPOSE_PROJECT_NAME=/' "$moved_root/.env"
chmod 600 "$moved_root/.env"
moved_marker="$WORK_DIR/moved.marker"
: > "$moved_marker"
if FAKE_DOCKER_MARKER="$moved_marker" FAKE_DOCKER_PROJECT=moved-source \
    FAKE_DOCKER_NO_VOLUMES=1 PATH="$src_fake_bin:$PATH" bash -c 'hash -r; exec bash "$1"' _ "$moved_root/deploy/install.sh" >/dev/null 2>&1; then
    printf '%s\n' 'moved source without identifiable volumes unexpectedly succeeded' >&2
    exit 1
fi
! grep -q '^up$' "$moved_marker"

printf '%s\n' 'deployment contract passed'
