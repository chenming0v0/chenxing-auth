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

assert_no_release_staging() {
    local root="$1" leftovers
    # `find -type f` alone cannot see this: the upgrade path stages the verified
    # manager copy (mode 700, security material) inside a `.release.XXXXXX`
    # directory. If the staging directory survives, every upgrade leaves another
    # executable copy of the installer behind in the deployment directory.
    leftovers="$(find "$root" -maxdepth 1 -name '.release.*' -printf '%f\n' | sort | tr '\n' ' ')"
    if [[ -n "$leftovers" ]]; then
        printf '%s\n' "release staging directories survived in $root: $leftovers" >&2
        return 1
    fi
}

external_key='external-value-must-not-be-used'
export AUTH_ENCRYPTION_KEY="$external_key"
mkdir -p "$WORK_DIR/install"
cp "$ROOT_DIR/manage.sh" "$WORK_DIR/install/manage.sh"
release_version=v0.0.0
script_sha256="$(sha256sum "$ROOT_DIR/manage.sh" | awk '{print $1}')"
release_manifest="$WORK_DIR/release.env"
cat > "$release_manifest" <<EOF
schema=1
version=${release_version}
image=ghcr.io/chenming0v0/chenxing-auth:${release_version}@sha256:0000000000000000000000000000000000000000000000000000000000000000
image_digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
script=chenxing-auth-manage.sh
script_sha256=${script_sha256}
EOF
CHENXING_PORT=8080 CHENXING_RELEASE_VERSION="$release_version" \
    CHENXING_RELEASE_MANIFEST_FILE="$release_manifest" \
    bash "$WORK_DIR/install/manage.sh" --prepare-only >/dev/null

env_file="$WORK_DIR/install/.env"
compose_file="$WORK_DIR/install/compose.yml"
manager_file="$WORK_DIR/install/manage.sh"
[[ -f "$manager_file" ]]
[[ "$(find "$WORK_DIR/install" -maxdepth 1 -type f -printf '%f\n' | sort | tr '\n' ' ')" == '.env compose.yml manage.sh ' ]]
assert_no_release_staging "$WORK_DIR/install"
[[ "$(stat -c '%a' "$manager_file")" == 700 ]]
actual_key="$(awk -F= '$1 == "AUTH_ENCRYPTION_KEY" { print substr($0, index($0, "=") + 1); exit }' "$env_file")"
ring="$(awk -F= '$1 == "AUTH_ENCRYPTION_KEYS" { print substr($0, index($0, "=") + 1); exit }' "$env_file")"
[[ -n "$actual_key" && "$actual_key" != "$external_key" ]]
[[ "$ring" == "kid=active:${actual_key}" ]]
grep -q "^CHENXING_RELEASE_VERSION=${release_version}$" "$env_file"
grep -q '^CHENXING_RELEASE_MANIFEST_SHA256=[0-9a-f]\{64\}$' "$env_file"
grep -q '^CHENXING_SCRIPT_SHA256=[0-9a-f]\{64\}$' "$env_file"
grep -q '^CHENXING_IMAGE=ghcr.io/chenming0v0/chenxing-auth:v0.0.0@sha256:' "$env_file"
assert_private_mode "$env_file"
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

# Existing deployments upgrade by running the same file again. Fake the
# versioned release asset download and Docker boundary to prove the temporary
# copy is removed.
upgrade_root="$WORK_DIR/upgrade"
mkdir -p "$upgrade_root"
cp "$ROOT_DIR/manage.sh" "$upgrade_root/manage.sh"
cp "$env_file" "$upgrade_root/.env"
upgrade_bin="$WORK_DIR/upgrade-bin"
mkdir -p "$upgrade_bin"
cat > "$upgrade_bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -Eeuo pipefail
output=''
while (($#)); do
    if [[ "$1" == -o ]]; then
        output="$2"
        shift 2
    else
        shift
    fi
done
cp "${FAKE_MANAGER_SOURCE:?}" "$output"
FAKE_CURL
cat > "$upgrade_bin/docker" <<'FAKE_DOCKER_UPGRADE'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == compose ]]; then
    shift
    command_line="$*"
    case "$command_line" in
        *" config --quiet"*) exit 0 ;;
        *" exec -T postgres pg_isready"*) exit 0 ;;
        *" run --rm migrate"*) exit 0 ;;
        *" exec -T app curl"*) exit 0 ;;
        *" up "*) exit 0 ;;
        *" ps"*) exit 0 ;;
        *) exit 0 ;;
    esac
fi
if [[ "${1:-}" == info || "${1:-}" == version || "${1:-}" == pull ]]; then exit 0; fi
FAKE_DOCKER_UPGRADE
chmod 755 "$upgrade_bin/curl" "$upgrade_bin/docker"
FAKE_MANAGER_SOURCE="$ROOT_DIR/manage.sh" CHENXING_RELEASE_VERSION="$release_version" \
    CHENXING_RELEASE_MANIFEST_FILE="$release_manifest" PATH="$upgrade_bin:$PATH" \
    bash "$upgrade_root/manage.sh" >/dev/null
[[ "$(find "$upgrade_root" -maxdepth 1 -type f -printf '%f\n' | sort | tr '\n' ' ')" == '.env compose.yml manage.sh ' ]]
assert_no_release_staging "$upgrade_root"

# Exercise the source installer upgrade path with a minimal temporary checkout.
# The fake Docker implementation records whether `up` was reached and reports
# legacy volume labels for the directory-derived project name.
source_root="$WORK_DIR/source-copy"
mkdir -p "$source_root/deploy"
cp "$ROOT_DIR/deploy/install.sh" "$source_root/deploy/install.sh"
cp "$ROOT_DIR/docker-compose.prod.yml" "$source_root/docker-compose.prod.yml"
fake_bin="$WORK_DIR/fake-bin"
mkdir -p "$fake_bin"
cat > "$fake_bin/docker" <<'FAKE_DOCKER'
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
cat > "$fake_bin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
exit 0
FAKE_CURL
chmod 755 "$fake_bin/docker" "$fake_bin/curl"

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
    PATH="$fake_bin:$PATH" bash -c 'hash -r; exec bash "$1"' _ "$source_root/deploy/install.sh" >/dev/null
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
    FAKE_DOCKER_NO_VOLUMES=1 PATH="$fake_bin:$PATH" bash -c 'hash -r; exec bash "$1"' _ "$moved_root/deploy/install.sh" >/dev/null 2>&1; then
    printf '%s\n' 'moved source without identifiable volumes unexpectedly succeeded' >&2
    exit 1
fi
! grep -q '^up$' "$moved_marker"

printf '%s\n' 'deployment contract passed'
