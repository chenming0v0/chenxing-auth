#!/usr/bin/env bash
# issue #710 stage 1: contract test for test_sh/test_database.sh.
#
# This test never compiles anything. It installs a fake `cargo` on PATH that only
# records its arguments and the presence/emptiness of the relevant environment
# variables (never their values), so it can pin the wrapper's mode validation,
# exact forwarding, and fail-before-cargo behavior without the toolchain. A fake
# repo root with its own `.env` and a copy of `dev-env.sh` pins the env-fill
# precedence rules.

set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
temp_root="$(mktemp -d)"
rm_bin="$(command -v rm)"

cleanup() {
    "$rm_bin" -rf "$temp_root"
}
trap cleanup EXIT

fake_bin="$temp_root/bin"
mkdir -p "$fake_bin"
cargo_log="$temp_root/cargo-args.log"
env_log="$temp_root/cargo-env.log"
: >"$cargo_log"
: >"$env_log"

# Records only `set-empty` / `set-nonempty` / `unset` per variable, never a value.
cat >"$fake_bin/cargo" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$cargo_log"
for v in MIGRATION_DATABASE_URL CHENXING_TEST_TEMPLATE_DATABASE CHENXING_TEST_DATABASE_PREFIX DATABASE_URL; do
    if [[ -v \$v ]]; then
        if [[ -n \${!v} ]]; then
            printf '%s=set-nonempty\n' "\$v" >>"$env_log"
        else
            printf '%s=set-empty\n' "\$v" >>"$env_log"
        fi
    else
        printf '%s=unset\n' "\$v" >>"$env_log"
    fi
done
exit "\${FAKE_CARGO_EXIT:-0}"
EOF
chmod +x "$fake_bin/cargo"

fail() {
    printf 'test_database contract failed: %s\n' "$1" >&2
    exit 1
}

reset_logs() {
    : >"$cargo_log"
    : >"$env_log"
}

# Runs the real script from the real repo root, with the fake cargo first on PATH.
run_wrapper() {
    PATH="$fake_bin:$PATH" \
        MIGRATION_DATABASE_URL="postgres://fake:fake@127.0.0.1:5432/fake_owner" \
        CHENXING_TEST_TEMPLATE_DATABASE="ctest_contract_template" \
        CHENXING_TEST_DATABASE_PREFIX="ctest_contract_" \
        bash "$repo_root/test_sh/test_database.sh" "$@"
}

# ---------------------------------------------------------------- fake repo
fake_repo="$temp_root/fake-repo"
fake_env_file="$fake_repo/.env"

# setup_fake_repo <env-file-content>
setup_fake_repo() {
    rm -rf "$fake_repo"
    mkdir -p "$fake_repo/test_sh"
    cp "$repo_root/dev-env.sh" "$fake_repo/dev-env.sh"
    cp "$repo_root/test_sh/test_database.sh" "$fake_repo/test_sh/test_database.sh"
    printf '%s\n' "$1" >"$fake_env_file"
}

# run_fake_repo <mode> [VAR=value ...]; clean environment so nothing leaks in.
run_fake_repo() {
    local mode="$1"
    shift
    env -i PATH="$fake_bin:/usr/bin:/bin" "$@" \
        bash "$fake_repo/test_sh/test_database.sh" "$mode"
}

env_has() {
    grep -qx "$1" "$env_log"
}

FULL_ENV_FILE="MIGRATION_DATABASE_URL=postgres://envfile-owner.invalid/owner
CHENXING_TEST_TEMPLATE_DATABASE=ctest_envfile_template
CHENXING_TEST_DATABASE_PREFIX=ctest_envfile_
DATABASE_URL=postgres://envfile-runtime.invalid/runtime"

# 1. Syntax only.
bash -n "$repo_root/test_sh/test_database.sh" || fail "bash -n rejected the script"

# 2. prepare forwards exactly once.
reset_logs
run_wrapper prepare >/dev/null 2>"$temp_root/prepare.err" || fail "prepare must succeed"
[ "$(cat "$cargo_log")" = "run --example test_database -- prepare" ] \
    || fail "prepare forwarded: $(cat "$cargo_log")"

# 3. cleanup forwards exactly once.
reset_logs
run_wrapper cleanup >/dev/null 2>"$temp_root/cleanup.err" || fail "cleanup must succeed"
[ "$(cat "$cargo_log")" = "run --example test_database -- cleanup" ] \
    || fail "cleanup forwarded: $(cat "$cargo_log")"

# 4. Wrong argument count is rejected before cargo.
for args in "" "prepare extra"; do
    reset_logs
    # shellcheck disable=SC2086  # deliberate word splitting of the empty/2-arg case
    if run_wrapper $args >/dev/null 2>&1; then
        fail "argument count '$args' must be rejected"
    fi
    [ ! -s "$cargo_log" ] || fail "cargo ran for rejected args '$args'"
done

# 5. Unknown mode is rejected before cargo.
reset_logs
if run_wrapper drop >/dev/null 2>&1; then
    fail "unknown mode must be rejected"
fi
[ ! -s "$cargo_log" ] || fail "cargo ran for an unknown mode"

# 6. Missing required variable fails before cargo. The prefix is not defined in
#    the real repo .env, so unsetting it is a reliable missing-variable case.
reset_logs
if PATH="$fake_bin:$PATH" \
    MIGRATION_DATABASE_URL="postgres://fake:fake@127.0.0.1:5432/fake_owner" \
    CHENXING_TEST_TEMPLATE_DATABASE="ctest_contract_template" \
    env -u CHENXING_TEST_DATABASE_PREFIX \
    bash "$repo_root/test_sh/test_database.sh" prepare >/dev/null 2>&1; then
    fail "missing required variable must be rejected"
fi
[ ! -s "$cargo_log" ] || fail "cargo ran despite a missing required variable"

# 7. No connection string leaks to stdout/stderr.
if grep -q "fake_owner\|postgres://" "$temp_root/prepare.err" "$temp_root/cleanup.err"; then
    fail "wrapper leaked a connection URL"
fi

# 8. Cargo failure propagates as a non-zero exit.
reset_logs
if PATH="$fake_bin:$PATH" FAKE_CARGO_EXIT=7 \
    MIGRATION_DATABASE_URL="postgres://fake:fake@127.0.0.1:5432/fake_owner" \
    CHENXING_TEST_TEMPLATE_DATABASE="ctest_contract_template" \
    CHENXING_TEST_DATABASE_PREFIX="ctest_contract_" \
    bash "$repo_root/test_sh/test_database.sh" prepare >/dev/null 2>&1; then
    fail "cargo failure must not be masked"
fi

# 9. Explicit empty required values are set, never overridden from .env; they must
#    still fail the missing-variable check and never reach cargo. Each case has a
#    valid value for that variable in .env, so a wrongly-filled empty would pass.
for empty in MIGRATION_DATABASE_URL CHENXING_TEST_TEMPLATE_DATABASE CHENXING_TEST_DATABASE_PREFIX; do
    setup_fake_repo "$FULL_ENV_FILE"
    reset_logs
    args=(
        "CHENXING_TEST_TEMPLATE_DATABASE=ctest_live_template"
        "CHENXING_TEST_DATABASE_PREFIX=ctest_live_"
        "MIGRATION_DATABASE_URL=postgres://live-owner.invalid/owner"
        "DATABASE_URL=postgres://live-runtime.invalid/runtime"
    )
    # Replace the chosen variable with an explicit empty assignment.
    for index in "${!args[@]}"; do
        [[ "${args[$index]%%=*}" == "$empty" ]] && args[$index]="$empty="
    done
    if run_fake_repo prepare "${args[@]}" >/dev/null 2>&1; then
        fail "explicit empty $empty must fail, not be filled from .env"
    fi
    [ ! -s "$cargo_log" ] || fail "cargo ran for explicit empty $empty"
done

# 10. Unset required variables are filled from .env and forwarded.
setup_fake_repo "$FULL_ENV_FILE"
reset_logs
run_fake_repo prepare >/dev/null 2>&1 || fail "unset required vars must be filled from .env"
env_has "MIGRATION_DATABASE_URL=set-nonempty" || fail "owner not filled from .env"
env_has "CHENXING_TEST_TEMPLATE_DATABASE=set-nonempty" || fail "template not filled from .env"
env_has "CHENXING_TEST_DATABASE_PREFIX=set-nonempty" || fail "prefix not filled from .env"
# Optional runtime URL is loaded too, for source protection, but is never required.
env_has "DATABASE_URL=set-nonempty" || fail "optional DATABASE_URL not loaded from .env"

# 11. DATABASE_URL is optional: absent everywhere still succeeds.
setup_fake_repo "MIGRATION_DATABASE_URL=postgres://envfile-owner.invalid/owner
CHENXING_TEST_TEMPLATE_DATABASE=ctest_envfile_template
CHENXING_TEST_DATABASE_PREFIX=ctest_envfile_"
reset_logs
run_fake_repo prepare >/dev/null 2>&1 || fail "absent DATABASE_URL must not be required"
env_has "DATABASE_URL=unset" || fail "DATABASE_URL must stay unset when absent"

# 12. No fallback: a valid DATABASE_URL must never satisfy a missing owner.
setup_fake_repo "DATABASE_URL=postgres://envfile-runtime.invalid/runtime
CHENXING_TEST_TEMPLATE_DATABASE=ctest_envfile_template
CHENXING_TEST_DATABASE_PREFIX=ctest_envfile_"
reset_logs
if run_fake_repo prepare \
    CHENXING_TEST_TEMPLATE_DATABASE=ctest_live_template \
    CHENXING_TEST_DATABASE_PREFIX=ctest_live_ \
    DATABASE_URL=postgres://live-runtime.invalid/runtime >/dev/null 2>&1; then
    fail "missing owner must not fall back to DATABASE_URL"
fi
[ ! -s "$cargo_log" ] || fail "cargo ran despite a missing owner"

# 13. The wrapper must never source .env as a shell script. A .env value that
#     contains a command substitution must be read literally, not executed.
marker="$temp_root/marker"
setup_fake_repo "MIGRATION_DATABASE_URL=\$(touch $marker)
CHENXING_TEST_TEMPLATE_DATABASE=ctest_envfile_template
CHENXING_TEST_DATABASE_PREFIX=ctest_envfile_"
reset_logs
run_fake_repo prepare >/dev/null 2>&1 || fail "literal command-substitution value must forward"
[ ! -e "$marker" ] || fail "wrapper sourced .env as a script"
[ "$(cat "$cargo_log")" = "run --example test_database -- prepare" ] \
    || fail "command-substitution .env did not forward"

printf '%s\n' 'test_database wrapper contract passed'
