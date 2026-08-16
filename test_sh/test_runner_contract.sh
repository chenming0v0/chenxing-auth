#!/usr/bin/env bash
set -Eeuo pipefail

# Issue #478: validate missing-tool behavior without compiling or running tests.
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
original_path="$PATH"
temp_root="$(mktemp -d)"
rm_bin="$(command -v rm)"

cleanup() {
    "$rm_bin" -rf "$temp_root"
}
trap cleanup EXIT

mkdir -p "$temp_root/log" "$temp_root/empty-path"

# shellcheck source=test_sh/phases.sh
source "$repo_root/test_sh/phases.sh"

now_ms() { printf '0\n'; }
err() { :; }
info() { :; }

record() {
    recorded_name="$1"
    recorded_status="$2"
    recorded_note="${4:-}"
}

assert_failed_phase() {
    local expected_name="$1"
    shift
    recorded_name=""
    recorded_status=""
    recorded_note=""
    "$@"
    if [[ "$recorded_name" != "$expected_name" || "$recorded_status" != "fail" ]]; then
        printf 'expected %s to record fail, got name=%s status=%s note=%s\n' \
            "$expected_name" "$recorded_name" "$recorded_status" "$recorded_note" >&2
        exit 1
    fi
}

LOG_DIR="$temp_root/log"
PATH="$temp_root/empty-path"

MODE=filter
NEXTEST=0
assert_failed_phase "测试" phase_test
assert_failed_phase "覆盖检查" phase_coverage
assert_failed_phase "依赖审计" phase_audit

PATH="$original_path"
printf '%s\n' 'test runner missing-tool contract passed'
