#!/usr/bin/env bash
# 辰星认证中枢 - 模板数据库生命周期引导（issue #710 stage 1）。
#
# 用法：test_sh/test_database.sh prepare|cleanup
#
# 本脚本只是一个严格转发器：解析 mode、准备环境变量、拒绝缺参，然后把
# `prepare` 或 `cleanup` 原样交给 `cargo run --example test_database`。所有数据库
# 命名、校验、建库/克隆/清理逻辑都在示例里，脚本本身不连接数据库、不打印任何
# 连接串。
#
# 三个变量必须显式提供，绝不回退到 DATABASE_URL：
#   MIGRATION_DATABASE_URL
#   CHENXING_TEST_TEMPLATE_DATABASE
#   CHENXING_TEST_DATABASE_PREFIX
# 调用方（CI 或本地 shell）已导出的值优先；只有**未设置**的变量才用 dev-env.sh
# 的 chenxing_env_value 从 .env 补一个键，绝不 source .env。显式设为空串仍算
# “已设置”，不会被 .env 覆盖，会走到缺参失败。
# 可选加载 DATABASE_URL：不要求、不回退，只是把 .env 里已有的运行时连接串带进
# 子进程，供示例的源库保护逻辑使用。

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
    printf '用法：%s prepare|cleanup\n' "${0##*/}" >&2
}

if [ "$#" -ne 1 ]; then
    usage
    exit 2
fi

mode="$1"
case "$mode" in
    prepare | cleanup) ;;
    *)
        usage
        exit 2
        ;;
esac

required=(MIGRATION_DATABASE_URL CHENXING_TEST_TEMPLATE_DATABASE CHENXING_TEST_DATABASE_PREFIX)
optional=(DATABASE_URL)

# dev-env.sh 只定义函数，无副作用；缺失时跳过，运行时环境仍可能已提供变量。
if [ -f dev-env.sh ]; then
    # shellcheck source=../dev-env.sh
    source ./dev-env.sh
fi

# 仅补“未设置”的变量；已设置（含显式空串）优先，不覆盖。`[[ -v ]]` 区分
# unset 与 set-empty，`${!name:-}` 做不到这一点（空串会被误当作缺失）。
fill_from_env_file() {
    local name="$1" value
    [[ -v $name ]] && return 0
    [ -f .env ] || return 0
    command -v chenxing_env_value >/dev/null 2>&1 || return 0
    value="$(chenxing_env_value "$name" .env || true)"
    if [ -n "$value" ]; then
        export "$name=$value"
    fi
}

for name in "${required[@]}" "${optional[@]}"; do
    fill_from_env_file "$name"
done

missing=()
for name in "${required[@]}"; do
    [ -n "${!name:-}" ] || missing+=("$name")
done

# 在建库/清理之前就把缺参挡下来，避免半初始化。这里不打印任何值。
if [ "${#missing[@]}" -gt 0 ]; then
    printf '缺少必需的环境变量：%s\n' "${missing[*]}" >&2
    printf '请显式提供（MIGRATION_DATABASE_URL 不回退到 DATABASE_URL）\n' >&2
    exit 2
fi

exec cargo run --example test_database -- "$mode"
