#!/usr/bin/env bash
set -Eeuo pipefail

# 辰星认证中枢 · 一键安装引导器
#
# 用户只需要两行命令：
#   wget -O manage.sh https://raw.githubusercontent.com/chenming0v0/chenxing-auth/releases/manage.sh
#   bash ./manage.sh
#
# 本脚本只做“下载”和“分发”，不含任何安装/升级业务逻辑：
#   1. 每次运行都从发布分支重新下载最新的 install.sh / update.sh / compose.yml。
#   2. 部署目录没有 .env → 移交 install.sh（首次安装）；已有 .env → 移交 update.sh（升级）。
#   3. 命令行参数原样透传给被移交的脚本。
# 安装怎么装、升级怎么升，全部写在 install.sh / update.sh 里。

RAW_BASE="${CHENXING_RAW_BASE:-https://raw.githubusercontent.com/chenming0v0/chenxing-auth/releases}"
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
INSTALL_DIR="$(dirname -- "$SCRIPT_PATH")"

fail() {
    printf '\n安装失败: %s\n' "$1" >&2
    exit 1
}

on_error() {
    local status=$?
    printf '\n引导在第 %s 行失败，退出码 %s。\n' "${BASH_LINENO[0]:-unknown}" "$status" >&2
    exit "$status"
}
trap on_error ERR

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

download() {
    local url="$1" output="$2"
    if command_exists curl; then
        curl --fail --silent --show-error --location --retry 3 \
            --connect-timeout 10 -o "$output" "$url" \
            || fail "下载失败：$url。请检查网络后重试；现有部署未改变。"
    elif command_exists wget; then
        wget --quiet --tries=3 --timeout=10 -O "$output" "$url" \
            || fail "下载失败：$url。请检查网络后重试；现有部署未改变。"
    else
        fail "需要 curl 或 wget。请先安装其中一个再重新运行本脚本。"
    fi
}

# 下载到临时文件，校验通过后才原子替换；失败时现有文件保持不变。
fetch_script() {
    local remote_name="$1" local_name="$2" temp_file
    temp_file="$(mktemp "$INSTALL_DIR/.${local_name}.tmp.XXXXXX")"
    trap 'rm -f -- "${temp_file:-}"' RETURN
    download "$RAW_BASE/$remote_name" "$temp_file"
    bash -n "$temp_file" || fail "下载的 $local_name 语法校验失败；现有部署未改变。"
    chmod 700 -- "$temp_file"
    mv -f -- "$temp_file" "$INSTALL_DIR/$local_name"
    trap - RETURN
}

fetch_compose() {
    local temp_file
    temp_file="$(mktemp "$INSTALL_DIR/.compose.yml.tmp.XXXXXX")"
    trap 'rm -f -- "${temp_file:-}"' RETURN
    download "$RAW_BASE/deploy/compose.yml" "$temp_file"
    [[ -s "$temp_file" ]] && grep -q '^services:' "$temp_file" \
        || fail "下载的 compose.yml 内容无效；现有部署未改变。"
    chmod 644 -- "$temp_file"
    mv -f -- "$temp_file" "$INSTALL_DIR/compose.yml"
    trap - RETURN
}

fetch_script install.sh install.sh
fetch_script update.sh update.sh
fetch_compose

if [[ -f "$INSTALL_DIR/.env" ]]; then
    exec bash "$INSTALL_DIR/update.sh" "$@"
else
    exec bash "$INSTALL_DIR/install.sh" "$@"
fi
