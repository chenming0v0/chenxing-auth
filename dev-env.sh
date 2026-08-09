#!/usr/bin/env bash
# 辰星认证中枢 - 开发环境 .env 引导（被 dev-docker.sh / dev-services.sh source）
# 职责：保证本地 .env 存在，且开发必需的随机密钥是后端能接受的合法值。
# 只服务本地开发：生产密钥由 deploy/install.sh 或受保护的密钥存储负责。

# 调用方通常已定义带配色的 warn；单独 source 时给个兜底，避免未定义函数报错。
if ! declare -F warn >/dev/null 2>&1; then
    warn() { echo "[辰星] $1" >&2; }
fi

# 生成一个后端可接受的加密密钥：32 字节随机数的标准 base64。
chenxing_random_key() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32
    else
        # 退路：不依赖 openssl，直接读内核熵源
        head -c 32 /dev/urandom | base64 | tr -d '\n'
    fi
}

# 读取 .env 中某个变量的首个取值。dotenvy 只在变量未设置时写入，
# 因此首个出现才是后端真正看到的值。顺带去掉包裹引号和首尾空白。
chenxing_env_value() {
    local name="$1" file="$2" line value
    line="$(grep -m1 -E "^[[:space:]]*(export[[:space:]]+)?${name}[[:space:]]*=" "$file" 2>/dev/null || true)"
    [ -n "$line" ] || return 1
    value="${line#*=}"
    value="$(printf '%s' "$value" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    case "$value" in
        \"*\") value="${value#\"}"; value="${value%\"}" ;;
        \'*\') value="${value#\'}"; value="${value%\'}" ;;
    esac
    printf '%s' "$value"
}

# 与后端 parse_auth_encryption_key 对齐：标准 base64，解码后恰好 32 字节。
chenxing_key_is_valid() {
    local value="$1" decoded_bytes
    [ -n "$value" ] || return 1
    decoded_bytes="$(printf '%s' "$value" | base64 -d 2>/dev/null | wc -c)" || return 1
    [ "$decoded_bytes" -eq 32 ]
}

# 就地写入变量：已存在则替换所有同名行，不存在则追加。
# 用 awk 传值而非 sed，避免 base64 的 / + = 撞上分隔符或被当作反向引用。
chenxing_env_set() {
    local name="$1" value="$2" file="$3" tmp
    tmp="$(mktemp "${file}.XXXXXX")"
    awk -v name="$name" -v value="$value" '
        $0 ~ "^[[:space:]]*(export[[:space:]]+)?" name "[[:space:]]*=" {
            if (!done) { print name "=" value; done = 1 }
            next
        }
        { print }
        END { if (!done) print name "=" value }
    ' "$file" >"$tmp"
    # 保留原权限语义，密钥文件不该给同组和其他用户可读
    chmod 600 "$tmp"
    mv "$tmp" "$file"
}

# 按 APP_ISSUER 的方案（http / https）自动派生 COOKIE_SECURE 的正确值，
# 仅当当前值与派生值不符时才写入，避免不必要的文件修改。
# 不处理无 APP_ISSUER、方案非 http/https，以及已正确配置的情况。
chenxing_normalize_cookie_secure() {
    local file="$1" issuer current expected
    issuer="$(chenxing_env_value APP_ISSUER "$file" || true)"
    [ -n "$issuer" ] || return 0

    case "$issuer" in
        http://*) expected="false" ;;
        https://*) expected="true" ;;
        *) return 0 ;;
    esac

    current="$(chenxing_env_value COOKIE_SECURE "$file" || true)"
    [ "$current" = "$expected" ] && return 0

    chenxing_env_set COOKIE_SECURE "$expected" "$file"
    warn "COOKIE_SECURE 已按 APP_ISSUER 方案（${issuer%%://*}://）自动设为 ${expected}"
}

# 主流程：确保 .env 存在，把无效的 AUTH_ENCRYPTION_KEY 自动补成随机值，
# 并将 COOKIE_SECURE 规范化到与 APP_ISSUER 方案一致。
# 已显式配置轮换环 AUTH_ENCRYPTION_KEYS 时不插手单密钥，避免覆盖运维意图。
chenxing_ensure_env() {
    local file="${1:-.env}" key

    if [ ! -f "$file" ]; then
        warn ".env 不存在，从 .env.example 复制，请按本地环境检查配置"
        cp .env.example "$file"
    fi

    # .env 保存数据库口令和加密密钥，收紧权限
    chmod 600 "$file"

    if key="$(chenxing_env_value AUTH_ENCRYPTION_KEYS "$file")" && [ -n "$key" ]; then
        chenxing_normalize_cookie_secure "$file"
        return 0
    fi

    key="$(chenxing_env_value AUTH_ENCRYPTION_KEY "$file" || true)"
    if ! chenxing_key_is_valid "$key"; then
        chenxing_env_set AUTH_ENCRYPTION_KEY "$(chenxing_random_key)" "$file"
        warn "AUTH_ENCRYPTION_KEY 不是合法的 32 字节 base64 密钥，已写入随机开发密钥"
        warn "已加密的旧开发 Session 会失效，生产环境请使用受保护的密钥存储"
    fi

    chenxing_normalize_cookie_secure "$file"
}
