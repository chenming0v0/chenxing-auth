# 辰星认证中枢 - 测试运行器公共设施
#
# 本文件由 test_sh/test.sh source，不单独执行，因此没有 shebang。
# 职责边界：只提供配色、计时、汇总、日志目录、服务探测这类基础设施，
# 不含任何「谁能跑什么」的策略判断——策略在 test.sh，阶段在 phases.sh。

# ---------------------------------------------------------------- 输出
CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'; RESET='\033[0m'
# 非 TTY（CI、管道、模型上下文）里转义序列只是噪声，直接清空。
if [ ! -t 1 ]; then CYAN=''; GREEN=''; YELLOW=''; RED=''; DIM=''; RESET=''; fi

info() { printf '%b[辰星]%b %s\n' "$CYAN" "$RESET" "$1"; }
ok()   { printf '%b[辰星]%b %s\n' "$GREEN" "$RESET" "$1"; }
warn() { printf '%b[辰星]%b %s\n' "$YELLOW" "$RESET" "$1"; }
err()  { printf '%b[辰星]%b %s\n' "$RED" "$RESET" "$1" >&2; }

# ---------------------------------------------------------------- 计时
now_ms() {
    if [ -n "${EPOCHREALTIME:-}" ]; then
        local raw="${EPOCHREALTIME/,/.}" frac
        frac="${raw#*.}"
        printf '%s%s\n' "${raw%.*}" "${frac:0:3}"
    else
        date +%s%3N
    fi
}

fmt_duration() {
    # 分行赋值：同一条 local 里的算术展开发生在赋值之前，ms 还不存在。
    local ms="${1:-0}" total_s rest
    total_s=$((ms / 1000))
    rest=$((ms % 1000))
    if [ "$total_s" -ge 60 ]; then
        printf '%dm%02ds' "$((total_s / 60))" "$((total_s % 60))"
    else
        printf '%d.%01ds' "$total_s" "$((rest / 100))"
    fi
}

START_MS="$(now_ms)"

# ---------------------------------------------------------------- 进度指示
SPINNER_PID=""
spinner_start() {
    [ -t 1 ] || return 0
    local label="$1" begin
    begin="$(now_ms)"
    (
        local frames='|/-\' i=0
        while :; do
            printf '\r%b  %s %s %s%b' "$DIM" "${frames:i++%4:1}" "$label" \
                "$(fmt_duration $(( $(now_ms) - begin )))" "$RESET"
            sleep 0.2
        done
    ) &
    SPINNER_PID=$!
}

spinner_stop() {
    [ -n "$SPINNER_PID" ] || return 0
    kill "$SPINNER_PID" 2>/dev/null
    wait "$SPINNER_PID" 2>/dev/null
    SPINNER_PID=""
    [ -t 1 ] && printf '\r\033[K'
    return 0
}

cleanup_on_exit() { spinner_stop; }
trap cleanup_on_exit EXIT INT TERM

# ---------------------------------------------------------------- 汇总
# 四个并行数组而不是一个结构体：bash 没有结构体，下标对齐已经够用。
SUMMARY_LABELS=(); SUMMARY_STATES=(); SUMMARY_TIMES=(); SUMMARY_NOTES=()

record() { SUMMARY_LABELS+=("$1"); SUMMARY_STATES+=("$2"); SUMMARY_TIMES+=("$3"); SUMMARY_NOTES+=("${4:-}"); }

print_summary() {
    local total="$(( $(now_ms) - START_MS ))" i state color mark
    printf '\n'
    for i in "${!SUMMARY_LABELS[@]}"; do
        state="${SUMMARY_STATES[$i]}"
        case "$state" in
            ok)   color="$GREEN"; mark="通过" ;;
            fail) color="$RED";   mark="失败" ;;
            *)    color="$YELLOW"; mark="跳过" ;;
        esac
        printf '  %b%s%b  %-10s %8s  %s\n' "$color" "$mark" "$RESET" \
            "${SUMMARY_LABELS[$i]}" "$(fmt_duration "${SUMMARY_TIMES[$i]}")" "${SUMMARY_NOTES[$i]}"
    done
    printf '  %b总耗时%b      %-10s %8s  %b日志 %s%b\n' \
        "$CYAN" "$RESET" "" "$(fmt_duration "$total")" "$DIM" "$LOG_DIR" "$RESET"
}

summary_has_failure() {
    local state
    for state in ${SUMMARY_STATES[@]+"${SUMMARY_STATES[@]}"}; do
        [ "$state" = "fail" ] && return 0
    done
    return 1
}

# ---------------------------------------------------------------- 杂项
human_size() {
    python3 - "$1" <<'PY'
import sys
size = float(sys.argv[1] or 0)
for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
    if abs(size) < 1024 or unit == "TiB":
        print(f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}")
        break
    size /= 1024
PY
}

# 只显示编译诊断，跳过 Compiling/Finished 之类进度噪声。
show_diagnostics() {
    local log="$1" limit="${2:-200}" lines
    [ -s "$log" ] || return 0
    lines="$(awk '
        /^(error|warning)(\[|:| )/ { show = 1 }
        /^[[:space:]]*$/ { show = 0 }
        show { print }
    ' "$log" | head -n "$limit")"
    [ -n "$lines" ] && printf '%s\n' "$lines"
    return 0
}

# ---------------------------------------------------------------- 日志目录
# 设置全局 LOG_DIR。由 test.sh 在参数解析和角色闸门通过之后调用，
# 避免 --help 和被拒绝的调用也留下空目录。
setup_log_dir() {
    LOG_ROOT="target/test-logs"
    LOG_DIR="$LOG_ROOT/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$LOG_DIR"
    # 日志本身也是垃圾来源，只留最近 5 次。
    if [ -d "$LOG_ROOT" ]; then
        # shellcheck disable=SC2012  # 目录名是时间戳，按名排序即按时间排序
        ls -1d "$LOG_ROOT"/*/ 2>/dev/null | sort -r | tail -n +6 | while read -r stale; do
            rm -rf "$stale"
        done
    fi
}

# ---------------------------------------------------------------- 环境
# 集成测试直接读 std::env，不走 dotenvy，必须由脚本导出。
load_env() {
    if [ -f .env ] && [ -f dev-env.sh ]; then
        # shellcheck source=../dev-env.sh
        source ./dev-env.sh   # 只定义函数，无副作用
        : "${DATABASE_URL:=$(chenxing_env_value DATABASE_URL .env || true)}"
        : "${REDIS_URL:=$(chenxing_env_value REDIS_URL .env || true)}"
    fi
    : "${DATABASE_URL:=postgres://chenxing:chenxing@127.0.0.1:5432/chenxing_auth}"
    : "${REDIS_URL:=redis://127.0.0.1:6379}"
    export DATABASE_URL REDIS_URL

    # backtrace 默认关闭：一个失败就是 20 行栈帧，这正是要避免的噪声。
    # 断言消息和 panic 位置已足够定位，需要栈时用 --backtrace。
    if [ "${BACKTRACE:-0}" -eq 1 ]; then
        export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"
    else
        export RUST_BACKTRACE=0
    fi
}

# 从 URL 取 host:port，做存活探测。取不到就跳过探测，不猜。
url_host_port() {
    local url="$1" rest
    rest="${url#*://}"
    rest="${rest#*@}"
    rest="${rest%%/*}"
    rest="${rest%%\?*}"
    case "$rest" in
        \[*\]*) printf '%s %s\n' "${rest%%]*}]" "${rest##*]:}" ;;
        *:*) printf '%s %s\n' "${rest%%:*}" "${rest##*:}" ;;
        *) return 1 ;;
    esac
}

tcp_alive() {
    local host="$1" port="$2"
    [[ "$port" =~ ^[0-9]+$ ]] || return 0
    timeout 2 bash -c 'exec 3<>/dev/tcp/"$0"/"$1"' "$host" "$port" 2>/dev/null
}

require_service() {
    local url="$1" label="$2" host port
    if read -r host port < <(url_host_port "$url"); then
        tcp_alive "$host" "$port" || {
            err "$label 无法连接（$host:$port）。先启动基础设施：./dev-docker.sh"
            return 1
        }
    fi
    return 0
}
