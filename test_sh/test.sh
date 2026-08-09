#!/usr/bin/env bash
# 辰星认证中枢 - 安静测试运行器
#
# 四个目标：
#   1. 只输出失败信息和汇总，通过的用例不进终端（也就不污染模型上下文）
#   2. 报告每个阶段耗时和总耗时
#   3. 结束后自动清理 target 里陈旧的测试二进制
#   4. 按角色分离运行模式：子代理跑不动全量套件，编排者才行
#
# 完整输出始终写入 target/test-logs/<时间戳>/，需要时按路径查看。
# 用法见 --help。
set -uo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$PWD"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_sh/lib.sh
source "$SCRIPT_DIR/lib.sh"
# shellcheck source=test_sh/phases.sh
source "$SCRIPT_DIR/phases.sh"

# ---------------------------------------------------------------- 角色
# CHENXING_TEST_ROLE 只认 orchestrator，其余一切取值（包括未设置）都是 subagent。
# 默认值必须是受限的那一侧：忘记设置时得到的是安全行为，而不是全量套件。
ROLE="subagent"
[ "${CHENXING_TEST_ROLE:-}" = "orchestrator" ] && ROLE="orchestrator"

# ---------------------------------------------------------------- 参数状态
MODE=""             # 必须由参数显式指定，没有默认值
ONLY_LIB=0
TEST_TARGETS=()
FILTER_EXPR=""
JOBS=""
RUN_FMT=1
MAX_FAIL="5"
BACKTRACE=0
DEEP_CLEAN=0
DO_CLEAN=1
DRY_RUN=0
VERBOSE=0
SHOW_HELP=0

usage() {
    cat <<EOF
辰星认证中枢 - 安静测试运行器

用法：./test_sh/test.sh <模式> [选项]
当前角色：${ROLE}$([ "$ROLE" = subagent ] && printf '（默认；设 CHENXING_TEST_ROLE=orchestrator 解锁编排者模式）')

子代理可用
      --lib             只跑单元测试（不连数据库，最快）
      --test NAME       只跑指定集成测试目标（可重复）
      --clean-only      只清理陈旧产物，不编译不测试

编排者专属（需要 CHENXING_TEST_ROLE=orchestrator）
      --full            完整测试套件（等价 nextest --all-features）
      --gate            完整验证链：格式 / 全量检查 / 测试 / clippy / 覆盖 / 审计 / 行数 / 清理
      --clippy          只跑 cargo clippy -D warnings
      --coverage        只跑覆盖率门槛（cargo llvm-cov，行覆盖 75%）
      --audit           只跑 cargo audit
  -E, --filter EXPR     nextest filterset 表达式

通用选项
  -j, --jobs N          并发测试数（默认由 nextest 决定）
      --no-fmt          跳过 cargo fmt 检查
      --all-failures    不限制失败数量（默认最多报告 5 个）
      --backtrace       失败时打印 backtrace（默认关闭，避免刷屏）
      --deep-clean      连带清理 incremental 缓存与陈旧 rlib（下次编译变慢）
      --no-clean        跳过清理
      --dry-run         清理阶段只报告不删除
  -v, --verbose         打印完整测试日志与逐条清理项
  -h, --help            显示本帮助

不带任何模式调用会以退出码 2 失败：裸调用绝不隐式跑全量套件。
EOF
}

# 模式互斥：先到先得，冲突直接报错而不是静默覆盖。
set_mode() {
    if [ -n "$MODE" ] && [ "$MODE" != "$1" ]; then
        err "模式冲突：--$MODE 与 --$1 不能同时使用"
        exit 2
    fi
    MODE="$1"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) SHOW_HELP=1 ;;
        --lib) set_mode lib; ONLY_LIB=1 ;;
        --test)
            [ $# -ge 2 ] || { err "--test 需要目标名"; exit 2; }
            set_mode test; TEST_TARGETS+=("$2"); shift ;;
        --clean-only) set_mode clean-only ;;
        --full) set_mode full ;;
        --gate) set_mode gate ;;
        --clippy) set_mode clippy ;;
        --coverage) set_mode coverage ;;
        --audit) set_mode audit ;;
        -E|--filter)
            [ $# -ge 2 ] || { err "--filter 需要表达式"; exit 2; }
            set_mode filter; FILTER_EXPR="$2"; shift ;;
        -j|--jobs) [ $# -ge 2 ] || { err "--jobs 需要数字"; exit 2; }; JOBS="$2"; shift ;;
        --no-fmt) RUN_FMT=0 ;;
        --all-failures) MAX_FAIL="all" ;;
        --backtrace) BACKTRACE=1 ;;
        --deep-clean) DEEP_CLEAN=1 ;;
        --no-clean) DO_CLEAN=0 ;;
        --dry-run) DRY_RUN=1 ;;
        -v|--verbose) VERBOSE=1 ;;
        *) err "未知参数：$1（--help 查看用法）"; exit 2 ;;
    esac
    shift
done

if [ "$SHOW_HELP" -eq 1 ]; then usage; exit 0; fi

# ---------------------------------------------------------------- 角色闸门
#
# 这是防误触的护栏，不是安全边界。子代理完全有能力自己 export
# CHENXING_TEST_ROLE=orchestrator 绕过它；真正的权威是 AGENTS.md 的
# 「测试执行权限」一节。护栏做的只有两件事：让全量套件必须是有意为之，
# 以及把每次调用的角色和模式写进 transcript 第一行，绕过行为一眼可查。
#
# 因此这个变量必须按次内联传递，永远不要 export：
#   对：  CHENXING_TEST_ROLE=orchestrator ./test_sh/test.sh --gate
#   错：  export CHENXING_TEST_ROLE=orchestrator   # 派生的子代理会继承编排者权限
#
ORCHESTRATOR_ONLY=" full gate clippy coverage audit filter "

# 规则一：零参数是硬错误。裸调用曾经等于全量套件，这正是要堵的口子。
if [ -z "$MODE" ]; then
    err "必须显式指定运行模式，不存在默认模式"
    printf '\n  %b子代理可用%b\n' "$CYAN" "$RESET"
    printf '    --lib             只跑单元测试（不连数据库）\n'
    printf '    --test NAME       只跑指定集成测试目标（可重复）\n'
    printf '    --clean-only      只清理陈旧产物\n'
    printf '\n  %b编排者专属%b（需要 CHENXING_TEST_ROLE=orchestrator）\n' "$CYAN" "$RESET"
    printf '    --full            完整测试套件\n'
    printf '    --gate            完整验证链\n'
    printf '    --clippy          静态检查\n'
    printf '    --coverage        覆盖率门槛\n'
    printf '    --audit           依赖审计\n'
    printf '    -E, --filter EXPR nextest filterset 表达式\n'
    printf '\n  完整说明：./test_sh/test.sh --help\n'
    exit 2
fi

# 规则三：角色和模式是每次运行的第一行输出。
info "角色 ${ROLE} / 模式 --${MODE}"

# 规则二：子代理请求编排者模式直接拒绝。
# -E/--filter 之所以是编排者专属：-E 'all()' 就是全量套件，
# 放开它等于给闸门留一个一行绕过。
if [ "$ROLE" != "orchestrator" ] && [[ "$ORCHESTRATOR_ONLY" == *" $MODE "* ]]; then
    err "--${MODE} 需要 orchestrator 角色，当前角色是 ${ROLE}，已拒绝执行"
    err "编排者请按次内联传入（不要 export）：CHENXING_TEST_ROLE=orchestrator ./test_sh/test.sh --gate"
    err "依据：AGENTS.md「测试执行权限」——子代理不得运行完整测试套件"
    exit 2
fi

# ---------------------------------------------------------------- 模式配置
# CARGO_SCOPE：编译范围。PRUNE_MODE：剪枝判定方式。
# exact 只允许用在完整编译之后——prune_target.py 的 exact 依赖完整的 live
# 清单，受限编译（--lib / --test）的清单不完整，用 exact 会把约 15 GiB
# 合法测试二进制当成陈旧残留删掉。搞反方向的代价极高，这里必须显式。
CARGO_SCOPE=(--all-features)
PRUNE_MODE=heuristic
NEEDS_SERVICES=1

case "$MODE" in
    lib)
        CARGO_SCOPE+=(--lib)
        NEEDS_SERVICES=0 ;;
    test)
        for target in "${TEST_TARGETS[@]}"; do CARGO_SCOPE+=(--test "$target"); done ;;
    clean-only)
        NEEDS_SERVICES=0
        DO_CLEAN=1 ;;   # 模式本身就是清理，--no-clean 在这里没有意义
    full|gate)
        PRUNE_MODE=exact ;;
    filter)
        # 编译范围完整，但 filterset 只跑其中一部分，仍按 heuristic 处理。
        : ;;
    clippy|audit)
        NEEDS_SERVICES=0 ;;
    coverage)
        : ;;   # 覆盖率会跑集成测试，需要 Postgres / Redis
esac

# ---------------------------------------------------------------- 前置检查
command -v cargo >/dev/null || { err "需要 Cargo，请先安装 Rust"; exit 1; }

NEXTEST=1
command -v cargo-nextest >/dev/null 2>&1 || NEXTEST=0

setup_log_dir
LIVE_FILE="$LOG_DIR/artifacts.json"
BUILD_OK=0

load_env

PHASE_MS="$(now_ms)"
if [ "$NEEDS_SERVICES" -eq 1 ]; then
    require_service "$DATABASE_URL" PostgreSQL || exit 1
    require_service "$REDIS_URL" Redis || exit 1
fi
record "环境检查" ok "$(( $(now_ms) - PHASE_MS ))"

# ---------------------------------------------------------------- 分派
maybe_fmt() {
    if [ "$RUN_FMT" -eq 1 ]; then phase_fmt; else record "格式检查" skip 0 "--no-fmt"; fi
}

maybe_prune() {
    if [ "$DO_CLEAN" -eq 1 ]; then phase_prune; else record "清理产物" skip 0 "--no-clean"; fi
}

# 编译失败时测试没有意义，但其余阶段照跑：一次运行报完所有问题。
run_build_and_test() {
    phase_build
    if [ "$BUILD_OK" -eq 1 ]; then
        phase_test
    else
        record "测试" skip 0 "编译未通过"
        PRUNE_MODE=heuristic   # 清单不完整，不能用 exact
    fi
}

case "$MODE" in
    clean-only)
        phase_prune ;;
    lib|test|full|filter)
        maybe_fmt
        run_build_and_test
        maybe_prune ;;
    clippy)
        phase_clippy
        maybe_prune ;;
    coverage)
        phase_coverage
        maybe_prune ;;
    audit)
        phase_audit ;;
    gate)
        maybe_fmt
        phase_check_all
        run_build_and_test
        phase_clippy
        phase_coverage
        phase_audit
        phase_src_limit
        maybe_prune ;;
esac

# artifacts.json 是中间产物（约 470 行 JSON），本身也占空间。
[ "$VERBOSE" -eq 1 ] || rm -f "$LIVE_FILE"

print_summary

if summary_has_failure; then
    err "存在失败项"
    exit 1
fi
ok "全部通过"
exit 0
