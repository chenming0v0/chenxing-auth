#!/usr/bin/env bash
# 辰星认证中枢 - 启动前后端（不碰 Docker）
# 前置条件：PostgreSQL 和 Redis 已在运行（见 ./dev-docker.sh）
# Ctrl+C 只停止前后端，Docker 容器保持运行
set -euo pipefail

# 开启作业控制：每个后台任务成为独立进程组的组长。
# 这样 kill -TERM -$PID 能带走整组，cargo 的子进程（真正监听端口的 server）
# 和 npm 的子进程（vite）都会退出，不会留下占用 3000 / 5175 的孤儿进程。
set -m

cd "$(dirname "$0")"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
info() { echo -e "${CYAN}[辰星]${RESET} $1"; }
ok()   { echo -e "${GREEN}[辰星]${RESET} $1"; }
warn() { echo -e "${YELLOW}[辰星]${RESET} $1"; }
err()  { echo -e "${RED}[辰星]${RESET} $1" >&2; }

BACKEND_PID=""
FRONTEND_PID=""

stop_group() {
    local label="$1" pid="$2"
    [ -n "$pid" ] || return 0
    info "停止${label} (进程组 ${pid})"
    kill -TERM "-${pid}" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

cleanup() {
    trap - EXIT INT TERM
    echo
    warn "正在停止前后端..."
    stop_group 前端 "$FRONTEND_PID"
    stop_group 后端 "$BACKEND_PID"
    ok "前后端已停止（Docker 服务未受影响）"
}
trap cleanup EXIT INT TERM

command -v cargo >/dev/null || { err "需要 Cargo，请先安装 Rust"; exit 1; }
command -v npm   >/dev/null || { err "需要 npm，请先安装 Node.js"; exit 1; }

if [ ! -f .env ]; then
    warn ".env 不存在，从 .env.example 复制，请按本地环境检查配置"
    cp .env.example .env
fi

# 后端端口由 .env 的 APP_PORT 决定，缺失时回落到 3000
APP_PORT="$(sed -n 's/^APP_PORT=//p' .env | tail -1)"
APP_PORT="${APP_PORT:-3000}"

# migrate 会顺带完成编译，因此它同时是编译门禁，不需要额外 cargo build。
# 失败原因直接透传，不吞 stderr。
info "运行数据库迁移（同时编译后端）..."
if ! cargo run --quiet -- migrate; then
    err "迁移失败。若是连接错误，请先启动基础设施：./dev-docker.sh"
    exit 1
fi
ok "数据库迁移完成"

echo
info "启动后端 (端口 ${APP_PORT})..."
cargo run --quiet &
BACKEND_PID=$!

info "等待后端就绪..."
backend_ready=0
for _ in $(seq 30); do
    if curl -sf "http://localhost:${APP_PORT}/health" >/dev/null 2>&1; then
        backend_ready=1
        ok "后端已就绪"
        break
    fi
    # 后端已经退出就不必再等
    kill -0 "$BACKEND_PID" 2>/dev/null || break
    sleep 1
done
[ "$backend_ready" -eq 1 ] || warn "后端健康检查未通过，请看上方日志"

info "启动前端 (端口 5175)..."
(cd web && npm run dev) &
FRONTEND_PID=$!

echo
ok "======================================"
ok "  服务已启动"
ok "======================================"
info "前端:     http://localhost:5175"
info "后端:     http://localhost:${APP_PORT}"
info "健康检查: http://localhost:${APP_PORT}/health"
echo
warn "按 Ctrl+C 停止前后端（Docker 保持运行）"
echo

# 任一服务退出就收工，由 trap 收拾另一个，避免留下半死状态
wait -n
warn "有服务已退出"
