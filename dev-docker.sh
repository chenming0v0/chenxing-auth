#!/usr/bin/env bash
# 辰星认证中枢 - 启动 Docker 基础设施（PostgreSQL + Redis）
# 分离模式启动，脚本退出后容器继续运行；停止用 docker compose down
set -euo pipefail

cd "$(dirname "$0")"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
info() { echo -e "${CYAN}[辰星]${RESET} $1"; }
ok()   { echo -e "${GREEN}[辰星]${RESET} $1"; }
warn() { echo -e "${YELLOW}[辰星]${RESET} $1"; }
err()  { echo -e "${RED}[辰星]${RESET} $1" >&2; }

command -v docker >/dev/null || { err "需要 Docker"; exit 1; }

# docker compose 也从 .env 读 POSTGRES_*，先保证它存在且密钥合法
# shellcheck source=dev-env.sh
source ./dev-env.sh
chenxing_ensure_env .env

info "启动 PostgreSQL 和 Redis..."
docker compose up -d postgres redis

# 轮询就绪，而不是盲等固定秒数
wait_ready() {
    local name="$1"; shift
    for _ in $(seq 30); do
        if "$@" >/dev/null 2>&1; then
            ok "${name} 已就绪"
            return 0
        fi
        sleep 1
    done
    err "${name} 启动超时，请查看 docker compose logs ${name}"
    return 1
}

wait_ready postgres docker compose exec -T postgres pg_isready -U chenxing -d chenxing_auth
wait_ready redis docker compose exec -T redis redis-cli ping

echo
ok "Docker 基础设施已启动"
info "PostgreSQL: localhost:5432"
info "Redis:      localhost:6379"
info "停止服务：docker compose down"
