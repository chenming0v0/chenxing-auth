#!/usr/bin/env bash
# 辰星认证中枢 - 一键启动完整开发环境
# = dev-docker.sh（基础设施）+ dev-services.sh（前后端）
# Ctrl+C 只停止前后端，Docker 容器保持运行，停止用 docker compose down
set -euo pipefail

cd "$(dirname "$0")"

./dev-docker.sh
echo
exec ./dev-services.sh
