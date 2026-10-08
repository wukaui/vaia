#!/usr/bin/env bash
# 本地启动 AI AV Web UI（只绑 127.0.0.1）。
#   scripts/run_web.sh            # 默认 127.0.0.1:8080
#   AI_AV_WEB_PORT=9000 scripts/run_web.sh
# 依赖可选组：  .venv/bin/python -m pip install -e ".[web]"
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PY:-.venv/bin/python}"
HOST="${AI_AV_WEB_HOST:-127.0.0.1}"
PORT="${AI_AV_WEB_PORT:-8080}"
echo "Web UI: http://${HOST}:${PORT}  （Ctrl-C 停）"
exec "$PY" -m uvicorn aiav.web.app:app --host "$HOST" --port "$PORT"
