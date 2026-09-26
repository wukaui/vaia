#!/usr/bin/env python3
"""Windows 侧源码运行入口（开发/联调用）。

在 Windows 的 Python 上跑 aiav 时，依赖只用 win_amd64 wheel 解到 WSL 侧一个目录
（不污染 Windows 全局环境），本脚本负责把依赖目录和项目根目录加进 sys.path。

从 WSL 侧调用（实测用的就是这条）：

    /mnt/d/tools_for_python/python3.13/python.exe "$(wslpath -w scripts/win_dev_launch.py)" \
        scan "$(wslpath -w <目标目录>)" --no-ai -o "$(wslpath -w <输出目录>)"

依赖目录默认取「项目根目录的上一级 / ai-av-win-deps」，可用 AI_AV_WIN_DEPS 覆盖。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEPS_DIR = Path(os.getenv("AI_AV_WIN_DEPS", str(PROJECT_ROOT.parent / "ai-av-win-deps")))

for _p in (str(DEPS_DIR), str(PROJECT_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# 控制台按 UTF-8 输出，避免 Windows 代码页把中文和 rich 边框打成乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

if __name__ == "__main__":
    if not DEPS_DIR.is_dir():
        print(f"[!] 依赖目录不存在: {DEPS_DIR}（可用 AI_AV_WIN_DEPS 指定）", file=sys.stderr)
    from aiav.cli import app

    app()
