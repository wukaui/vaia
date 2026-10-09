"""pytest 全局隔离：每条用例一个独立状态目录（2026-09-29 修）。

**为什么必须钉在这里**：`scan_file(..., cache=None)` 不是"不用缓存"。`cache=None` 时
`scan_file` 走到 `cache_enabled()`（`AI_AV_CACHE` 默认 `1`）→ 用**默认状态目录**
（`~/ai-av-bench/ai-av-state`，生产的那一份）建 `ScanCache`。

后果（实测）：`tests/test_triage_pipeline.py` 每条用例写的桩文件内容都是
`b"MZ" + b"\x01" * 64`，缓存键是**内容 sha256**，于是第一条用例真跑完写进生产的
那条报告，被后面 5 条原样读走 —— `agent_used=True`、`triage.score=80（别的用例的分数）`、
假深度 AI 一次都没被调（缓存命中，根本没走到那一步）。5 条恒红，且红的原因跟被测代码
无关：**②层初筛唯一的回归护栏就这么废了**（入口 / 路由 / 报告字段 / 成本四件事全靠它们）。
铁证是缓存里那条 `path=/tmp/pytest-of-wukuai/pytest-7/test_triage_selected_.../t.exe`。

所以：测试**不许**碰生产状态目录 —— 缓存、白名单、隔离区、历史、初筛缓存全部跟着
`AI_AV_STATE_DIR` 走，钉进用例自己的 `tmp_path` 即可全隔离。
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_state_dir(tmp_path, monkeypatch):
    """把 aiav 的状态目录钉在本用例的 `tmp_path` 下（`default_store()` 按环境变量懒加载）。

    显式清掉那几个外部覆盖，免得外面 shell / CI 里设过就串进来 —— 状态目录跟着环境变量
    漂移过一次（跨 `--state-dir` 命中缓存），这类"串味"一律按同一原则挡掉。
    """
    state = tmp_path / "aiav-state"
    monkeypatch.setenv("AI_AV_STATE_DIR", str(state))
    monkeypatch.delenv("AI_AV_CACHE_DIR", raising=False)        # 扫描缓存
    monkeypatch.delenv("AI_AV_TRIAGE_CACHE_DIR", raising=False)  # ②层初筛缓存
    monkeypatch.delenv("AI_AV_WHITELIST", raising=False)
    return state
