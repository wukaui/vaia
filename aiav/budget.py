"""Token 预算硬闸：跑之前先估，跑起来实时记账，超了就停（而不是跑到超支才发现）。

三个层次：
1. **事前估算**：`estimate(n_files)` 用「每文件平均 token」× 文件数给出量级，超预算时 CLI 会明确警告；
2. **实时记账**：每次模型调用后把 usage 累加进来（`charge()`），跨文件累计；
3. **硬闸**：`exceeded()` 为真时，后续文件不再调用模型，降级为规则判定并在报告里标注
   （`AI_AV_TOKEN_BUDGET` 设 0 表示不限）。

每文件平均 token 的默认值来自本项目实测口径（一个文件平均 8~12 次工具调用、单次请求数千 token），
可用 `AI_AV_TOKEN_EST_PER_FILE` 覆盖。
"""
from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from typing import Any

DEFAULT_EST_PER_FILE = 12000

#: 单价假设（元 / 百万 token）—— **全项目只在这一处定义**，各脚本 `from budget import` 它。
#: 这是"偏高的一档"，宁可高估也不低估；**价目表不进仓库**（服务商调价 → 只改这一行）。
CNY_PER_MILLION_TOKENS = 8.0

# 进程级锁：TokenBudget 会被多个 worker 线程共享，记账必须原子
_LOCK = threading.Lock()


class _Scope:
    """一次 `token_scope()` 的计数容器（tokens / requests）。"""

    __slots__ = ("_cell",)

    def __init__(self) -> None:
        self._cell = [0, 0]

    def add(self, tokens: int) -> None:
        """记一次调用（调用方必须已持有 _LOCK）。"""
        self._cell[0] += tokens
        if tokens:
            self._cell[1] += 1

    @property
    def tokens(self) -> int:
        return self._cell[0]

    @property
    def requests(self) -> int:
        return self._cell[1]

    def as_dict(self) -> dict[str, int]:
        return {"tokens": self._cell[0], "requests": self._cell[1]}


def _usage_tokens(usage: Any) -> int:
    """从 pydantic_ai 的 usage 对象里取总 token（兼容不同版本字段名，也接受 dict）。"""
    if usage is None:
        return 0

    def get(attr: str) -> Any:
        if isinstance(usage, dict):
            return usage.get(attr)
        return getattr(usage, attr, None)

    for attr in ("total_tokens", "total"):
        value = get(attr)
        if isinstance(value, int) and value > 0:
            return value
    total = 0
    for attr in ("request_tokens", "response_tokens", "input_tokens", "output_tokens"):
        value = get(attr)
        if isinstance(value, int):
            total += value
    return total


class TokenBudget:
    def __init__(self, limit: int = 0, est_per_file: int | None = None) -> None:
        self.limit = max(0, int(limit or 0))
        try:
            self.est_per_file = int(est_per_file or os.getenv("AI_AV_TOKEN_EST_PER_FILE",
                                                              str(DEFAULT_EST_PER_FILE)))
        except ValueError:
            self.est_per_file = DEFAULT_EST_PER_FILE
        self.used = 0
        self.requests = 0
        self.files_charged = 0
        self.skipped_files = 0
        # token_scope() 的当前作用域：**线程局部** —— 多 worker 并发扫不同文件时
        # 每个线程必须有自己的一份，否则会被别的线程覆盖（实测 Σ单文件只有全局的 0.75×）
        self._local = threading.local()

    # ---------------- 状态 ----------------
    @property
    def unlimited(self) -> bool:
        return self.limit <= 0

    @property
    def remaining(self) -> int:
        return -1 if self.unlimited else max(0, self.limit - self.used)

    def exceeded(self) -> bool:
        return (not self.unlimited) and self.used >= self.limit

    # ---------------- 记账 ----------------
    def estimate(self, n_files: int) -> dict[str, Any]:
        est = max(0, int(n_files)) * self.est_per_file
        return {"files": int(n_files), "est_per_file": self.est_per_file,
                "est_tokens": est, "limit": self.limit, "unlimited": self.unlimited,
                "exceeds": (not self.unlimited) and est > self.limit}

    def charge(self, usage: Any) -> int:
        tokens = _usage_tokens(usage)
        self.used += tokens
        if tokens:
            self.requests += 1
        return tokens

    def note_file(self) -> None:
        self.files_charged += 1

    def note_skipped(self) -> None:
        self.skipped_files += 1

    # ---------------- 并发安全的"单文件增量"记账 ----------------
    def charge_scoped(self, usage: Any) -> int:
        """在 `token_scope()` 内记账：全局 `used`/`requests` 与"当前文件增量"同时更新。

        为什么要有这个方法（2026-09-20 修）：调用方以前用
        `before = budget.used` … `used = budget.used - before` 统计"单个文件花了多少"，
        但 `budget.used` 是**全局单计数器**、多个 worker 共享 —— 窗口互相重叠，
        每个文件把别人同期的增量也算进自己头上（实测 Σ单文件 = 3.3~3.5 × 全局真实值）。
        这个差值**只能虚高、不可能偏低**，所以历史产物里的"逐文件 token"只是**上界**。

        正确做法：让"全局记账"和"本次增量"在同一次加锁里完成。
        """
        tokens = _usage_tokens(usage)
        scope = getattr(self._local, "scope", None)
        with _LOCK:
            self.used += tokens
            if tokens:
                self.requests += 1
            if scope is not None:
                scope.add(tokens)
        return tokens

    @contextmanager
    def token_scope(self):
        """`with budget.token_scope() as scope:` → 退出后 `scope.tokens` / `scope.requests`。

        嵌套时内层独立计数（外层仍会累加内层消耗，符合"这一个文件总共花了多少"的语义）。
        """
        scope = _Scope()
        previous = getattr(self._local, "scope", None)
        self._local.scope = scope
        try:
            yield scope
        finally:
            self._local.scope = previous

    def as_dict(self) -> dict[str, Any]:
        return {
            "limit": self.limit,
            "unlimited": self.unlimited,
            "used_tokens": self.used,
            "remaining_tokens": self.remaining,
            "requests": self.requests,
            "files_charged": self.files_charged,
            "files_skipped_by_budget": self.skipped_files,
            "est_per_file": self.est_per_file,
        }


def budget_from_env() -> TokenBudget:
    try:
        limit = int(os.getenv("AI_AV_TOKEN_BUDGET", "0"))
    except ValueError:
        limit = 0
    return TokenBudget(limit=limit)
