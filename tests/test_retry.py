"""模型调用退避重试的单测（2026-09-26 修①）。

背景：Dike pilot 40 样本上 8 次 AI 调用失败（provider 上游 400 ×6、
`Exceeded maximum output retries (3)` ×2），旧实现零重试 → 直接降级成纯规则判定
→ 4 个恶意样本被判 clean。这里盯住三件事：

1. **可重试类错误真的会重试**（上游 400 / 5xx / 网络 / 空响应 / 输出截断）；
2. **确定性错误一次就放弃**（401/403/404、非上游 400）—— 无限重试只会白等；
3. **留痕不许静默**：失败尝试的 tool_calls 要回滚，降级必须写清"试了几次"。
"""
from __future__ import annotations

import random
from pathlib import Path

import httpx
import pytest
from pydantic_ai.exceptions import ModelHTTPError, UnexpectedModelBehavior

from aiav.agent import (
    EmptyAgentResponse,
    RetryPolicy,
    classify_agent_error,
    run_agent_with_retry,
)
from aiav.models import RiskLevel, ScanDeps, Verdict
from aiav.scanner import _degrade_note, merge_retry_infos


def _http(status: int, message: str = "") -> ModelHTTPError:
    return ModelHTTPError(status, "test-model", {"type": "server_error", "message": message})


UPSTREAM_400 = _http(400, "Upstream request failed: Invalid request parameters. "
                          "Please check your input and try again.")


# ---------------------------------------------------------------- 错误分类

@pytest.mark.parametrize("exc,expected", [
    (UPSTREAM_400, (True, "provider_upstream_400")),
    (_http(503, "bad gateway"), (True, "http_503")),
    (_http(429, "slow down"), (True, "http_429")),
    (_http(400, "model `foo` not found"), (False, "http_400_deterministic")),
    (_http(401, "bad key"), (False, "http_401_deterministic")),
    (_http(404, "no such model"), (False, "http_404_deterministic")),
    (UnexpectedModelBehavior("Exceeded maximum output retries (3)"), (True, "output_truncated")),
    (UnexpectedModelBehavior("Model token limit (3000) exceeded before any response"),
     (True, "output_truncated")),
    (UnexpectedModelBehavior("model produced nonsense"), (False, "unexpected_model_behavior")),
    (EmptyAgentResponse("空输出"), (True, "empty_response")),
    (httpx.ConnectError("connection reset"), (True, "network")),
    (httpx.ReadTimeout("timeout"), (True, "network")),
    (ValueError("boom"), (False, "unclassified_ValueError")),
])
def test_classify_agent_error(exc, expected):
    assert classify_agent_error(exc) == expected


# ---------------------------------------------------------------- 退避策略

def test_backoff_is_exponential_and_jittered():
    policy = RetryPolicy(retries=3, base_delay=1.0, max_delay=20.0, jitter=0.3)
    rng = random.Random(7)
    delays = [policy.delay_for(i, rng) for i in (1, 2, 3)]
    # 1s / 2s / 4s ± 30%
    assert 0.7 <= delays[0] <= 1.3
    assert 1.4 <= delays[1] <= 2.6
    assert 2.8 <= delays[2] <= 5.2
    assert policy.max_attempts == 4


def test_backoff_caps_at_max_delay():
    policy = RetryPolicy(retries=10, base_delay=1.0, max_delay=5.0, jitter=0.0)
    assert policy.delay_for(1) == 1.0
    assert policy.delay_for(9) == 5.0


def test_zero_retries_means_one_attempt():
    policy = RetryPolicy(retries=0, base_delay=1.0, max_delay=1.0, jitter=0.0)
    assert policy.max_attempts == 1


# ---------------------------------------------------------------- 重试循环

class _Result:
    def __init__(self, verdict: Verdict) -> None:
        self.output = verdict
        self.usage = None


class _FakeAgent:
    """按脚本依次抛异常/返回结论，并记录每次尝试。"""

    def __init__(self, outcomes: list[object], touch_tools: bool = False) -> None:
        self.outcomes = list(outcomes)
        self.calls = 0
        self.touch_tools = touch_tools

    def run_sync(self, prompt, *, deps, usage_limits):  # noqa: ANN001, ARG002
        self.calls += 1
        if self.touch_tools:
            deps.tool_calls.append({"tool": "fake", "summary": f"attempt {self.calls}"})
        item = self.outcomes.pop(0)
        if isinstance(item, BaseException):
            raise item
        return _Result(item)


def _deps() -> ScanDeps:
    return ScanDeps(file_path=Path("/tmp/x.exe"), sha256="0" * 64)


def _verdict() -> Verdict:
    return Verdict(risk=RiskLevel.suspicious, confidence=0.5, summary="ok")


def _policy(retries: int = 2) -> RetryPolicy:
    return RetryPolicy(retries=retries, base_delay=0.0, max_delay=0.0, jitter=0.0)


def test_retries_upstream_400_then_succeeds_and_records_trace():
    agent = _FakeAgent([UPSTREAM_400, _verdict()])
    deps = _deps()
    verdict, info = run_agent_with_retry(agent, "p", deps, policy=_policy())
    assert verdict.risk is RiskLevel.suspicious
    assert agent.calls == 2
    assert info["attempts"] == 2
    assert info["retried"] is True
    assert info["retry_count"] == 1
    assert info["outcome"] == "ok"
    assert info["failures"][0]["kind"] == "provider_upstream_400"
    assert info["failures"][0]["retryable"] is True
    assert deps.agent_retry is info          # 留痕挂在 deps 上，供 scanner 落库


def test_non_retryable_error_gives_up_immediately():
    agent = _FakeAgent([_http(401, "bad key"), _verdict()])
    deps = _deps()
    with pytest.raises(ModelHTTPError) as excinfo:
        run_agent_with_retry(agent, "p", deps, policy=_policy())
    assert agent.calls == 1                 # 确定性错误不重试
    info = excinfo.value.retry_info
    assert info["attempts"] == 1
    assert info["retried"] is False
    assert info["outcome"] == "degraded_to_rules"
    assert info["failures"][0]["kind"] == "http_401_deterministic"


def test_exhausted_retries_raise_with_degraded_trace():
    agent = _FakeAgent([UPSTREAM_400, UPSTREAM_400, UPSTREAM_400])
    deps = _deps()
    with pytest.raises(ModelHTTPError) as excinfo:
        run_agent_with_retry(agent, "p", deps, policy=_policy(retries=2))
    assert agent.calls == 3                 # 1 次首发 + 2 次重试
    info = excinfo.value.retry_info
    assert info["attempts"] == 3
    assert info["max_attempts"] == 3
    assert info["retry_count"] == 2
    assert info["outcome"] == "degraded_to_rules"
    assert len(info["failures"]) == 3


def test_failed_attempts_do_not_pollute_tool_calls():
    """重试要回滚失败尝试留下的调用链，否则报告里会出现重复记账。"""
    agent = _FakeAgent([UPSTREAM_400, _verdict()], touch_tools=True)
    deps = _deps()
    run_agent_with_retry(agent, "p", deps, policy=_policy())
    assert [c["summary"] for c in deps.tool_calls] == ["attempt 2"]


def test_empty_output_is_retried():
    agent = _FakeAgent([None, _verdict()])
    deps = _deps()
    verdict, info = run_agent_with_retry(agent, "p", deps, policy=_policy())
    assert verdict.risk is RiskLevel.suspicious
    assert info["retry_count"] == 1
    assert info["failures"][0]["kind"] == "empty_response"


def test_output_truncation_is_retried():
    agent = _FakeAgent([UnexpectedModelBehavior("Exceeded maximum output retries (3)"), _verdict()])
    deps = _deps()
    _v, info = run_agent_with_retry(agent, "p", deps, policy=_policy())
    assert info["failures"][0]["kind"] == "output_truncated"
    assert info["retry_count"] == 1


# ---------------------------------------------------------------- 留痕聚合 / 文案

def test_merge_retry_infos_sums_attempts_and_marks_degrade():
    a = {"attempts": 2, "max_attempts": 3, "retried": True, "retry_count": 1,
         "outcome": "ok", "failures": [{"kind": "provider_upstream_400"}]}
    b = {"attempts": 3, "max_attempts": 3, "retried": True, "retry_count": 2,
         "outcome": "degraded_to_rules", "failures": [{"kind": "output_truncated"}],
         "final_error": "boom"}
    merged = merge_retry_infos([a, b])
    assert merged["attempts"] == 5
    assert merged["retry_count"] == 3
    assert merged["retried"] is True
    assert merged["outcome"] == "degraded_to_rules"
    assert merged["final_error"] == "boom"
    assert merged["samples"] == 2
    assert len(merged["failures"]) == 2


def test_merge_retry_infos_passthrough_and_empty():
    one = {"attempts": 1, "outcome": "ok"}
    assert merge_retry_infos([one]) == one
    assert merge_retry_infos([]) == {}
    assert merge_retry_infos([{}, None]) == {}


def test_degrade_note_states_attempts_and_refuses_silence():
    info = {"attempts": 3, "max_attempts": 3, "retry_count": 2,
            "failures": [{"kind": "provider_upstream_400"}, {"kind": "output_truncated"}]}
    note = _degrade_note(UPSTREAM_400, info)
    assert "已尝试 3/3 次" in note
    assert "重试 2 次" in note
    assert "provider_upstream_400" in note
    assert "不是 AI 结论" in note


def test_degrade_note_marks_no_retry_case():
    note = _degrade_note(_http(401, "bad key"),
                         {"attempts": 1, "max_attempts": 3, "retry_count": 0,
                          "failures": [{"kind": "http_401_deterministic"}]})
    assert "未重试" in note
    assert "不可重试" in note
