"""报告层重试留痕的单测（2026-09-26 修①）。

要求原话：「报告里要能看出这次判定"用过重试"还是"最终降级到规则"，不许静默降级装正常」。
所以这里盯的是报告**聚合数字**与**HTML 可见性**，不是重试逻辑本身。
"""
from __future__ import annotations

from aiav.models import FileReport, RiskLevel, Verdict
from aiav.report import build_summary, _render_html


def _report(name: str, risk: RiskLevel = RiskLevel.clean, retry: dict | None = None,
            error: str | None = None, agent_used: bool = True) -> FileReport:
    return FileReport(
        path=f"/tmp/{name}", sha256="0" * 64, size=10, extension=".exe",
        prefilter_score=5, verdict=Verdict(risk=risk, confidence=0.5, summary="s"),
        agent_used=agent_used, error=error, agent_retry=retry or {},
    )


OK_RETRY = {"attempts": 2, "max_attempts": 3, "retried": True, "retry_count": 1,
            "outcome": "ok", "failures": [{"kind": "provider_upstream_400", "retryable": True}]}
DEGRADED = {"attempts": 3, "max_attempts": 3, "retried": True, "retry_count": 2,
            "outcome": "degraded_to_rules", "failures": [{"kind": "provider_upstream_400"},
                                                         {"kind": "output_truncated"}]}


def test_summary_counts_retry_and_degrade():
    reports = [
        _report("a.exe", retry=OK_RETRY),
        _report("b.exe", retry=DEGRADED, error="Agent 调用失败，已降级到规则判定（…）"),
        _report("c.exe"),                                  # 一次过
        _report("d.exe", retry=None, agent_used=False),     # 没走 AI
    ]
    summary = build_summary(reports)
    assert summary["retry"]["files_with_retry"] == 2
    assert summary["retry"]["retry_count"] == 3
    assert summary["retry"]["files_degraded"] == 1
    assert summary["retry"]["failure_kinds"]["provider_upstream_400"] == 2
    assert summary["retry"]["failure_kinds"]["output_truncated"] == 1


def test_html_surfaces_retry_and_degrade():
    reports = [_report("a.exe", retry=OK_RETRY), _report("b.exe", retry=DEGRADED, error="降级了")]
    html = _render_html(reports, build_summary(reports))
    assert "只看降级到规则" in html            # 可筛选
    assert "data-degraded=\"1\"" in html
    assert "最终降级到规则判定" in html
    assert "不是 AI 结论" in html              # 抬头说明里点名降级文件的 risk 不是 AI 给的
    assert "用过重试" in html


def test_html_without_retry_has_no_retry_banner():
    reports = [_report("c.exe")]
    html = _render_html(reports, build_summary(reports))
    assert "模型调用重试：" not in html
    assert "最终降级到规则判定" not in html
