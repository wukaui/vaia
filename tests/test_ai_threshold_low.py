"""两档送审（2026-09-27）—— 门槛拆成高档 / 低档这一处的回归测试。

守四件事（每一条都是"读产物的人会看错"的地方）：

  1. **路由**：分数落在 `[低档, 高档)` 的文件**真的送 AI**，`< 低档` 的还是静默放行；
     `--ai-threshold-low 0` = 关掉低档（退回单档行为）。
  2. **报告字段**：产物里能区分三类（`high` / `low` / `none`），且**确定性结案的文件
     不许被算成送审**（它的分数可能 ≥1000，按分数算会记成 high —— 那是假的）。
  3. **缓存键**：两个闸门进指纹。少了它，先跑的基线档会把"未送审"的结论喂给两档档，
     低档那批文件被静默跳过（与"AV 库指纹进缓存键"同一类坑）。
  4. **置信度**：低档这一档的 AI 置信度在报告抬头可见（`low_tier.confidence_*`），
     逐文件行的置信度标出是 AI 给的还是规则兜底给的。

一个模型调用都不发：用假 agent 顶掉 `analyze_file_with_agent`，只验路由与产物。
"""

from __future__ import annotations

from pathlib import Path

from aiav import criteria as C
from aiav import scanner
from aiav.cache import ScanCache
from aiav.models import RiskLevel, Verdict

# ------------------------------------------------------------------ 门槛本身


def test_effective_low_gate_normalises_both_ends() -> None:
    """`0` = 关掉低档；低档 ≥ 高档 = 低档不存在；正常情况取小的那个。"""
    assert C.effective_low_gate(300, 225) == 225
    assert C.effective_low_gate(300, 0) == 300          # 关掉低档
    assert C.effective_low_gate(300, -5) == 300
    assert C.effective_low_gate(300, 500) == 300        # 低档比高档还高 = 不放人进来
    assert C.effective_low_gate(0, 225) == 0            # 全送审档：低档无意义


def test_ai_tier_three_classes() -> None:
    assert C.ai_tier(300) == "high"
    assert C.ai_tier(1125) == "high"
    assert C.ai_tier(299) == "low"
    assert C.ai_tier(225) == "low"
    assert C.ai_tier(224) == "none"
    assert C.ai_tier(0) == "none"
    # 低档关掉时，275 分退回"未送"
    assert C.ai_tier(275, gate_low=0) == "none"


def test_decide_routes_low_band_to_ai() -> None:
    """纯函数层：275 分在 [225, 300) 里，处置必须是 `send_ai`（也送 AI）。"""
    from aiav.criteria import CriterionHit

    hits = [CriterionHit("HIGH_RISK_EXTENSION", "高风险扩展名", 1, ()),
            CriterionHit("STRUCT_TEXT_RATIO", "代码段占比失衡", 1, ())]
    total, _scored, _clean = C.file_score(hits)
    assert total == 275                      # 125 + 150：低档的典型分数

    default = C.decide(hits)                 # 默认：高档 300 / 低档 225
    assert default.disposition.value == "send_ai"
    assert default.sends_to_ai is True
    assert any("低档送审闸门" in r for r in default.reasons)

    off = C.decide(hits, gate_low=0)         # 关掉低档 = 旧行为
    assert off.disposition.value == "pass"
    assert off.sends_to_ai is False

    high = C.decide(hits, gate=225)          # 高档压到 225：还是送，但不再算"低档"
    assert high.disposition.value == "send_ai"
    assert not any("低档送审闸门" in r for r in high.reasons)


def test_decide_high_band_unchanged() -> None:
    """>= 高档的文件行为一个字没变（两档不是把高档也改了）。"""
    from aiav.criteria import CriterionHit

    hits = [CriterionHit("HIGH_RISK_EXTENSION", "高风险扩展名", 1, ()),
            CriterionHit("STRUCT_TEXT_RATIO", "代码段失衡", 1, ()),
            CriterionHit("STRUCT_SPARSE_IMPORTS", "导入表稀疏", 1, ())]
    v = C.decide(hits)
    assert C.file_score(hits)[0] == 425
    assert v.disposition.value == "send_ai"
    assert not any("低档送审闸门" in r for r in v.reasons)


# ------------------------------------------------------------------ 预筛字段

def _plain_exe(tmp_path: Path) -> tuple[Path, str]:
    """.exe 只靠"高风险扩展名"就是 125 分（判据表里的定值）。"""
    p = tmp_path / "plain.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    return p, scanner.compute_sha256(p)


def test_prefilter_reports_low_gate_and_tier(tmp_path) -> None:
    p, sha = _plain_exe(tmp_path)
    ev = scanner.quick_prefilter(p, sha)
    assert ev.prefilter_score == 125
    det = ev.deterministic
    assert det["gate"] == 300 and det["gate_low"] == 225
    assert det["ai_tier"] == "none" and det["disposition"] == "pass"   # 125 < 225：静默

    # 低档线压到 125：同一个文件变成"低档送审"
    ev2 = scanner.quick_prefilter(p, sha, ai_threshold_low=125)
    assert ev2.deterministic["disposition"] == "send_ai"
    assert ev2.deterministic["ai_tier"] == "low"
    assert ev2.deterministic["gate_low"] == 125

    # 关掉低档：又回到"未结案"
    ev3 = scanner.quick_prefilter(p, sha, ai_threshold_low=0)
    assert ev3.deterministic["disposition"] == "pass"
    assert ev3.deterministic["ai_tier"] == "none"
    assert ev3.deterministic["gate_low"] == 300


def test_closed_files_are_never_labelled_sent(tmp_path) -> None:
    """确定性结案的文件（分数可能 ≥1000）不许被算成"高档送审"。"""
    import json

    p, sha = _plain_exe(tmp_path)
    truth = tmp_path / "whitelist.json"
    truth.write_text(json.dumps({sha: "测试白名单"}), encoding="utf-8")
    import os

    os.environ["AI_AV_WHITELIST"] = str(truth)
    try:
        ev = scanner.quick_prefilter(p, sha)
    finally:
        os.environ.pop("AI_AV_WHITELIST", None)
    if ev.deterministic["disposition"] == "closed_clean":
        assert ev.deterministic["ai_tier"] == "none"
        assert ev.deterministic["sends_to_ai"] is False


# ------------------------------------------------------------------ 路由（scan_file）

def test_scan_file_sends_low_band_to_agent(tmp_path, monkeypatch) -> None:
    """275 分的文件在默认两档配置下**真的会调 agent**；关掉低档就不调。"""
    monkeypatch.setenv("AI_AV_CACHE", "0")
    monkeypatch.setenv("AI_AV_SIGNATURE_CHECK", "0")
    p = tmp_path / "t.exe"
    p.write_bytes(b"MZ" + b"\x01" * 64)
    monkeypatch.setattr(scanner, "quick_prefilter",
                        lambda *a, **k: _stub_evidence(str(p), 275, k))
    called: list[int] = []

    def fake_analyze(agent, deps, evidence, budget=None, preload=None):
        called.append(evidence.prefilter_score)
        return Verdict(risk=RiskLevel.clean, confidence=0.77, category="clean", summary="ok")

    monkeypatch.setattr(scanner, "analyze_file_with_agent", fake_analyze)

    two_tier = scanner.scan_file(p, agent=object(), ai_threshold=300, ai_threshold_low=225,
                                store=None, allow_unpack=False, allow_archives=False,
                                cache=None, deep_evidence_threshold=0)
    assert called == [275]
    assert two_tier.deterministic["ai_tier"] == "low"
    assert two_tier.agent_used is True

    called.clear()
    single = scanner.scan_file(p, agent=object(), ai_threshold=300, ai_threshold_low=0,
                               store=None, allow_unpack=False, allow_archives=False,
                               cache=None, deep_evidence_threshold=0)
    assert called == []                     # 低档关掉：这个文件不送审
    assert single.deterministic["ai_tier"] == "none"
    assert single.agent_used is False


def _stub_evidence(path: str, score: int, kwargs: dict):
    """替掉 `quick_prefilter` 的最小证据块（只带两档路由要看的那几个字段）。"""
    from aiav.models import PreliminaryEvidence

    gate = kwargs.get("ai_threshold") or 300
    gate_low = kwargs.get("ai_threshold_low")
    gate_low = C.AI_GATE_LOW if gate_low is None else gate_low
    low = C.effective_low_gate(int(gate), int(gate_low))
    return PreliminaryEvidence(
        path=path, sha256="a" * 64, size=66, extension=".exe", prefilter_score=score,
        deterministic={
            "disposition": "send_ai" if score >= low else "pass",
            "tier": "weak", "band": "suspicious", "band_label": "可疑", "score": score,
            "sends_to_ai": score >= low, "reasons": ["（测试桩）"],
            "gate": int(gate), "gate_low": low,
            "ai_tier": C.ai_tier(score, gate=int(gate), gate_low=int(gate_low))
            if score >= low else "none",
        },
    )


# ------------------------------------------------------------------ 缓存键

def test_cache_mode_includes_both_gates() -> None:
    """两个闸门必须进指纹：否则两档档会命中基线档的旧结论（低档被静默跳过）。"""
    base = ScanCache.mode(True, True, True)
    two_tier = ScanCache.mode(True, True, True, ai_threshold=300, ai_threshold_low=225)
    single = ScanCache.mode(True, True, True, ai_threshold=300, ai_threshold_low=0)
    other_high = ScanCache.mode(True, True, True, ai_threshold=200, ai_threshold_low=225)
    assert two_tier != single and two_tier != other_high
    assert "gate=300" in two_tier and "gate_low=225" in two_tier
    # 老调用点（不传闸门）指纹不变 —— 缓存键与旧条目保持一致
    assert base == ScanCache.mode(True, True, True, ai_threshold=None, ai_threshold_low=None)


# ------------------------------------------------------------------ 报告

def test_report_summary_separates_the_two_tiers(tmp_path, monkeypatch) -> None:
    """报告抬头/账本要能把三类送审分开数，并写出低档的 AI 置信度。"""
    from aiav.report import build_summary, write_reports

    monkeypatch.setenv("AI_AV_CACHE", "0")
    monkeypatch.setenv("AI_AV_SIGNATURE_CHECK", "0")

    def mk(name: str, score: int, gate_low: int, risk: RiskLevel, conf: float,
           used: bool, tmp: Path):
        p = tmp / name
        p.write_bytes(b"MZ" + bytes([score % 251]) * 64)
        return scanner.scan_file(p, agent=None, ai_threshold=300, ai_threshold_low=gate_low,
                                 store=None, allow_unpack=False, allow_archives=False,
                                 cache=None)

    # 直接造 FileReport 更省事：这里要验的是聚合口径，不是扫描本身
    from aiav.models import FileReport

    def rep(score: int, tier: str, risk: RiskLevel, conf: float, used: bool) -> FileReport:
        return FileReport(
            path=f"/x/{score}-{tier}-{risk.value}.exe", sha256=f"{score:064d}"[:64],
            size=1, extension=".exe", prefilter_score=score,
            deterministic={"disposition": "send_ai" if tier != "none" else "pass",
                           "tier": "weak", "band": "suspicious", "band_label": "可疑",
                           "score": score, "sends_to_ai": tier != "none", "reasons": [],
                           "gate": 300, "gate_low": 225, "ai_tier": tier},
            verdict=Verdict(risk=risk, confidence=conf, category="test", summary="x"),
            agent_used=used,
        )

    reports = [
        rep(425, "high", RiskLevel.malicious, 0.61, True),
        rep(275, "low", RiskLevel.malicious, 0.62, True),     # 低档抓到恶意
        rep(275, "low", RiskLevel.suspicious, 0.42, True),    # 低档里被判 flag 的良性
        rep(275, "low", RiskLevel.clean, 0.71, True),
        rep(125, "none", RiskLevel.clean, 0.65, False),
    ]
    s = build_summary(reports)["deterministic"]
    assert s["gate"] == 300 and s["gate_low"] == 225
    assert s["sent_high"] == 1 and s["sent_low"] == 3
    assert s["sent"] == 4 and s["send_rate"] == 0.8
    assert s["ai_tiers"] == {"high": 1, "low": 3, "none": 1}
    assert s["low_tier"]["files"] == 3 and s["low_tier"]["ai_files"] == 3
    assert s["low_tier"]["flagged"] == 2
    assert s["low_tier"]["confidence_mean"] == round((0.62 + 0.42 + 0.71) / 3, 3)
    assert s["low_tier"]["confidence_min"] == 0.42
    assert s["low_tier"]["confidence_max"] == 0.71

    _json, html, _audit = write_reports(reports, tmp_path / "out")
    text = html.read_text(encoding="utf-8")
    assert "两档送审" in text
    assert "低档送审" in text                      # 逐文件行的档位标签
    assert "AI 置信度" in text                      # 抬头把低档的置信度写出来了
    assert "只看低档送审" in text                    # 工具栏能筛
    assert "data-tier=\"low\"" in text


def test_report_head_keeps_baseline_numbers_when_low_gate_off(tmp_path) -> None:
    """关掉低档时，报告抬头要明说"低档已关闭"，不许假装有两档。"""
    from aiav.models import FileReport
    from aiav.report import build_summary, write_reports

    def rep(score: int, tier: str) -> FileReport:
        return FileReport(
            path=f"/x/{score}.exe", sha256=f"{score:064d}"[:64], size=1, extension=".exe",
            prefilter_score=score,
            deterministic={"disposition": "send_ai" if tier != "none" else "pass",
                           "tier": "weak", "band": "suspicious", "band_label": "可疑",
                           "score": score, "sends_to_ai": tier != "none", "reasons": [],
                           "gate": 300, "gate_low": 300, "ai_tier": tier},
            verdict=Verdict(risk=RiskLevel.clean, confidence=0.5, category="test", summary="x"),
            agent_used=tier != "none",
        )

    reports = [rep(425, "high"), rep(275, "none")]
    s = build_summary(reports)["deterministic"]
    assert s["sent_high"] == 1 and s["sent_low"] == 0
    _json, html, _audit = write_reports(reports, tmp_path / "out")
    assert "低档已关闭" in html.read_text(encoding="utf-8")
