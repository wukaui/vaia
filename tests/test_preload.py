"""确定性证据前置（2026-09-27）的单元测试。

覆盖四件事：
  1. 按类型挑工具（非 PE 不跑 capa/floss、非脚本不跑 script_analyze、无宏容器不跑宏分析）
  2. 去重（signature_verify 每个文件只算一次，且复用预筛采的那一份）
  3. 送审渲染口径（给事实不给判断：不出现预筛分数 / strong·weak 分档）
  4. 留痕口径（预采集不算 AI 的工具调用次数；证据仍能被 attribute_evidence 对上）

所有测试都用**假的工具实现**（`_TOOL_FUNCS` 打桩），不真的跑 capa/floss ——
单测要的是"编排对不对"，不是"capa 准不准"（那是评测集的事）。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiav import preload
from aiav.models import PreliminaryEvidence, ScanDeps, Verdict, RiskLevel
from aiav.scanner import (
    _collect_preload,
    attribute_evidence,
    ai_tool_calls,
    find_repetition_warnings,
    prompt_fact_texts,
)


# ---------------------------------------------------------------- 打桩

@pytest.fixture
def fake_tools(monkeypatch):
    """把预采集要调的工具换成固定输出的桩，并假装 capa/floss 都可用。"""
    calls: list[str] = []

    def make(name: str):
        def _fn(ctx):
            calls.append(name)
            # 载荷故意做大一点（约 300 字符）：预算/裁剪那几条测试要真的超预算才有效
            return json.dumps({"tool": name, "file": Path(ctx.deps.file_path).name,
                               "padding": "x" * 260}, ensure_ascii=False)
        return _fn

    monkeypatch.setattr(preload, "_TOOL_FUNCS", {
        name: make(name) for name in
        ("pe_analyze", "strings_ioc", "capa_scan", "floss_scan",
         "script_analyze", "office_macro_analyze", "pdf_analyze")
    })
    monkeypatch.setattr(preload, "capa_ready", lambda: (True, ""))
    monkeypatch.setattr(preload, "_find_exe", lambda *a, **k: "/usr/bin/fake")
    return calls


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


# ---------------------------------------------------------------- 1. 类型识别与工具挑拣

@pytest.mark.parametrize("name,data,kind", [
    ("a.exe", b"MZ\x90\x00rest", "pe"),
    ("a.dat", b"MZ\x90\x00rest", "pe"),                 # 魔数优先于扩展名
    ("b.pdf", b"%PDF-1.7\n", "pdf"),
    ("c.ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00", "ole"),
    ("d.ps1", b"Write-Host hi", "script"),
    ("e.docm", b"PK\x03\x04zzz", "ole"),
    ("f.bin", b"\x00\x01\x02\x03", "other"),
])
def test_detect_kind(tmp_path, name, data, kind):
    assert preload.detect_kind(_write(tmp_path / name, data)) == kind


def test_pe_gets_pe_tools_and_no_script_tool(tmp_path, fake_tools):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    tools, skipped = preload.plan_tools("pe", p)
    assert tools == ["signature_verify", "pe_analyze", "strings_ioc", "capa_scan", "floss_scan"]
    assert any("script_analyze" in s for s in skipped)


def test_non_pe_does_not_run_capa_or_floss(tmp_path, fake_tools):
    p = _write(tmp_path / "x.ps1", b"Write-Host hi")
    tools, skipped = preload.plan_tools("script", p)
    assert "capa_scan" not in tools and "floss_scan" not in tools
    assert "script_analyze" in tools
    assert any("capa_scan" in s for s in skipped) and any("floss_scan" in s for s in skipped)


def test_ole_without_macro_storage_skips_macro_analysis(tmp_path, fake_tools, monkeypatch):
    """无宏的容器不跑宏反混淆 —— 但要把探针结果**当成一条证据**给出去。

    第一版把这条丢进"没跑"清单，实测 AI 会自己去补调 `office_macro_analyze`
    （5/40 个文件），每次都只拿回 has_macros=false，白花一整个往返。
    """
    p = _write(tmp_path / "x.ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00")
    monkeypatch.setattr(preload, "_macro_storage_probe", lambda _p: False)
    tools, skipped = preload.plan_tools("ole", p)
    assert "office_macro_analyze" not in tools

    result = preload.collect(p, "9" * 64, {}, kind="ole")
    macro = [e for e in result["entries"] if e["tool"] == "office_macro_analyze"]
    assert len(macro) == 1, "探针结果必须以一条 office_macro_analyze 证据的形式给出去"
    assert json.loads(macro[0]["payload"])["has_macros"] is False
    assert "XLM" in macro[0]["payload"]


def test_ole_with_macro_storage_runs_macro_analysis(tmp_path, fake_tools, monkeypatch):
    p = _write(tmp_path / "x.ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\x00")
    monkeypatch.setattr(preload, "_macro_storage_probe", lambda _p: True)
    tools, _ = preload.plan_tools("ole", p)
    assert "office_macro_analyze" in tools


# ---------------------------------------------------------------- 2. 去重

def test_signature_collected_once_from_prefilter(tmp_path, fake_tools):
    """签名证据复用预筛那一份：不进工具调用，也不会出现两次。"""
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    sig = {"status": "unknown", "conclusion": "no_embedded_signature"}
    result = preload.collect(p, "a" * 64, sig, kind="pe")
    sig_entries = [e for e in result["entries"] if e["tool"] == "signature_verify"]
    assert len(sig_entries) == 1
    assert sig_entries[0]["source"] == "prefilter"
    # 桩工具里没有 signature_verify，说明确实没再跑一遍
    assert "signature_verify" not in fake_tools
    assert [c["tool"] for c in result["calls"]].count("signature_verify") == 1


def test_collect_tags_every_entry_with_source_tool(tmp_path, fake_tools):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    result = preload.collect(p, "b" * 64, {"status": "unknown"}, kind="pe")
    assert result["policy"] == "by_type"
    for entry in result["entries"]:
        assert entry["tool"] and entry["payload"]
        assert entry["source"] in ("preload", "prefilter")
    # 进调用链的条目带 source，供"算不算 AI 的调用"和"证据溯源"两件事共用
    for call in result["calls"]:
        assert call["source"] in ("preload", "prefilter")


def test_signature_failure_is_recorded_not_silent(tmp_path, fake_tools):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    result = preload.collect(p, "c" * 64, None, kind="pe")
    assert not [e for e in result["entries"] if e["tool"] == "signature_verify"]
    assert any("signature_verify" in s for s in result["skipped"])


# ---------------------------------------------------------------- 3. 渲染口径

def test_render_section_gives_facts_with_source_tool_names(tmp_path, fake_tools):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    result = preload.collect(p, "d" * 64, {"status": "unknown"}, kind="pe")
    section = preload.render_section(result)
    for name in ("pe_analyze", "capa_scan", "strings_ioc", "signature_verify"):
        assert f"来源工具: {name}" in section
    assert "与本次文件类型无关" in section


def test_render_section_has_no_scores_or_tiers(tmp_path, fake_tools):
    """与 YARA 段同口径：不给预筛分数、不给 strong/weak 分档。"""
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    section = preload.render_section(preload.collect(p, "e" * 64, {}, kind="pe"))
    assert "不含任何结论" in section          # 明确声明这是事实不是判断
    assert "strong_hits" not in section and "weak_hits" not in section
    assert "score=" not in section and "预筛分数 " not in section


def test_render_section_explains_unavailable_tools(tmp_path, fake_tools):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    section = preload.render_section(preload.collect(p, "f" * 64, {}, kind="pe"))
    assert "不需要再调" in section            # 措辞是"不适用"，不是"没跑"（后者会诱使 AI 去补）
    assert "按类型未跑" not in section


def test_render_section_empty_is_explicit():
    assert "未预采集" in preload.render_section({})


def test_render_section_says_why_when_disabled():
    section = preload.render_section({"policy": "disabled", "entries": [], "tools": []})
    assert "预采集被显式关闭" in section


def test_render_section_says_why_when_budget_ate_everything():
    section = preload.render_section({"entries": [], "tools": [],
                                      "budget_note": "证据块超出预算 100 字符"})
    assert "超出预算" in section


# ---------------------------------------------------------------- 4. 预算与有界化

def test_total_budget_shrinks_then_drops(tmp_path, fake_tools, monkeypatch):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    monkeypatch.setenv("AI_AV_PRELOAD_MAX_CHARS", "200")
    result = preload.collect(p, "0" * 64, {"status": "unknown"}, kind="pe")
    assert result["truncated"] is True
    assert result["chars"] <= 200
    assert "降级" in result["budget_note"]
    # 优先级最高的签名证据必须活下来
    assert result["tools"][0] == "signature_verify"


def test_budget_note_surfaces_in_section(tmp_path, fake_tools, monkeypatch):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    monkeypatch.setenv("AI_AV_PRELOAD_MAX_CHARS", "200")
    section = preload.render_section(preload.collect(p, "1" * 64, {}, kind="pe"))
    assert "超出预算" in section


def test_payload_stays_valid_json_when_capped(tmp_path, monkeypatch):
    """超预算时走结构化裁剪：仍是合法 JSON，且留痕"这里被截了"，绝不裸切字符串。"""
    monkeypatch.setattr(preload, "PER_TOOL_CHARS", {"strings_ioc": 300})
    monkeypatch.setattr(preload, "_TOOL_FUNCS", {
        "strings_ioc": lambda ctx: json.dumps(
            {"interesting_strings": [f"string-{i}" for i in range(200)]}, ensure_ascii=False)
    })
    monkeypatch.setattr(preload, "capa_ready", lambda: (False, "x"))
    monkeypatch.setattr(preload, "_find_exe", lambda *a, **k: None)
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    result = preload.collect(p, "2" * 64, {}, kind="pe")
    payload = [e for e in result["entries"] if e["tool"] == "strings_ioc"][0]["payload"]
    json.loads(payload)                      # 不抛 = 合法 JSON
    assert "省略" in payload or "截断" in payload


# ---------------------------------------------------------------- 5. 留痕与溯源口径

def test_ai_tool_calls_excludes_preload_and_prefilter():
    calls = [
        {"tool": "pe_analyze", "source": "preload"},
        {"tool": "signature_verify", "source": "prefilter"},
        {"tool": "capa_scan"},
        {"tool": "strings_ioc", "source": "preload"},
    ]
    assert [c["tool"] for c in ai_tool_calls(calls)] == ["capa_scan"]
    assert ai_tool_calls([]) == []


def test_preloaded_evidence_is_attributable(tmp_path, fake_tools):
    """预采集输出进调用链后，引用它的结论要能被溯源成 explicit —— 这是"证据前置"的前提。"""
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    result = preload.collect(p, "3" * 64, {}, kind="pe")
    claims = ["pe_analyze 显示导入表只有 KERNEL32.dll"]
    sources = attribute_evidence(claims, result["calls"], agent_used=True)
    assert sources[0]["support"] == "explicit"
    assert sources[0]["source"] == "pe_analyze"


def test_repetition_warning_counts_only_ai_calls(tmp_path, fake_tools):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    result = preload.collect(p, "4" * 64, {}, kind="pe")
    calls = result["calls"] + [{"tool": "capa_scan", "summary": "x"}]
    sources = [{"claim": "c", "source": "送审事实", "support": "prompt_fact"}]
    warning = find_repetition_warnings(sources, calls)
    assert warning and "实际调用工具 1 次" in warning[0]


def test_prompt_facts_include_prefilter_signals():
    facts = prompt_fact_texts([], ["ClamAV —— 未安装"], extra_facts=["预筛信号 高风险扩展名: .exe"])
    assert any("高风险扩展名" in f for f in facts)
    assert any("ClamAV" in f for f in facts)


def test_prompt_facts_without_extra_still_works():
    assert prompt_fact_texts([], []) == []


# ---------------------------------------------------------------- 6. 开关与报告字段

def test_preload_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("AI_AV_PRELOAD", "0")
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    evidence = PreliminaryEvidence(path=str(p), sha256="5" * 64, size=4,
                                   extension=".exe", prefilter_score=5)
    result = _collect_preload(p, "5" * 64, evidence)
    assert result["policy"] == "disabled"
    assert result["tools"] == []
    # 关掉也要留痕"为什么没有证据"，不能是空对象
    assert result["skipped"] and "AI_AV_PRELOAD=0" in result["skipped"][0]


def test_scan_file_records_usage_and_preload(tmp_path, monkeypatch, fake_tools):
    """集成口径：预采集条目进调用链但**不算** AI 的工具调用次数。"""
    from aiav import scanner

    p = _write(tmp_path / "s.exe", b"MZ\x90\x00" + b"\x00" * 64)
    monkeypatch.setenv("AI_AV_SIGNATURE_CHECK", "0")
    monkeypatch.setenv("AI_AV_ARCHIVE_MAX_CHILDREN", "0")
    # 关缓存：默认缓存目录是共享的，同一份内容会被上一条测试的结论命中
    monkeypatch.setenv("AI_AV_CACHE", "0")

    def fake_analyze(agent, deps, evidence, budget=None, preload=None):
        assert preload and preload.get("tools"), "送审必须带上预采集证据"
        deps.tool_calls.append({"tool": "capa_scan", "summary": "{}"})   # 假装 AI 深挖了一次
        deps.agent_retry = {"attempts": 1, "outcome": "ok", "retried": False,
                            "retry_count": 0, "failures": [], "policy": {}, "tokens": 1234}
        return Verdict(risk=RiskLevel.clean, confidence=0.6, category="clean",
                       summary="ok", evidence=["pe_analyze 显示只有 KERNEL32.dll"])

    monkeypatch.setattr(scanner, "analyze_file_with_agent", fake_analyze)
    report = scanner.scan_file(p, agent=object(), ai_threshold=0, store=None,
                               allow_unpack=False, allow_archives=False, cache=None)

    assert report.agent_used is True
    assert report.agent_usage["tool_calls"] == 1
    assert report.agent_usage["deep_dive"] is True
    assert report.agent_usage["tokens"] == 1234
    assert report.agent_usage["preloaded_tools"]
    assert report.evidence_preload["kind"] == "pe"
    # 预采集条目在调用链里，但不计入 AI 的调用次数
    assert len(report.agent_trace) > report.agent_usage["tool_calls"]
    assert not any(c.get("tool") == "prefilter" for c in report.agent_trace)


def test_report_summary_and_html_show_usage(tmp_path, monkeypatch, fake_tools):
    from aiav import scanner
    from aiav.report import build_summary, write_reports

    p = _write(tmp_path / "t.exe", b"MZ\x90\x01" + b"\x01" * 64)
    monkeypatch.setenv("AI_AV_SIGNATURE_CHECK", "0")
    monkeypatch.setenv("AI_AV_CACHE", "0")

    def fake_analyze(agent, deps, evidence, budget=None, preload=None):
        deps.agent_retry = {"attempts": 1, "outcome": "ok", "retried": False,
                            "retry_count": 0, "failures": [], "policy": {}, "tokens": 999}
        return Verdict(risk=RiskLevel.suspicious, confidence=0.5, category="unknown",
                       summary="可疑", evidence=["capa_scan 命中了 RWX 分配模式"])

    monkeypatch.setattr(scanner, "analyze_file_with_agent", fake_analyze)
    report = scanner.scan_file(p, agent=object(), ai_threshold=0, store=None,
                               allow_unpack=False, allow_archives=False, cache=None)

    summary = build_summary([report])
    assert summary["usage"]["tool_calls"] == 0
    assert summary["usage"]["files_no_tool_call"] == 1
    assert summary["usage"]["tokens"] == 999
    assert summary["preload"]["files_preloaded"] == 1
    assert summary["preload"]["tools"].get("pe_analyze") == 1

    _json, html, _audit = write_reports([report], tmp_path / "out")
    text = html.read_text(encoding="utf-8")
    assert "纯读预采集证据" in text
    assert "确定性证据前置" in text or "预采集" in text
    assert "只看走了深挖" in text


# ---------------------------------------------------------------- 5. 分流·取证层（B 档）

def test_deep_false_drops_capa_and_floss(tmp_path, fake_tools):
    """`deep=False` 时 capa/floss 从工具清单里摘掉（其余轻量证据照采）。"""
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    tools, _ = preload.plan_tools("pe", p, deep=False)
    assert tools == ["signature_verify", "pe_analyze", "strings_ioc"]
    assert not (set(tools) & set(preload.DEEP_FORENSICS_TOOLS))


def test_deep_false_never_actually_runs_capa_or_floss(tmp_path, fake_tools):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    preload.collect(p, "a" * 64, {"status": "unsigned"}, kind="pe", deep=False,
                    score=5, threshold=12)
    assert fake_tools, "轻量工具应该跑过"
    assert "capa_scan" not in fake_tools and "floss_scan" not in fake_tools


def test_deep_false_records_state_and_note(tmp_path, fake_tools):
    """跳过必须**留痕**：报告里要能看出这次没跑深度取证。"""
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    result = preload.collect(p, "a" * 64, {}, kind="pe", deep=False, score=5, threshold=12)
    assert result["deep_forensics"] == "skipped"
    assert "深度取证已跳过" in result["deep_note"]
    assert "5" in result["deep_note"] and "12" in result["deep_note"]   # 读数要写出来


def test_deep_true_keeps_capa_and_floss(tmp_path, fake_tools):
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    tools, _ = preload.plan_tools("pe", p, deep=True)
    assert "capa_scan" in tools and "floss_scan" in tools
    result = preload.collect(p, "a" * 64, {}, kind="pe", deep=True)
    assert result["deep_forensics"] == "done"
    assert result["deep_note"] == ""


@pytest.mark.parametrize("style,needle", [
    ("policy", "已知的检测边界"),
    ("invite", "不等于"),
])
def test_rendered_deep_skip_says_not_clean(tmp_path, fake_tools, monkeypatch, style, needle):
    """送审里必须**明确**说：跳过 ≠ 通过。否则 AI 会把"没看到 capa 输出"读成"没发现问题"。

    两种措辞档（`AI_AV_DEEP_SKIP_NOTE`）都必须做到这一点 —— 它们的区别只在
    "要不要邀请 AI 补调"，**不是**在"要不要说清这是没跑"。
    """
    monkeypatch.setenv("AI_AV_DEEP_SKIP_NOTE", style)
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    result = preload.collect(p, "a" * 64, {}, kind="pe", deep=False, score=5, threshold=12)
    text = preload.render_section(result)
    assert "深度取证已跳过" in text
    assert needle in text
    assert "缺证据支撑" in text
    # 声明必须排在**证据条目**前面（读的人先看到"缺了什么"）
    assert text.index("深度取证已跳过") < text.index("▸ 来源工具")


def test_deep_skip_note_style_env(monkeypatch):
    monkeypatch.delenv("AI_AV_DEEP_SKIP_NOTE", raising=False)
    assert preload._deep_skip_note_style() == "policy"
    monkeypatch.setenv("AI_AV_DEEP_SKIP_NOTE", "invite")
    assert preload._deep_skip_note_style() == "invite"
    monkeypatch.setenv("AI_AV_DEEP_SKIP_NOTE", "whatever")
    assert preload._deep_skip_note_style() == "policy"


def test_deep_skip_note_not_mixed_with_type_not_applicable(tmp_path, fake_tools):
    """分流跳过（有面但没采）与类型不适用（没有可分析的面）是两件事，不能混。"""
    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    result = preload.collect(p, "a" * 64, {}, kind="pe", deep=False, score=5, threshold=12)
    assert "capa_scan" not in " ".join(result["skipped"]), \
        "分流跳过不该混进『与类型无关』清单（那会被读成『不适用』）"


def test_non_pe_gets_no_deep_skip_note(tmp_path, fake_tools):
    """非 PE 本来就不跑 capa/floss，那是"不适用"，不能写成分流跳过。"""
    p = _write(tmp_path / "x.ps1", b"Write-Host hi")
    result = preload.collect(p, "a" * 64, {}, kind="script", deep=False, score=5, threshold=12)
    assert result["deep_forensics"] == "done"
    assert result["deep_note"] == ""


def test_collect_preload_passes_deep_flag(tmp_path, fake_tools):
    """`scanner._collect_preload` 要把 deep/threshold 透传到采集层。"""
    from aiav.models import PreliminaryEvidence

    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    ev = PreliminaryEvidence(path=str(p), sha256="b" * 64, size=4, extension=".exe",
                             prefilter_score=5)
    result = _collect_preload(p, "b" * 64, ev, deep=False, threshold=12)
    assert result["deep_forensics"] == "skipped"
    assert "capa_scan" not in result["tools"]


def test_preload_disabled_result_has_deep_fields(tmp_path, fake_tools, monkeypatch):
    """关掉预采集时也要有**结构完整**的 deep 字段（不能是空对象）。"""
    monkeypatch.setenv("AI_AV_PRELOAD", "0")
    from aiav.models import PreliminaryEvidence

    p = _write(tmp_path / "x.exe", b"MZ\x90\x00")
    ev = PreliminaryEvidence(path=str(p), sha256="c" * 64, size=4, extension=".exe",
                             prefilter_score=5)
    result = _collect_preload(p, "c" * 64, ev)
    assert result["policy"] == "disabled"
    assert result["deep_forensics"] == "disabled" and "deep_note" in result


def test_deep_evidence_threshold_env(monkeypatch):
    """默认 0 = 不分流；非法值不炸。"""
    monkeypatch.delenv("AI_AV_DEEP_EVIDENCE_THRESHOLD", raising=False)
    assert preload.deep_evidence_threshold() == 0
    monkeypatch.setenv("AI_AV_DEEP_EVIDENCE_THRESHOLD", "12")
    assert preload.deep_evidence_threshold() == 12
    monkeypatch.setenv("AI_AV_DEEP_EVIDENCE_THRESHOLD", "not-a-number")
    assert preload.deep_evidence_threshold() == 0
    monkeypatch.setenv("AI_AV_DEEP_EVIDENCE_THRESHOLD", "-3")
    assert preload.deep_evidence_threshold() == 0


def test_report_summary_and_html_show_deep_skip(tmp_path, monkeypatch, fake_tools):
    """报告里必须看得见"跳过深度取证" —— 否则读报告的人会把"没报注入能力"读成"查过了没有"。

    阈值单位是 **Assemblyline 刻度**（2026-09-27 换的）：300 = 老口径的 12。
    这个假 PE 只靠"高风险扩展名"拿到 125，所以 300 会把它分到轻量档。
    """
    from aiav import scanner
    from aiav.report import build_summary, write_reports

    p = _write(tmp_path / "t.exe", b"MZ\x90\x01" + b"\x01" * 64)
    monkeypatch.setenv("AI_AV_SIGNATURE_CHECK", "0")
    monkeypatch.setenv("AI_AV_CACHE", "0")

    def fake_analyze(agent, deps, evidence, budget=None, preload=None):
        assert preload.get("deep_forensics") == "skipped"
        return Verdict(risk=RiskLevel.clean, confidence=0.5, category="clean",
                       summary="ok", evidence=["pe_analyze 显示导入表正常"])

    monkeypatch.setattr(scanner, "analyze_file_with_agent", fake_analyze)
    report = scanner.scan_file(p, agent=object(), ai_threshold=0, store=None,
                               allow_unpack=False, allow_archives=False, cache=None,
                               deep_evidence_threshold=300)

    assert report.evidence_preload["deep_forensics"] == "skipped"
    assert "capa_scan" not in report.evidence_preload["tools"]

    summary = build_summary([report])
    assert summary["preload"]["deep_skipped"] == 1
    assert summary["preload"]["deep_done"] == 0

    _json, html, _audit = write_reports([report], tmp_path / "out")
    text = html.read_text(encoding="utf-8")
    assert "跳过深度取证" in text
    assert "只看跳过深度取证" in text
