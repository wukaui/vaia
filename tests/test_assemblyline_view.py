"""报告结构测试：产物必须**过得上游 `Result` 模型的校验**。

"照 Assemblyline 改报告结构"这句话如果没有校验就是自说自话 ——
所以这里的每条测试最后都落到 `Result(payload)` 能不能构造出来。
"""

from __future__ import annotations

from pathlib import Path

from aiav.assemblyline_core.odm.models.result import Result
from aiav.assemblyline_view import (
    build_result,
    build_submission,
    criteria_catalog,
    service_tool_version,
    tool_versions,
    validate_result,
)
from aiav.models import FileReport, RiskLevel, Verdict


def _report(**over) -> FileReport:
    base = dict(
        path="/tmp/x.exe",
        sha256="a" * 64,
        size=1024,
        extension=".exe",
        prefilter_score=275,          # 125 + 150，与下面两条判据的和对上
        prefilter_reasons=["高风险扩展名: .exe"],
        criteria_hits=[
            {
                "heur_id": "HIGH_RISK_EXTENSION",
                "name": "高风险扩展名",
                "description": "可执行/脚本类扩展名。",
                "score": 125,
                "max_score": 125,
                "frequency": 1,
                "filetype": "*",
                "produced_by": "文件名后缀",
                "attack": [{"attack_id": "T1204.002", "name": "Malicious File",
                            "categories": ["execution"]}],
                "signature": [],
                "safelisted": False,
                "direction": "suspect",
                "conclusive": False,
            },
            {
                "heur_id": "STRUCT_TEXT_RATIO",
                "name": "代码段占比失衡",
                "description": "小 stub + 大载荷。",
                "score": 150,
                "max_score": 150,
                "frequency": 1,
                "filetype": "PE",
                "produced_by": "pefile",
                "attack": [{"attack_id": "T1027", "name": "Obfuscated Files or Information",
                            "categories": ["stealth"]}],
                "signature": [],
                "safelisted": False,
                "direction": "suspect",
                "conclusive": False,
            },
        ],
        deterministic={"disposition": "send_ai", "tier": "strong", "score": 275},
        verdict=Verdict(risk=RiskLevel.suspicious, confidence=0.7, summary="s"),
        agent_used=True,
    )
    base.update(over)
    return FileReport(**base)


# --------------------------------------------------------------------------------------
# 结构
# --------------------------------------------------------------------------------------
def test_result_passes_upstream_schema():
    payload = build_result(_report())
    validate_result(payload)          # 过不了会抛
    assert isinstance(Result(payload), Result)


def test_sections_carry_heuristic_attack_and_signature():
    payload = build_result(_report())
    sections = payload["result"]["sections"]
    assert len(sections) == 2
    heur = sections[0]["heuristic"]
    assert heur["heur_id"] == "HIGH_RISK_EXTENSION"
    assert heur["score"] == 125
    assert heur["attack"][0]["attack_id"] == "T1204.002"
    assert heur["attack"][0]["pattern"] == "Malicious File"
    assert heur["attack"][0]["categories"] == ["execution"]


def test_signature_frequency_and_safe_flag_are_rendered():
    """依据 = 命中**次数** + **是否白名单**，两个字段都要能看见。"""
    rep = _report()
    rep.criteria_hits[0]["signature"] = [
        {"name": "clamav:Win.Trojan.A", "frequency": 3, "safe": False},
        {"name": "yara:Loader", "frequency": 1, "safe": True},
    ]
    payload = build_result(rep)
    sigs = payload["result"]["sections"][0]["heuristic"]["signature"]
    assert [s["frequency"] for s in sigs] == [3, 1]
    assert [s["safe"] for s in sigs] == [False, True]


def test_score_is_the_sum_of_sections():
    payload = build_result(_report())
    assert payload["result"]["score"] == 275
    assert sum(s["heuristic"]["score"] for s in payload["result"]["sections"]) == 275


def test_service_block_gives_reproducible_tool_versions():
    payload = build_result(_report())
    assert payload["response"]["service_name"] == "aiav-deterministic"
    assert payload["response"]["service_version"]
    versions = payload["response"]["service_tool_version"]
    assert "yara-python" in versions and "pefile" in versions
    assert "not installed" in versions or all(v != "" for v in tool_versions().values())


def test_extracted_files_carry_lineage():
    rep = _report(archive={"is_archive": True, "children": [
        {"name": "inner.exe", "sha256": "b" * 64, "kind": "pe"}]},
        packing={"unpack": {"ok": True, "path": "/tmp/x.unpacked.exe", "sha256": "c" * 64,
                            "packer": "UPX"}})
    payload = build_result(rep)
    extracted = payload["response"]["extracted"]
    relations = {e["name"]: e["parent_relation"] for e in extracted}
    assert relations["inner.exe"] == "EXTRACTED"
    assert relations["x.unpacked.exe"] == "EXTRACTED"
    validate_result(payload)


def test_closed_clean_explains_why_the_score_was_zeroed():
    """`safelisted_tags` 要写清"这一段为什么没算分"，而不是让读者自己猜。"""
    rep = _report(
        prefilter_score=0,
        deterministic={"disposition": "closed_clean", "score": 0},
        criteria_hits=[{
            "heur_id": "DET_TRUSTED_SIGNATURE",
            "name": "内嵌签名有效且签发者可信",
            "description": "…",
            "score": 1000,
            "max_score": 1000,
            "frequency": 1,
            "filetype": "PE",
            "produced_by": "aiav.authenticode",
            "attack": [],
            "signature": [],
            "safelisted": False,
            "direction": "clean",
            "conclusive": True,
        }],
    )
    payload = build_result(rep)
    safe = payload["result"]["sections"][0]["safelisted_tags"]
    assert safe, "判干净结案的文件必须写清分数归零的原因"
    assert any("DET_TRUSTED_SIGNATURE" in v[0] for v in safe.values())
    validate_result(payload)


def test_file_with_no_hits_still_has_a_section():
    """一条判据都没命中的文件也要有结论段 —— 否则报告里它是空白，看不出跑没跑。"""
    rep = _report(prefilter_score=0, criteria_hits=[], deterministic={"disposition": "pass"})
    payload = build_result(rep)
    assert payload["result"]["sections"]
    assert payload["result"]["sections"][0]["heuristic"]["heur_id"] == "NO_CRITERION_HIT"
    validate_result(payload)


def test_tags_use_real_upstream_fields():
    """tags 用的是上游 `Tagging` 模型的真实字段，不是我们自己造的键。"""
    rep = _report()
    rep.criteria_hits[0]["signature"] = [{"name": "yara:Loader", "frequency": 1, "safe": False}]
    rep.criteria_hits[0]["heur_id"] = "STRONG_YARA"
    rep.criteria_hits[0]["name"] = "高置信 YARA 命中"
    rep.archive = {"children": [{"name": "inner.exe", "sha256": "b" * 64}]}
    payload = build_result(rep)
    # 只要 Result 构造得出来，就说明 tags 全部落在 Tagging 的合法字段上
    validate_result(payload)


# --------------------------------------------------------------------------------------
# 提交级
# --------------------------------------------------------------------------------------
def test_submission_score_is_the_max_file_score():
    reports = [_report(), _report(sha256="b" * 64, prefilter_score=1000),
               _report(sha256="c" * 64, prefilter_score=125)]
    sub = build_submission(reports)
    assert sub["max_score"] == 1000
    assert sub["file_count"] == 3


def test_submission_reports_send_rate_and_close_rate():
    reports = [
        _report(deterministic={"disposition": "closed_malicious"}, agent_used=False),
        _report(deterministic={"disposition": "closed_clean"}, agent_used=False),
        _report(deterministic={"disposition": "pass"}, agent_used=False),
        _report(deterministic={"disposition": "send_ai"}, agent_used=True),
    ]
    sub = build_submission(reports)
    det = sub["deterministic"]
    assert det["send_rate"] == 0.25
    assert det["closed_malicious_rate"] == 0.25
    assert det["closed_clean_rate"] == 0.25
    assert det["unresolved_rate"] == 0.25


# --------------------------------------------------------------------------------------
# 判据表本身
# --------------------------------------------------------------------------------------
def test_criteria_catalog_is_complete():
    catalog = criteria_catalog()
    assert len(catalog) >= 30
    for row in catalog:
        assert row["heur_id"] and row["name"] and row["description"]
        assert row["filetype"] and row["produced_by"]
        for a in row["attack"]:
            assert a["attack_id"]
            assert a.get("name"), f"{row['heur_id']} 的 ATT&CK {a['attack_id']} 没取到名字"


def test_catalog_has_the_three_tiers():
    catalog = criteria_catalog()
    conclusive = [c for c in catalog if c["conclusive"]]
    strong = [c for c in catalog if not c["conclusive"] and c["score"] >= 500]
    weak = [c for c in catalog if not c["conclusive"] and c["score"] < 500]
    assert conclusive, "≥1000 档（确定性结案）不能是空的"
    assert strong, "500-1000 档（强可疑）不能是空的"
    assert weak, "<500 档（弱信号）不能是空的"


def test_service_tool_version_is_not_empty():
    assert len(service_tool_version()) > 10
    assert Path("/tmp").exists()
