"""①层判据表的测试。

盯三件事：
1. **三档归位是对的** —— 弱信号必须复合、强信号能单独送审、确定性判据能结案。
2. **max_score / 频次 / 白名单归零** 这些上游语义没走样（算式在上游包里，我们只搬进搬出）。
3. **产出方不许有"幽灵分"** —— 任何一处 `reasons.append(...)` 里的信号，
   判据表都得认得出是哪条判据。认不出就是"加了分但报告里没有判据"，
   这条测试直接失败（核验铁律：静默降级计数必须为 0）。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aiav import criteria as C
from aiav.assemblyline_core.attack_ids import ATTACK_IDS

REPO = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------------------
# 1. 三档
# --------------------------------------------------------------------------------------
def test_signal_unit_derivation():
    """SIGNAL_UNIT 是推出来的，不是拍的：老口径 12 ≡ 上游 verdict.suspicious 300。"""
    assert C.SIGNAL_UNIT == 25
    assert 12 * C.SIGNAL_UNIT == C.AI_GATE == 300


def test_weak_signal_alone_never_crosses_the_gate():
    """一条弱信号过不了闸门 —— 这是"必须复合"的全部意义。"""
    for crit in C.CRITERIA.values():
        if crit.conclusive or crit.score >= C.AI_GATE:
            continue
        verdict = C.decide([C.CriterionHit(crit.heur_id, crit.name)])
        assert verdict.disposition is C.Disposition.PASS, (
            f"{crit.heur_id} 单条就过了闸门（{verdict.score}），弱信号不许单独顶过门槛"
        )


def test_two_weak_signals_can_cross_the_gate():
    """两条 6 分档的结构信号（6×25=150 各一条）加起来正好 300 = 闸门。"""
    hits = [
        C.CriterionHit("STRUCT_WX_SECTION", "结构信号 +6: 可写且可执行段 ×1"),
        C.CriterionHit("STRUCT_TEXT_RATIO", "结构信号 +6: 代码段占比失衡"),
    ]
    verdict = C.decide(hits)
    assert verdict.score == 300
    assert verdict.disposition is C.Disposition.SEND_AI


def test_strong_yara_lands_in_the_strong_band():
    verdict = C.decide([C.CriterionHit("STRONG_YARA", "YARA 命中: X", signatures=("X",))])
    assert verdict.score == 750
    assert verdict.tier is C.ScoreTier.STRONG
    assert verdict.disposition is C.Disposition.SEND_AI


def test_conclusive_criteria_close_the_case():
    mal = C.decide([C.CriterionHit("DET_EICAR", "EICAR 测试文件")])
    assert mal.disposition is C.Disposition.CLOSED_MALICIOUS
    assert mal.score == C.CONCLUSIVE_SCORE

    clean = C.decide([C.CriterionHit("DET_TRUSTED_SIGNATURE", "签名可信")])
    assert clean.disposition is C.Disposition.CLOSED_CLEAN
    assert clean.score == 0


def test_weak_signals_cannot_add_up_to_a_conclusive_verdict():
    """加严规则：没有 ≥1000 档判据命中时，弱信号累加再多也只能停在 STRONG。"""
    hits = [C.CriterionHit("CONTAINER_PATTERN", f"容器可疑模式: p{i}", signatures=(f"p{i}",))
            for i in range(12)]
    verdict = C.decide(hits)
    assert verdict.score >= C.CONCLUSIVE_SCORE      # 分数确实堆到了 1000 以上
    assert verdict.tier is C.ScoreTier.STRONG       # 但不许结案
    assert verdict.disposition is C.Disposition.SEND_AI


def test_clean_close_beats_malicious_weak_signals():
    """判白优先：一条可信签名不会被别处的弱信号推翻（上游 safelist 语义）。"""
    hits = [
        C.CriterionHit("DET_TRUSTED_SIGNATURE", "签名可信"),
        C.CriterionHit("STRUCT_WX_SECTION", "结构信号 +6: 可写且可执行段 ×1"),
    ]
    verdict = C.decide(hits)
    assert verdict.disposition is C.Disposition.CLOSED_CLEAN
    assert verdict.score == 0


def test_pass_is_not_clean():
    """`pass` 与 `closed_clean` 必须是两个不同的处置 —— 报告里不许混。"""
    verdict = C.decide([])
    assert verdict.disposition is C.Disposition.PASS
    assert verdict.disposition is not C.Disposition.CLOSED_CLEAN


# --------------------------------------------------------------------------------------
# 2. 上游计分语义
# --------------------------------------------------------------------------------------
def test_max_score_clamps():
    crit = C.CRITERIA["STRONG_YARA"]
    assert crit.max_score == 750
    hit = C.CriterionHit("STRONG_YARA", "YARA 命中: X", frequency=99, signatures=("X",))
    scored = C.score_hits([hit])[0]
    assert scored.score == 750


def test_frequency_multiplies():
    one = C.score_hits([C.CriterionHit("SCRIPT_STRONG", "脚本强特征: a",
                                       frequency=1, signatures=("a",))])[0].score
    three = C.score_hits([C.CriterionHit("SCRIPT_STRONG", "脚本强特征: a",
                                         frequency=3, signatures=("a",))])[0].score
    assert three == one * 3


def test_frequency_is_ignored_for_non_scaled_criteria():
    """没声明 `frequency_scaled` 的判据，命中次数不影响分数（上游：只有签名才 ×N）。"""
    one = C.score_hits([C.CriterionHit("HIGH_RISK_EXTENSION", "高风险扩展名: .exe", frequency=1)])[0].score
    five = C.score_hits([C.CriterionHit("HIGH_RISK_EXTENSION", "高风险扩展名: .exe", frequency=5)])[0].score
    assert one == five == 125


def test_safelisted_signature_zeroes_the_section():
    """上游 `Signature.safe`：签名全部 safe → 该段分数归零。"""
    hit = C.CriterionHit("STRONG_YARA", "YARA 命中: X", signatures=("X",), safelisted=True)
    scored = C.score_hits([hit])[0]
    assert scored.score == 0
    assert scored.zeroed_by_safelist is True


def test_structural_weight_is_read_back_from_the_reason():
    """结构信号的分是从理由文本里的 `+N` 还原的 —— 表里的分和产出方的权重必须对得上。"""
    assert C.raw_weight_of("结构信号 +6: 可写且可执行段 ×1", "STRUCT_WX_SECTION") == 6
    assert C.raw_weight_of("结构信号 +4: 资源段占比异常", "STRUCT_RSRC_RATIO") == 4
    assert C.raw_weight_of("结构信号 +8: 容器内含公式编辑器对象", "STRUCT_OLE_EQUATION") == 8


def test_band_labels():
    assert C.band_label(0) == "参考"
    assert C.band_label(299) == "参考"
    assert C.band_label(300) == "可疑"
    assert C.band_label(700) == "高度可疑"
    assert C.band_label(1000) == "恶意"


# --------------------------------------------------------------------------------------
# 3. 判据表完整性 + 产出方不许有幽灵分
# --------------------------------------------------------------------------------------
def test_every_criterion_is_fully_declared():
    """每条判据都得写全：名字 / 说明 / 分数 / 上限 / 适用类型 / 产出工具 / ATT&CK。"""
    for crit in C.CRITERIA.values():
        assert crit.name, crit.heur_id
        assert crit.description, crit.heur_id
        assert crit.filetype, crit.heur_id
        assert crit.produced_by, crit.heur_id
        assert crit.score >= 0, crit.heur_id
        if crit.score and not crit.conclusive:
            assert crit.max_score is not None, f"{crit.heur_id} 有分却没写 max_score 上限"
            assert crit.max_score >= crit.score or crit.score == 0
        # ATT&CK 只对"可疑/恶意"方向要求；判干净的判据没有对应技术编号
        if crit.direction is not C.Direction.CLEAN and crit.heur_id not in C.ATTACK_EXEMPT:
            assert crit.attack_ids, f"{crit.heur_id} 没写 ATT&CK ID（故意没有的请登记进 ATTACK_EXEMPT）"
        for aid in crit.attack_ids:
            assert aid in ATTACK_IDS, f"{crit.heur_id} 的 ATT&CK ID {aid} 在上游表里查不到"


def test_no_criterion_scores_into_the_conclusive_band_by_accident():
    """除了明确标 `conclusive` 的判据，没有判据能单条落到 ≥1000。"""
    for crit in C.CRITERIA.values():
        if crit.conclusive:
            continue
        assert crit.score < C.CONCLUSIVE_SCORE, crit.heur_id
        if crit.max_score is not None:
            assert crit.max_score <= C.CONCLUSIVE_SCORE, crit.heur_id


def _emitted_reasons() -> list[tuple[str, str]]:
    """扫产出方源码，把每一处 `reasons.append(...)` 的第一个字符串字面量捞出来。"""
    out: list[tuple[str, str]] = []
    pattern = re.compile(r"reasons\.append\(\s*(f?)(\"\"\"|'''|\"|')(.*?)\2", re.S)
    for path in sorted((REPO / "aiav").glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for m in pattern.finditer(text):
            literal = m.group(3)
            if literal.startswith("#"):
                continue
            out.append((path.name, literal))
    return out


def test_every_emitted_reason_is_classified():
    """产出方的每一条理由，判据表都得认得出是哪条判据（防幽灵分）。"""
    unclassified = [
        (src, lit) for src, lit in _emitted_reasons() if C.classify_reason(lit) is None
    ]
    assert not unclassified, (
        "这些理由文本分不出判据 ID（说明有信号加了分却没进判据表）：\n"
        + "\n".join(f"  {src}: {lit[:80]}" for src, lit in unclassified)
    )


def test_classify_reason_known_cases():
    assert C.classify_reason("高风险扩展名: .exe") == "HIGH_RISK_EXTENSION"
    assert C.classify_reason("弱 YARA 命中: foo") == "WEAK_YARA"
    assert C.classify_reason("YARA 命中: foo") == "STRONG_YARA"
    assert C.classify_reason("结构信号 +6: 可写且可执行段 ×1") == "STRUCT_WX_SECTION"
    assert C.classify_reason("完全没见过的一句话") is None


def test_deprecated_signals_are_explicitly_listed():
    """已弃用的结构信号（权重 0）必须单独列出来，不许偷偷留在分类规则里当分算。"""
    assert "STRUCT_FUTURE_TIMESTAMP_DEPRECATED" in C.DEPRECATED_SIGNALS
    assert C.raw_weight_of("结构信号 +0: 编译时间戳在未来（2033-01-01）",
                           "STRUCT_FUTURE_TIMESTAMP_DEPRECATED") == 0


# --------------------------------------------------------------------------------------
# 4. 统计
# --------------------------------------------------------------------------------------
def test_stats_accumulate():
    stats = C.update_stats(None, C.score_hits([
        C.CriterionHit("HIGH_RISK_EXTENSION", "高风险扩展名: .exe"),
    ]), "2026-09-27T00:00:00Z")
    assert stats["HIGH_RISK_EXTENSION"]["count"] == 1
    assert stats["HIGH_RISK_EXTENSION"]["avg"] == 125

    stats = C.update_stats(stats, C.score_hits([
        C.CriterionHit("HIGH_RISK_EXTENSION", "高风险扩展名: .exe"),
        C.CriterionHit("STRUCT_WX_SECTION", "结构信号 +6: 可写且可执行段 ×1"),
    ]), "2026-09-27T01:00:00Z")
    assert stats["HIGH_RISK_EXTENSION"]["count"] == 2
    assert stats["HIGH_RISK_EXTENSION"]["sum"] == 250
    assert stats["STRUCT_WX_SECTION"]["count"] == 1
    assert stats["HIGH_RISK_EXTENSION"]["first_hit"] == "2026-09-27T00:00:00Z"


def test_zero_score_hits_do_not_enter_stats():
    stats = C.update_stats(None, C.score_hits([
        C.CriterionHit("XLM_INFO_PATTERN", "XLM 宏内信息类模式（不计分）: a"),
    ]), "2026-09-27T00:00:00Z")
    assert stats == {}


@pytest.mark.parametrize("heur_id", sorted(C.CRITERIA))
def test_criterion_can_be_scored(heur_id):
    """每条判据都要能真的算一遍分（防止表里有字段写错到跑不起来）。"""
    crit = C.CRITERIA[heur_id]
    scored = C.score_hits([C.CriterionHit(heur_id, crit.name)])[0]
    assert scored.heur_id == heur_id
    assert scored.score <= (crit.max_score if crit.max_score is not None else 10**9)


# --------------------------------------------------------------------------------------
# 5. ClamAV 产出方（≥1000 档判据里最有价值的一条）
# --------------------------------------------------------------------------------------
def test_clamav_reports_unavailable_instead_of_clean():
    """**没装 ClamAV ≠ 扫过且干净** —— 这条如果反了，整批数字都会被读错。"""
    from aiav.tools import clamav_evidence

    ev = clamav_evidence(Path("/tmp/whatever.exe"))
    if not ev["available"]:
        assert ev["infected"] is False
        assert "未安装" in ev["error"]
    else:  # 装了的话至少得能跑出结构
        assert set(ev) >= {"available", "infected", "signature", "raw", "error"}


def test_clamav_hit_becomes_a_conclusive_criterion(tmp_path, monkeypatch):
    """注入一个假的 clamscan，验证命中真的能走到"确定性结案判恶意"。"""
    from aiav import tools

    fake = tmp_path / "clamscan"
    fake.write_text("#!/bin/sh\necho \"$3: Win.Trojan.Agent-123 FOUND\"\nexit 1\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CLAMAV_EXE", str(fake))

    def runner(cmd):
        class P:
            stdout = b"/tmp/x.exe: Win.Trojan.Agent-123 FOUND\n"
            stderr = b""
            returncode = 1
        return P()

    ev = tools.clamav_evidence(Path("/tmp/x.exe"), runner=runner)
    assert ev["available"] and ev["infected"]
    assert ev["signature"] == "Win.Trojan.Agent-123"

    verdict = C.decide([C.CriterionHit("DET_CLAMAV_SIGNATURE", f"ClamAV 命中: {ev['signature']}",
                                       signatures=(ev["signature"],))])
    assert verdict.disposition is C.Disposition.CLOSED_MALICIOUS
    assert verdict.score == C.CONCLUSIVE_SCORE


def test_any_clean_conclusive_criterion_closes_clean():
    """判干净方向的结案判据**任何一条**命中都要结案 —— 不许写死 ID 清单漏掉新的那条。"""
    for crit in C.CRITERIA.values():
        if crit.conclusive and crit.direction is C.Direction.CLEAN:
            verdict = C.decide([C.CriterionHit(crit.heur_id, crit.name)])
            assert verdict.disposition is C.Disposition.CLOSED_CLEAN, crit.heur_id
            assert verdict.score == 0, crit.heur_id


# --------------------------------------------------------------------------------------
# 6. ClamAV 批量调用 + 签名名三档（2026-09-27）
# --------------------------------------------------------------------------------------
class _FakeProc:
    """只带 `.stdout` / `.stderr` 的假 subprocess 返回值（tools 里只读这两个字段）。"""

    def __init__(self, stdout: bytes):
        self.stdout = stdout
        self.stderr = b""


def _fake_clamscan(tmp_path, monkeypatch, stdout: bytes):
    """注入一个假的 clamscan：`_find_exe` 找得到（`CLAMAV_EXE` 指过去），输出由调用方给。"""
    from aiav import tools

    fake = tmp_path / "clamscan"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("CLAMAV_EXE", str(fake))

    def runner(_cmd):
        return _FakeProc(stdout)

    return tools, runner


def test_clamav_batch_parses_found_and_ok_and_classifies(tmp_path, monkeypatch):
    """一次进程扫一批：`FOUND` / `OK` 两种行都要认，签名名分三档。"""
    files = [tmp_path / n for n in ("a.exe", "b.exe", "c.exe", "d.exe")]
    out = (f"{files[0]}: Win.Trojan.Agent-123 FOUND\n"
           f"{files[1]}: OK\n"
           f"{files[2]}: Heur.AdvML.B FOUND\n"
           f"{files[3]}: PUA.Adware.InstallCore FOUND\n").encode()
    tools, runner = _fake_clamscan(tmp_path, monkeypatch, out)

    batch = tools.clamav_scan_batch(files, runner=runner)
    assert batch["available"] and batch["scanned"] == 4 and batch["found"] == 3
    assert batch["kinds"] == {"malware": 1, "heuristic": 1, "pua": 1}
    assert batch["unreported"] == []
    assert batch["invocations"] == 1                       # **批量的证据**：4 个文件 1 次进程
    assert batch["results"][str(files[1])]["infected"] is False
    assert batch["results"][str(files[2])]["kind"] == "heuristic"


def test_clamav_batch_counts_files_without_a_result_line(tmp_path, monkeypatch):
    """传进去却没出现在输出里 = **静默跳过**，必须单独计数（不许读成"扫过且干净"）。"""
    files = [tmp_path / n for n in ("a.exe", "b.exe")]
    out = f"{files[0]}: OK\n".encode()
    tools, runner = _fake_clamscan(tmp_path, monkeypatch, out)

    batch = tools.clamav_scan_batch(files, runner=runner)
    assert batch["scanned"] == 1
    assert batch["unreported"] == [str(files[1])]


def test_clamav_heuristic_hit_is_suspicious_not_conclusive():
    """启发式命中**不算 1000 分**：送 AI 复核，永远不结案。"""
    hit = C.CriterionHit("DET_CLAMAV_HEUR", "ClamAV 启发式命中: Heur.AdvML.B",
                         signatures=("Heur.AdvML.B",))
    verdict = C.decide([hit])
    assert verdict.score == C.SUSPICIOUS_SCORE == 300
    assert verdict.tier is not C.ScoreTier.CONCLUSIVE
    assert verdict.disposition is C.Disposition.SEND_AI


def test_clamav_heuristic_hits_never_reach_the_conclusive_band():
    """启发式命中再多也不结案 —— `decide()` 只认判据上的 `conclusive`，不认分数。

    （单条判据自己的分数被 `max_score` 夹在 500；但文件分是各判据段**求和**，
    所以条数堆上去总分能过 1000 —— 靠的正是"没有结案判据就不许结案"这条加严规则。）
    """
    one = C.score_hits([C.CriterionHit("DET_CLAMAV_HEUR", "ClamAV 启发式命中: Heur.X0",
                                       frequency=99, signatures=("Heur.X0",))])[0]
    assert one.score == C.STRONG_FLOOR == 500        # 单段被 max_score 夹住

    hits = [C.CriterionHit("DET_CLAMAV_HEUR", f"ClamAV 启发式命中: Heur.X{i}", signatures=(f"Heur.X{i}",))
            for i in range(5)]
    verdict = C.decide(hits)
    assert verdict.score > C.CONCLUSIVE_SCORE        # 总分确实过了 1000
    assert verdict.tier is C.ScoreTier.STRONG        # 但不许结案
    assert verdict.disposition is C.Disposition.SEND_AI


def test_clamav_pua_hit_scores_zero_but_keeps_the_signature_name():
    """PUA/adware 归零（上游 `kw_score_revision_map` 的 `adware: 0`）—— 留痕，不定级。"""
    hit = C.CriterionHit("DET_CLAMAV_PUA", "ClamAV PUA 命中: PUA.Adware.InstallCore",
                         signatures=("PUA.Adware.InstallCore",))
    scored = C.score_hits([hit])[0]
    assert scored.score == 0
    assert scored.signatures == {"PUA.Adware.InstallCore": 1}   # 签名名还在证据链里
    verdict = C.decide([hit])
    assert verdict.disposition is C.Disposition.PASS
    assert verdict.score == 0


def test_clamav_kinds_map_to_three_separate_criteria():
    """三档必须是三条判据 ID —— `decide()` 认的是判据上的 `conclusive`，不是分数。"""
    from aiav.scanner import _CLAMAV_KIND_CRITERIA

    ids = [heur_id for heur_id, _ in _CLAMAV_KIND_CRITERIA.values()]
    assert len(set(ids)) == 3
    conclusive = [C.CRITERIA[i].conclusive for i in ids]
    assert conclusive == [True, False, False]


def test_scanner_uses_the_batch_index(tmp_path):
    """①层真的会去查批量索引：命中 → 确定性结案，签名名原样进证据链。"""
    from aiav import scanner

    p = tmp_path / "x.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    batch = {"available": True, "results": {str(p): {
        "infected": True, "signature": "Win.Trojan.Zbot-9757924-0", "kind": "malware"}}}

    ev = scanner.quick_prefilter(p, scanner.compute_sha256(p), clamav_batch=batch)
    assert ev.deterministic["disposition"] == "closed_malicious"
    hit = next(h for h in ev.criteria_hits if h["heur_id"] == "DET_CLAMAV_SIGNATURE")
    assert hit["signature"] == [{"name": "Win.Trojan.Zbot-9757924-0", "frequency": 1, "safe": False}]
    assert ev.clamav == {"available": True, "infected": True,
                         "signature": "Win.Trojan.Zbot-9757924-0",
                         "kind": "malware", "batch": True, "error": ""}


def test_scanner_marks_a_file_missing_from_the_batch_as_not_scanned(tmp_path):
    """批次里没有这个文件 ≠ 扫过且干净 —— 必须显式记成"静默跳过"。"""
    from aiav import scanner

    p = tmp_path / "y.exe"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    ev = scanner.quick_prefilter(p, scanner.compute_sha256(p),
                                 clamav_batch={"available": True, "results": {}})
    assert ev.clamav["available"] is True
    assert ev.clamav["infected"] is False
    assert "静默跳过" in ev.clamav["error"]
    assert ev.deterministic["disposition"] != "closed_malicious"


def test_scanner_scans_every_extension_in_batch_mode(tmp_path):
    """批量路径不按扩展名过滤：`.ole` 不在旧白名单里，但 ClamAV 对它是能出命中的。"""
    from aiav import scanner

    p = tmp_path / "sample.ole"
    p.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 64)
    batch = {"available": True, "results": {str(p): {
        "infected": True, "signature": "Doc.Dropper.Emotet-9761056-0", "kind": "malware"}}}

    ev = scanner.quick_prefilter(p, scanner.compute_sha256(p), clamav_batch=batch)
    assert ev.deterministic["disposition"] == "closed_malicious"
