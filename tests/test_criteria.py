"""①层判据表的测试。

盯三件事：
1. **三档归位是对的** —— 弱信号必须复合、强信号能单独送审、确定性判据能结案。
2. **max_score / 频次 / 白名单归零** 这些上游语义照抄没走样。
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
