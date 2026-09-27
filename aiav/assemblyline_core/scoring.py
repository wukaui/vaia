"""Assemblyline 的三档计分语义 —— 我们在它上面包了一层，用来决定"谁送 AI、谁不送"。

上游 `common/heuristics.py`（原文抄在 `_compat/heuristics.py`）只做一件事：
把"一条判据 + 命中次数 + 每条签名自己的分数"算成一个整数分，并夹在 `max_score` 以内。
**它自己不做判决** —— 分算出来给人看。我们的分工是：

    确定性层（抄它的）：拦掉绝大部分，给出可解释证据，能结案就结案
    AI 层（我们的）    ：只判"规则说不清"的中间带

三档语义（上游文档，`<500` / `500-1000` / `≥1000`）：

    < 500      弱信号。单条什么都不算，**必须多条复合**才够看。
               理由：任何一条单独拿出来误报率都高（加壳、稀疏导入表、高熵都可能是正常软件）。
    500-1000   作者相对确信可疑，但不能定性。→ 送 AI，且**优先**送。
    ≥ 1000     高置信，单条即可定恶意，几乎无误报。
               上游明说这类分数来自**签名类服务**（AV / VT / YARA 命中已知家族）。

分数映射（给人看的档位，与上面三档是两套刻度，别混）：

    -1000 安全 | 0-299 参考 | 300-699 可疑 | 700-999 高度可疑 | ≥1000 恶意

计分规则（照抄上游）：

    同一段内各信号分数**累加**；
    同一签名命中 N 次，该签名分数 **× N**；
    每条判据有 `max_score` 上限，累加后再夹；
    文件分 = 各证据段的分数**求和**；
    提交分 = 所有文件里**最高的那个**；
    若一段里所有签名都被白名单标记为 safe，该段分数**归零**（不是扣分，是归零）。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Mapping, Sequence


# --------------------------------------------------------------------------------------
# 档位
# --------------------------------------------------------------------------------------
class ScoreBand(str, Enum):
    """上游的分数档位（给人看的那个刻度）。"""

    SAFE = "safe"                       # -1000
    REFERENCE = "reference"             # 0-299
    SUSPICIOUS = "suspicious"           # 300-699
    HIGHLY_SUSPICIOUS = "highly_suspicious"  # 700-999
    MALICIOUS = "malicious"             # >= 1000


#: 档位边界（左闭右开），照上游文档。负数分只在"白名单命中扣分"的场景出现，这里不产生负数。
SCORE_BANDS: tuple[tuple[int, ScoreBand], ...] = (
    (-1000, ScoreBand.SAFE),
    (0, ScoreBand.REFERENCE),
    (300, ScoreBand.SUSPICIOUS),
    (700, ScoreBand.HIGHLY_SUSPICIOUS),
    (1000, ScoreBand.MALICIOUS),
)

#: 三档**处置**语义 —— 这才是"送审率"的闸门。
WEAK_MAX = 500
STRONG_MAX = 1000


class ScoreTier(str, Enum):
    WEAK = "weak"               # < 500  必须复合
    STRONG = "strong"           # 500-1000 送 AI，优先
    CONCLUSIVE = "conclusive"   # >= 1000 确定性结案，永不送 AI


def band_of(score: int) -> ScoreBand:
    """整数分 → 档位标签。"""
    band = SCORE_BANDS[0][1]
    for floor, name in SCORE_BANDS:
        if score >= floor:
            band = name
    return band


def tier_of(score: int) -> ScoreTier:
    """整数分 → 三档处置语义。"""
    if score >= STRONG_MAX:
        return ScoreTier.CONCLUSIVE
    if score >= WEAK_MAX:
        return ScoreTier.STRONG
    return ScoreTier.WEAK


# --------------------------------------------------------------------------------------
# 判据定义与计分（上游 Heuristic 的等价物）
# --------------------------------------------------------------------------------------
@dataclass(frozen=True)
class HeuristicScore:
    """一条判据的**定义**。字段名对齐上游 `odm/models/heuristic.py`。"""

    heur_id: str
    name: str
    description: str
    score: int
    filetype: str = "*"
    attack_ids: tuple[str, ...] = ()
    signature_score_map: Mapping[str, int] = field(default_factory=dict)
    max_score: int | None = None
    #: 我们自己的扩展：这条判据由哪个确定性工具产出（写进报告"服务"段，保证可复现）
    produced_by: str = ""


@dataclass
class ScoredHeuristic:
    """一条判据的**命中结果**（上游 `odm/models/result.py` 的 Heuristic 段）。"""

    heur_id: str
    name: str
    score: int
    frequency: int = 1
    signatures: dict[str, int] = field(default_factory=dict)
    attack: list[dict] = field(default_factory=list)
    #: 命中的签名里，哪些被白名单标记为 safe（上游 `Signature.safe`）
    signature_safe: dict[str, bool] = field(default_factory=dict)
    #: 全段签名都 safe 时置真 —— 分数归零，写进报告的 `safelisted_tags` 里解释
    zeroed_by_safelist: bool = False


def score_heuristic(
    definition: HeuristicScore,
    *,
    frequency: int = 1,
    signatures: Mapping[str, int] | None = None,
    signature_safe: Mapping[str, bool] | None = None,
    attack_lookup=None,
) -> ScoredHeuristic:
    """算一条判据的分数。语义逐条对齐上游 `common/heuristics.py::Heuristic.__init__`：

    1. 有签名命中 → 分 = Σ 每条签名分数 × 该签名命中次数；
       签名分数取值优先级：`signature_score_map[name]` > 本次 `score_map[name]` > 判据默认分。
    2. 没有签名 → 分 = 判据默认分 × 频次（频次缺省 1）。
    3. 夹到 `max_score`。
    4. 若所有签名都 safe → 分归零（上游 `HeuristicHandler.service_heuristic_to_result_heuristic`）。
    """
    sigs = dict(signatures or {})
    safe_map = dict(signature_safe or {})

    if sigs:
        total = 0
        for sig_name, freq in sigs.items():
            sig_score = definition.signature_score_map.get(sig_name, definition.score)
            total += sig_score * (freq or 1)
        score = total
    else:
        score = definition.score * (frequency or 1)

    if definition.max_score is not None:
        score = min(score, definition.max_score)

    zeroed = False
    if sigs and all(safe_map.get(name, False) for name in sigs):
        score = 0
        zeroed = True

    attack = []
    if attack_lookup is not None:
        for aid in definition.attack_ids:
            item = attack_lookup(aid)
            if item:
                attack.append({"attack_id": aid, **item})
            else:
                attack.append({"attack_id": aid})

    return ScoredHeuristic(
        heur_id=definition.heur_id,
        name=definition.name,
        score=score,
        frequency=frequency or 1,
        signatures=sigs,
        attack=attack,
        signature_safe=safe_map,
        zeroed_by_safelist=zeroed,
    )


# --------------------------------------------------------------------------------------
# 聚合（文件 / 提交）
# --------------------------------------------------------------------------------------
def aggregate_file_score(sections: Iterable[ScoredHeuristic]) -> int:
    """文件分 = 各证据段分数**求和**（上游 `ResultBody.score`：aggregate of the score for all heuristics）。"""
    return sum(s.score for s in sections)


def aggregate_submission_score(file_scores: Iterable[int]) -> int:
    """提交分 = 所有文件里**最高的那个**（上游 `Submission.max_score`）。"""
    scores: Sequence[int] = [int(s) for s in file_scores]
    return max(scores) if scores else 0


# --------------------------------------------------------------------------------------
# 送审闸门
# --------------------------------------------------------------------------------------
class Disposition(str, Enum):
    """一个文件走完确定性层之后的去向。"""

    CLOSED_MALICIOUS = "closed_malicious"   # ≥1000 且方向为恶意：确定性结案，不送 AI
    CLOSED_CLEAN = "closed_clean"           # 白名单 / 干净签名：确定性结案，不送 AI
    SEND_AI = "send_ai"                     # 中间带：送 AI
    PASS = "pass"                           # 连弱信号都没有：不送 AI，记"未结案"（不是判白）


@dataclass
class DeterministicVerdict:
    """确定性层的结论。**注意：`PASS` 不等于"判白"**，只是"没线索，不值得花 token"。"""

    disposition: Disposition
    score: int
    tier: ScoreTier
    band: ScoreBand
    reasons: list[str] = field(default_factory=list)

    @property
    def sends_to_ai(self) -> bool:
        return self.disposition is Disposition.SEND_AI
