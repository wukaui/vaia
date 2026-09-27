"""Assemblyline 的三档计分语义 —— **数值由上游包算，我们只做档位与处置**。

这个模块是"装包路线"的接口面：`pip install assemblyline` 装进来的那个包，
我们只用它两样东西 —— **模型**（`odm/models/*`）和**计分语义**（`common/heuristics.py`）。
这里不复制它的任何一行代码，只做一层薄适配：

    我们的 HeuristicScore（判据定义） → 上游 odm.models.heuristic.Heuristic（模型）
    我们的命中记录                    → 上游 common.heuristics.HeuristicHandler（算分：
                                        累加 / 频次乘 / max_score 夹逼 / 签名白名单归零 / ATT&CK 展开）

**不碰它的平台**（MongoDB / Elasticsearch / Redis / K8s）：全程 `HeuristicHandler(datastore=None)`，
不需要任何服务在跑。上游那份 `forge.get_datastore()` 我们一次都不调 ——
`tests/test_assemblyline_core.py` 把 socket 拦掉跑，调了当场炸。

三档语义（上游文档，`<500` / `500-1000` / `≥1000`）：

    < 500      弱信号。单条什么都不算，**必须多条复合**才够看。
               理由：任何一条单独拿出来误报率都高（加壳、稀疏导入表、高熵都可能是正常软件）。
    500-1000   作者相对确信可疑，但不能定性。→ 送 AI，且**优先**送。
    ≥ 1000     高置信，单条即可定恶意，几乎无误报。
               上游明说这类分数来自**签名类服务**（AV / VT / YARA 命中已知家族）。

档位边界**从上游 `odm/models/config.py::DEFAULT_VERDICTS` 读**（0 / 300 / 700 / 1000），
不再是我们自己写的字面量 —— 上游改默认值我们跟着改，不用动代码。

计分规则（上游 `common/heuristics.py::Heuristic.__init__` 的原文实现，不是我们重写的）：

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

from assemblyline.common.heuristics import HeuristicHandler, get_safelist_key
from assemblyline.odm.models.config import DEFAULT_VERDICTS
from assemblyline.odm.models.heuristic import Heuristic as UpstreamHeuristicModel


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


#: 上游把 `< info` 一律当"安全"，没有负数档。我们留一个负数档位，
#: 给"白名单命中扣分"这类场景留位置（当前不产生负数）。
SAFE_FLOOR = -1000

#: 档位边界（左闭右开）—— 除 SAFE_FLOOR 外全部来自上游 `DEFAULT_VERDICTS`。
SCORE_BANDS: tuple[tuple[int, ScoreBand], ...] = (
    (SAFE_FLOOR, ScoreBand.SAFE),
    (DEFAULT_VERDICTS["info"], ScoreBand.REFERENCE),
    (DEFAULT_VERDICTS["suspicious"], ScoreBand.SUSPICIOUS),
    (DEFAULT_VERDICTS["highly_suspicious"], ScoreBand.HIGHLY_SUSPICIOUS),
    (DEFAULT_VERDICTS["malicious"], ScoreBand.MALICIOUS),
)

#: 三档**处置**语义 —— 这才是"送审率"的闸门。
#: 300 = 上游 `verdicts.suspicious`（"算可疑"的那条线），1000 = `verdicts.malicious`（结案线）。
SUSPICIOUS_SCORE = DEFAULT_VERDICTS["suspicious"]
MALICIOUS_SCORE = DEFAULT_VERDICTS["malicious"]
WEAK_MAX = 500              # 我们的：可疑档（300）与结案档（1000）之间的分界
STRONG_MAX = MALICIOUS_SCORE


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


def _as_upstream_model(definition: HeuristicScore) -> UpstreamHeuristicModel:
    """我们的判据定义 → 上游 `Heuristic` 模型。分数与上限原样搬过去，一个都不改。

    上游模型对 `description` / `filetype` 不接受空串（空串 = 校验失败），
    我们这边允许留空，所以补个兜底值 —— 补的是"名字"，不是编一个描述出来。
    """
    return UpstreamHeuristicModel({
        "heur_id": definition.heur_id,
        "name": definition.name or definition.heur_id,
        "description": definition.description or definition.name or definition.heur_id,
        "filetype": definition.filetype or "*",
        "score": int(definition.score),
        "signature_score_map": {k: int(v) for k, v in dict(definition.signature_score_map).items()},
        "max_score": None if definition.max_score is None else int(definition.max_score),
    })


def _handler(signature_safe: Mapping[str, bool]) -> HeuristicHandler:
    """构造上游 `HeuristicHandler`，**不接 datastore**（接了就代表要连平台）。

    上游在白名单上只用一件事：`safelist.get("signature__<名字>")` 存不存在。
    它没有 datastore 时 `self.safelist` 是个空 dict，我们按它的键格式塞进去即可 ——
    "全段签名 safe 则归零"这条规则仍然由上游的代码执行。
    """
    handler = HeuristicHandler()
    handler.safelist = {
        get_safelist_key("signature", name): True
        for name, is_safe in signature_safe.items() if is_safe
    }
    return handler


def score_heuristic(
    definition: HeuristicScore,
    *,
    frequency: int = 1,
    signatures: Mapping[str, int] | None = None,
    signature_safe: Mapping[str, bool] | None = None,
) -> ScoredHeuristic:
    """算一条判据的分数。**算式在上游，这里只搬进搬出。**

    上游 `HeuristicHandler.service_heuristic_to_result_heuristic()` 干完了全部四件事：
    分数累加 / 频次乘 / `max_score` 夹逼 / 全段 safe 归零，外加 ATT&CK 展开
    （含 `software_map` / `group_map` 的关联展开 —— 以前我们自己抄的那份只认 technique）。

    ⚠️ 上游的 `signatures` 参数是 `{签名名: 命中次数}`，不是 `{签名名: 分数}`。
    弄反过一次：把分数当次数传进去，125 × 125 直接被 max_score 夹到上限，
    于是"命中一次"和"命中三次"给出同一个数。分数从判据定义里取，次数从命中记录里取。

    ⚠️ 上游对签名频次是 `sig_score * freq`，`freq=0` 会算出 0 分。我们把频次夹到 ≥1 ——
    命中记录里"命中 0 次"是不存在的输入，不是"这条不算分"的表达方式。
    """
    sigs = {str(name): max(int(freq), 1) for name, freq in dict(signatures or {}).items()}
    safe_map = {str(name): bool(ok) for name, ok in dict(signature_safe or {}).items()}
    freq = max(int(frequency or 1), 1)

    service_heuristic = {
        "heur_id": definition.heur_id,
        "attack_ids": list(definition.attack_ids),
        "signatures": sigs,
        "frequency": freq,
        "score_map": {},
    }
    output, _tags = _handler(safe_map).service_heuristic_to_result_heuristic(
        service_heuristic, {definition.heur_id: _as_upstream_model(definition)}
    )

    score = int(output["score"])
    return ScoredHeuristic(
        heur_id=output["heur_id"],
        name=output["name"],
        score=score,
        frequency=freq,
        signatures=sigs,
        attack=list(output["attack"]),
        signature_safe=safe_map,
        # 上游是"算完发现全 safe 就把分改成 0"，不额外告诉你是被归零的。
        # 这个标记只给报告解释用，不改上游算出来的分。
        zeroed_by_safelist=bool(sigs) and score == 0 and all(safe_map.get(n, False) for n in sigs),
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
