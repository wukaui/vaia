"""Assemblyline 适配层 —— **装包路线，不是抄来的副本**。

上游包 `assemblyline`（CybercentreCanada/assemblyline，MIT）是 `pyproject.toml` 里的一个依赖：
`pip install assemblyline`，我们用它的**模型**与**计分语义**。这个目录里没有它的任何一行代码，
只有两层薄适配：

| 文件 | 干什么 |
|---|---|
| `scoring.py` | 我们的判据定义 ↔ 上游 `odm/models/heuristic.py` 模型；算分交给上游 `common/heuristics.py`；档位边界从上游 `DEFAULT_VERDICTS` 读 |
| `attack_ids.py` | ATT&CK ID → 名字/分类，直接查上游 `common/attack_map.py` |

模型直接用上游的，不经过我们这层：

    from assemblyline.odm.models.result import Result        # 报告结构校验
    from assemblyline.odm.models.submission import Submission
    from assemblyline.odm.models.tagging import Tagging

**红线：不依赖它的平台。** 不碰 MongoDB / Elasticsearch / Redis / K8s ——
不跑它的 datastore / filestore / cachestore / remote / run，不调 `forge.get_datastore()`。
理由是**运维负担**：我们要的是它的模型与评分语义能跑起来并接进我们的流水线，
不是把它的服务器也搬过来。证据在 `tests/test_assemblyline_core.py`：
把 socket 拦掉，导入 + 算分 + 构造 `Result` 全程零连接。

（它的客户端库 `elasticapm` / `elasticsearch` 会随包进来、会进 `sys.modules` ——
那是依赖树的事，不是"要平台"。它们没被调用，也没有服务需要跑。）
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from . import attack_ids, scoring  # noqa: F401
from .attack_ids import ATTACK_IDS, USED_ATTACK_IDS, describe  # noqa: F401
from .scoring import (  # noqa: F401
    MALICIOUS_SCORE,
    SCORE_BANDS,
    SUSPICIOUS_SCORE,
    DeterministicVerdict,
    Disposition,
    HeuristicScore,
    ScoreBand,
    ScoreTier,
    ScoredHeuristic,
    aggregate_file_score,
    aggregate_submission_score,
    band_of,
    score_heuristic,
    tier_of,
)

UPSTREAM = "CybercentreCanada/assemblyline"
LICENCE = "MIT"


def upstream_version() -> str:
    """装进来的上游包版本。没装就明说 —— 不许静默降级成"没有 Assemblyline 语义"。"""
    try:
        return version("assemblyline")
    except PackageNotFoundError as exc:  # pragma: no cover - 环境问题，不是逻辑分支
        raise RuntimeError(
            "没装 assemblyline 包。装包路线要求 `pip install assemblyline`"
            "（pyproject.toml 里已列为依赖）。"
        ) from exc


__all__ = [
    "UPSTREAM",
    "LICENCE",
    "upstream_version",
    "attack_ids",
    "scoring",
    "ATTACK_IDS",
    "USED_ATTACK_IDS",
    "describe",
    "SCORE_BANDS",
    "SUSPICIOUS_SCORE",
    "MALICIOUS_SCORE",
    "ScoreBand",
    "ScoreTier",
    "band_of",
    "tier_of",
    "HeuristicScore",
    "ScoredHeuristic",
    "score_heuristic",
    "aggregate_file_score",
    "aggregate_submission_score",
    "Disposition",
    "DeterministicVerdict",
]
