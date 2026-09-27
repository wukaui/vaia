"""Assemblyline 核心子集（抄来的，MIT）。

**这个包里没有平台。** 没有 Elasticsearch、没有 Redis、没有 S3、没有 K8s、没有 MongoDB。
只有两样东西：

1. `odm/` —— 上游的 ODM 模型定义（`odm/base.py` + 9 个模型），**逐字抄**，只改 import 路径。
   它们给出的是 Assemblyline 的**报告结构与字段语义**：判据 / 依据 / 证据段 / 服务 / 血缘。
2. `scoring.py` —— 上游 `common/heuristics.py` 的三档计分语义（累加 / 频次乘 / max_score 上限 /
   签名安全则归零），以及文件分 = 各段求和、提交分 = 最高文件分的聚合规则。

抄来的部分由 `scripts/vendor_assemblyline.py` 生成，`VENDOR.json` 记着每个文件的上游
sha256 与 import 改写记录，`LICENCE.md` 是上游 MIT 原文。`_compat/forge.py` 是手写垫片
（上游那份 import elasticapm / hauntedhouse，会拖进整个平台）。

**我们不用它的分数做判定** —— 判定仍然是 AI 的活。这里抄的是"怎么把证据摆成一条链"。
"""

from __future__ import annotations

from . import odm  # noqa: F401  便于 `from aiav.assemblyline_core import odm`
from .scoring import (  # noqa: F401
    SCORE_BANDS,
    DeterministicVerdict,
    HeuristicScore,
    ScoreBand,
    aggregate_file_score,
    aggregate_submission_score,
    band_of,
    score_heuristic,
)

__all__ = [
    "odm",
    "SCORE_BANDS",
    "ScoreBand",
    "band_of",
    "HeuristicScore",
    "score_heuristic",
    "aggregate_file_score",
    "aggregate_submission_score",
    "DeterministicVerdict",
]

UPSTREAM = "CybercentreCanada/assemblyline"
UPSTREAM_VERSION = "4.7.4.20"
LICENCE = "MIT"
