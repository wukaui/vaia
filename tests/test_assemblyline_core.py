"""抄来的 Assemblyline 核心（`aiav/assemblyline_core/`）的自检。

盯两件事：
1. **副本没被手改** —— `VENDOR.json` 记着每个文件抄下来时的 sha256，对不上就报错。
   手改副本是最容易发生、也最难发现的一种漂移。
2. **不依赖平台** —— 导入这些模型不许把 elasticsearch / redis / boto3 / azure 拉进来。
   这条如果破了，"脱离 ES+Redis 独立运行"就是空话。
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CORE = REPO / "aiav" / "assemblyline_core"


def test_vendor_manifest_exists_and_matches():
    manifest = json.loads((CORE / "VENDOR.json").read_text(encoding="utf-8"))
    assert manifest["upstream"] == "CybercentreCanada/assemblyline"
    assert manifest["licence"] == "MIT"
    assert manifest["files"], "VENDOR.json 里一个文件都没有"

    changed = []
    for rel, meta in manifest["files"].items():
        path = CORE / rel
        assert path.exists(), f"副本缺文件 {rel}"
        want = meta.get("vendored_sha256")
        if want and hashlib.sha256(path.read_bytes()).hexdigest() != want:
            changed.append(rel)
    assert not changed, f"这些副本被手改过（用 scripts/vendor_assemblyline.py 重新生成）：{changed}"


def test_upstream_licence_is_kept():
    text = (CORE / "LICENCE.md").read_text(encoding="utf-8")
    assert "MIT License" in text
    assert "Crown Copyright" in text


def test_every_vendored_file_has_provenance_header():
    """抄来的每个 .py 都要带出处抬头 —— MIT 要求保留版权声明。"""
    for path in sorted(CORE.rglob("*.py")):
        if path.name == "__init__.py" and path.parent in (CORE, CORE / "_compat"):
            continue
        if path.name in ("scoring.py", "attack_ids.py", "forge.py"):
            continue          # 手写的 / 派生的，见各自 docstring
        head = path.read_text(encoding="utf-8")[:400]
        assert "CybercentreCanada/assemblyline" in head, f"{path} 没有出处抬头"
        assert "MIT" in head, f"{path} 没写许可证"


@pytest.mark.parametrize("model", [
    "heuristic", "statistics", "filescore", "file", "result", "tagging",
    "badlist", "safelist", "submission",
])
def test_vendored_models_import(model):
    mod = __import__(f"aiav.assemblyline_core.odm.models.{model}", fromlist=["*"])
    assert mod is not None


def test_importing_models_pulls_no_platform():
    """抄模型路线必须能脱离 ES / Redis / S3 / Azure 独立跑 —— 用子进程验证。"""
    code = (
        "import sys;"
        "import aiav.assemblyline_core.odm.models.result;"
        "bad=sorted({m.split('.')[0] for m in sys.modules} & "
        "{'elasticsearch','redis','boto3','azure','paramiko','pysftp','hauntedhouse',"
        "'elasticapm','onnxruntime','magika','numpy'});"
        "print(','.join(bad))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         cwd=str(REPO), check=True)
    assert out.stdout.strip() == "", f"抄模型路线被拉进了平台模块：{out.stdout.strip()}"


def test_forge_shim_refuses_to_reach_the_platform():
    """垫片碰到"要连平台"的调用必须**明确报错**，不许静默返回 None。"""
    from aiav.assemblyline_core._compat import forge

    with pytest.raises(forge.PlatformNotVendoredError):
        forge.get_datastore()
    with pytest.raises(forge.PlatformNotVendoredError):
        forge.get_config()


def test_classification_engine_is_the_real_one():
    """分类引擎是上游原文 + 真实 yml，不是"返回一个常量"的假货。"""
    from aiav.assemblyline_core._compat import forge

    engine = forge.get_classification()
    assert engine.is_valid("UNRESTRICTED")
    assert engine.normalize_classification("UNRESTRICTED") == "TLP:C"


# --------------------------------------------------------------------------------------
# 计分语义（上游 `common/heuristics.py` 的等价物）
# --------------------------------------------------------------------------------------
def test_score_without_signature_uses_frequency():
    from aiav.assemblyline_core.scoring import HeuristicScore, score_heuristic

    d = HeuristicScore(heur_id="X", name="X", description="", score=300)
    assert score_heuristic(d, frequency=1).score == 300
    assert score_heuristic(d, frequency=3).score == 900


def test_score_with_signatures_sums_and_multiplies_by_hit_count():
    from aiav.assemblyline_core.scoring import HeuristicScore, score_heuristic

    d = HeuristicScore(heur_id="X", name="X", description="", score=300)
    scored = score_heuristic(d, signatures={"a": 2, "b": 1})
    assert scored.score == 900          # 300×2 + 300×1


def test_max_score_clamps_and_safelist_zeroes():
    from aiav.assemblyline_core.scoring import HeuristicScore, score_heuristic

    d = HeuristicScore(heur_id="X", name="X", description="", score=800, max_score=500)
    assert score_heuristic(d).score == 500

    safe = score_heuristic(d, signatures={"a": 1}, signature_safe={"a": True})
    assert safe.score == 0
    assert safe.zeroed_by_safelist is True


def test_aggregation_rules():
    from aiav.assemblyline_core.scoring import (
        ScoredHeuristic, aggregate_file_score, aggregate_submission_score, tier_of, ScoreTier,
    )

    sections = [ScoredHeuristic(heur_id="a", name="a", score=300),
                ScoredHeuristic(heur_id="b", name="b", score=750)]
    assert aggregate_file_score(sections) == 1050          # 文件分 = 各段求和
    assert aggregate_submission_score([1050, 300, 125]) == 1050   # 提交分 = 最高的那个
    assert tier_of(499) is ScoreTier.WEAK
    assert tier_of(500) is ScoreTier.STRONG
    assert tier_of(1000) is ScoreTier.CONCLUSIVE


def test_attack_ids_are_derived_not_whole_file():
    """ATT&CK 是**派生**的（只捞用到的 ID），不是把上游 3MB 的 attack_map 整份抄进来。"""
    from aiav.assemblyline_core.attack_ids import ATTACK_IDS, describe

    assert 0 < len(ATTACK_IDS) < 100
    assert describe("T1204.002")["name"] == "Malicious File"
    assert describe("不存在的ID") is None
