"""Assemblyline 适配层（`aiav/assemblyline_core/`）的自检 —— **装包路线**。

盯三件事：
1. **用的是上游包，不是仓库里的副本** —— 模型来自 site-packages 里的 `assemblyline`，
   版本与 `pyproject.toml` 钉的一致；仓库里不许再出现上游源码副本。
2. **不依赖它的平台** —— 把 socket 拦掉，导入 + 算分 + 构造 `Result` 全程零连接。
   这条如果破了，"脱离 ES+Redis 独立运行"就是空话。
3. **算分与档位是上游的语义** —— 累加 / 频次乘 / `max_score` 夹逼 / 白名单归零 / 档位边界，
   数值全部来自上游 `common/heuristics.py` 与 `DEFAULT_VERDICTS`。
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CORE = REPO / "aiav" / "assemblyline_core"
PINNED = "4.7.4.20"


def _run_blocked(code: str) -> str:
    """在子进程里拦掉所有 socket 连接后跑一段代码，返回它的 stdout。

    拦网是最硬的证据：只要碰了 ES / Redis / Mongo / K8s，代码当场炸。
    """
    harness = (
        "import socket\n"
        "def _blocked(*a, **k):\n"
        "    raise RuntimeError(f'PLATFORM TOUCHED: {a[:2]}')\n"
        "socket.socket.connect = _blocked\n"
        "socket.socket.connect_ex = _blocked\n"
        "socket.create_connection = _blocked\n"
    ) + code
    out = subprocess.run([sys.executable, "-c", harness], capture_output=True, text=True,
                         cwd=str(REPO))
    assert out.returncode == 0, f"拦网环境下跑挂了：\n{out.stdout}\n{out.stderr}"
    return out.stdout.strip()


# --------------------------------------------------------------------------------------
# 用的是上游包，不是副本
# --------------------------------------------------------------------------------------
def test_upstream_package_is_installed_and_pinned():
    import importlib.metadata as md

    from aiav.assemblyline_core import upstream_version

    assert upstream_version() == PINNED
    assert md.version("assemblyline") == PINNED
    pinned = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    deps = pinned["project"]["dependencies"]
    assert f"assemblyline=={PINNED}" in deps, "上游包没钉在 pyproject 依赖里"


def test_models_we_use_come_from_the_installed_package():
    """报告校验用的 `Result` 必须是 site-packages 里那个，不是我们仓库里的。"""
    from assemblyline.odm.models.result import Result

    path = Path(sys.modules[Result.__module__].__file__).resolve()
    assert "site-packages" in str(path), f"Result 不是装包来的：{path}"
    assert CORE not in path.parents
    assert Result.__module__.startswith("assemblyline.")


def test_no_vendored_copy_in_repo():
    """抄模型路线的产物必须一个不剩 —— 否则"用哪个"说不清。"""
    leftovers = [
        CORE / "odm", CORE / "_compat", CORE / "VENDOR.json", CORE / "LICENCE.md",
        REPO / "scripts" / "vendor_assemblyline.py",
        REPO / "scripts" / "parity_check_assemblyline.py",
    ]
    assert not [p for p in leftovers if p.exists()], \
        f"这些抄模型路线的东西还在：{[str(p) for p in leftovers if p.exists()]}"
    # 按"上游源码的指纹"认，不按出处抬头认（适配层自己也会写出处）：
    # 上游 ODM 的模型声明装饰器，以及它每份文件的许可证抬头。
    # 指纹拼出来，免得这个测试文件自己命中自己。
    needles = ("Crown " + "Copyright", "@odm." + "model(")
    copied = [
        p.relative_to(REPO) for p in REPO.rglob("*.py")
        if not any(part in {".venv", "build", "third_party", ".git", ".pytest_cache"}
                   for part in p.parts)
        and any(n in p.read_text(encoding="utf-8") for n in needles)
    ]
    assert copied == [], f"仓库里还有上游源码副本：{copied}"
    assert not list(REPO.rglob("VENDOR.json")), "还有 VENDOR.json"


def test_core_is_only_an_adapter():
    """适配层就三个文件：出口 / 计分 / ATT&CK。多出来的都是没删干净的副本。"""
    files = sorted(p.name for p in CORE.glob("*.py"))
    assert files == ["__init__.py", "attack_ids.py", "scoring.py"]


# --------------------------------------------------------------------------------------
# 不依赖平台
# --------------------------------------------------------------------------------------
def test_semantics_run_with_sockets_blocked():
    """导入 + 算分 + 构造并校验 `Result`，全程零连接。"""
    out = _run_blocked(
        "from aiav.assemblyline_core import score_heuristic, HeuristicScore\n"
        "from aiav.models import FileReport, RiskLevel, Verdict\n"
        "from aiav.assemblyline_view import build_result, validate_result\n"
        "d = HeuristicScore(heur_id='STRONG_YARA', name='强 YARA', description='x',\n"
        "                   score=750, max_score=750, attack_ids=('T1204.002',))\n"
        "s = score_heuristic(d, signatures={'yara:Loader': 2})\n"
        "assert s.score == 750, s.score\n"
        "rep = FileReport(path='/tmp/x.exe', sha256='a'*64, size=1024, extension='.exe',\n"
        "                 prefilter_score=750, prefilter_reasons=['强 YARA'],\n"
        "                 criteria_hits=[{'heur_id': 'STRONG_YARA', 'name': '强 YARA',\n"
        "                                 'description': 'x', 'score': 750, 'max_score': 750,\n"
        "                                 'frequency': 1, 'filetype': '*',\n"
        "                                 'produced_by': 'yara-python', 'direction': 'suspect',\n"
        "                                 'conclusive': False, 'safelisted': False,\n"
        "                                 'attack': s.attack, 'signature': []}],\n"
        "                 deterministic={'disposition': 'send_ai'},\n"
        "                 verdict=Verdict(risk=RiskLevel.suspicious, confidence=0.7, summary='s'))\n"
        "validate_result(build_result(rep))\n"
        "print('OK')\n"
    )
    assert out == "OK"


def test_forge_datastore_really_needs_a_server():
    """`forge.get_datastore()` 一调就要连 127.0.0.1:9200 —— 所以它绝不能出现在我们的代码里。

    这条测试是**反证**：如果哪天我们的扫描链路真去连 ES 了，上面那条测试会当场炸，
    而不是变成"跑得慢但没报错"。
    """
    out = _run_blocked(
        "from assemblyline.common import forge\n"
        "try:\n"
        "    forge.get_datastore()\n"
        "except RuntimeError as e:\n"
        "    print('NEEDS_SERVER' if 'PLATFORM TOUCHED' in str(e) else f'其他错: {e}')\n"
        "else:\n"
        "    print('CONNECTED')\n"
    )
    assert out == "NEEDS_SERVER"


def test_no_platform_entrypoints_in_our_source():
    """源码里不许出现"要连平台"的上游入口 —— 靠自律不如靠 AST 扫。

    只看**代码**，不看注释与 docstring：适配层的说明文字里当然会提到这些名字
    （"我们不调 get_datastore"这句话本身就得写出 get_datastore）。
    """
    import ast

    banned_names = {"get_datastore", "get_client", "get_cache", "get_filestore",
                    "Elasticsearch", "MongoClient", "Redis"}
    banned_modules = {"elasticsearch", "redis", "pymongo", "kubernetes",
                      "assemblyline.datastore", "assemblyline.filestore",
                      "assemblyline.cachestore", "assemblyline.remote",
                      "assemblyline.run"}

    hits: list[str] = []
    for path in sorted((REPO / "aiav").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in banned_names:
                hits.append(f"{path.relative_to(REPO)}:{node.lineno} .{node.attr}")
            elif isinstance(node, ast.Name) and node.id in banned_names:
                hits.append(f"{path.relative_to(REPO)}:{node.lineno} {node.id}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in banned_modules:
                        hits.append(f"{path.relative_to(REPO)}:{node.lineno} import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module in banned_modules:
                hits.append(f"{path.relative_to(REPO)}:{node.lineno} from {node.module}")
    assert hits == [], f"这些地方碰了平台入口：{hits}"


def test_elasticsearch_client_is_never_imported_by_us():
    """它的客户端库随依赖树进来是允许的，但我们自己的代码不许 import 它。"""
    code = (
        "import aiav.cli, aiav.scanner, aiav.criteria, aiav.assemblyline_view,"
        " aiav.assemblyline_core, aiav.report\n"
        "import sys\n"
        "bad = sorted({m.split('.')[0] for m in sys.modules} &"
        " {'elasticsearch', 'redis', 'pymongo', 'kubernetes'})\n"
        "print(','.join(bad))\n"
    )
    out = _run_blocked(code)
    assert out == "", f"我们的模块把平台客户端拉进来了：{out}"


# --------------------------------------------------------------------------------------
# 计分语义（上游 `common/heuristics.py`）
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


def test_signature_score_map_overrides_default_score():
    """上游 `signature_score_map` 优先于判据默认分 —— 同一个 heur_id 下不同签名不同价。

    ⚠️ 上游对这张表的**键**有格式要求（`^[a-z][a-z0-9_]*$`，`odm/base.py::FIELD_SANITIZER`）：
    小写字母开头、只许小写字母/数字/下划线。`clamav:Win.Trojan.A` 这种真实签名名**放不进去**。
    我们的判据表里这张表一直是空的，所以没踩到；这条测试把它钉住，免得以后有人想加时才发现。
    """
    from aiav.assemblyline_core.scoring import HeuristicScore, score_heuristic

    d = HeuristicScore(heur_id="X", name="X", description="", score=300,
                       signature_score_map={"expensive_sig": 500})
    assert score_heuristic(d, signatures={"expensive_sig": 1}).score == 500
    assert score_heuristic(d, signatures={"other_sig": 1}).score == 300

    for bad_key in ("EXPENSIVE_SIG", "clamav:Win.Trojan.A", "中文签名"):
        with pytest.raises(KeyError):
            score_heuristic(HeuristicScore(heur_id="X", name="X", description="", score=300,
                                           signature_score_map={bad_key: 500}))


def test_max_score_clamps_and_safelist_zeroes():
    from aiav.assemblyline_core.scoring import HeuristicScore, score_heuristic

    d = HeuristicScore(heur_id="X", name="X", description="", score=800, max_score=500)
    assert score_heuristic(d).score == 500

    safe = score_heuristic(d, signatures={"a": 1}, signature_safe={"a": True})
    assert safe.score == 0
    assert safe.zeroed_by_safelist is True


def test_attack_expansion_is_done_by_upstream():
    """ATT&CK 展开在上游做（含 software → technique 的关联展开），我们只搬结果。"""
    from aiav.assemblyline_core.scoring import HeuristicScore, score_heuristic

    d = HeuristicScore(heur_id="X", name="X", description="", score=1,
                       attack_ids=("T1204.002",))
    scored = score_heuristic(d)
    assert scored.attack[0]["attack_id"] == "T1204.002"
    assert scored.attack[0]["pattern"] == "Malicious File"
    assert scored.attack[0]["categories"] == ["execution"]


def test_aggregation_rules():
    from aiav.assemblyline_core.scoring import (
        ScoreTier,
        ScoredHeuristic,
        aggregate_file_score,
        aggregate_submission_score,
        tier_of,
    )

    sections = [ScoredHeuristic(heur_id="a", name="a", score=300),
                ScoredHeuristic(heur_id="b", name="b", score=750)]
    assert aggregate_file_score(sections) == 1050          # 文件分 = 各段求和
    assert aggregate_submission_score([1050, 300, 125]) == 1050   # 提交分 = 最高的那个
    assert tier_of(499) is ScoreTier.WEAK
    assert tier_of(500) is ScoreTier.STRONG
    assert tier_of(1000) is ScoreTier.CONCLUSIVE


def test_band_boundaries_come_from_upstream_config():
    """档位边界是上游 `DEFAULT_VERDICTS` 的值，不是我们写的字面量。"""
    from assemblyline.odm.models.config import DEFAULT_VERDICTS

    from aiav.assemblyline_core import scoring
    from aiav.criteria import AI_GATE, CONCLUSIVE_SCORE, STRONG_FLOOR

    assert dict(scoring.SCORE_BANDS) == {
        scoring.SAFE_FLOOR: scoring.ScoreBand.SAFE,
        DEFAULT_VERDICTS["info"]: scoring.ScoreBand.REFERENCE,
        DEFAULT_VERDICTS["suspicious"]: scoring.ScoreBand.SUSPICIOUS,
        DEFAULT_VERDICTS["highly_suspicious"]: scoring.ScoreBand.HIGHLY_SUSPICIOUS,
        DEFAULT_VERDICTS["malicious"]: scoring.ScoreBand.MALICIOUS,
    }
    assert AI_GATE == DEFAULT_VERDICTS["suspicious"] == 300
    assert CONCLUSIVE_SCORE == DEFAULT_VERDICTS["malicious"] == 1000
    assert STRONG_FLOOR == 500
    # 上游改默认值，我们跟着走 —— 这几条断言就是"跟着走"的证明
    assert scoring.MALICIOUS_SCORE == DEFAULT_VERDICTS["malicious"]


def test_unknown_heuristic_raises_instead_of_scoring_zero():
    """判据 ID 不在定义表里 → 上游抛 `InvalidHeuristicException`，不许静默算 0 分。"""
    from assemblyline.common.heuristics import InvalidHeuristicException

    from aiav.assemblyline_core.scoring import HeuristicScore, _as_upstream_model, _handler

    d = HeuristicScore(heur_id="不存在", name="x", description="", score=1)
    with pytest.raises(InvalidHeuristicException):
        _handler({}).service_heuristic_to_result_heuristic(
            {"heur_id": "不存在", "attack_ids": [], "signatures": {}, "frequency": 1},
            {"别的判据": _as_upstream_model(d)},
        )


# --------------------------------------------------------------------------------------
# ATT&CK
# --------------------------------------------------------------------------------------
def test_attack_ids_come_from_upstream_map():
    from assemblyline.common.attack_map import attack_map

    from aiav.assemblyline_core.attack_ids import ATTACK_IDS, USED_ATTACK_IDS, describe

    assert len(ATTACK_IDS) == len(USED_ATTACK_IDS), "有用到的 ID 在上游查不到名字"
    assert describe("T1204.002")["name"] == attack_map["T1204.002"]["name"] == "Malicious File"
    assert describe("不存在的ID") is None
    assert describe("") is None


def test_used_attack_ids_are_actually_referenced_by_criteria():
    """`USED_ATTACK_IDS` 必须真的被判据表引用 —— 别留没人用的 ID 在报告里。"""
    from aiav.assemblyline_core.attack_ids import USED_ATTACK_IDS
    from aiav.criteria import CRITERIA

    referenced = {a for c in CRITERIA.values() for a in c.attack_ids}
    assert referenced == set(USED_ATTACK_IDS)
    assert not re.search(r"[^T0-9.]", "".join(USED_ATTACK_IDS))
