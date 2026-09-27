#!/usr/bin/env python3
"""一致性核验：我们抄的副本 / 移植的计分，跟上游 assemblyline 是不是**行为一致**。

这是"抄模型"路线的唯一硬证据 —— 不是"看起来一样"，是同输入同输出。

跑法（上游装在另一个环境里，两边分别跑，再比哈希）：

    UP=<装了 assemblyline 的 python>  OURS=<项目 venv 的 python>
    $UP   scripts/parity_check_assemblyline.py --emit /tmp/parity_up.json
    $OURS scripts/parity_check_assemblyline.py --emit /tmp/parity_ours.json
    python3 scripts/parity_check_assemblyline.py --compare /tmp/parity_up.json /tmp/parity_ours.json

`--emit` 只输出**确定性**部分：模型字段表、构造出的 JSON（时间戳字段已被抹平）、
以及计分用例的结果。`created` / `milestones` 这类"取当前时间"的字段不参与比对。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

VOLATILE = {"created", "service_started", "service_completed", "expiry_ts", "archive_ts"}


def _scrub(obj):
    """抹掉"取当前时间"的字段，剩下的必须逐字节相同。"""
    if isinstance(obj, dict):
        return {k: ("<time>" if k in VOLATILE and v is not None else _scrub(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(x) for x in obj]
    return obj


# --------------------------------------------------------------------------------------
# 用例
# --------------------------------------------------------------------------------------
RESULT_PAYLOAD = {
    "sha256": "a" * 64,
    "classification": "UNRESTRICTED",
    "response": {
        "service_name": "aiav-deterministic",
        "service_version": "0.1.0",
        "service_tool_version": "capa 9.4.0",
        "extracted": [
            {
                "name": "inner.exe",
                "sha256": "b" * 64,
                "description": "解包产物",
                "classification": "UNRESTRICTED",
                "parent_relation": "EXTRACTED",
            },
            {
                "name": "dropper.dll",
                "sha256": "c" * 64,
                "description": "下载产物",
                "classification": "UNRESTRICTED",
                "parent_relation": "DOWNLOADED",
            },
        ],
    },
    "result": {
        "score": 1050,
        "sections": [
            {
                "title_text": "确定性判据：ClamAV 哈希命中",
                "body": "sha256 命中已知恶意哈希表",
                "body_format": "TEXT",
                "classification": "UNRESTRICTED",
                "depth": 0,
                "tags": {
                    "attribution": {"implant": ["EMOTET"]},
                    "file": {"name": {"extracted": ["inner.exe"]}},
                },
                "safelisted_tags": {"av.virus_name": ["Eicar-Test-Signature"]},
                "heuristic": {
                    "heur_id": "DET_KNOWN_BAD_HASH",
                    "name": "已知恶意哈希",
                    "score": 1000,
                    "attack": [
                        {"attack_id": "T1204.002", "pattern": "Malicious File", "categories": ["execution"]}
                    ],
                    "signature": [
                        {"name": "clamav:Win.Trojan.Agent", "frequency": 2, "safe": False},
                        {"name": "yara:Emotet_Loader", "frequency": 1, "safe": False},
                    ],
                },
            }
        ],
    },
}

# 计分用例：(判据默认分, max_score, 签名命中, 频次, 期望语义说明)
SCORING_CASES = [
    ("no-signature-freq1", 300, None, {}, 1),
    ("no-signature-freq3", 300, None, {}, 3),
    ("max-score-clamp", 800, 500, {}, 1),
    ("signature-sum", 300, None, {"sig_a": 2, "sig_b": 3}, 1),
    ("signature-frequency-multiplier", 300, None, {"sig_a": 3}, 4),
    ("signature-clamp", 300, 100, {"sig_a": 5}, 2),
]


def emit() -> dict:
    try:
        import assemblyline.odm as odm  # noqa: PLC0415
        from assemblyline.common.heuristics import Heuristic as UpstreamHeuristic  # noqa: PLC0415
        from assemblyline.odm.models.result import Result  # noqa: PLC0415

        flavour = "upstream"
    except ImportError:
        sys.path.insert(0, str(REPO))
        import aiav.assemblyline_core.odm as odm  # noqa: PLC0415
        from aiav.assemblyline_core.odm.models.result import Result  # noqa: PLC0415

        UpstreamHeuristic = None
        flavour = "vendored"

    out: dict = {"flavour": flavour}

    # 1) 模型字段表
    flat = sorted(Result.flat_fields().keys())
    out["result_flat_fields_count"] = len(flat)
    out["result_flat_fields_sha"] = hashlib.sha256("\n".join(flat).encode()).hexdigest()

    # 2) 构造同一份内容，比 JSON
    r = Result(json.loads(json.dumps(RESULT_PAYLOAD)))
    scrubbed = _scrub(r.as_primitives())
    out["result_json"] = scrubbed
    out["result_json_sha"] = hashlib.sha256(
        json.dumps(scrubbed, sort_keys=True, default=str).encode()
    ).hexdigest()

    # 3) 计分语义
    scored = {}
    for name, base, max_score, sigs, freq in SCORING_CASES:
        if flavour == "upstream":
            definition = _UpstreamDef(base, max_score, sigs)
            h = UpstreamHeuristic("X", [], sigs, {}, freq, {"X": definition})
            scored[name] = h.score
        else:
            from aiav.assemblyline_core.scoring import HeuristicScore, score_heuristic  # noqa: PLC0415

            definition = HeuristicScore(
                heur_id="X",
                name="X",
                description="",
                score=base,
                signature_score_map={k: v for k, v in sigs.items()},
                max_score=max_score,
            )
            scored[name] = score_heuristic(definition, frequency=freq, signatures=sigs).score
    out["scoring"] = scored
    return out


class _UpstreamDef:
    """喂给上游 Heuristic 的最小判据定义。"""

    def __init__(self, score, max_score, sigs):
        self.name = "X"
        self.classification = "UNRESTRICTED"
        self.score = score
        self.max_score = max_score
        self.signature_score_map = dict(sigs)


def compare(a_path: Path, b_path: Path) -> int:
    a = json.loads(a_path.read_text())
    b = json.loads(b_path.read_text())
    bad = 0
    for key in ("result_flat_fields_count", "result_flat_fields_sha", "result_json_sha", "scoring"):
        same = a.get(key) == b.get(key)
        print(f"{'一致' if same else '不一致'}  {key}: {a.get(key) if key != 'scoring' else ''}")
        if not same:
            bad += 1
            if key == "scoring":
                for case in sorted(set(a["scoring"]) | set(b["scoring"])):
                    if a["scoring"].get(case) != b["scoring"].get(case):
                        print(f"    {case}: 上游={a['scoring'].get(case)} 我们={b['scoring'].get(case)}")
            else:
                print(f"    上游={a.get(key)}  我们={b.get(key)}")
    if a.get("result_json") != b.get("result_json"):
        print("不一致  result_json 正文")
        bad += 1
    print(f"\n{'全部一致' if not bad else f'{bad} 项不一致'}（上游={a['flavour']} 我们={b['flavour']}）")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--emit", type=Path, help="把本环境的结果写到这个 JSON")
    ap.add_argument("--compare", nargs=2, type=Path, metavar=("UPSTREAM", "OURS"))
    args = ap.parse_args()

    if args.compare:
        return compare(*args.compare)
    data = emit()
    if args.emit:
        args.emit.write_text(json.dumps(data, indent=2, sort_keys=True, default=str))
        print(f"写入 {args.emit}（flavour={data['flavour']}）")
    else:
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
