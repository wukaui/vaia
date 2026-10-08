#!/usr/bin/env python3
"""两档送审 · **holdout** 规则档扫描（2026-09-27）。

为什么要单独一个脚本：`aiav scan` 一次只吃一个路径，而 holdout 语料散在十几个目录里
（`mb-bat` / `mb-doc` / … / `benign-win`），一个目录起一次 CLI = 十几次 ClamAV 批量预扫。
这里直接用库跑一批文件、写一份**与 `aiav scan` 同形状的产物**（`reports[]`），
交给 `scripts/two_tier_measure.py` 汇总 —— 口径与主实测完全一致。

只跑**规则档**（`agent=None`）：holdout 要回答的是"低档会在真实语料上多送多少、多抓多少"，
这件事在①层就定死了，不需要花钱调模型。**只读静态，不执行、不上传。**

用法：
    .venv/bin/python scripts/two_tier_holdout_scan.py \
        --set malicious=/home/wukuai/ai-av-bench/mb-bat \
        --set malicious=/home/wukuai/ai-av-bench/mb-doc \
        --set clean=/home/wukuai/ai-av-bench/benign-win \
        --out /tmp/two-tier/holdout-scan.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()

from aiav.criteria import AI_GATE, AI_GATE_LOW  # noqa: E402
from aiav.scanner import iter_files, scan_file  # noqa: E402
from aiav.tools import clamav_scan_batch  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="holdout 规则档扫描（两档闸门）")
    ap.add_argument("--set", action="append", default=[],
                    help="标签=目录（可重复），标签 ∈ {clean, malicious}")
    ap.add_argument("--gate", type=int, default=AI_GATE)
    ap.add_argument("--gate-low", type=int, default=AI_GATE_LOW)
    ap.add_argument("--max-size-mb", type=int, default=50)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    files: list[tuple[Path, str]] = []
    for spec in args.set:
        label, _, root = spec.partition("=")
        if label not in ("clean", "malicious") or not root:
            raise SystemExit(f"--set 要写成 标签=目录，收到 {spec!r}")
        got = [(p, label) for p in iter_files(Path(root), max_size_mb=args.max_size_mb)]
        print(f"{label:<9} {root}: {len(got)} 个文件")
        files.extend(got)

    paths = [p for p, _ in files]
    t0 = time.time()
    batch = clamav_scan_batch(paths)
    print(f"ClamAV: available={batch['available']} scanned={batch['scanned']} "
          f"found={batch['found']} unreported={len(batch['unreported'])} "
          f"error={batch['error']!r} · {time.time() - t0:.1f}s")

    reports = []
    t1 = time.time()
    for i, (p, label) in enumerate(files, 1):
        r = scan_file(p, agent=None, ai_threshold=args.gate,
                      ai_threshold_low=args.gate_low, store=None,
                      allow_unpack=True, allow_archives=True, cache=None,
                      clamav_batch=batch)
        d = r.model_dump(mode="json")
        d["_label"] = label          # holdout 侧标签（由目录决定），汇总脚本读它
        reports.append(d)
        if i % 500 == 0:
            print(f"  {i}/{len(files)} … {time.time() - t1:.0f}s")

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "gate": args.gate, "gate_low": args.gate_low,
        "clamav_batch": {k: v for k, v in batch.items() if k != "hits"},
        "reports": reports,
    }
    Path(args.out).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    print(f"写到 {args.out}（{len(reports)} 个文件，{time.time() - t1:.0f}s）")


if __name__ == "__main__":
    main()
