#!/usr/bin/env python3
"""回归：**非 PDF 类型的摘要渲染必须逐字节不变**（2026-09-27，PDF 盲区修复的核验）。

为什么要单独一个脚本：这一轮给②层加了"PDF 单独一条解析路径"。改的是
`aiav/triage.py` 的 `build_summary` / `render_user_prompt` / `render_prompt`
—— 都是**共用函数**。vbs / js / bat / rtf / xls 这几类在批次 A 里已经跑对了
（召回 1.000 / 1.000 / 0.950 / 0.825 / 0.967），**一个字都不许被带坏**。

口径：把改动前的 `triage.py`（`--old-module`）与改动后的 `aiav.triage`
同时装进内存，对同一批文件各跑一遍
`render_prompt(build_summary(f))`，**逐字节比 `user` / `system` 两个字段**。

只读静态：不执行样本、不调模型、不花钱。

用法：
    .venv/bin/python scripts/pdf_summary_regression.py \
        --old-module /tmp/pdf-fix/triage_old.py \
        --per-type 8 --out /tmp/pdf-fix/regression.json
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: 语料目录 → 类型名（批次 A 里跑对的那几类，各抽几个）。
DEFAULT_SETS = {
    "vbs": "~/ai-av-bench/mb-vbs",
    "js": "~/ai-av-bench/mb-js",
    "bat": "~/ai-av-bench/mb-bat",
    "rtf": "~/ai-av-bench/mb-rtf",
    "xls": "~/ai-av-bench/mb-xls",
    "ps1": "~/ai-av-bench/mb-ps1",
    "wsf": "~/ai-av-bench/mb-wsf",
    "hta": "~/ai-av-bench/mb-hta",
    "docm": "~/ai-av-bench/mb-docm",
    "pe": "~/ai-av-bench/benign-win",
}


def load_old(path: Path):
    spec = importlib.util.spec_from_file_location("triage_old_snapshot", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"装不进旧模块: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["triage_old_snapshot"] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    ap = argparse.ArgumentParser(description="非 PDF 摘要渲染回归（逐字节）")
    ap.add_argument("--old-module", type=Path, required=True,
                    help="改动前的 triage.py 快照（例：/tmp/pdf-fix/triage_old.py）")
    ap.add_argument("--per-type", type=int, default=8, help="每类抽几个文件")
    ap.add_argument("--include-ext", default="", help="benign-win 这类目录只取这些扩展名")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    old = load_old(args.old_module)
    from aiav.triage import build_summary, render_prompt  # noqa: E402

    wanted = [e.strip().lower() for e in args.include_ext.split(",") if e.strip()]
    report: dict[str, object] = {"per_type": {}, "checked": 0, "differ": 0, "errors": []}
    per_type: dict[str, dict[str, object]] = report["per_type"]  # type: ignore[assignment]

    for kind, root in DEFAULT_SETS.items():
        base = Path(root).expanduser()
        if not base.is_dir():
            continue
        files = [Path(p) for p in sorted(glob.glob(str(base / "*")))]
        # 扩展名过滤**只对 PE 那一类**生效（`benign-win` 是混着的系统目录）；
        # 脚本/文档类的目录里本来就只有那一种扩展名，再过滤会一个都选不出来。
        if wanted and kind == "pe":
            files = [f for f in files if f.suffix.lower() in {f".{e}" for e in wanted}]
        files = [f for f in files if f.is_file()][: args.per_type]
        if not files:
            continue
        same = 0
        diffs: list[dict[str, str]] = []
        for path in files:
            try:
                new_summary = build_summary(path)
                new_prompt = render_prompt(new_summary)
                old_prompt = old.render_prompt(old.build_summary(path))
            except Exception as exc:  # noqa: BLE001
                report["errors"].append(f"{kind}/{path.name}: {type(exc).__name__}: {exc}"[:200])
                continue
            report["checked"] = int(report["checked"]) + 1
            if (new_prompt.user == old_prompt.user
                    and new_prompt.system == old_prompt.system
                    and new_prompt.est_tokens == old_prompt.est_tokens):
                same += 1
                continue
            report["differ"] = int(report["differ"]) + 1
            diffs.append({
                "file": path.name,
                "old_tokens": str(old_prompt.est_tokens),
                "new_tokens": str(new_prompt.est_tokens),
                "old_user_head": old_prompt.user[:300],
                "new_user_head": new_prompt.user[:300],
            })
        per_type[kind] = {
            "n": len(files), "identical": same, "differ": len(diffs),
            "kind_detected": sorted({str((build_summary(f).get("kind"))) for f in files}),
            "diff_samples": diffs[:2],
        }
        print(f"{kind:<6} n={len(files):<3} 逐字节一致={same:<3} 不一致={len(diffs)}")

    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n合计 检查 {report['checked']} 个文件，不一致 {report['differ']} 个")
    print(f"产物: {args.out}")
    if report["differ"] or report["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
