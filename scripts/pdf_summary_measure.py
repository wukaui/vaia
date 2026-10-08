#!/usr/bin/env python3
"""PDF 盲区修复 · ②层摘要对照实测（2026-09-27）—— **只跑 PDF。**

量的是同一件事的两遍：同一批 PDF 文件，**旧摘要**（批次 A 那一版）与
**新摘要**（PDF 单独解析路径）各跑一遍②层 LLM 初筛，逐文件打分。

为什么把"旧摘要"也重跑一遍，而不是直接引用历史数字：
批次 A 的 0.283 是**完整链路**（①层路由 + ② + ③）在 `mb-pdf` 上的召回，
受①层入口闸 125 影响（60 个里 42 个根本没进②层）。要判断"摘要修复本身有没有用"，
必须把①层路由这个变量**按住**，让两遍只差"摘要"这一个东西 —— 所以两遍都在
**同一份文件清单**、同一模型、同一门槛下跑，唯一变量是摘要渲染。

口径：
  · `--summary-module` 传旧快照（`/tmp/pdf-fix/triage_old.py`）就是旧摘要臂；
    不传（默认 `aiav.triage`）就是新摘要臂。两个模块的 `TRIAGE_VERSION` 不同
    （1 vs 2），缓存键天然隔离 —— 但仍然**默认不吃缓存**（要的是"真跑"）。
  · 只读静态：不执行样本、不打开 PDF、不上传文件本体（发出去的是摘要文本）。
  · 逐文件留痕：`ok / error / model / parse_mode / usage_source / from_cache`，
    失败数或降级数不为 0 的批次要作废。

用法：
    .venv/bin/python scripts/pdf_summary_measure.py \
        --label malicious=~/ai-av-bench/mb-pdf \
        --label clean=/tmp/pdf-fix/corpus/benign \
        --summary-module /tmp/pdf-fix/triage_old.py \
        --out /tmp/pdf-fix/arm-old.json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv  # noqa: E402

load_dotenv()
load_dotenv(Path.cwd() / ".env")

from aiav.budget import CNY_PER_MILLION_TOKENS  # noqa: E402
from aiav.triage import TARGET_PROMPT_TOKENS, TriageClient  # noqa: E402

#: 与批次 A / 11.5 同一套门槛（**不许改**：改了就与前几批不可比）。
THRESHOLD = 60
ENTRY_GATE = 125
GATE = 200


def load_summary_module(spec: str):
    """`aiav.triage` 或一个 triage.py 快照文件。"""
    if spec in ("aiav.triage", "default"):
        from aiav import triage

        return triage, "aiav.triage"
    path = Path(spec).expanduser()
    if not path.is_file():
        raise SystemExit(f"找不到摘要模块快照: {path}")
    module_spec = importlib.util.spec_from_file_location("triage_snapshot", path)
    if module_spec is None or module_spec.loader is None:
        raise SystemExit(f"装不进模块: {path}")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules["triage_snapshot"] = module
    module_spec.loader.exec_module(module)
    return module, str(path)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect(specs: list[str]) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    for spec in specs:
        label, _, root = spec.partition("=")
        base = Path(root).expanduser()
        if not base.is_dir():
            raise SystemExit(f"语料目录不存在: {base}")
        files = sorted(p for p in base.iterdir() if p.is_file() and p.suffix.lower() != ".json")
        print(f"  {label:<9} {base}: {len(files)} 个文件")
        out.extend((p, label) for p in files)
    return out


def _spread(scores: list[int]) -> dict[str, object]:
    if not scores:
        return {"n": 0}
    ordered = sorted(scores)
    return {
        "n": len(scores),
        "min": ordered[0],
        "median": ordered[len(ordered) // 2],
        "max": ordered[-1],
        "mean": round(sum(ordered) / len(ordered), 1),
        "ge50": sum(1 for s in ordered if s >= 50),
        "ge60": sum(1 for s in ordered if s >= THRESHOLD),
        "ge70": sum(1 for s in ordered if s >= 70),
    }


def measure(rows: list[dict], labels: list[str]) -> dict[str, object]:
    out: dict[str, object] = {}
    for label in sorted(set(labels)):
        subset = [r for r in rows if r["label"] == label]
        scored = [r for r in subset if r["ok"] and r["score"] is not None]
        scores = [int(r["score"]) for r in scored]
        block: dict[str, object] = {"files": len(subset), "scored": len(scored)}
        block["score_spread"] = _spread(scores)
        if label == "malicious":
            block["recall_at_60"] = round(
                sum(1 for s in scores if s >= THRESHOLD) / len(scores), 4) if scores else None
            block["hits_at_60"] = sum(1 for s in scores if s >= THRESHOLD)
            block["denominator"] = len(scores)
            block["note"] = ("**②层召回** = 初筛分 ≥ 门槛 60 的恶意 / 该批恶意总数。"
                             "这是层内口径，不含①层路由（生产上 ② 只看得到入口闸 125 以上的文件）。")
        else:
            selected = sum(1 for s in scores if s >= THRESHOLD)
            block["sent_to_deep"] = selected
            block["send_rate"] = round(selected / len(scores), 4) if scores else None
            block["false_positive_note"] = (
                "门槛 60 下的 **②层送审率**。真正的误报要看③层"
                "（②层只管值不值得看，不管是不是恶意）。")
        out[label] = block
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="PDF ②层摘要对照实测（只跑 PDF）")
    ap.add_argument("--label", action="append", default=[], required=True,
                    help="标签=目录（可重复）：malicious / clean")
    ap.add_argument("--summary-module", default="aiav.triage",
                    help="aiav.triage（新摘要）或 triage.py 快照路径（旧摘要）")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--model", default=None, help="覆盖 AGENT_MODEL")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--max-prompt-tokens", type=int, default=TARGET_PROMPT_TOKENS)
    ap.add_argument("--arm-name", default="", help="产物里记的臂名")
    args = ap.parse_args()

    module, module_name = load_summary_module(args.summary_module)
    print(f"摘要模块: {module_name}（TRIAGE_VERSION={module.TRIAGE_VERSION}）")
    files = collect(args.label)

    client = TriageClient(model=args.model)
    print(f"模型: {client.model} · 文件 {len(files)} 个 · workers {args.workers}")

    rows: list[dict] = []
    started = time.time()
    with __import__("httpx").Client(
        timeout=client.timeout,
        headers={"Authorization": f"Bearer {client.api_key}",
                 "Content-Type": "application/json", **client.headers},
    ) as http:
        from concurrent.futures import ThreadPoolExecutor

        def run(item: tuple[Path, str]) -> dict:
            path, label = item
            digest = sha256_of(path)
            summary = module.build_summary(path, digest)
            prompt = module.render_prompt(summary, max_tokens=args.max_prompt_tokens)
            call = client.classify(prompt, client=http)
            pdf = summary.get("pdf") or {}
            return {
                "name": path.name, "path": str(path), "label": label,
                "sha256": digest, "size": summary.get("size"),
                "kind": summary.get("kind"),
                "score": call.score, "reason": call.reason, "ok": call.ok,
                "error": call.error, "parse_mode": call.parse_mode,
                "attempts": call.attempts, "model": call.model,
                "prompt_tokens": call.prompt_tokens,
                "completion_tokens": call.completion_tokens,
                "total_tokens": call.total_tokens,
                "usage_source": call.usage_source,
                "est_tokens": prompt.est_tokens,
                "summary_truncated": prompt.truncated,
                "summary_over_budget": prompt.over_budget,
                "strings_used": prompt.strings_used,
                "elapsed_ms": call.elapsed_ms,
                "pdf_facts": {
                    "structure": pdf.get("structure"),
                    "actions": pdf.get("actions"),
                    "js_total": pdf.get("js_total"),
                    "js_blocks": pdf.get("js_blocks"),
                    "js_snippets": pdf.get("js_snippets"),
                    "uris": pdf.get("uris"),
                    "embedded_files": pdf.get("embedded_files"),
                    "errors": pdf.get("errors"),
                } if pdf else None,
                "prompt_excerpt": prompt.user[:1400],
            }

        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            for record in pool.map(run, files):
                rows.append(record)
                mark = "ok " if record["ok"] else "ERR"
                print(f"  [{mark}] {str(record['score']):>4}  {record['label']:<9} "
                      f"{record['name'][:44]}")

    wall = round(time.time() - started, 1)
    charged = [r for r in rows if not r.get("from_cache")]
    total_tokens = sum(int(r["total_tokens"] or 0) for r in charged)
    metrics = measure(rows, [label for _p, label in files])
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "arm": args.arm_name or module_name,
        "summary_module": module_name,
        "triage_version": module.TRIAGE_VERSION,
        "model": client.model,
        "threshold": THRESHOLD, "entry_gate": ENTRY_GATE, "gate": GATE,
        "max_prompt_tokens": args.max_prompt_tokens,
        "corpus": {label: sum(1 for _p, l in files if l == label)
                   for label in sorted({l for _p, l in files})},
        "metrics": metrics,
        "cost": {
            "files": len(rows),
            "total_tokens": total_tokens,
            "prompt_tokens": sum(int(r["prompt_tokens"] or 0) for r in charged),
            "completion_tokens": sum(int(r["completion_tokens"] or 0) for r in charged),
            "tokens_per_file": round(total_tokens / len(charged), 1) if charged else 0,
            "est_tokens_per_file": round(
                sum(int(r["est_tokens"] or 0) for r in charged) / len(charged), 1) if charged else 0,
            "cny_per_million": CNY_PER_MILLION_TOKENS,
            "cost_cny": round(total_tokens / 1_000_000 * CNY_PER_MILLION_TOKENS, 4),
        },
        "verification": {
            "ok": sum(1 for r in rows if r["ok"]),
            "failed": sum(1 for r in rows if not r["ok"]),
            "errors": [f"{r['name']}: {r['error']}" for r in rows if not r["ok"]][:10],
            "from_cache": sum(1 for r in rows if r.get("from_cache")),
            "usage_source": {src: sum(1 for r in rows if r["usage_source"] == src)
                             for src in {r["usage_source"] for r in rows}},
            "parse_modes": {mode: sum(1 for r in rows if r["parse_mode"] == mode)
                            for mode in {r["parse_mode"] for r in rows}},
            "summary_truncated": sum(1 for r in rows if r["summary_truncated"]),
            "summary_over_budget": sum(1 for r in rows if r["summary_over_budget"]),
            "pdf_facts_present": sum(1 for r in rows if r.get("pdf_facts")),
            "usable": (sum(1 for r in rows if not r["ok"]) == 0
                       and sum(1 for r in rows if r.get("from_cache")) == 0),
        },
        "wall_s": wall,
        "rows": rows,
    }
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items()
                      if k in ("metrics", "cost", "verification", "wall_s")},
                     ensure_ascii=False, indent=1))
    print(f"产物: {args.out}")


if __name__ == "__main__":
    main()
