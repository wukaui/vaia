#!/usr/bin/env python3
"""LLM 初筛 · 灰区跑批驱动（2026-09-27）。

干三件事，都不改判据表、不动扫描器：
  1. 从确定性扫描产物里**按预筛分数**挑出灰区文件（默认 125/225/275 三档）；
  2. 用 `aiav.triage` 跑便宜档模型的初筛（最小摘要 ≤1000 token/文件）；
  3. 把逐文件结果 + 成本 + 核验块写成一个 JSON，交给 `llm_triage_report.py` 算指标。

口径写明：
  · `--pilot N` 只跑前 N 个（**试水**：先报一次成本量级再跑剩下的）；
  · 缓存按 sha256 命中（`TriageCache`），`--no-cache` 关掉；
  · **只读静态**：不执行样本、不上传、不落地。

用法：
    .venv/bin/python scripts/llm_triage_gray.py \
        --scan-report /tmp/dike400-norules/scan_*.json \
        --labels ~/ai-av-bench/dike-bench/labels.json \
        --buckets 125,225,275 --out /tmp/triage-gray/results.json
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
load_dotenv(Path.cwd() / ".env")
load_dotenv(Path.home() / ".config" / "aiav" / ".env")

from aiav.cache import TriageCache, default_triage_cache_dir, cache_enabled  # noqa: E402
from aiav.scanner import compute_sha256  # noqa: E402
from aiav.triage import (  # noqa: E402
    TARGET_PROMPT_TOKENS,
    TRIAGE_VERSION,
    TriageClient,
    run_batch,
    summarize_cost,
)


def load_scores(scan_report: Path) -> dict[str, dict]:
    """从扫描产物里取 {文件名: {score, path, verdict}}（只读产物，不重算）。"""
    data = json.loads(scan_report.read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for report in data.get("reports") or []:
        name = Path(report["path"]).name
        out[name] = {
            "score": report.get("prefilter_score", 0),
            "path": report.get("path"),
            "verdict": (report.get("verdict") or {}).get("risk"),
            "criteria_hits": [h.get("heur_id") for h in (report.get("criteria_hits") or [])],
        }
    return out


def select_buckets(scores: dict[str, dict], labels: dict[str, str],
                   buckets: list[int]) -> tuple[list[dict], dict]:
    """按预筛分数挑灰区文件，并**顺手核对类别构成**（不信任任何手抄的表）。"""
    wanted = set(buckets)
    picked: list[dict] = []
    for name, info in sorted(scores.items()):
        if info["score"] not in wanted:
            continue
        picked.append({
            "name": name,
            "path": info["path"],
            "score": info["score"],
            "label": labels.get(name, "unknown"),
            "criteria_hits": info["criteria_hits"],
        })
    composition = {}
    for b in buckets:
        rows = [p for p in picked if p["score"] == b]
        composition[str(b)] = {
            "malicious": sum(1 for r in rows if r["label"] == "malicious"),
            "benign": sum(1 for r in rows if r["label"] != "malicious"),
            "total": len(rows),
        }
    return picked, composition


def main() -> None:
    ap = argparse.ArgumentParser(description="LLM 初筛 · 灰区跑批")
    ap.add_argument("--scan-report", type=Path, required=True,
                    help="确定性扫描产物 JSON（提供预筛分数与文件路径）")
    ap.add_argument("--labels", type=Path, required=True, help="标签 JSON")
    ap.add_argument("--buckets", default="125,225,275", help="要跑的预筛分数档（逗号分隔）")
    ap.add_argument("--out", type=Path, required=True, help="结果 JSON 输出路径")
    ap.add_argument("--model", default=None, help="覆盖 AGENT_MODEL（默认环境变量）")
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--pilot", type=int, default=0, help="只跑前 N 个（试水用，0=全跑）")
    ap.add_argument("--max-prompt-tokens", type=int, default=TARGET_PROMPT_TOKENS)
    ap.add_argument("--no-cache", action="store_true", help="关掉 sha256 缓存（每次真跑）")
    ap.add_argument("--cache-dir", type=Path, default=None)
    ap.add_argument("--holdout-dir", type=Path, action="append", default=None,
                    help="holdout 模式：直接扫这些目录（可多次给；不吃 --scan-report 的分档）")
    ap.add_argument("--holdout-label", default="malicious",
                    choices=["malicious", "benign"],
                    help="holdout 目录的默认标签（标签表里没有该文件名时用它）")
    ap.add_argument("--sample", type=int, default=0,
                    help="抽样 N 个（0=全要）。**固定 seed**，可复现")
    ap.add_argument("--seed", type=int, default=20260927)
    ap.add_argument("--include-ext", default="",
                    help="holdout 只收这些扩展名（逗号分隔，空=全收）。"
                         "良性语料里混着 .inf/.cat/.mui 这类非 PE 文件，"
                         "不过滤的话测的是'摘要能不能处理杂类'，不是'会不会误伤良性 PE'")
    args = ap.parse_args()

    scores = load_scores(args.scan_report)
    labels = json.loads(args.labels.read_text(encoding="utf-8"))
    buckets = [int(x) for x in args.buckets.split(",") if x.strip()]

    if args.holdout_dir:
        picked = [{
            "name": p.name, "path": str(p), "score": None,
            "label": labels.get(p.name, args.holdout_label),
            "criteria_hits": [],
        } for root in args.holdout_dir for p in sorted(Path(root).rglob("*")) if p.is_file()]
        if args.include_ext:
            wanted_ext = {("." + e.strip().lower().lstrip("."))
                          for e in args.include_ext.split(",") if e.strip()}
            picked = [r for r in picked if Path(r["path"]).suffix.lower() in wanted_ext]
        if args.sample and args.sample < len(picked):
            # 固定 seed 抽样：holdout 的样本集合必须可复现，否则"没参与调试"这句话就没法核。
            # 按**子目录分层**抽（mb-* 是按类别分的，纯随机抽会让某一类消失）。
            import random

            rng = random.Random(args.seed)
            groups: dict[str, list[dict]] = {}
            for row in picked:
                key = Path(row["path"]).parent.name
                groups.setdefault(key, []).append(row)
            per = max(1, args.sample // max(1, len(groups)))
            sample_rows: list[dict] = []
            for _key, rows in sorted(groups.items()):
                sample_rows.extend(rng.sample(rows, min(per, len(rows))))
            if len(sample_rows) < args.sample:
                chosen = {r["path"] for r in sample_rows}
                rest = [r for r in picked if r["path"] not in chosen]
                sample_rows.extend(rng.sample(rest, min(args.sample - len(sample_rows), len(rest))))
            picked = sorted(sample_rows, key=lambda r: r["path"])[:args.sample]
        composition = {"holdout": {
            "malicious": sum(1 for r in picked if r["label"] == "malicious"),
            "benign": sum(1 for r in picked if r["label"] != "malicious"),
            "total": len(picked)}}
    else:
        picked, composition = select_buckets(scores, labels, buckets)

    print(f"[select] 分档构成: {json.dumps(composition, ensure_ascii=False)}")
    print(f"[select] 合计 {len(picked)} 个文件")

    if args.pilot and args.pilot < len(picked):
        # 试水**按分层比例抽**：这是"报成本量级"用的，样本必须**代表全批**，
        # 不能顺着目录顺序先跑（那样先跑到的全是 125 档的良性，成本能对上、分数分布对不上）。
        # 每一层内部按"恶意优先、其余按序"取 —— 恶意是稀缺类（15/158），
        # 每档都要有，否则试水看不出召回。
        by_bucket: dict[object, list[dict]] = {}
        for row in picked:
            by_bucket.setdefault(row["score"], []).append(row)
        total_all = len(picked)
        pilot: list[dict] = []
        for _bucket, rows in sorted(by_bucket.items(), key=lambda kv: str(kv[0])):
            quota = max(1, round(args.pilot * len(rows) / total_all))
            mal = [r for r in rows if r["label"] == "malicious"]
            ben = [r for r in rows if r["label"] != "malicious"]
            take_mal = min(len(mal), max(1, round(quota * len(mal) / max(1, len(rows)))))
            take_ben = min(len(ben), max(1, quota - take_mal))
            pilot.extend(mal[:take_mal] + ben[:take_ben])
        # 配额取整会少几个：用 125 档（占比最大）的良性补齐到 N
        if len(pilot) < args.pilot:
            chosen = {r["name"] for r in pilot}
            filler = [r for r in picked
                      if r["label"] != "malicious" and r["name"] not in chosen]
            pilot.extend(filler[:args.pilot - len(pilot)])
        picked = pilot[:args.pilot]
        print(f"[pilot] 只跑 {len(picked)} 个（分层抽样，"
              f"恶意 {sum(1 for r in picked if r['label'] == 'malicious')} / "
              f"良性 {sum(1 for r in picked if r['label'] != 'malicious')}）")

    items: list[tuple[Path, str]] = []
    meta_by_sha: dict[str, dict] = {}
    for row in picked:
        path = Path(row["path"])
        if not path.is_file():
            print(f"[warn] 缺文件，跳过: {path}")
            continue
        sha = compute_sha256(path)
        items.append((path, sha))
        meta_by_sha[sha] = row

    client = TriageClient(model=args.model, base_url=args.base_url)
    print(f"[model] {client.model} @ {client.base_url}")

    cache = None
    if not args.no_cache and cache_enabled():
        cache = TriageCache(root=args.cache_dir or default_triage_cache_dir())
        print(f"[cache] {cache.root}")
    else:
        print("[cache] 关闭（本次全部真跑）")

    started = time.time()
    done = {"n": 0}

    def on_result(record: dict) -> None:
        done["n"] += 1
        if done["n"] % 10 == 0 or done["n"] == len(items):
            cost = summarize_cost(results_so_far)
            print(f"  ... {done['n']}/{len(items)}  token={cost['total_tokens']} "
                  f"¥{cost['cost_cny']}  失败={cost['failed']}")

    results_so_far: list[dict] = []
    original_on_result = on_result

    def collect(record: dict) -> None:
        results_so_far.append(record)
        original_on_result(record)

    results = run_batch(items, client, workers=args.workers,
                        max_prompt_tokens=args.max_prompt_tokens,
                        cache=cache, on_result=collect)
    results = list(results)
    elapsed = round(time.time() - started, 1)

    for r in results:
        row = meta_by_sha.get(r.get("sha256") or "")
        if row:
            r["label"] = row["label"]
            r["prefilter_score"] = row["score"]
            r["criteria_hits"] = row["criteria_hits"]

    cost = summarize_cost(results)
    verification = {
        "model_called": cost["ok"] > 0,
        "failed_entries": cost["failed"],
        "degraded_entries": sum(1 for r in results if not r.get("ok")),
        "from_cache": cost["from_cache"],
        "usage_source": cost["usage_source"],
        "estimated_entries": cost["estimated_entries"],
        "parse_modes": cost["parse_modes"],
        "repaired_or_fallback": cost["repaired_or_fallback"],
        "all_rows_have_score_or_error": all(
            (r.get("score") is not None) or bool(r.get("error")) for r in results),
        "verdict_batch_usable": cost["failed"] == 0,
    }

    out = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "model": client.model,
        "base_url": client.base_url,
        "workers": args.workers,
        "elapsed_s": elapsed,
        "buckets": buckets,
        "composition": composition,
        "summary_version": TRIAGE_VERSION,
        "max_prompt_tokens": args.max_prompt_tokens,
        "scan_report": str(args.scan_report),
        "cost": cost,
        "verification": verification,
        "results": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"\n[完成] {len(results)} 个文件，{elapsed}s")
    print(f"[成本] 总 token {cost['total_tokens']}（prompt {cost['prompt_tokens']} / "
          f"completion {cost['completion_tokens']}）  ¥{cost['cost_cny']}  "
          f"平均 {cost['avg_tokens_per_file']} token/文件")
    print(f"[核验] 成功 {cost['ok']} / 失败 {cost['failed']} / 缓存命中 {cost['from_cache']} "
          f"/ usage 来源 {cost['usage_source']}")
    print(f"[产物] {args.out}")


if __name__ == "__main__":
    main()
