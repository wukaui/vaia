#!/usr/bin/env python3
"""「全送 AI 对照」的**抽样口径**：不把整个语料过一遍模型，只抽一小批，再按规模外推。

为什么要有这个脚本（2026-09-27 的口径变更）：
  把 320 个文件全送一遍 AI 要 **2.2M token / 41 分钟**，而这个数**抽样就能拿到**。
  所以对照臂的正式口径改成：**分层抽样 → 算每文件均值 → 按原集合规模外推**。

三条硬规矩（写在代码里，免得换说法）：

  1. **分层**：按 `类别 × 来源池` 分层，按各层在语料里的占比**按比例分配**名额
     （最大余数法）。所以"干净 : 恶意"这个比例在样本里与全集合**完全一致** ——
     默认 `--n 48` 时是 45 良 + 3 恶 = 6.25%，与 300:20 一模一样（20/320 = 3/48）。
  2. **可复现**：固定 `--seed`，层内按文件名排序后抽样。同一个 seed + 同一份语料
     → 永远抽出同一批（脚本会把 seed 与抽中的清单一起写进产物）。
  3. **实测 ≠ 外推**：产物里 `sample_measured` 是**这批文件真测到的数**，
     `extrapolated` 是**按规模乘出来的数**，两块分开存、分开印，不混在一张表里。

用法：

    .venv/bin/python scripts/sample_ai_arm.py \
        --ai-report /tmp/real-dist-ai-out/scan_*.json \
        --manifest /tmp/real-dist-320/manifest.json \
        --corpus-root /tmp/real-dist-320/files \
        --n 48 --seed 20260927 \
        --out bench/real-dist-320/ai_arm_sample.json

产物里 `files` 就是**抽中的文件清单**（含类别 / 来源池 / sha256 / 该文件实测 token）。
"""

from __future__ import annotations

import argparse
import glob
import json
import random
import statistics
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

DEFAULT_SEED = 20260927
DEFAULT_N = 48  # 45 良 + 3 恶：与语料 300:20 的比例**完全相等**（6.25%）


def load_one(pattern: str) -> dict:
    """读一份产物（支持通配；跳过 audit）。"""
    hits = [p for p in sorted(glob.glob(pattern)) if "audit" not in p]
    if not hits:
        raise SystemExit(f"找不到产物：{pattern}")
    return json.loads(Path(hits[-1]).read_text(encoding="utf-8"))


def resolve_dirs(manifest: dict, corpus_root: Path) -> dict[str, str]:
    """类别 → 语料子目录名（manifest 里类别叫 `malicious`，目录却叫 `malware`，所以按文件对一遍）。"""
    classes = {k: v for k, v in manifest["classes"].items() if isinstance(v, dict)}
    subdirs = [d.name for d in sorted(corpus_root.iterdir()) if d.is_dir()]
    if not subdirs:
        raise SystemExit(f"语料目录里没有子目录：{corpus_root}")
    dir_of: dict[str, str] = {}
    for label, spec in classes.items():
        names = {f["name"] for f in spec["files"]}
        best, best_hits = subdirs[0], -1
        for sub in subdirs:
            hits = sum(1 for n in names if (corpus_root / sub / n).exists())
            if hits > best_hits:
                best, best_hits = sub, hits
        if best_hits <= 0:
            raise SystemExit(f"类别 {label} 的文件在 {corpus_root} 的任何子目录里都找不到")
        dir_of[label] = best
    return dir_of


def load_corpus(manifest: dict, corpus_root: Path) -> list[dict]:
    """把 manifest 摊平成 `[{path, name, label, pool, sha256, bytes}]`（按类别 + 名字排序）。"""
    out: list[dict] = []
    classes = {k: v for k, v in manifest["classes"].items() if isinstance(v, dict)}
    dir_of = resolve_dirs(manifest, corpus_root)
    for label in sorted(classes):
        for f in classes[label]["files"]:
            out.append({
                "path": str(corpus_root / dir_of[label] / f["name"]),
                "name": f["name"],
                "label": label,
                "pool": f.get("pool") or label,
                "sha256": f.get("sha256"),
                "bytes": f.get("bytes"),
            })
    out.sort(key=lambda r: (r["label"], r["name"]))
    return out


def allocate(strata: dict[str, int], n: int) -> dict[str, int]:
    """最大余数法按比例分配名额；层数比 n 还多时给每层至少 1 个。"""
    total = sum(strata.values())
    if n > total:
        raise SystemExit(f"抽 {n} 个 > 语料 {total} 个")
    exact = {k: n * v / total for k, v in strata.items()}
    quota = {k: int(v) for k, v in exact.items()}
    left = n - sum(quota.values())
    # 余数大的先补；并列时按层名排序（确定性）
    order = sorted(exact, key=lambda k: (-(exact[k] - quota[k]), k))
    for k in order[:left]:
        quota[k] += 1
    return quota


def draw_sample(corpus: list[dict], n: int, seed: int) -> list[dict]:
    """分层抽样：层 = `类别 × 来源池`，层内按名字排序后 `random.Random(seed).sample`。"""
    strata: dict[str, list[dict]] = {}
    for r in corpus:
        strata.setdefault(f"{r['label']}/{r['pool']}", []).append(r)
    quota = allocate({k: len(v) for k, v in strata.items()}, n)
    rng = random.Random(seed)
    picked: list[dict] = []
    for key in sorted(strata):
        pool = sorted(strata[key], key=lambda r: r["name"])
        picked.extend(rng.sample(pool, quota[key]))
    picked.sort(key=lambda r: (r["label"], r["name"]))
    return picked


def outcome_of(row: dict | None) -> str:
    """抽样文件的结局：出了 AI 结论 / 确定性结案短路 / 送审但调用失败降级 / 没进报告。"""
    if row is None:
        return "not_scanned"
    if row.get("agent_used"):
        return "ai_verdict"
    if row.get("error"):
        return "degraded_to_rules"
    if str((row.get("deterministic") or {}).get("disposition") or "").startswith("closed_"):
        return "closed_deterministic"
    return "unknown"


def measure_sample(sample: list[dict], ai_report: dict) -> dict:
    """从**已经跑过的那一轮**的逐文件行里取抽样文件的实测数（不再调模型）。"""
    rows = {r["path"]: r for r in (ai_report.get("reports") or [])}
    per_file: list[dict] = []
    for r in sample:
        row = rows.get(r["path"])
        usage = (row or {}).get("agent_usage") or {}
        reached = bool(row and row.get("agent_used"))
        per_file.append({
            **{k: r[k] for k in ("name", "label", "pool", "sha256", "bytes")},
            "path": r["path"],
            "in_ai_report": row is not None,
            "reached_ai": reached,
            "outcome": outcome_of(row),
            "tokens": int(usage.get("tokens") or 0) if reached else None,
            "preload_ms": (round(usage["preload_ms"], 1)
                           if reached and usage.get("preload_ms") is not None else None),
            "tool_calls": usage.get("tool_calls") if reached else None,
            "risk": ((row or {}).get("verdict") or {}).get("risk") if reached else None,
        })
    return {"files": per_file, "rows": rows}


def summarize(sample: list[dict], per_file: list[dict], n_corpus: int,
              unit_price: float, wall_clock_s: float | None, n_full_ai: int | None,
              full_run: dict | None = None) -> dict:
    """把抽样结果压成：抽样实测块 + 外推块（两块分开），外加一份"抽样代表性"参照。"""
    ai_files = [f for f in per_file if f["reached_ai"]]
    tokens = [f["tokens"] for f in ai_files]
    preload = [f["preload_ms"] for f in ai_files if f["preload_ms"] is not None]

    mean_tokens = statistics.fmean(tokens) if tokens else 0.0
    median_tokens = statistics.median(tokens) if tokens else 0
    mean_preload_ms = statistics.fmean(preload) if preload else 0.0
    # 整臂墙钟摊到单文件（6 并发下的有效吞吐）——这是**摊算**，不是逐文件计时
    per_file_wall = (wall_clock_s / n_full_ai) if (wall_clock_s and n_full_ai) else None

    by_label = {}
    for label in sorted({f["label"] for f in per_file}):
        sub = [f for f in per_file if f["label"] == label]
        sub_ai = [f for f in sub if f["reached_ai"]]
        by_label[label] = {
            "drawn": len(sub),
            "reached_ai": len(sub_ai),
            "tokens_mean": round(statistics.fmean([f["tokens"] for f in sub_ai]), 1) if sub_ai else None,
        }

    measured = {
        "kind": "measured",
        "scope": "sample",
        "files_drawn": len(per_file),
        "files_reaching_ai": len(ai_files),
        "files_short_circuited": sum(1 for f in per_file if f["outcome"] == "closed_deterministic"),
        "files_degraded_to_rules": sum(1 for f in per_file if f["outcome"] == "degraded_to_rules"),
        "tokens_measured": sum(tokens),
        "mean_tokens_per_ai_file": round(mean_tokens, 1),
        "median_tokens_per_ai_file": median_tokens,
        "mean_preload_ms_per_ai_file": round(mean_preload_ms, 1),
        "mean_cny_per_ai_file": round(mean_tokens / 1_000_000 * unit_price, 4),
        "wall_clock_s_per_ai_file_amortized": (round(per_file_wall, 2)
                                               if per_file_wall is not None else None),
        "by_label": by_label,
        "note": "抽样文件在**已跑过的那一轮**里的逐文件实测值；本轮没有再调模型",
    }

    extrapolated = {
        "kind": "extrapolated",
        "basis": f"抽样实测均值 {round(mean_tokens, 1)} token/文件 × 语料 {n_corpus} 个文件",
        "tokens": round(mean_tokens * n_corpus),
        "cny": round(mean_tokens * n_corpus / 1_000_000 * unit_price, 2),
        "tokens_per_file": round(mean_tokens, 1),
        "unit_price_cny_per_million": unit_price,
        "wall_clock_s": (round(per_file_wall * n_corpus, 1) if per_file_wall is not None else None),
        "note": "**外推，不是实测**：按抽样均值乘语料规模得来，别当实测值用",
    }
    # 同口径外推（乘"实测真进 AI 的文件数"而不是语料总数）—— 用来和全量实测对齐核验
    if n_full_ai:
        extrapolated["same_scope"] = {
            "basis": f"抽样实测均值 {round(mean_tokens, 1)} token/文件 × 出了 AI 结论的 {n_full_ai} 个文件",
            "tokens": round(mean_tokens * n_full_ai),
            "cny": round(mean_tokens * n_full_ai / 1_000_000 * unit_price, 2),
            "note": "确定性结案的那批在送审前就短路了，所以「全送」实际只有这批文件真花了 token",
        }

    blocks = {"sample_measured": measured, "extrapolated": extrapolated}
    if full_run:
        full_mean = full_run["mean_tokens_per_ai_file"]
        full_total = full_run["tokens"]
        blocks["sampling_check_vs_full_run"] = {
            "kind": "measured",
            "scope": "full-run reference",
            "note": "对照臂在**指令到达前已经全量跑完**（没有重复花钱）；这里只把它当抽样口径的参照，"
                    "不是抽样产物的一部分",
            "full_run_files_reaching_ai": full_run["files_reaching_ai"],
            "full_run_files_sent_to_ai": full_run.get("files_sent_to_ai"),
            "full_run_files_degraded_to_rules": full_run.get("files_degraded_to_rules"),
            "full_run_tokens": full_total,
            "full_run_mean_tokens_per_ai_file": full_mean,
            "sample_vs_full_mean_delta_pct": round((mean_tokens - full_mean) / full_mean * 100, 2)
            if full_mean else None,
            "sample_extrapolated_same_scope_tokens": round(mean_tokens * full_run["files_reaching_ai"]),
            "sample_vs_full_total_delta_pct": round(
                (mean_tokens * full_run["files_reaching_ai"] - full_total) / full_total * 100, 2)
            if full_total else None,
        }
    return blocks


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ai-report", required=True, help="已跑过的对照臂 scan JSON（支持通配）")
    ap.add_argument("--manifest", required=True, help="语料 manifest.json（要里面的类别 / 池 / sha256）")
    ap.add_argument("--corpus-root", default="/tmp/real-dist-320/files", help="语料目录（files/）")
    ap.add_argument("--n", type=int, default=DEFAULT_N, help=f"抽多少（默认 {DEFAULT_N}）")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help=f"随机种子（默认 {DEFAULT_SEED}）")
    ap.add_argument("--wall-clock-s", type=float, default=None,
                    help="整臂墙钟秒数（用来摊每文件耗时；不给就不报耗时）")
    ap.add_argument("--full-ai-files", type=int, default=None,
                    help="整臂里真进 AI 的文件数（摊墙钟用）")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    from aiav.budget import CNY_PER_MILLION_TOKENS

    ai = load_one(args.ai_report)
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    corpus = load_corpus(manifest, Path(args.corpus_root))
    sample = draw_sample(corpus, args.n, args.seed)
    got = measure_sample(sample, ai)

    n_corpus = len(corpus)
    ai_rows = [r for r in (ai.get("reports") or []) if r.get("agent_used")]
    n_ai_full = args.full_ai_files or len(ai_rows)
    full_run = {
        "files_reaching_ai": len(ai_rows),
        "files_sent_to_ai": sum(1 for r in (ai.get("reports") or [])
                                if r.get("agent_used") or r.get("error")),
        "files_degraded_to_rules": sum(1 for r in (ai.get("reports") or [])
                                       if not r.get("agent_used") and r.get("error")),
        "tokens": sum(int(((r.get("agent_usage") or {}).get("tokens")) or 0) for r in ai_rows),
        "mean_tokens_per_ai_file": (statistics.fmean(
            [int(((r.get("agent_usage") or {}).get("tokens")) or 0) for r in ai_rows])
            if ai_rows else 0.0),
    } if ai_rows else None
    blocks = summarize(sample, got["files"], n_corpus, CNY_PER_MILLION_TOKENS,
                       args.wall_clock_s, n_ai_full, full_run)

    payload = {
        "kind": "ai-arm-sampling",
        "corpus": {
            "total": n_corpus,
            "by_label": {k: len([r for r in corpus if r["label"] == k])
                         for k in sorted({r["label"] for r in corpus})},
            "malicious_ratio": round(len([r for r in corpus if r["label"] == "malicious"]) / n_corpus, 4),
        },
        "method": {
            "stratified_by": "类别 × 来源池（按各层占比分配名额，最大余数法）",
            "seed": args.seed,
            "n": args.n,
            "order": "层内按文件名排序后 random.Random(seed).sample（可复现）",
        },
        "sample_ratio": {
            "malicious": round(len([f for f in got["files"] if f["label"] == "malicious"]) / len(got["files"]), 4),
            "matches_corpus": (len([f for f in got["files"] if f["label"] == "malicious"]) / len(got["files"])
                               == len([r for r in corpus if r["label"] == "malicious"]) / n_corpus),
        },
        **blocks,
        "files": got["files"],
    }
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    m, e = blocks["sample_measured"], blocks["extrapolated"]
    print(f"抽样（seed={args.seed}，n={args.n}，分层=类别×来源池）"
          f" · 恶意占比 {payload['sample_ratio']['malicious']:.4f}"
          f"（语料 {payload['corpus']['malicious_ratio']:.4f}，一致={payload['sample_ratio']['matches_corpus']}）")
    print(f"  实测：抽中 {m['files_drawn']} 个 · 真进 AI {m['files_reaching_ai']} 个 · "
          f"{m['tokens_measured']:,} token · 均值 {m['mean_tokens_per_ai_file']:,}/文件"
          f"（中位 {m['median_tokens_per_ai_file']:,}）· 均值 ¥{m['mean_cny_per_ai_file']}/文件")
    print(f"  实测：预采集均值 {m['mean_preload_ms_per_ai_file']:,} ms/文件"
          + (f" · 整臂墙钟摊 {m['wall_clock_s_per_ai_file_amortized']}s/文件（摊算）"
             if m["wall_clock_s_per_ai_file_amortized"] is not None else ""))
    print(f"  外推：{e['tokens']:,} token ≈ ¥{e['cny']}（= 抽样均值 × {n_corpus} 个文件；**外推，不是实测**）")
    c = blocks.get("sampling_check_vs_full_run")
    if c:
        print(f"  参照（全量实测，指令前已跑完）：均值 {c['full_run_mean_tokens_per_ai_file']:,}/文件 · "
              f"总量 {c['full_run_tokens']:,} token → 抽样均值偏差 "
              f"{c['sample_vs_full_mean_delta_pct']:+.2f}%")
    if args.out:
        print(f"\n写入 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
