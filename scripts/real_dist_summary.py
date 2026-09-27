#!/usr/bin/env python3
"""真实分布实测的**汇总口径**：把散在几个产物里的数拉成一张表（报告里的数就是这个脚本打的）。

输入产物（都由别的脚本/一轮扫描产出，这里只读、不重算判定）：

  · `--measure`    `scripts/measure_deterministic.py` 的 JSON —— ①层那一臂（无 AI，全量实测）
  · `--ai-report`  `aiav scan --ai-threshold 0` 的 JSON —— "全部送 AI"对照臂（全量实测）
  · `--manifest` / `--corpus-root` 语料清单（抽样要用它的类别 / 来源池）
  · `--unit-price` 单价（元/百万 token），默认取 `aiav/budget.py` 里唯一定义的那一处

四个数（本轮交付）：
  1. **送审率**  = ①层处置为 `send_ai` 的文件 / 总数      —— 实测，全量
  2. **①层结案率** =（确定性判恶意 + 确定性判干净）/ 总数   —— 实测，全量
  3. **召回**（①层口径）= 恶意文件里被"确定性判恶意"或"送 AI"覆盖的比例 —— 实测，全量
  4. **成本** = token 总量 / 按单价折的钱 / 平均每文件     —— 生产档是实测；对照臂是**抽样 + 外推**

口径变更（2026-09-27，李沫儒的补充指令："抽样吧"）—— 写死在这里，免得每次换说法：
  · 对照臂**不再全量跑**：分层抽 48 个（与语料同为 6.25% 恶意，固定 seed，清单在产物里），
    只算这批的每文件均值，再乘语料规模 —— **乘出来的数一律标"外推"**，
    和实测数**分块存、分表印**，不许混在一张表里当实测值用。
  · 对照臂**在指令到达前已经全量跑完了**（319 个文件 / 273 个进 AI / 2,195,054 token）：
    按"不用推翻重来"的指示，那一轮**原样保留当实测参照**（`ai_arm_full_run_measured`），
    本轮**没有再调一次模型**（0 token）。
  · `gate 0` 那一轮**并不是真的 320/320 都进 AI** —— 确定性结案的（ClamAV 命中、签名可信）
    在送审前就短路了。所以实测到的是"273 个进了 AI"，320 那个数是外推。

用法：

    .venv/bin/python scripts/real_dist_summary.py \
        --measure /tmp/real-dist-out/measure_gate300_*.json \
        --ai-report /tmp/real-dist-ai-out/scan_*.json \
        --manifest /tmp/real-dist-320/manifest.json \
        --corpus-root /tmp/real-dist-320/files \
        --wall-clock-s 2460 --out bench/real-dist-320/summary.json \
        --sample-out bench/real-dist-320/ai_arm_sample.json
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sample_ai_arm import (DEFAULT_N as SAMPLE_N, DEFAULT_SEED as SAMPLE_SEED,
                           draw_sample, load_corpus, outcome_of,
                           load_one as load_artifact, summarize as summarize_sample)


def load_one(pattern: str) -> dict:
    hits = [p for p in sorted(glob.glob(pattern)) if "audit" not in p]
    if not hits:
        raise SystemExit(f"找不到产物：{pattern}")
    return json.loads(Path(hits[-1]).read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--measure", required=True, help="measure_deterministic.py 的 JSON（支持通配）")
    ap.add_argument("--ai-report", required=True, help="gate 0 那一轮的 scan JSON（支持通配）")
    ap.add_argument("--corpus", default=None, help="measure JSON 里的语料名（默认取第一个）")
    ap.add_argument("--manifest", default=None, help="语料 manifest.json（抽样要类别 / 来源池；不给就不出抽样块）")
    ap.add_argument("--corpus-root", default="/tmp/real-dist-320/files", help="语料目录")
    ap.add_argument("--sample-n", type=int, default=SAMPLE_N, help=f"抽样个数（默认 {SAMPLE_N}）")
    ap.add_argument("--sample-seed", type=int, default=SAMPLE_SEED, help=f"抽样种子（默认 {SAMPLE_SEED}）")
    ap.add_argument("--wall-clock-s", type=float, default=None, help="对照臂整臂墙钟秒数（摊每文件耗时）")
    ap.add_argument("--sample-out", type=Path, default=None, help="抽样产物（含抽中的文件清单）")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    from aiav.budget import CNY_PER_MILLION_TOKENS, DEFAULT_EST_PER_FILE

    measure = load_one(args.measure)
    name = args.corpus or next(iter(measure["corpora"]))
    layer1 = measure["corpora"][name]
    s = layer1["summary"]

    # ---- ①层那一臂 ----
    n = s["total"]
    layer1_arm = {
        "corpus": name,
        "n": n,
        "n_malicious": s["labeled_malicious"],
        "n_benign": s["labeled_benign"],
        "send_rate": s["send_rate"],
        "sent": s["sent"],
        "closed_rate": s["closed_rate"],
        "closed_malicious": s["closed_malicious"],
        "closed_clean": s["closed_clean"],
        "unresolved": s["unresolved"],
        "recall_layer1": s["recall_layer1"],
        "recall_deterministic_only": s["recall_deterministic_only"],
        "benign_send_rate": s["benign_send_rate"],
        "layer1_seconds": layer1["elapsed_s"],
        "clamav_seconds": layer1["clamav_batch"]["elapsed_s"],
        "total_seconds": layer1["elapsed_s_with_clamav"],
        "seconds_per_file": round(layer1["elapsed_s_with_clamav"] / n, 4),
        "clamav": s["clamav"],
        "consistency": measure.get("consistency"),
        "verification_ok": measure["verification"]["ok"],
        "unclassified_signals": s["unclassified_signals"],
        "errors": s["errors"],
    }

    # ---- "全部送 AI"对照臂：**全量那一轮**（实测；指令到达前已跑完，原样保留当参照） ----
    ai = load_one(args.ai_report)
    reports = ai.get("reports") or []
    sent = [r for r in reports if r.get("agent_used")]
    tokens_by_file = {r["path"]: int(((r.get("agent_usage") or {}).get("tokens")) or 0) for r in sent}
    total_tokens = sum(tokens_by_file.values())
    mean_tokens = total_tokens / len(sent) if sent else 0
    ai_arm_full = {
        "kind": "measured",
        "scope": "full-run",
        "note": "指令到达前那一轮已经全量跑完（13:47 结束 / 墙钟 41 分钟）；本轮没有再调模型，0 token",
        "files_scanned": ai.get("total"),
        "files_reaching_ai": len(sent),
        "tokens_measured": total_tokens,
        "mean_tokens_per_ai_file": round(mean_tokens, 1),
        "median_tokens_per_ai_file": (sorted(tokens_by_file.values())[len(sent) // 2]
                                      if sent else 0),
        "tool_calls_total": (ai.get("summary") or {}).get("tool_calls"),
        "files_deep_dive": (ai.get("summary") or {}).get("files_deep_dive"),
        "files_degraded": (ai.get("summary") or {}).get("files_with_retry"),
    }

    # ---- 对照臂的**正式口径**：分层抽样 + 按规模外推（不再全量跑） ----
    sample_blocks: dict = {}
    sample_payload: dict | None = None
    if args.manifest:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        corpus = load_corpus(manifest, Path(args.corpus_root))
        picked = draw_sample(corpus, args.sample_n, args.sample_seed)
        rows = {r["path"]: r for r in reports}
        per_file = []
        for r in picked:
            row = rows.get(r["path"])
            usage = (row or {}).get("agent_usage") or {}
            reached = bool(row and row.get("agent_used"))
            per_file.append({**{k: r[k] for k in ("name", "label", "pool", "sha256", "bytes")},
                             "path": r["path"], "in_ai_report": row is not None,
                             "reached_ai": reached, "outcome": outcome_of(row),
                             "tokens": int(usage.get("tokens") or 0) if reached else None,
                             "preload_ms": (round(usage["preload_ms"], 1)
                                            if reached and usage.get("preload_ms") is not None else None),
                             "tool_calls": usage.get("tool_calls") if reached else None,
                             "risk": ((row or {}).get("verdict") or {}).get("risk") if reached else None})
        full_run = {"files_reaching_ai": len(sent), "tokens": total_tokens,
                    "mean_tokens_per_ai_file": mean_tokens,
                    "files_sent_to_ai": sum(1 for r in reports if r.get("agent_used") or r.get("error")),
                    "files_degraded_to_rules": sum(1 for r in reports
                                                   if not r.get("agent_used") and r.get("error"))}
        sample_blocks = summarize_sample(picked, per_file, len(corpus),
                                        CNY_PER_MILLION_TOKENS, args.wall_clock_s,
                                        len(sent) or None, full_run)
        n_mal = len([r for r in corpus if r["label"] == "malicious"])
        sample_payload = {
            "kind": "ai-arm-sampling",
            "corpus": {"total": len(corpus),
                       "by_label": {k: len([r for r in corpus if r["label"] == k])
                                    for k in sorted({r["label"] for r in corpus})},
                       "malicious_ratio": round(n_mal / len(corpus), 4)},
            "method": {"stratified_by": "类别 × 来源池（按各层占比分配名额，最大余数法）",
                       "seed": args.sample_seed, "n": args.sample_n,
                       "order": "层内按文件名排序后 random.Random(seed).sample（可复现）"},
            "sample_ratio": {
                "malicious": round(len([f for f in per_file if f["label"] == "malicious"])
                                   / len(per_file), 4),
                "matches_corpus": (len([f for f in per_file if f["label"] == "malicious"]) / len(per_file)
                                   == n_mal / len(corpus))},
            **sample_blocks,
            "files": per_file,
        }
        if args.sample_out:
            args.sample_out.parent.mkdir(parents=True, exist_ok=True)
            args.sample_out.write_text(json.dumps(sample_payload, ensure_ascii=False, indent=2),
                                       encoding="utf-8")

    # ---- 对照：全部送 AI 的成本（**外推**，口径写在这里） ----
    sample_mean = (sample_blocks.get("sample_measured", {}).get("mean_tokens_per_ai_file")
                   if sample_blocks else round(mean_tokens, 1))
    sample_basis = (f"抽样实测均值 {sample_mean} token/文件 × 语料 {n} 个文件"
                    if sample_blocks else f"实测每文件均值 {round(mean_tokens, 1)} token × 语料 {n} 个文件")
    all_ai_tokens = round(sample_mean * n)
    counterfactual = {
        "kind": "extrapolated",
        "scope": "corpus",
        "basis": f"{sample_basis}（外推，不是实测）",
        "tokens": all_ai_tokens,
        "cny": round(all_ai_tokens / 1_000_000 * CNY_PER_MILLION_TOKENS, 2),
        "tokens_per_file": sample_mean,
        "unit_price_cny_per_million": CNY_PER_MILLION_TOKENS,
        "note": "单价是项目里唯一定义的那一处（偏高的一档），不是服务商报价单",
    }
    # 生产档（gate 300）实际会花的钱：只有真送审的那几个文件的 token（在对照臂里逐个取）
    production_tokens = sum(tokens_by_file.get(r["path"], 0)
                            for r in reports
                            if (r.get("deterministic") or {}).get("disposition") == "send_ai")
    production = {
        "kind": "measured",
        "scope": "production-gate-300",
        "files_sent": s["sent"],
        "tokens": production_tokens,
        "cny": round(production_tokens / 1_000_000 * CNY_PER_MILLION_TOKENS, 2),
        "note": "送审文件的 token 取自对照臂的同一条流水线（同一路径、同一预采集），不是另跑一轮",
    }
    saved = {
        "kind": "derived",
        "note": "「全部送 AI」那一列是外推值，所以省下的量也带着外推口径；生产档那一列是实测",
        "files": n - s["sent"],
        "tokens": all_ai_tokens - production_tokens,
        "cny": round((all_ai_tokens - production_tokens) / 1_000_000 * CNY_PER_MILLION_TOKENS, 2),
        "ratio": round(1 - production_tokens / all_ai_tokens, 4) if all_ai_tokens else None,
    }

    # ---- 消融：把 ClamAV 那 1000 分摘掉，看这一层到底挣了多少（从同一批 rows 重算，不重扫） ----
    # 口径：`DET_CLAMAV_SIGNATURE` 命中 = 1000 分（判据表里 `score == max_score == 1000`），
    # 摘掉之后按同一个闸门重判处置 —— 分数是各段求和，摘一段就是减掉它，不涉及其它判据。
    gate = measure.get("gate", 300)
    rows = layer1["rows"]
    no_av_sent = 0
    no_av_caught = 0
    av_closed = 0
    for r in rows:
        av = 1000 * sum(1 for c in (r.get("clamav") or [])
                        if c.get("heur_id") == "DET_CLAMAV_SIGNATURE")
        if av:
            av_closed += int(r.get("disposition") == "closed_malicious")
        base = int(r.get("score") or 0) - av
        sent_no_av = base >= gate or (av == 0 and r.get("disposition") == "send_ai")
        if sent_no_av:
            no_av_sent += 1
        if r.get("label") == "malicious" and sent_no_av:
            no_av_caught += 1
    mal_n = layer1_arm["n_malicious"] or 1
    ablation = {
        "note": "从同一批 rows 里摘掉 ClamAV 的 1000 分后重算处置（不重扫）；"
                "口径是分数各段求和、摘一段就是减掉它",
        "without_clamav_send_rate": round(no_av_sent / n, 4),
        "without_clamav_sent": no_av_sent,
        "without_clamav_recall": round(no_av_caught / mal_n, 4),
        "clamav_hit_files": layer1_arm["clamav"]["hit_files"],
        "clamav_hit_closed_malicious": av_closed,
        "clamav_hit_close_rate": round(av_closed / layer1_arm["clamav"]["hit_files"], 4)
        if layer1_arm["clamav"]["hit_files"] else None,
        "files_rescued_from_pass": sum(
            1 for r in rows
            if sum(1 for c in (r.get("clamav") or []) if c.get("heur_id") == "DET_CLAMAV_SIGNATURE")
            and int(r.get("score") or 0) - 1000 < gate),
    }

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "kind_note": "每个块都带 `kind`：measured = 实测，extrapolated = 外推，derived = 由两者算出。"
                     "**外推的数不许当实测值用**",
        "layer1_arm": layer1_arm,
        "ablation_without_clamav": ablation,
        "ai_arm_full_run_measured": ai_arm_full,
        "ai_arm_sampled": sample_blocks or None,
        "counterfactual_all_ai": counterfactual,
        "production_gate300": production,
        "saved": saved,
        "assumed_est_per_file": DEFAULT_EST_PER_FILE,
    }
    if args.out:
        args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---- 打印 ----
    print(f"①层臂（gate 300，无 AI）· 语料 {name} · n={n}（恶意 {layer1_arm['n_malicious']} / "
          f"良性 {layer1_arm['n_benign']}）")
    print(f"  送审率        {layer1_arm['send_rate']:.4f}  ({layer1_arm['sent']}/{n})")
    print(f"  ①层结案率     {layer1_arm['closed_rate']:.4f}  "
          f"(判恶意 {layer1_arm['closed_malicious']} / 判干净 {layer1_arm['closed_clean']})")
    print(f"  召回(①层口径) {layer1_arm['recall_layer1']}  "
          f"(纯①层判恶意口径 {layer1_arm['recall_deterministic_only']})")
    print(f"  未结案        {layer1_arm['unresolved']}（未结案 ≠ 判白）")
    print(f"  耗时          {layer1_arm['total_seconds']}s = ①层 {layer1_arm['layer1_seconds']}s + "
          f"ClamAV {layer1_arm['clamav_seconds']}s → {layer1_arm['seconds_per_file']}s/文件")
    print(f"  核验          一致率 {layer1_arm['consistency']} · 核验通过 {layer1_arm['verification_ok']} · "
          f"未分类信号 {layer1_arm['unclassified_signals']} · 错误 {layer1_arm['errors']}")
    print()
    print("【实测】对照臂·全量（指令到达前已跑完，本轮 0 token）")
    print(f"  gate 0 · 扫 {ai_arm_full['files_scanned']} 个 · 真进 AI {ai_arm_full['files_reaching_ai']} 个 · "
          f"{ai_arm_full['tokens_measured']:,} token · 均值 {ai_arm_full['mean_tokens_per_ai_file']:,}/文件")
    if sample_blocks:
        m = sample_blocks["sample_measured"]
        c = sample_blocks.get("sampling_check_vs_full_run") or {}
        print()
        print(f"【实测】对照臂·抽样（seed={args.sample_seed} · n={m['files_drawn']} · "
              f"恶意占比 {sample_payload['sample_ratio']['malicious']:.4f}"
              f"（语料 {sample_payload['corpus']['malicious_ratio']:.4f}，一致="
              f"{sample_payload['sample_ratio']['matches_corpus']}））")
        print(f"  真进 AI {m['files_reaching_ai']} 个 · {m['tokens_measured']:,} token · "
              f"均值 {m['mean_tokens_per_ai_file']:,}/文件（中位 {m['median_tokens_per_ai_file']:,}）· "
              f"均值 ¥{m['mean_cny_per_ai_file']}/文件")
        print(f"  预采集 {m['mean_preload_ms_per_ai_file']:,} ms/文件"
              + (f" · 整臂墙钟摊 {m['wall_clock_s_per_ai_file_amortized']}s/文件（摊算，非逐文件计时）"
                 if m["wall_clock_s_per_ai_file_amortized"] is not None else ""))
        if c:
            print(f"  抽样代表性（拿全量实测当参照）: 均值偏差 "
                  f"{c['sample_vs_full_mean_delta_pct']:+.2f}% · 同口径总量偏差 "
                  f"{c['sample_vs_full_total_delta_pct']:+.2f}%")
    print()
    print("【外推】全部送 AI（= 抽样均值 × 语料规模；**不是实测**）")
    print(f"  {counterfactual['basis']}")
    print(f"  {counterfactual['tokens']:,} token ≈ ¥{counterfactual['cny']}"
          f"（单价 ¥{counterfactual['unit_price_cny_per_million']}/百万）")
    if sample_blocks and sample_blocks["extrapolated"].get("same_scope"):
        ss = sample_blocks["extrapolated"]["same_scope"]
        print(f"  同口径（× 实测进 AI 的 {ai_arm_full['files_reaching_ai']} 个）: "
              f"{ss['tokens']:,} token ≈ ¥{ss['cny']}")
    print()
    print("【实测】生产档（gate 300）")
    print(f"  送审 {production['files_sent']} 个 · {production['tokens']:,} token ≈ ¥{production['cny']}")
    print(f"  省下（对照列是外推）: {saved['files']} 个文件送审 · {saved['tokens']:,} token ≈ ¥{saved['cny']}"
          f"（省 {saved['ratio']:.2%}）")
    print()
    print(f"消融（摘掉 ClamAV 的 1000 分，同一批 rows 重算）: 送审率 "
          f"{ablation['without_clamav_send_rate']:.4f}（{ablation['without_clamav_sent']} 个）· "
          f"召回 {ablation['without_clamav_recall']} · "
          f"ClamAV 命中即结案 {ablation['clamav_hit_closed_malicious']}/"
          f"{ablation['clamav_hit_files']}")
    if args.out:
        print(f"\n写入 {args.out}")
    if args.sample_out and sample_payload:
        print(f"写入 {args.sample_out}（含抽中的 {len(sample_payload['files'])} 个文件清单）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
