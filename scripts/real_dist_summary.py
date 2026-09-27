#!/usr/bin/env python3
"""真实分布实测的**汇总口径**：把散在几个产物里的数拉成一张表（报告里的数就是这个脚本打的）。

输入三份产物（都由别的脚本产出，这里只读、不重算判定）：

  · `--measure`    `scripts/measure_deterministic.py` 的 JSON —— ①层那一臂（无 AI）
  · `--ai-report`  `aiav scan --ai-threshold 0` 的 JSON —— "全部送 AI"对照臂
  · `--unit-price` 单价（元/百万 token），默认取 `aiav/budget.py` 里唯一定义的那一处

四个数（本轮交付）：
  1. **送审率**  = ①层处置为 `send_ai` 的文件 / 总数
  2. **①层结案率** =（确定性判恶意 + 确定性判干净）/ 总数
  3. **召回**（①层口径）= 恶意文件里被"确定性判恶意"或"送 AI"覆盖的比例
  4. **成本** = token 总量 / 按单价折的钱 / 平均每文件

对照臂的算法写死在这里，免得每次换说法：
  · `gate 0` 那一轮**并不是真的 320/320 都进 AI** —— 确定性结案的（ClamAV 命中、签名可信）
    在送审前就短路了。所以实测到的是"274 个进了 AI"。
  · "全部送 AI"的成本 = **实测每文件均值 × 语料总数**（外推，不是又跑一遍）。
    外推口径在报告里必须写明，不许当成实测值。

用法：

    .venv/bin/python scripts/real_dist_summary.py \
        --measure /tmp/real-dist-out/measure_gate300_*.json \
        --ai-report /tmp/real-dist-ai-out/scan_*.json \
        --out /tmp/real-dist-summary.json
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


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

    # ---- "全部送 AI"对照臂（gate 0，实测） ----
    ai = load_one(args.ai_report)
    reports = ai.get("reports") or []
    sent = [r for r in reports if r.get("agent_used")]
    tokens_by_file = {r["path"]: int(((r.get("agent_usage") or {}).get("tokens")) or 0) for r in sent}
    total_tokens = sum(tokens_by_file.values())
    mean_tokens = total_tokens / len(sent) if sent else 0
    ai_arm = {
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

    # ---- 对照：全部送 AI 的成本（外推，口径写在这里） ----
    all_ai_tokens = round(mean_tokens * n)
    counterfactual = {
        "basis": f"实测每文件均值 {round(mean_tokens, 1)} token × 语料 {n} 个文件（外推，不是实测）",
        "tokens": all_ai_tokens,
        "cny": round(all_ai_tokens / 1_000_000 * CNY_PER_MILLION_TOKENS, 2),
        "tokens_per_file": round(mean_tokens, 1),
        "unit_price_cny_per_million": CNY_PER_MILLION_TOKENS,
        "note": "单价是项目里唯一定义的那一处（偏高的一档），不是服务商报价单",
    }
    # 生产档（gate 300）实际会花的钱：只有真送审的那几个文件的 token（在对照臂里逐个取）
    production_tokens = sum(tokens_by_file.get(r["path"], 0)
                            for r in reports
                            if (r.get("deterministic") or {}).get("disposition") == "send_ai")
    production = {
        "files_sent": s["sent"],
        "tokens": production_tokens,
        "cny": round(production_tokens / 1_000_000 * CNY_PER_MILLION_TOKENS, 2),
        "note": "送审文件的 token 取自对照臂的同一条流水线（同一路径、同一预采集），不是另跑一轮",
    }
    saved = {
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
        "layer1_arm": layer1_arm,
        "ablation_without_clamav": ablation,
        "ai_arm_gate0": ai_arm,
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
    print(f"对照臂（gate 0，全部送 AI）· 扫 {ai_arm['files_scanned']} 个 · "
          f"真进 AI {ai_arm['files_reaching_ai']} 个 · {ai_arm['tokens_measured']:,} token · "
          f"均值 {ai_arm['mean_tokens_per_ai_file']:,}/文件")
    print(f"  全部送 AI（外推 320）: {counterfactual['tokens']:,} token ≈ "
          f"¥{counterfactual['cny']}（单价 ¥{counterfactual['unit_price_cny_per_million']}/百万）")
    print(f"  生产档（gate 300）实际: {production['tokens']:,} token ≈ ¥{production['cny']}")
    print(f"  省下: {saved['files']} 个文件送审 · {saved['tokens']:,} token ≈ ¥{saved['cny']}"
          f"（省 {saved['ratio']:.2%}）")
    print()
    print(f"消融（摘掉 ClamAV 的 1000 分，同一批 rows 重算）: 送审率 "
          f"{ablation['without_clamav_send_rate']:.4f}（{ablation['without_clamav_sent']} 个）· "
          f"召回 {ablation['without_clamav_recall']} · "
          f"ClamAV 命中即结案 {ablation['clamav_hit_closed_malicious']}/"
          f"{ablation['clamav_hit_files']}")
    if args.out:
        print(f"\n写入 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
