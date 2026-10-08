#!/usr/bin/env python3
"""LLM 初筛 · 指标汇总（只读产物，**不重算判定、不再调模型**）。

算这几样（任务点名的交付）：
  · 15 个漏掉的恶意 LLM 认出几个（按 ≥50 / ≥70 两档给召回）
  · 137 个良性里误报几个
  · 125 档的区分度 AUC（LLM 分 vs 真值），并跟规则分对照
  · 成本（总 token / 金额 / 平均每文件），含 5000 文件的外推（**标清是外推**）
  · 建议门槛：用"边际代价"曲线算出来，不是拍的
  · 高分良性给了什么理由 / 低分恶意漏在哪（逐条列出来给人看）

口径写死在这里，报告直接引用，不在别处重算：
  · 召回 = 该门槛上被判"送深度 AI"的恶意数 / 恶意总数
  · 良性误报 = 该门槛上被送审的良性数（**不是"判错"** —— 初筛只负责排序、
    不负责定性；初筛说"高分"，深度 AI 还有机会平反）
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def auc(scores: list[float], labels: list[bool]) -> float | None:
    """Mann-Whitney U 版 AUC（并列取平均秩）。

    为什么不用第三方库：项目里没有 sklearn，而这条公式短到不值得为它加依赖；
    更要紧的是**并列怎么算必须自己说清** —— 125 档全是同一个规则分，
    并列处理错了会算出 0.5 以外的数（那正是这条对比的意义所在）。
    """
    pos = [s for s, y in zip(scores, labels) if y]
    neg = [s for s, y in zip(scores, labels) if not y]
    if not pos or not neg:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    rank_sum = sum(r for r, y in zip(ranks, labels) if y)
    n1, n2 = len(pos), len(neg)
    u = rank_sum - n1 * (n1 + 1) / 2
    return round(u / (n1 * n2), 4)


def sweep(results: list[dict], thresholds: list[int]) -> list[dict]:
    mal = [r for r in results if r.get("label") == "malicious" and r.get("score") is not None]
    ben = [r for r in results if r.get("label") != "malicious" and r.get("score") is not None]
    rows = []
    for t in thresholds:
        tp = sum(1 for r in mal if r["score"] >= t)
        fp = sum(1 for r in ben if r["score"] >= t)
        rows.append({
            "threshold": t,
            "malicious_total": len(mal),
            "benign_total": len(ben),
            "recall": round(tp / len(mal), 4) if mal else None,
            "recall_hits": tp,
            "benign_sent": fp,
            "benign_send_rate": round(fp / len(ben), 4) if ben else None,
            "sent_total": tp + fp,
            "precision_sent": round(tp / (tp + fp), 4) if (tp + fp) else None,
        })
    return rows


def recommend(rows: list[dict]) -> dict:
    """算建议门槛：**最大化召回，约束在"良性送审率 ≤ 10%"**。

    为什么用这条准则（而不是拍一个数）：
      · 初筛的活是"别漏 + 别淹" —— 全送（阈值 0）召回最高但等于没筛，没有意义；
      · 良性送审率 10% 是**成本闸**：深度 AI 每个文件约 1 万 token，
        10% × 158 ≈ 16 个文件；放到 5000 文件规模就是 500 个 ≈ ¥40，可接受；
      · 在这条约束下能拿到的最高召回，就是"花这些钱值不值"的答案。
    同时给出**边际代价**（每多召回一个恶意要多送几个良性），因为门槛附近这个数会突变。
    """
    best = None
    for row in rows:
        if row["benign_send_rate"] is None:
            continue
        if row["benign_send_rate"] <= 0.10:
            if best is None or (row["recall"], -row["benign_sent"]) > (best["recall"], -best["benign_sent"]):
                best = row
    # 边际代价：**把门槛从 T 降一步到 T⁻**，每多召回一个恶意要多送几个良性。
    # 方向必须说清（门槛越低召回越高、代价越大）—— 这里只算**建议门槛附近**那一档，
    # 因为"该不该再往下挪一格"就是在那一点上做决定；离得太远的价码不影响决策。
    ordered = sorted(rows, key=lambda r: r["threshold"])   # 阈值升序：ordered[0] 最低
    by_threshold = {r["threshold"]: r for r in ordered}
    marginal: dict | None = None
    if best is not None:
        step = (ordered[1]["threshold"] - ordered[0]["threshold"]) if len(ordered) > 1 else 0
        lower = by_threshold.get(best["threshold"] - step) if step else None
        if lower is not None:
            # 门槛从 best 降到 lower：召回**增加** d_tp 个，良性**多送** d_fp 个
            d_tp = lower["recall_hits"] - best["recall_hits"]
            d_fp = lower["benign_sent"] - best["benign_sent"]
            marginal = {
                "from_threshold": lower["threshold"], "to_threshold": best["threshold"],
                "step": step,
                "extra_malicious_if_lowered": d_tp,
                "extra_benign_if_lowered": d_fp,
                "benign_per_extra_malicious": (round(d_fp / d_tp, 2) if d_tp else None),
            }
    return {"criterion": "max recall s.t. benign_send_rate <= 10%", "pick": best,
            "marginal_cost_near_pick": marginal}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    ap = argparse.ArgumentParser(description="LLM 初筛 · 指标汇总")
    ap.add_argument("--gray", type=Path, required=True, help="灰区跑批结果 JSON")
    ap.add_argument("--holdout", type=Path, action="append", default=[],
                    help="holdout 结果 JSON（可多次给）")
    ap.add_argument("--rules-scan", type=Path, default=None,
                    help="确定性扫描产物（提供规则分做 AUC 对照）")
    ap.add_argument("--thresholds", default="0,5,10,15,20,25,30,35,40,45,50,55,60,65,70,75,80,85,90",
                    help="扫的阈值（逗号分隔）")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    thresholds = [int(x) for x in args.thresholds.split(",") if x.strip()]
    gray = load(args.gray)
    results = [r for r in gray["results"] if r.get("score") is not None]
    dropped = [r for r in gray["results"] if r.get("score") is None]

    mal = [r for r in results if r.get("label") == "malicious"]
    ben = [r for r in results if r.get("label") != "malicious"]
    b125 = [r for r in results if r.get("prefilter_score") == 125]
    rows = sweep(results, thresholds)

    report: dict = {
        "generated_at": gray.get("generated_at"),
        "model": gray.get("model"),
        "source": {"gray": str(args.gray), "rules_scan": str(args.rules_scan or "")},
        "composition": gray.get("composition"),
        "n": {"total": len(gray["results"]), "scored": len(results),
              "unscored": len(dropped), "malicious": len(mal), "benign": len(ben),
              "bucket125": len(b125)},
        "cost": gray["cost"],
        "verification": gray["verification"],
        "auc": {
            "llm_gray_zone_all": auc([r["score"] for r in results],
                                     [r.get("label") == "malicious" for r in results]),
            "llm_bucket125": auc([r["score"] for r in b125],
                                 [r.get("label") == "malicious" for r in b125]),
            "rule_score_gray_zone_all": auc(
                [r["prefilter_score"] for r in results],
                [r.get("label") == "malicious" for r in results]),
            # 125 档里规则分**是同一个常数**（都命中 HIGH_RISK_EXTENSION）→ 并列秩 → 正好 0.5。
            # 这就是"判据分不开、门槛也分不开"的量化版本：0.5 = 完全无区分度。
            "rule_score_bucket125": auc(
                [r["prefilter_score"] for r in b125],
                [r.get("label") == "malicious" for r in b125]),
        },
        "per_bucket": [],
        "score_distribution": {
            "malicious": {"n": len(mal), "min": min((r["score"] for r in mal), default=None),
                          "median": statistics.median([r["score"] for r in mal]) if mal else None,
                          "max": max((r["score"] for r in mal), default=None)},
            "benign": {"n": len(ben), "min": min((r["score"] for r in ben), default=None),
                       "median": statistics.median([r["score"] for r in ben]) if ben else None,
                       "max": max((r["score"] for r in ben), default=None)},
        },
        "sweep": rows,
        "recommendation": recommend(rows),
        "missed_malicious_detail": [
            {"name": r["name"], "score": r["score"], "bucket": r["prefilter_score"],
             "category": r.get("category"), "reason": r.get("reason")}
            for r in sorted(mal, key=lambda x: x["score"])
        ],
        "high_score_benign_detail": [
            {"name": r["name"], "score": r["score"], "bucket": r["prefilter_score"],
             "reason": r.get("reason")}
            for r in sorted(ben, key=lambda x: -x["score"])
            if r["score"] >= 50
        ],
    }

    # 逐档：AUC + 扫描 + 分数分布（"LLM 的增量落在哪一档"要能分开看）
    for bucket in sorted({r["prefilter_score"] for r in results if r.get("prefilter_score")}):
        rows_b = [r for r in results if r.get("prefilter_score") == bucket]
        mal_b = [r for r in rows_b if r.get("label") == "malicious"]
        ben_b = [r for r in rows_b if r.get("label") != "malicious"]
        report["per_bucket"].append({
            "prefilter_score": bucket,
            "n": {"total": len(rows_b), "malicious": len(mal_b), "benign": len(ben_b)},
            "auc_llm": auc([r["score"] for r in rows_b],
                           [r.get("label") == "malicious" for r in rows_b]),
            "malicious_scores": sorted(r["score"] for r in mal_b),
            "benign_median": statistics.median([r["score"] for r in ben_b]) if ben_b else None,
            "benign_max": max((r["score"] for r in ben_b), default=None),
        })

    # 规则分对照：从扫描产物里取（只读，不重算）
    if args.rules_scan and args.rules_scan.is_file():
        scan = load(args.rules_scan)
        by_name = {Path(x["path"]).name: x.get("prefilter_score", 0)
                   for x in scan.get("reports") or []}
        report["rule_scores_in_gray"] = {
            r["name"]: by_name.get(r["name"]) for r in results
        }

    # holdout
    holdouts = []
    for hp in args.holdout:
        if not hp.is_file():
            continue
        h = load(hp)
        hres = [r for r in h["results"] if r.get("score") is not None]
        hmal = [r for r in hres if r.get("label") == "malicious"]
        hben = [r for r in hres if r.get("label") != "malicious"]
        entry = {
            "path": str(hp),
            "n": {"total": len(h["results"]), "scored": len(hres),
                  "malicious": len(hmal), "benign": len(hben)},
            "cost": h["cost"],
            "verification": h["verification"],
            "auc": auc([r["score"] for r in hres],
                       [r.get("label") == "malicious" for r in hres]) if hben else None,
            "sweep": sweep(hres, thresholds),
        }
        # 用**灰区上定出来的门槛**去套 holdout（这才是 holdout 该干的事）
        pick = (report["recommendation"].get("pick") or {}).get("threshold")
        if pick is not None:
            entry["at_recommended_threshold"] = next(
                (row for row in entry["sweep"] if row["threshold"] == pick), None)
        holdouts.append(entry)
    report["holdouts"] = holdouts

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")

    print(json.dumps({
        "n": report["n"], "auc": report["auc"],
        "score_distribution": report["score_distribution"],
        "recommendation": report["recommendation"],
        "cost": {k: report["cost"][k] for k in
                 ("total_tokens", "avg_tokens_per_file", "cost_cny", "failed", "from_cache")},
    }, ensure_ascii=False, indent=1))
    print(f"[产物] {args.out}")


if __name__ == "__main__":
    main()
