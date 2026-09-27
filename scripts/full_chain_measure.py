#!/usr/bin/env python3
"""完整链路 · Dike 400 最终水平（2026-09-27）—— 只读产物、不再调模型。

三层链路：① 确定性（ClamAV/可信签名/白名单）→ ② LLM 初筛（最小摘要 → 0~100 分）
→ ③ 深度 AI（全证据 → malicious/suspicious/clean）。

这一版要回答的五组数（与任务单一一对应）：

  1. **最终水平**：召回 / 误报（200 良里判 malicious 几个）/ 送审率 / 成本（初筛 vs 深度 AI 分开）
  2. **闭环**：良性被送进 ③ 几个 → ③ 平反（判 clean）几个 → 平反完实际误报率
     ⚠️ 口径：**送审率 ≠ 误报率**
  3. **增量归因**：上版（无初筛、单档 300）漏的 15 个恶意，这一版捞回几个、③ 判成什么
  4. **分层卸载**：①层结案（恶/净）、②层送审、③层判决分布
  5. **时间**：墙钟 + 取证时间（与 10.4/10.5 同口径）

基线口径（**说清来路，不重跑**）：上版 = `--ai-threshold 300 --ai-threshold-low 0`，
无初筛。它的逐文件产物来自 `/tmp/two-tier/a1`（同一批语料、同一份代码的确定性层）。
本脚本会**逐文件核对两边的预筛分是否一致** —— 不一致就报出来（否则"增量"就是假的）。

用法：
    .venv/bin/python scripts/full_chain_measure.py \
        --labels ~/ai-av-bench/dike-bench/labels.json \
        --run /tmp/triage-full/r1/scan_*.json /tmp/triage-full/r2/scan_*.json \
        --baseline /tmp/two-tier/a1/scan_*.json \
        --wall /tmp/triage-full/runlog.tsv \
        --out bench/full-chain-dike400.json
"""
from __future__ import annotations

import argparse
import glob
import json
from collections import Counter
from pathlib import Path
from typing import Any

FLAG = ("malicious", "suspicious")


def _load(pattern: str) -> dict[str, Any]:
    paths = [p for p in sorted(glob.glob(pattern)) if not p.endswith(".audit.json")]
    if not paths:
        raise SystemExit(f"找不到扫描产物: {pattern}")
    return json.loads(Path(paths[-1]).read_text(encoding="utf-8"))


def _rows(report: dict[str, Any], labels: dict[str, str]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in report.get("reports") or []:
        name = Path(r["path"]).name
        det = r.get("deterministic") or {}
        tri = det.get("triage") or {}
        verdict = r.get("verdict") or {}
        usage = r.get("agent_usage") or {}
        preload = r.get("evidence_preload") or {}
        out[name] = {
            "name": name,
            "sha256": r.get("sha256", ""),
            "label": labels.get(name, "unknown"),
            "score": int(r.get("prefilter_score") or 0),
            "disposition": det.get("disposition"),
            "ai_tier": det.get("ai_tier"),
            "sends_to_ai": bool(det.get("sends_to_ai")),
            "gate": det.get("gate"),
            "gate_low": det.get("gate_low"),
            "criteria": [h.get("heur_id") for h in (r.get("criteria_hits") or [])],
            "agent_used": bool(r.get("agent_used")),
            "risk": verdict.get("risk"),
            "confidence": verdict.get("confidence"),
            "category": verdict.get("category"),
            "summary": (verdict.get("summary") or "")[:200],
            "ai_tokens": int(usage.get("tokens") or 0),
            "tool_calls": int(usage.get("tool_calls") or 0),
            "preload_ms": preload.get("elapsed_ms"),
            "preload_kind": preload.get("preload_kind"),
            "deep_forensics": preload.get("deep_forensics"),
            "degraded": (r.get("agent_retry") or {}).get("outcome") == "degraded_to_rules",
            "error": r.get("error") or "",
            "unclassified": list(r.get("unclassified_signals") or []),
            "clamav": r.get("clamav") or {},
            "triage": {
                "enabled": bool(tri.get("enabled")),
                "candidate": bool(tri.get("candidate")),
                "score": tri.get("score"),
                "tier": tri.get("tier"),
                "threshold": tri.get("threshold"),
                "entry_gate": tri.get("entry_gate"),
                "model": tri.get("model"),
                "reason": tri.get("reason") or "",
                "source": tri.get("source"),
                "error": tri.get("error") or "",
                "tokens": int(tri.get("total_tokens") or 0),
                "usage_source": tri.get("usage_source") or "none",
            },
        }
    return out


def _counts(rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
    mal = [r for r in rows.values() if r["label"] == "malicious"]
    ben = [r for r in rows.values() if r["label"] == "clean"]
    caught = [r for r in mal if r["risk"] in FLAG]
    return {
        "malicious_total": len(mal),
        "benign_total": len(ben),
        "recall": round(len(caught) / len(mal), 4) if mal else None,
        "recall_hits": len(caught),
        "missed": sorted(r["name"] for r in mal if r["risk"] not in FLAG),
        "benign_malicious": sorted(r["name"] for r in ben if r["risk"] == "malicious"),
        "benign_suspicious": sorted(r["name"] for r in ben if r["risk"] == "suspicious"),
        "benign_flagged": sorted(r["name"] for r in ben if r["risk"] in FLAG),
        "risk": dict(Counter(r["risk"] for r in rows.values())),
    }


def measure(run: dict[str, dict[str, Any]], baseline: dict[str, dict[str, Any]],
            extra: dict[str, Any]) -> dict[str, Any]:
    n = len(run)
    mal = [r for r in run.values() if r["label"] == "malicious"]
    ben = [r for r in run.values() if r["label"] == "clean"]

    # ---- 1. 最终水平 ----
    final = _counts(run)
    base = _counts(baseline)

    sent = [r for r in run.values() if r["sends_to_ai"] or r["agent_used"]]
    by_tier = Counter(r["ai_tier"] or "none" for r in run.values())
    closed_mal = [r for r in run.values() if r["disposition"] == "closed_malicious"]
    closed_clean = [r for r in run.values() if r["disposition"] == "closed_clean"]
    passed = [r for r in run.values() if r["disposition"] == "pass"]

    # ---- 2. 闭环：良性送审之后的结局 ----
    ben_sent = [r for r in ben if r["sends_to_ai"] or r["agent_used"]]
    ben_rehab = [r for r in ben_sent if r["risk"] == "clean"]
    ben_still = [r for r in ben_sent if r["risk"] in FLAG]

    # ---- 3. 增量归因：上版漏的恶意 ----
    # 只比**两边都有**的文件（子集跑测时不该炸）。
    missed_before = {r["name"] for r in baseline.values()
                     if r["label"] == "malicious" and r["risk"] not in FLAG} & set(run)
    recovered = [run[nm] for nm in missed_before if run[nm]["risk"] in FLAG]
    still_missed = sorted(nm for nm in missed_before if run[nm]["risk"] not in FLAG)
    recovered_rows = [{
        "name": r["name"], "score": r["score"], "criteria": r["criteria"],
        "triage_score": r["triage"]["score"], "triage_tier": r["triage"]["tier"],
        "ai_tier": r["ai_tier"], "risk": r["risk"], "confidence": r["confidence"],
        "category": r["category"], "summary": r["summary"],
    } for r in sorted(recovered, key=lambda x: -x["score"])]

    # 初筛送审 → ③ 平反（判 clean）：正常现象，要报数不藏
    triage_selected = [r for r in run.values() if r["triage"]["tier"] == "select"]
    triage_selected_clean = [r for r in triage_selected if r["risk"] == "clean"]
    triage_selected_flag = [r for r in triage_selected if r["risk"] in FLAG]

    # ---- 4. 分层卸载 ----
    layers = {
        "layer1_closed_malicious": len(closed_mal),
        "layer1_closed_clean": len(closed_clean),
        "layer1_closed": len(closed_mal) + len(closed_clean),
        "layer2_candidates": sum(1 for r in run.values() if r["triage"]["candidate"]),
        "layer2_selected": len(triage_selected),
        "layer2_dropped": sum(1 for r in run.values() if r["triage"]["tier"] == "drop"),
        "layer2_no_score": sum(1 for r in run.values()
                               if r["triage"]["candidate"] and r["triage"]["score"] is None),
        "layer2_unresolved_after": len(passed),
        "layer3_ai_files": sum(1 for r in run.values() if r["agent_used"]),
        "layer3_malicious": sum(1 for r in run.values() if r["agent_used"]
                                and r["risk"] == "malicious"),
        "layer3_suspicious": sum(1 for r in run.values() if r["agent_used"]
                                 and r["risk"] == "suspicious"),
        "layer3_clean": sum(1 for r in run.values() if r["agent_used"]
                            and r["risk"] == "clean"),
    }

    # ---- 5. 成本 ----
    triage_tokens = sum(r["triage"]["tokens"] for r in run.values())
    triage_est = sum(1 for r in run.values()
                     if r["triage"]["candidate"] and r["triage"]["usage_source"] == "estimate")
    ai_tokens = sum(r["ai_tokens"] for r in run.values() if r["agent_used"])
    price = extra.get("cny_per_million")
    cost = {
        "triage_tokens": triage_tokens,
        "triage_files": sum(1 for r in run.values() if r["triage"]["candidate"]),
        "triage_usage_estimated_entries": triage_est,
        "deep_ai_tokens": ai_tokens,
        "deep_ai_files": layers["layer3_ai_files"],
        "total_tokens": triage_tokens + ai_tokens,
        "cny_per_million": price,
        "triage_cny": round(triage_tokens * price / 1e6, 4) if price else None,
        "deep_ai_cny": round(ai_tokens * price / 1e6, 4) if price else None,
        "total_cny": round((triage_tokens + ai_tokens) * price / 1e6, 4) if price else None,
    }

    # ---- 核验（核验铁律：失败/降级不为 0 则该批作废）----
    verification = {
        "triage_failed": sum(1 for r in run.values()
                             if r["triage"]["candidate"] and r["triage"]["score"] is None),
        "triage_errors": sorted({r["triage"]["error"] for r in run.values()
                                 if r["triage"]["error"]}),
        "ai_degraded": sum(1 for r in run.values() if r["degraded"]),
        "scan_errors": sum(1 for r in run.values() if r["error"]),
        "unclassified_signals": sum(1 for r in run.values() if r["unclassified"]),
        "clamav_unavailable": sum(1 for r in run.values()
                                  if not (r["clamav"] or {}).get("available")),
        "clamav_batch_errors": sum(1 for r in run.values()
                                   if (r["clamav"] or {}).get("error")),
        "baseline_score_mismatch": sorted(
            nm for nm in run if nm in baseline and baseline[nm]["score"] != run[nm]["score"]),
    }

    # 取证时间（与 10.4/10.5 同口径：只统计真采过证据的文件）
    preloads = [r["preload_ms"] for r in run.values() if r["preload_ms"] is not None]
    timing = {
        "wall_s": extra.get("wall_s"),
        "preload_files": len(preloads),
        "preload_ms_sum": round(sum(preloads), 1) if preloads else 0.0,
        "preload_ms_mean": round(sum(preloads) / len(preloads), 1) if preloads else None,
        "preload_ms_max": round(max(preloads), 1) if preloads else None,
        "preload_deep_skipped": sum(1 for r in run.values()
                                    if r.get("deep_forensics") == "skipped"),
    }

    return {
        "n": n,
        "config": extra.get("config"),
        "final": final,
        "baseline": base,
        "send": {
            "files": len(sent),
            "rate": round(len(sent) / n, 4),
            "by_tier": dict(by_tier),
            "high": by_tier.get("high", 0),
            "low": by_tier.get("low", 0),
            "triage": by_tier.get("triage", 0),
        },
        "closure": {
            "benign_sent_to_deep_ai": len(ben_sent),
            "benign_rehabilitated_clean": len(ben_rehab),
            "benign_still_flagged": len(ben_still),
            "benign_send_rate": round(len(ben_sent) / len(ben), 4) if ben else None,
            "benign_false_positive_rate": (round(len(ben_still) / len(ben), 4)
                                           if ben else None),
            "benign_malicious_rate": (round(len(final["benign_malicious"]) / len(ben), 4)
                                      if ben else None),
        },
        "increment": {
            "missed_before": len(missed_before),
            "recovered": len(recovered),
            "recovered_rows": recovered_rows,
            "still_missed": still_missed,
            "triage_selected": len(triage_selected),
            "triage_selected_clean": len(triage_selected_clean),
            "triage_selected_flag": len(triage_selected_flag),
            "triage_selected_clean_rows": [
                {"name": r["name"], "label": r["label"], "score": r["score"],
                 "triage_score": r["triage"]["score"], "risk": r["risk"],
                 "confidence": r["confidence"], "summary": r["summary"]}
                for r in triage_selected_clean],
            "triage_selected_flag_rows": [
                {"name": r["name"], "label": r["label"], "score": r["score"],
                 "triage_score": r["triage"]["score"], "risk": r["risk"],
                 "confidence": r["confidence"]}
                for r in triage_selected_flag],
        },
        "layers": layers,
        "cost": cost,
        "verification": verification,
        "timing": timing,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", required=True)
    ap.add_argument("--run", nargs="+", required=True, help="主臂（可给两遍比一致率）")
    ap.add_argument("--baseline", required=True, help="上版（无初筛、单档 300）产物")
    ap.add_argument("--wall", help="runlog.tsv（臂名 \\t 墙钟 \\t rc \\t 参数）")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    from aiav.budget import CNY_PER_MILLION_TOKENS

    labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    runs = [_rows(_load(p), labels) for p in args.run]
    baseline = _rows(_load(args.baseline), labels)

    walls = {}
    if args.wall and Path(args.wall).exists():
        for line in Path(args.wall).read_text(encoding="utf-8").splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                walls[parts[0]] = int(parts[1])
    config = None
    if args.wall and Path(args.wall).exists():
        lines = Path(args.wall).read_text(encoding="utf-8").splitlines()
        if lines and len(lines[0].split("\t")) >= 4:
            config = lines[0].split("\t")[3]

    extra = {"cny_per_million": CNY_PER_MILLION_TOKENS, "config": config}
    out: dict[str, Any] = {
        "generated_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        "arms": list(walls),
        "wall_s": walls,
        "config": config,
        "price_note": ("¥/百万 token 取项目常量（`budget.CNY_PER_MILLION_TOKENS`，"
                       "偏高的一档 = 上界）；初筛与深度 AI 用的是**同一个单价**，"
                       "所以两笔账可以相加，但都是上界。"),
        # 每一遍各自配自己的墙钟（别让两遍共用同一个值 —— 踩过：r1/r2 都报成 r1 的墙钟）
        "runs": [measure(r, baseline, {**extra, "wall_s": walls.get(f"r{i + 1}")})
                 for i, r in enumerate(runs)],
    }
    # 两遍一致率（同一配置跑两次）：路由一致 + 结论一致
    if len(runs) == 2:
        a, b = runs
        route_same = sum(1 for nm in a if (a[nm]["ai_tier"] or "none") == (b[nm]["ai_tier"] or "none"))
        verdict_same = sum(1 for nm in a if a[nm]["risk"] == b[nm]["risk"])
        tri_same = sum(1 for nm in a if a[nm]["triage"]["score"] == b[nm]["triage"]["score"])
        out["consistency"] = {
            "files": len(a),
            "route_same": route_same,
            "route_rate": round(route_same / len(a), 4),
            "verdict_same": verdict_same,
            "verdict_rate": round(verdict_same / len(a), 4),
            "triage_score_same": tri_same,
            "triage_score_rate": round(tri_same / len(a), 4),
            "route_diff": sorted(nm for nm in a
                                 if (a[nm]["ai_tier"] or "none") != (b[nm]["ai_tier"] or "none")),
            "verdict_diff": sorted(nm for nm in a if a[nm]["risk"] != b[nm]["risk"]),
        }
    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"out": args.out, "wall_s": walls,
                      "r1_final": out["runs"][0]["final"],
                      "r1_send": out["runs"][0]["send"],
                      "r1_cost": out["runs"][0]["cost"],
                      "r1_verification": out["runs"][0]["verification"],
                      "consistency": out.get("consistency")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
