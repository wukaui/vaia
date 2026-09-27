#!/usr/bin/env python3
"""批次汇总（2026-09-27）—— 只读产物、不再调模型。

**一批一产物**：这个脚本一次只吃**一批**语料，输出一份 JSON。
它的存在就是为了不让"这一堆测试"混表 —— 每个数字都带批次名，
**分母写清**（全恶意批次没有误报率），**不做任何跨批合并指标**。

它量的是完整链路的三层：

    ① 确定性（ClamAV / 可信签名 / 白名单，0 token）
    ② LLM 初筛（最小摘要 → 0~100 分，门槛 60，入口 125）
    ③ 深度 AI（全证据 → malicious / suspicious / clean）

用法：

    .venv/bin/python scripts/batch_measure.py \
        --batch-id mb280-scriptdoc \
        --batch-title "mb-* 脚本/文档类 280（全恶意）" \
        --labels /tmp/batch2-20260927/a-labels.json \
        --types /tmp/batch2-20260927/a-types.json \
        --run '/tmp/batch2-20260927/out/a-r1/scan_*.json' \
              '/tmp/batch2-20260927/out/a-r2/scan_*.json' \
        --baseline '/tmp/batch2-20260927/out/a-base1/scan_*.json' \
        --wall /tmp/batch2-20260927/runlog.tsv \
        --out bench/batch-mb280-full-chain.json
"""
from __future__ import annotations

import argparse
import glob
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

FLAG = ("malicious", "suspicious")


def _load(pattern: str) -> dict[str, Any]:
    paths = [p for p in sorted(glob.glob(pattern)) if not p.endswith(".audit.json")]
    if not paths:
        raise SystemExit(f"找不到扫描产物: {pattern}")
    return json.loads(Path(paths[-1]).read_text(encoding="utf-8"))


def _rows(report: dict[str, Any], labels: dict[str, str],
          types: dict[str, str]) -> dict[str, dict[str, Any]]:
    """逐文件行。字段口径与 scripts/full_chain_measure.py 一致（同一份产物形状）。"""
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
            "type": types.get(name, ""),
            "score": int(r.get("prefilter_score") or 0),
            "disposition": det.get("disposition"),
            "ai_tier": det.get("ai_tier"),
            "sends_to_ai": bool(det.get("sends_to_ai")),
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


def _route(r: dict[str, Any]) -> str:
    """这一批里每个文件**走的是哪条路** —— 只按各层自己的口径说话。"""
    disp = r["disposition"]
    if disp == "closed_malicious":
        return "①层结案·判恶意"
    if disp == "closed_clean":
        return "①层结案·判干净"
    tier = r["ai_tier"]
    if tier == "high":
        return "规则直送③（≥闸门）"
    if tier == "low":
        return "低档送③"
    if tier == "triage":
        return "②初筛选送③"
    if r["triage"]["tier"] == "drop":
        return "②初筛未达门槛"
    if r["triage"]["candidate"]:
        return "②初筛没拿到分数"
    return "未结案·静默放行"


def _by_type(rows: dict[str, dict[str, Any]], key) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows.values():
        groups[r["type"] or "(无来源)"].append(r)
    out = {}
    for t in sorted(groups):
        rs = groups[t]
        mal = [r for r in rs if r["label"] == "malicious"]
        ben = [r for r in rs if r["label"] == "clean"]
        caught = [r for r in mal if r["risk"] in FLAG]
        sent = [r for r in rs if r["sends_to_ai"] or r["agent_used"]]
        tri_cand = [r for r in rs if r["triage"]["candidate"]]
        tri_sel = [r for r in rs if r["triage"]["tier"] == "select"]
        out[t] = {
            "n": len(rs),
            "malicious": len(mal),
            "benign": len(ben),
            "layer1_closed": sum(1 for r in rs
                                 if r["disposition"] in ("closed_malicious", "closed_clean")),
            "layer1_closed_malicious": sum(1 for r in rs
                                           if r["disposition"] == "closed_malicious"),
            "layer1_closed_clean": sum(1 for r in rs
                                       if r["disposition"] == "closed_clean"),
            "gray_zone_125_199": sum(1 for r in rs
                                     if 125 <= r["score"] < 200 and r["disposition"] not in
                                     ("closed_malicious", "closed_clean")),
            "gate_direct_ge200": sum(1 for r in rs if r["ai_tier"] == "high"),
            "silent_pass_lt125": sum(1 for r in rs if _route(r) == "未结案·静默放行"),
            "sent_to_ai": len(sent),
            "triage_candidates": len(tri_cand),
            "triage_selected": len(tri_sel),
            "triage_dropped": sum(1 for r in rs if r["triage"]["tier"] == "drop"),
            "recall": round(len(caught) / len(mal), 4) if mal else None,
            "recall_hits": len(caught),
            "missed": sorted(r["name"] for r in mal if r["risk"] not in FLAG),
            "triage_recall": (round(sum(1 for r in tri_cand
                                        if r["triage"]["tier"] == "select") / len(tri_cand), 4)
                              if tri_cand else None),
            "risk": dict(Counter(r["risk"] for r in rs)),
        }
    return out


def _counts(rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
    mal = [r for r in rows.values() if r["label"] == "malicious"]
    ben = [r for r in rows.values() if r["label"] == "clean"]
    caught = [r for r in mal if r["risk"] in FLAG]
    res: dict[str, Any] = {
        "malicious_total": len(mal),
        "benign_total": len(ben),
        "recall": round(len(caught) / len(mal), 4) if mal else None,
        "recall_hits": len(caught),
        "recall_denominator": len(mal),
        "recall_note": ("召回 = 最终判 flag（malicious + suspicious）/ 该批恶意总数。"
                        "全恶意批次分母 = 全部文件。"),
        "missed": sorted(r["name"] for r in mal if r["risk"] not in FLAG),
        "risk": dict(Counter(r["risk"] for r in rows.values())),
    }
    if ben:
        ben_flag = [r for r in ben if r["risk"] in FLAG]
        ben_mal = [r for r in ben if r["risk"] == "malicious"]
        res.update({
            "benign_flagged": len(ben_flag),
            "benign_malicious": len(ben_mal),
            "false_positive_rate": round(len(ben_flag) / len(ben), 4),
            "false_positive_rate_malicious_only": round(len(ben_mal) / len(ben), 4),
            "false_positive_denominator": len(ben),
            "benign_flagged_names": sorted(r["name"] for r in ben_flag),
        })
    else:
        res["false_positive_rate"] = None
        res["false_positive_note"] = "**全恶意批次：良性分母为 0，这一批没有误报率**"
    return res


def measure(run: dict[str, dict[str, Any]], labels: dict[str, str],
            types: dict[str, str], extra: dict[str, Any]) -> dict[str, Any]:
    n = len(run)
    final = _counts(run)
    mal = [r for r in run.values() if r["label"] == "malicious"]
    ben = [r for r in run.values() if r["label"] == "clean"]

    routes = Counter(_route(r) for r in run.values())
    closed_mal = [r for r in run.values() if r["disposition"] == "closed_malicious"]
    closed_clean = [r for r in run.values() if r["disposition"] == "closed_clean"]
    sent = [r for r in run.values() if r["sends_to_ai"] or r["agent_used"]]
    by_tier = Counter(r["ai_tier"] or "none" for r in run.values())
    tri_cand = [r for r in run.values() if r["triage"]["candidate"]]
    tri_sel = [r for r in run.values() if r["triage"]["tier"] == "select"]
    tri_drop = [r for r in run.values() if r["triage"]["tier"] == "drop"]
    ai_used = [r for r in run.values() if r["agent_used"]]

    # ①层结案的原因（ClamAV 命中 / 可信签名 / 白名单）—— 逐类看得见
    closure_reasons = Counter()
    for r in closed_mal + closed_clean:
        for c in r["criteria"] or ["(无判据)"]:
            closure_reasons[c] += 1

    layers = {
        "layer1_closed": len(closed_mal) + len(closed_clean),
        "layer1_closed_rate": round((len(closed_mal) + len(closed_clean)) / n, 4) if n else None,
        "layer1_closed_malicious": len(closed_mal),
        "layer1_closed_clean": len(closed_clean),
        "layer1_closure_reasons": dict(closure_reasons.most_common()),
        "layer2_candidates": len(tri_cand),
        "layer2_selected": len(tri_sel),
        "layer2_dropped": len(tri_drop),
        "layer2_no_score": sum(1 for r in tri_cand if r["triage"]["score"] is None),
        "layer2_send_rate": round(len(tri_sel) / n, 4) if n else None,
        "layer3_files": len(ai_used),
        "layer3_malicious": sum(1 for r in ai_used if r["risk"] == "malicious"),
        "layer3_suspicious": sum(1 for r in ai_used if r["risk"] == "suspicious"),
        "layer3_clean": sum(1 for r in ai_used if r["risk"] == "clean"),
        "unresolved_pass": sum(1 for r in run.values() if _route(r) == "未结案·静默放行"),
    }

    send = {
        "files": len(sent),
        "rate": round(len(sent) / n, 4) if n else None,
        "denominator": n,
        "by_tier": dict(by_tier),
        "high": by_tier.get("high", 0),
        "low": by_tier.get("low", 0),
        "triage": by_tier.get("triage", 0),
        "note": ("送审率 = 进了 ③ 的文件 / 该批文件总数（**花钱的比例**，不是冤枉的比例）。"
                 "口径 = `sends_to_ai` 或真跑过 AI。"),
    }

    triage = {
        "entry_gate": extra.get("triage_entry_gate"),
        "threshold": extra.get("triage_threshold"),
        "candidates": len(tri_cand),
        "selected": len(tri_sel),
        "dropped": len(tri_drop),
        "no_score": sum(1 for r in tri_cand if r["triage"]["score"] is None),
        "selected_clean": sum(1 for r in tri_sel if r["risk"] == "clean"),
        "selected_flag": sum(1 for r in tri_sel if r["risk"] in FLAG),
        "selected_malicious_hits": sum(1 for r in tri_sel if r["label"] == "malicious"
                                       and r["risk"] in FLAG),
        "selected_malicious_total": sum(1 for r in tri_sel if r["label"] == "malicious"),
        "recall_on_candidates": (round(sum(1 for r in tri_cand if r["triage"]["tier"] == "select")
                                       / len(tri_cand), 4) if tri_cand else None),
        "score_distribution": {
            lab: {
                "n": len([r for r in tri_cand if r["label"] == lab and r["triage"]["score"] is not None]),
                "min": min([r["triage"]["score"] for r in tri_cand
                            if r["label"] == lab and r["triage"]["score"] is not None], default=None),
                "median": _median([r["triage"]["score"] for r in tri_cand
                                   if r["label"] == lab and r["triage"]["score"] is not None]),
                "max": max([r["triage"]["score"] for r in tri_cand
                            if r["label"] == lab and r["triage"]["score"] is not None], default=None),
            } for lab in ("malicious", "clean")},
        "model": next((r["triage"]["model"] for r in tri_cand if r["triage"]["model"]), ""),
        "rows": sorted([{
            "name": r["name"], "type": r["type"], "label": r["label"],
            "prefilter_score": r["score"], "triage_score": r["triage"]["score"],
            "tier": r["triage"]["tier"], "risk": r["risk"],
            "confidence": r["confidence"], "reason": r["triage"]["reason"][:160],
        } for r in tri_cand], key=lambda x: -(x["triage_score"] or 0)),
    }

    # ---- 成本（分②③两层报；每文件成本只在混合批次里报）----
    tri_tokens = sum(r["triage"]["tokens"] for r in run.values())
    ai_tokens = sum(r["ai_tokens"] for r in ai_used)
    price = extra.get("cny_per_million")
    cost = {
        "layer2_triage_tokens": tri_tokens,
        "layer2_triage_files_ran": len(tri_cand),
        "layer2_triage_tokens_per_file_ran": (round(tri_tokens / len(tri_cand), 1)
                                              if tri_cand else None),
        "layer3_deep_ai_tokens": ai_tokens,
        "layer3_deep_ai_files": len(ai_used),
        "layer3_deep_ai_tokens_per_file": (round(ai_tokens / len(ai_used), 1)
                                           if ai_used else None),
        "total_tokens": tri_tokens + ai_tokens,
        "tokens_per_file_whole_batch": round((tri_tokens + ai_tokens) / n, 1) if n else None,
        "cny_per_million": price,
        "layer2_triage_cny": round(tri_tokens * price / 1e6, 4) if price else None,
        "layer3_deep_ai_cny": round(ai_tokens * price / 1e6, 4) if price else None,
        "total_cny": round((tri_tokens + ai_tokens) * price / 1e6, 4) if price else None,
        "per_file_note": ("`tokens_per_file_whole_batch` 只在**混合批次**里读作生产成本"
                          "（生产上 97% 是良性，初筛的 token 基本花在良性上）；"
                          "全恶意批次这个数没有生产含义，别引用。"),
    }

    # ---- 核验（铁律：失败 / 降级不为 0 则该批作废）----
    verification = {
        "triage_batch_summary": extra.get("triage_batch"),
        "triage_failed": sum(1 for r in tri_cand if r["triage"]["score"] is None),
        "triage_errors": sorted({r["triage"]["error"] for r in run.values()
                                 if r["triage"]["error"]}),
        "triage_usage_source": dict(Counter(r["triage"]["usage_source"] for r in tri_cand)),
        "ai_degraded": sum(1 for r in run.values() if r["degraded"]),
        "ai_degraded_names": sorted(r["name"] for r in run.values() if r["degraded"]),
        "scan_errors": sum(1 for r in run.values() if r["error"]),
        "unclassified_signals": sum(1 for r in run.values() if r["unclassified"]),
        "clamav_unavailable": sum(1 for r in run.values()
                                  if not (r["clamav"] or {}).get("available")),
        "clamav_batch_errors": sum(1 for r in run.values() if (r["clamav"] or {}).get("error")),
        "clamav_hits": sum(1 for r in run.values() if (r["clamav"] or {}).get("infected")),
        "clamav_scan_summary": extra.get("clamav_batch"),
    }
    verification["batch_usable"] = (
        verification["triage_failed"] == 0
        and verification["ai_degraded"] == 0
        and verification["scan_errors"] == 0
        and verification["unclassified_signals"] == 0
        and verification["clamav_unavailable"] == 0
        and verification["clamav_batch_errors"] == 0
    )

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
        "final": final,
        "routes": dict(routes.most_common()),
        "send": send,
        "layers": layers,
        "triage": triage,
        "by_type": _by_type(run, None),
        "cost": cost,
        "verification": verification,
        "timing": timing,
    }


def _median(xs: list[int]) -> float | None:
    if not xs:
        return None
    ys = sorted(xs)
    m = len(ys) // 2
    return float(ys[m]) if len(ys) % 2 else (ys[m - 1] + ys[m]) / 2


def main() -> None:
    ap = argparse.ArgumentParser(description="一批一产物的批次汇总（只读产物）")
    ap.add_argument("--batch-id", required=True, help="批次名（写进产物，防止混表）")
    ap.add_argument("--batch-title", default="")
    ap.add_argument("--labels", required=True, help="文件名 → clean/malicious")
    ap.add_argument("--types", help="文件名 → 类别（可选；按扩展名目录分组时用）")
    ap.add_argument("--run", nargs="+", required=True, help="主臂（可给两遍比一致率）")
    ap.add_argument("--baseline", help="对照臂：**同一批**无 LLM 初筛那一轮（可选）")
    ap.add_argument("--baseline-label", default="无 LLM 初筛（同批对照）")
    ap.add_argument("--wall", help="runlog.tsv（臂名 \\t 墙钟 \\t rc \\t 参数）")
    ap.add_argument("--entry-gate", type=int, default=125)
    ap.add_argument("--triage-threshold", type=int, default=60)
    ap.add_argument("--gate", type=int, default=200)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    from aiav.budget import CNY_PER_MILLION_TOKENS

    labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    types = json.loads(Path(args.types).read_text(encoding="utf-8")) if args.types else {}
    runs = [_rows(_load(p), labels, types) for p in args.run]
    baseline = _rows(_load(args.baseline), labels, types) if args.baseline else None

    walls: dict[str, int] = {}
    config = None
    if args.wall and Path(args.wall).exists():
        lines = Path(args.wall).read_text(encoding="utf-8").splitlines()
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 2:
                try:
                    walls[parts[0]] = int(parts[1])
                except ValueError:
                    pass
        if lines and len(lines[0].split("\t")) >= 4:
            config = lines[0].split("\t")[3]

    # 批次级的 ClamAV / 初筛总账（从产物的 aggregate 里读，不重算）
    def _aggregate(pattern: str) -> dict[str, Any]:
        """批次级总账：ClamAV 批量预扫 + 初筛批量（从产物里读，不重算）。"""
        rep = _load(pattern)
        agg = rep.get("aggregate") or {}
        det = agg.get("deterministic") or {}
        tri = rep.get("triage") if isinstance(rep.get("triage"), dict) else {}
        if not tri:
            tri = (det.get("triage") or {}).get("batch") or {}
        clam = rep.get("clamav_batch") or agg.get("clamav_batch") or {}
        if not clam:
            rows = rep.get("reports") or []
            clam = {
                "available": sum(1 for r in rows
                                 if (r.get("clamav") or {}).get("available")),
                "infected": sum(1 for r in rows if (r.get("clamav") or {}).get("infected")),
                "errors": sum(1 for r in rows if (r.get("clamav") or {}).get("error")),
                "scanned": len(rows),
                "note": "批次级对象没落在产物里，这里由逐文件行汇总（available/infected/errors）",
            }
        return {"clamav_batch": clam, "triage_batch": tri or None}

    base_extra = {
        "cny_per_million": CNY_PER_MILLION_TOKENS,
        "triage_entry_gate": args.entry_gate,
        "triage_threshold": args.triage_threshold,
        "gate": args.gate,
    }
    run_blocks = []
    for i, (pattern, rows) in enumerate(zip(args.run, runs)):
        agg = _aggregate(pattern)
        run_blocks.append({
            "arm": f"r{i + 1}",
            "wall_s": walls.get(f"r{i + 1}"),
            **measure(rows, labels, types, {**base_extra, **agg,
                                            "wall_s": walls.get(f"r{i + 1}")}),
        })

    out: dict[str, Any] = {
        "generated_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        "batch_id": args.batch_id,
        "batch_title": args.batch_title,
        "discipline": ("一批一产物；每个数字都带批次；分母写清；**不做跨批合并指标**"
                       "（没有「总召回」「总送审率」这种数）"),
        "config": config,
        "price_note": ("¥/百万 token 取项目常量（`budget.CNY_PER_MILLION_TOKENS` = 8.0，"
                       "偏高的一档 = 上界）；初筛与深度 AI 同一单价。"),
        "composition": {
            "files": len(labels),
            "malicious": sum(1 for v in labels.values() if v == "malicious"),
            "benign": sum(1 for v in labels.values() if v == "clean"),
            "kind": ("纯恶意" if all(v == "malicious" for v in labels.values())
                     else "纯良性" if all(v == "clean" for v in labels.values()) else "混合"),
            "types": dict(Counter(types.values())) if types else {},
        },
        "arms": list(walls),
        "wall_s": walls,
        "runs": run_blocks,
    }
    if len(runs) == 2:
        a, b = runs
        route_same = sum(1 for nm in a if _route(a[nm]) == _route(b[nm]))
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
            "verdict_diff": sorted(nm for nm in a if a[nm]["risk"] != b[nm]["risk"]),
            "triage_score_diff": sorted(nm for nm in a
                                        if a[nm]["triage"]["score"] != b[nm]["triage"]["score"]),
        }
    if baseline is not None:
        out["baseline"] = {
            "label": args.baseline_label,
            "wall_s": walls.get("base1"),
            **measure(baseline, labels, types,
                      {**base_extra, "wall_s": walls.get("base1")}),
        }
        out["baseline"]["note"] = ("**同一批语料**的对照臂（无 LLM 初筛、单档 200）。"
                                   "只报绝对值，**不写「快 N 倍 / 省 N%」这种自比**。")

    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    head = out["runs"][0]
    print(json.dumps({
        "out": args.out,
        "batch": args.batch_id,
        "composition": out["composition"],
        "r1_final": head["final"],
        "r1_layers": head["layers"],
        "r1_triage": {k: v for k, v in head["triage"].items() if k != "rows"},
        "r1_send": head["send"],
        "r1_cost": head["cost"],
        "r1_verification": {k: v for k, v in head["verification"].items()
                            if k not in ("triage_errors",)},
        "consistency": out.get("consistency"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
