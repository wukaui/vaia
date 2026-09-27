#!/usr/bin/env python3
"""两档送审实测 · 汇总（2026-09-27）。

读 `aiav scan` 的 JSON 产物（可选：两档臂 + 基线臂 + 第二遍），算出交付要的那几个数：

  1. **送审率**：高档（`ai_tier=high`）/ 低档（`low`）分开数，再给总数与占比；
  2. **召回**（①层口径，与报告里一致）=（确定性判恶意 + 送审里被判 flag 的）/ 恶意总数；
  3. **误报**：良性里被判 malicious 的、被判 suspicious 的，分开数（0/200 是哪种口径要说清）；
  4. **成本**：这一轮的 token 总量，以及**低档那一档自己花的 token**（增量 = 低档 token）；
  5. **低档逐文件**：抓到的恶意（名字 + ①层判据 + AI 结论/置信度）与那批良性（AI 判了什么）；
  6. **核验**：ClamAV 是否真跑（available/error/未报行）、模型是否真被调用（降级/重试/error）、
     判据表未分类信号数 —— 按核验铁律，这几项不为 0 该批作废；
  7. **两遍一致率**：同一配置跑两次，逐文件判定一致率（路由一致 + 结论一致）。

用法：
    .venv/bin/python scripts/two_tier_measure.py \
        --labels ~/ai-av-bench/dike-bench/labels.json \
        --baseline /tmp/two-tier/a1/scan_*.json \
        --two-tier /tmp/two-tier/b1/scan_*.json /tmp/two-tier/b2/scan_*.json \
        --out bench/two-tier-dike400.json
"""
from __future__ import annotations

import argparse
import glob
import json
from collections import Counter
from pathlib import Path
from typing import Any

FLAG = ("malicious", "suspicious")


def _load_report(pattern: str) -> dict[str, Any]:
    """接受**通配符**（一轮跑出来带时间戳的文件名），自己挑 JSON 主产物（不是 audit）。"""
    paths = sorted(glob.glob(pattern))
    paths = [p for p in paths if not p.endswith(".audit.json")]
    if not paths:
        raise SystemExit(f"找不到扫描产物: {pattern}")
    return json.loads(Path(paths[-1]).read_text(encoding="utf-8"))


def _rows(report: dict[str, Any], labels: dict[str, str]) -> list[dict[str, Any]]:
    out = []
    for r in report.get("reports") or []:
        name = Path(r["path"]).name
        # holdout 那一轮（`two_tier_holdout_scan.py`）的标签按**目录**写进产物 `_label`；
        # 主实测那一轮用 labels.json（文件名 → 标签）。两边都认，口径一致。
        label = r.get("_label") or labels.get(name, "unknown")
        det = r.get("deterministic") or {}
        tier = det.get("ai_tier")
        if tier not in ("high", "low", "none"):
            tier = ("high" if (det.get("disposition") == "send_ai" or r.get("agent_used"))
                    else "none")
        verdict = r.get("verdict") or {}
        out.append({
            "name": name,
            "sha256": r.get("sha256", ""),
            "score": int(r.get("prefilter_score") or 0),
            "label": label,
            "tier": tier,
            "disposition": det.get("disposition"),
            "gate": det.get("gate"),
            "gate_low": det.get("gate_low"),
            "agent_used": bool(r.get("agent_used")),
            "risk": verdict.get("risk"),
            "confidence": verdict.get("confidence"),
            "category": verdict.get("category"),
            "summary": (verdict.get("summary") or "")[:160],
            "criteria": [h.get("heur_id") for h in (r.get("criteria_hits") or [])],
            "tokens": int((r.get("agent_usage") or {}).get("tokens") or 0),
            "degraded": (r.get("agent_retry") or {}).get("outcome") == "degraded_to_rules",
            "error": r.get("error") or "",
            "unclassified": list(r.get("unclassified_signals") or []),
            "clamav": r.get("clamav") or {},
        })
    return out


def measure(rows: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(rows)
    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "clean"]
    tiers = Counter(r["tier"] for r in rows)
    sent = [r for r in rows if r["tier"] in ("high", "low")]
    high = [r for r in rows if r["tier"] == "high"]
    low = [r for r in rows if r["tier"] == "low"]
    closed_mal = [r for r in rows if r["disposition"] == "closed_malicious"]
    closed_clean = [r for r in rows if r["disposition"] == "closed_clean"]

    def flagged(group: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [r for r in group if r["risk"] in FLAG]

    # 召回（①层口径，与本项目报告的算法一致）：确定性判恶意 + 送审后被判 flag
    recall_hits = [r for r in closed_mal if r["label"] == "malicious"] + flagged(sent)
    recall = len([r for r in recall_hits if r["label"] == "malicious"]) / max(1, len(mal))
    # 召回（AI 口径）：只看 AI **真的下了结论**的文件（排除降级到规则的那些）
    ai_sent = [r for r in sent if r["agent_used"] and not r["degraded"]]
    recall_ai_hits = ([r for r in closed_mal if r["label"] == "malicious"]
                      + [r for r in ai_sent if r["risk"] in FLAG])
    recall_ai = (len([r for r in recall_ai_hits if r["label"] == "malicious"])
                 / max(1, len(mal)))

    fp_mal = [r for r in flagged(ben) if r["risk"] == "malicious"]
    fp_sus = [r for r in flagged(ben) if r["risk"] == "suspicious"]

    low_conf = [float(r["confidence"]) for r in low
                if r["agent_used"] and r["confidence"] is not None]

    return {
        "n": n,
        "malicious_total": len(mal),
        "benign_total": len(ben),
        "send": {
            "sent": len(sent), "send_rate": round(len(sent) / n, 4) if n else 0.0,
            "high": len(high), "low": len(low),
            "high_malicious": len([r for r in high if r["label"] == "malicious"]),
            "high_benign": len([r for r in high if r["label"] == "clean"]),
            "low_malicious": len([r for r in low if r["label"] == "malicious"]),
            "low_benign": len([r for r in low if r["label"] == "clean"]),
            "silent": tiers.get("none", 0),
            "benign_send_rate": (round(len([r for r in sent if r["label"] == "clean"]) / len(ben), 4)
                                 if ben else None),
        },
        "recall": {
            "rule_and_ai": round(recall, 4),
            "ai_only": round(recall_ai, 4),
            "closed_malicious": len([r for r in closed_mal if r["label"] == "malicious"]),
            "ai_flagged_malicious": len([r for r in sent if r["label"] == "malicious"
                                         and r["risk"] in FLAG]),
            "missed_malicious": sorted([(r["score"], r["name"]) for r in mal
                                        if r not in recall_hits]),
        },
        "false_positive": {
            "benign_flagged_malicious": len(fp_mal),
            "benign_flagged_suspicious": len(fp_sus),
            "detail": [{"name": r["name"], "score": r["score"], "risk": r["risk"],
                        "confidence": r["confidence"], "category": r["category"],
                        "summary": r["summary"], "tier": r["tier"]} for r in fp_mal + fp_sus],
        },
        "cost": {
            "tokens_total": sum(r["tokens"] for r in rows),
            "tokens_ai_files": sum(r["tokens"] for r in sent),
            "tokens_high": sum(r["tokens"] for r in high),
            "tokens_low": sum(r["tokens"] for r in low),
            "ai_files": len([r for r in sent if r["agent_used"]]),
            "tokens_per_ai_file": (round(sum(r["tokens"] for r in sent if r["agent_used"])
                                         / max(1, len(ai_sent)), 1)),
            "per_low_file": [{"name": r["name"], "score": r["score"], "label": r["label"],
                              "tokens": r["tokens"], "risk": r["risk"],
                              "confidence": r["confidence"]} for r in low],
        },
        "low_tier_files": [
            {"name": r["name"], "score": r["score"], "label": r["label"],
             "criteria": r["criteria"], "risk": r["risk"], "confidence": r["confidence"],
             "category": r["category"], "summary": r["summary"], "degraded": r["degraded"]}
            for r in low
        ],
        "low_tier_confidence": {
            "n": len(low_conf),
            "mean": round(sum(low_conf) / len(low_conf), 3) if low_conf else None,
            "min": min(low_conf) if low_conf else None,
            "max": max(low_conf) if low_conf else None,
        },
        "closed": {
            "closed_malicious": len(closed_mal), "closed_clean": len(closed_clean),
            "pass": len([r for r in rows if r["disposition"] == "pass"]),
        },
        # ---- 核验铁律：这几项不为 0 就该批作废 ----
        "verification": {
            "files": n,
            "errors": len([r for r in rows if r["error"]]),
            "degraded_to_rules": len([r for r in rows if r["degraded"]]),
            "files_with_unclassified_signals": len([r for r in rows if r["unclassified"]]),
            "clamav_available": len([r for r in rows if (r["clamav"] or {}).get("available")]),
            "clamav_error": len([r for r in rows if (r["clamav"] or {}).get("error")]),
            "clamav_infected": len([r for r in rows if (r["clamav"] or {}).get("infected")]),
            "ai_files": len([r for r in rows if r["agent_used"]]),
            "ai_files_with_tokens": len([r for r in rows if r["agent_used"] and r["tokens"] > 0]),
        },
    }


def consistency(a: list[dict[str, Any]], b: list[dict[str, Any]]) -> dict[str, Any]:
    """两遍一致率（同一配置跑两次）：路由一致 + 结论一致。"""
    by_a = {r["sha256"]: r for r in a}
    by_b = {r["sha256"]: r for r in b}
    common = sorted(set(by_a) & set(by_b))
    tier_same = [s for s in common if by_a[s]["tier"] == by_b[s]["tier"]]
    both_sent = [s for s in common if by_a[s]["tier"] in ("high", "low")
                 and by_b[s]["tier"] in ("high", "low")]
    verdict_same = [s for s in both_sent if by_a[s]["risk"] == by_b[s]["risk"]]
    flag_same = [s for s in both_sent
                 if (by_a[s]["risk"] in FLAG) == (by_b[s]["risk"] in FLAG)]
    mismatched = [{"name": by_a[s]["name"], "label": by_a[s]["label"],
                   "score": by_a[s]["score"], "tier": by_a[s]["tier"],
                   "pass1": by_a[s]["risk"], "pass2": by_b[s]["risk"]}
                  for s in both_sent if by_a[s]["risk"] != by_b[s]["risk"]]
    return {
        "common_files": len(common),
        "routing_agreement": round(len(tier_same) / max(1, len(common)), 4),
        "sent_in_both": len(both_sent),
        "verdict_agreement": round(len(verdict_same) / max(1, len(both_sent)), 4),
        "flag_agreement": round(len(flag_same) / max(1, len(both_sent)), 4),
        "verdict_mismatches": mismatched,
    }


def _by_source(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """holdout 规则档：按语料来源（mb-* / benign-win）分别数三个档。"""
    out: dict[str, Any] = {}
    for r in rows:
        # 语料来源按**标签**分（holdout 就两批：mb-* 全恶意 / benign-win 全良性）
        src = "mb" if r["label"] == "malicious" else "benign-win"
        row = out.setdefault(src, {"n": 0, "label": r["label"],
                                   "tiers": {"high": 0, "low": 0, "none": 0},
                                   "closed": {"closed_malicious": 0, "closed_clean": 0,
                                              "pass": 0}})
        row["n"] += 1
        row["tiers"][r["tier"]] += 1
        row["closed"][r["disposition"]] = row["closed"].get(r["disposition"], 0) + 1
    for src, row in out.items():
        n = row["n"] or 1
        row["send_rate_before"] = round(row["tiers"]["high"] / n, 4)
        row["send_rate_after"] = round((row["tiers"]["high"] + row["tiers"]["low"]) / n, 4)
    return out


def _by_extension(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """holdout AI 臂：按扩展名数"判 flag 的比例"（低档的短板在哪一类文件上一眼可见）。"""
    out: dict[str, Any] = {}
    for r in rows:
        ext = Path(r["name"]).suffix.lower() or "(none)"
        row = out.setdefault(ext, {k: {"n": 0, "flag": 0} for k in ("clean", "malicious")})
        row[r["label"]]["n"] += 1
        row[r["label"]]["flag"] += int(r["risk"] in FLAG)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="两档送审实测汇总")
    ap.add_argument("--labels", required=True, help="{文件名: clean|malicious} 的 JSON")
    ap.add_argument("--baseline", default="", help="基线臂（单档 ≥300）的扫描 JSON（可用通配符）")
    ap.add_argument("--two-tier", nargs="*", default=[], help="两档臂的扫描 JSON（第 1/2 遍）")
    ap.add_argument("--holdout-rules", default="", help="holdout 规则档产物（`two_tier_holdout_scan.py`）")
    ap.add_argument("--holdout-ai", default="", help="holdout 低档那一批真跑 AI 的产物")
    ap.add_argument("--holdout-labels", default="", help="holdout AI 臂的标签（文件名 → 标签）")
    ap.add_argument("--out", default="", help="汇总产物写到这里（JSON）")
    args = ap.parse_args()

    labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    result: dict[str, Any] = {"labels": str(Path(args.labels).resolve())}

    if args.baseline:
        base = _load_report(args.baseline)
        rows = _rows(base, labels)
        result["baseline"] = measure(rows)
        result["baseline"]["generated_at"] = base.get("generated_at")

    arms = []
    for pattern in args.two_tier:
        rep = _load_report(pattern)
        rows = _rows(rep, labels)
        arms.append({"generated_at": rep.get("generated_at"), "rows": rows,
                     "metrics": measure(rows), "gate": rows[0]["gate"] if rows else None,
                     "gate_low": rows[0]["gate_low"] if rows else None})
    if arms:
        result["two_tier"] = arms[0]["metrics"]
        result["two_tier"]["generated_at"] = arms[0]["generated_at"]
        result["two_tier"]["gate"] = arms[0]["gate"]
        result["two_tier"]["gate_low"] = arms[0]["gate_low"]
        if len(arms) > 1:
            result["consistency"] = consistency(arms[0]["rows"], arms[1]["rows"])
        # 基线臂的 AI 结论与两档臂里**同一批高档文件**逐文件对照（闸门是同一个）
        if args.baseline and arms:
            b_rows = _rows(_load_report(args.baseline), labels)
            result["high_tier_cross_arm"] = consistency(b_rows, arms[0]["rows"])

    # ---- holdout：规则档回答"多送多少"，AI 臂回答"送进去之后抓没抓到" ----
    if args.holdout_rules:
        h_rows = _rows(_load_report(args.holdout_rules), labels)
        result["holdout_rules"] = measure(h_rows)
        result["holdout_rules"]["by_source"] = _by_source(h_rows)
    if args.holdout_ai:
        h_labels = (json.loads(Path(args.holdout_labels).read_text(encoding="utf-8"))
                    if args.holdout_labels else labels)
        h_labels = {Path(k).name: v for k, v in h_labels.items()}
        ai_rows = _rows(_load_report(args.holdout_ai), h_labels)
        result["holdout_ai"] = measure(ai_rows)
        result["holdout_ai"]["by_extension"] = _by_extension(ai_rows)
        result["holdout_ai"]["degraded_files"] = [
            {"name": r["name"], "label": r["label"], "risk": r["risk"], "error": r["error"][:200]}
            for r in ai_rows if r["degraded"] or r["error"]
        ]

    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"写到 {args.out}")
    print(text)


if __name__ == "__main__":
    main()
