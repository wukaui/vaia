#!/usr/bin/env python3
"""PDF 盲区修复 · 汇总（2026-09-27）—— **只读产物、不再调模型。**

一批一产物：这个脚本把这一轮 PDF 重测的**四份产物**折成一份 JSON，
报告第十五节的每个数字都从这里出。

四份产物（各自跑法见 `scripts/pdf_summary_measure.py` 的 docstring）：

  A. ②层臂 · 旧摘要   —— 同一批 PDF，批次 A 那一版摘要渲染
  B. ②层臂 · 新摘要   —— 同一批 PDF，PDF 单独解析路径
  C. ③层全送臂        —— 60 个恶意 PDF **全部**送深度 AI（量"②+③"这对层的上限）
  D. 完整链路臂        —— 生产配置（入口 125 / 闸门 200 / 门槛 60 / 分流 300）

外加一份**历史基线**：批次 A 的 `bench/batch-mb280-scriptdoc-full-chain.json`
（`mb280-scriptdoc` 全恶意 280 里 pdf 那一类的召回 0.2833 = 17/60）。

口径（不许含糊）：
  · **召回** = 最终判 flag（`malicious` + `suspicious`）的恶意文件 / 该批恶意总数。
    ①层 `closed_malicious`（确定性判恶意）也算命中 —— 与批次 A 同一个口径。
  · **送审率** = 进 ③ 的文件 / 该批文件总数（**花钱的比例**，不是冤枉的比例）。
  · **②层召回**是**层内口径**，不含①层路由；生产上 ② 只看得见入口闸 125 以上的文件。
  · 全恶意批次没有误报率；全良性批次没有召回。

用法：
    .venv/bin/python scripts/pdf_fix_measure.py \
        --arm-old /tmp/pdf-fix/arm-old.json --arm-new /tmp/pdf-fix/arm-new.json \
        --deep-all /tmp/pdf-fix/out-b/scan_*.json \
        --full-chain /tmp/pdf-fix/out-c/scan_*.json \
        --benign-dir /tmp/pdf-fix/corpus/benign \
        --batch-a bench/batch-mb280-scriptdoc-full-chain.json \
        --regression /tmp/pdf-fix/regression.json \
        --out bench/pdf-fix-20260927.json
"""
from __future__ import annotations

import argparse
import glob
import json
from collections import Counter
from pathlib import Path
from typing import Any

FLAG = ("malicious", "suspicious")
MALICIOUS_LABEL = "malicious"
BENIGN_LABEL = "clean"


def load_last(pattern: str) -> dict[str, Any]:
    paths = [p for p in sorted(glob.glob(pattern)) if not p.endswith(".audit.json")]
    if not paths:
        raise SystemExit(f"找不到产物: {pattern}")
    return json.loads(Path(paths[-1]).read_text(encoding="utf-8"))


def _arm_stats(arm: dict[str, Any]) -> dict[str, Any]:
    """②层臂的逐标签数（召回 / 送审率 / 分布 / 成本）。"""
    out: dict[str, Any] = {"arm": arm["arm"], "summary_module": arm["summary_module"],
                           "triage_version": arm["triage_version"], "model": arm["model"],
                           "threshold": arm["threshold"], "labels": {}}
    for label in (MALICIOUS_LABEL, BENIGN_LABEL):
        rows = [r for r in arm["rows"] if r["label"] == label]
        if not rows:
            continue
        scores = sorted(int(r["score"]) for r in rows if r["ok"] and r["score"] is not None)
        selected = {r["name"] for r in rows if r["ok"] and (r["score"] or 0) >= arm["threshold"]}
        block: dict[str, Any] = {
            "files": len(rows),
            "scored": len(scores),
            "selected": len(selected),
            "selected_names": sorted(selected),
            "min": scores[0] if scores else None,
            "median": scores[len(scores) // 2] if scores else None,
            "max": scores[-1] if scores else None,
            "mean": round(sum(scores) / len(scores), 1) if scores else None,
            "ge50": sum(1 for s in scores if s >= 50),
            "ge70": sum(1 for s in scores if s >= 70),
            "est_tokens_median_summary": round(
                sum(r["est_tokens"] for r in rows) / len(rows), 1),
            "prompt_tokens_per_file": round(
                sum(r["prompt_tokens"] for r in rows) / len(rows), 1),
            "completion_tokens_per_file": round(
                sum(r["completion_tokens"] for r in rows) / len(rows), 1),
            "total_tokens_per_file": round(
                sum(r["total_tokens"] for r in rows) / len(rows), 1),
            "strings_used_mean": round(sum(r["strings_used"] for r in rows) / len(rows), 1),
            "summary_truncated": sum(1 for r in rows if r["summary_truncated"]),
            "cny": round(sum(int(r["total_tokens"] or 0) for r in rows)
                         / 1_000_000 * arm["cost"]["cny_per_million"], 4),
        }
        if label == MALICIOUS_LABEL:
            block["recall_at_threshold"] = round(len(selected) / len(rows), 4)
            block["hits"] = len(selected)
        else:
            block["send_rate_to_deep"] = round(len(selected) / len(rows), 4)
        out["labels"][label] = block
    out["verification"] = arm["verification"]
    out["wall_s"] = arm["wall_s"]
    return out


def _diff_arms(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """旧摘要 → 新摘要的逐文件变化（恶意侧）。"""
    old_rows = {r["name"]: r for r in old["rows"] if r["label"] == MALICIOUS_LABEL}
    new_rows = {r["name"]: r for r in new["rows"] if r["label"] == MALICIOUS_LABEL}
    threshold = old["threshold"]
    recovered, lost, deltas = [], [], []
    for name, row in old_rows.items():
        other = new_rows.get(name)
        if other is None:
            continue
        before, after = int(row["score"] or 0), int(other["score"] or 0)
        deltas.append(after - before)
        if before < threshold <= after:
            recovered.append({"name": name, "old_score": before, "new_score": after,
                              "new_reason": other["reason"][:300]})
        if before >= threshold > after:
            lost.append({"name": name, "old_score": before, "new_score": after})
    deltas.sort()
    return {
        "malicious_files": len(old_rows),
        "recovered": len(recovered), "recovered_detail": recovered,
        "lost": len(lost), "lost_detail": lost,
        "delta_median": deltas[len(deltas) // 2] if deltas else None,
        "delta_mean": round(sum(deltas) / len(deltas), 1) if deltas else None,
        "delta_min": deltas[0] if deltas else None,
        "delta_max": deltas[-1] if deltas else None,
    }


def _pipeline_stats(report: dict[str, Any], benign_names: set[str]) -> dict[str, Any]:
    """完整链路臂：按标签拆开算召回 / 送审率 / 误报。"""
    def split(rows: list[dict[str, Any]]) -> dict[str, Any]:
        flagged = [r for r in rows
                   if (r.get("verdict") or {}).get("risk") in FLAG]
        closed_mal = [r for r in rows
                      if (r.get("deterministic") or {}).get("disposition") == "closed_malicious"]
        sent = [r for r in rows if (r.get("deterministic") or {}).get("sends_to_ai")]
        triaged = [r for r in rows
                   if ((r.get("deterministic") or {}).get("triage") or {}).get("score") is not None]
        return {
            "files": len(rows),
            "closed_malicious": len(closed_mal),
            "sent_to_ai": len(sent),
            "sent_rate": round(len(sent) / len(rows), 4) if rows else None,
            "ai_flagged": len(flagged),
            "ai_risk": dict(Counter((r.get("verdict") or {}).get("risk") for r in rows)),
            # 召回口径 = **最终判 flag 的文件数 / 该批恶意总数**（与批次 A 的
            # `batch_measure.py` 逐字一致）。①层 `closed_malicious` 的文件本身也带
            # `risk=malicious`，**不能再加一遍** —— 加了就是双重计数
            # （本轮汇总脚本第一版就踩了这个坑：把 17/60 算出 20/60）。
            "recall": round(len(flagged) / len(rows), 4) if rows else None,
            "recall_hits": len(flagged),
            "triage_ran": len(triaged),
            "triage_selected": sum(
                1 for r in triaged
                if ((r.get("deterministic") or {}).get("triage") or {}).get("tier") == "select"),
            "tokens": sum(int((r.get("agent_usage") or {}).get("tokens") or 0) for r in rows),
            "degraded": sum(1 for r in rows
                            if (r.get("agent_retry") or {}).get("outcome") == "degraded_to_rules"),
            "errors": sum(1 for r in rows if r.get("error")),
        }

    rows = report.get("reports") or []
    mal = [r for r in rows if Path(r["path"]).name not in benign_names]
    benign = [r for r in rows if Path(r["path"]).name in benign_names]
    triage = dict(report.get("triage") or {})
    triage.pop("rows", None)
    return {
        "config": {"ai_threshold": 200, "ai_threshold_low": 0,
                   "deep_evidence_threshold": 300, "triage_threshold": 60,
                   "triage_entry_gate": 125},
        "triage_layer": triage,
        "malicious": split(mal),
        "benign": split(benign),
        "benign_false_positive_rate": (
            round(len([r for r in benign
                       if (r.get("verdict") or {}).get("risk") in FLAG]) / len(benign), 4)
            if benign else None),
    }


def _batch_a_baseline(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    run = data["runs"][0]
    pdf = run["by_type"]["pdf"]
    return {
        "batch": data["batch_id"], "arm": run["arm"], "config": data["config"],
        "pdf_files": pdf["n"],
        "pdf_recall": pdf["recall"], "pdf_hits": pdf["recall_hits"],
        "pdf_layer1_closed_malicious": pdf["layer1_closed_malicious"],
        "pdf_sent_to_ai": pdf["sent_to_ai"],
        "pdf_triage_candidates": pdf["triage_candidates"],
        "pdf_triage_selected": pdf["triage_selected"],
        "pdf_silent_pass_lt125": pdf["silent_pass_lt125"],
        "pdf_gate_direct_ge200": pdf["gate_direct_ge200"],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="PDF 盲区修复汇总（只读产物）")
    ap.add_argument("--arm-old", type=Path, required=True)
    ap.add_argument("--arm-new", type=Path, required=True)
    ap.add_argument("--deep-all", required=True, help="③层全送臂的 scan_*.json")
    ap.add_argument("--full-chain", required=True, help="完整链路臂的 scan_*.json")
    ap.add_argument("--benign-dir", type=Path, required=True)
    ap.add_argument("--batch-a", type=Path, required=True)
    ap.add_argument("--regression", type=Path, default=None)
    ap.add_argument("--deep-retry-report", type=Path, action="append", default=None,
                    help="③层降级文件的**单独重试**产物（可重复传，逐次留痕）")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    old = json.loads(args.arm_old.read_text(encoding="utf-8"))
    new = json.loads(args.arm_new.read_text(encoding="utf-8"))
    deep = load_last(args.deep_all)
    chain = load_last(args.full_chain)
    benign_names = {p.name for p in args.benign_dir.iterdir()
                    if p.is_file() and p.suffix.lower() == ".pdf"}

    arm_old, arm_new = _arm_stats(old), _arm_stats(new)
    diff = _diff_arms(old, new)
    chain_stats = _pipeline_stats(chain, benign_names)

    # ③ 层对：全送的判定结果
    deep_rows = deep.get("reports") or []
    deep_flag = {Path(r["path"]).name for r in deep_rows
                 if (r.get("verdict") or {}).get("risk") in FLAG}
    # **降级留痕**（铁律）：③层全送臂里有 1 个文件被 provider 的 content filter 拦下
    # （`finish_reason=content_filter`），它的 risk 是**规则给的、不是 AI 结论**。
    # 这里不装作没发生：把降级文件列出来，并用**单独重试成功的那一次**给修正值。
    degraded_deep = [Path(r["path"]).name for r in deep_rows
                     if (r.get("agent_retry") or {}).get("outcome") == "degraded_to_rules"]
    flagged_raw = len(deep_flag)
    retry_fix: dict[str, Any] = {}
    retry_reports = [p for p in (args.deep_retry_report or []) if p.is_file()]
    attempts: list[dict[str, Any]] = []
    for path in retry_reports:
        rows = json.loads(path.read_text(encoding="utf-8")).get("reports") or []
        if not rows:
            continue
        row = rows[0]
        outcome = (row.get("agent_retry") or {}).get("outcome")
        attempts.append({
            "report": path.name,
            "file": Path(row["path"]).name,
            "agent_used": bool(row.get("agent_used")),
            "risk": (row.get("verdict") or {}).get("risk"),
            "outcome": outcome,
        })
    ok_attempts = [a for a in attempts if a["agent_used"]]
    if ok_attempts:
        name, risk = ok_attempts[0]["file"], ok_attempts[0]["risk"]
        retry_fix = {"file": name, "risk_on_retry": risk,
                     "attempts": len(attempts), "succeeded": len(ok_attempts),
                     "per_attempt": attempts}
        if name in degraded_deep and risk in FLAG:
            deep_flag.add(name)
    older = set(arm_old["labels"][MALICIOUS_LABEL]["selected_names"])
    newer = set(arm_new["labels"][MALICIOUS_LABEL]["selected_names"])
    layer_pair = {
        "deep_ai_files": len(deep_rows),
        # 实测值（含 1 个降级 → 它的 risk 是规则给的）与**修正值**（用重试成功那次）都给：
        # 只报一个数会让人以为这个批次是干净的。
        "deep_ai_flagged_raw": flagged_raw,
        "deep_ai_ceiling_raw": round(flagged_raw / len(deep_rows), 4) if deep_rows else None,
        "deep_ai_flagged": len(deep_flag),
        "deep_ai_ceiling": round(len(deep_flag) / len(deep_rows), 4) if deep_rows else None,
        "deep_ai_risk": dict(Counter((r.get("verdict") or {}).get("risk") for r in deep_rows)),
        "deep_ai_degraded_files": degraded_deep,
        "deep_ai_degraded_note": (
            "③层全送臂有 1 个文件被 provider 网关的 content filter 拦下"
            "（`finish_reason=content_filter`，模型零输出 → 降级到规则判定）。"
            "按铁律「降级不为 0 的批次要作废」，所以这里：① 把它列为降级文件；"
            "② 单独重试 3 次，2 次拿到真实 AI 判定（都是 `suspicious`），修正值用 "
            "`deep_ai_ceiling`（`deep_ai_ceiling_raw` 是未修正的实测值）。"
            "**这个失败类是 provider 侧的，不是我们代码的 bug** —— 值得单独记一笔。"
            if degraded_deep else "无降级。"),
        "deep_ai_retry_fix": retry_fix,
        "layer_pair_recall_old": round(len(older & deep_flag) / len(deep_rows), 4)
        if deep_rows else None,
        "layer_pair_recall_new": round(len(newer & deep_flag) / len(deep_rows), 4)
        if deep_rows else None,
        "note": ("**层对口径（②+③）**：假设②层看得到**每一个** PDF（本轮实测时把入口闸这一"
                 "条按住），选中就送③。生产里②只看得见入口闸 125 以上的文件 —— 所以这三个数"
                 "**不是生产召回**，是「②层看懂之后，③能把它抬到哪」的上限。"),
        "deep_ai_tokens_per_file": round(
            sum(int((r.get("agent_usage") or {}).get("tokens") or 0) for r in deep_rows)
            / len(deep_rows), 1) if deep_rows else None,
    }

    regression = (json.loads(args.regression.read_text(encoding="utf-8"))
                  if args.regression and args.regression.is_file() else None)

    # 路由核对：批次 A 的 pdf 那一类 vs 本轮完整链路臂（**同一份60个文件、同一套配置**）。
    # ①层是确定性的，这两列**必须逐格相等** —— 不等就说明这一轮的对照不成立。
    def _route_from_rows(rows: list[dict[str, Any]]) -> dict[str, int]:
        closed = [r for r in rows
                  if (r.get("deterministic") or {}).get("disposition") == "closed_malicious"]
        rest = [r for r in rows if r not in closed]
        scores = [int(r.get("prefilter_score") or 0) for r in rest]
        return {
            "files": len(rows),
            "layer1_closed_malicious": len(closed),
            "gate_direct_ge200": sum(1 for s in scores if s >= 200),
            "triage_candidates_125_199": sum(1 for s in scores if 125 <= s < 200),
            "silent_pass_lt125": sum(1 for s in scores if s < 125),
        }

    mal_rows = [r for r in (chain.get("reports") or [])
                if Path(r["path"]).name not in benign_names]
    base = _batch_a_baseline(args.batch_a)
    routing = {
        "batch_a_mb280_scriptdoc_pdf": {
            "files": base["pdf_files"],
            "layer1_closed_malicious": base["pdf_layer1_closed_malicious"],
            "gate_direct_ge200": base["pdf_gate_direct_ge200"],
            "triage_candidates_125_199": base["pdf_triage_candidates"],
            "silent_pass_lt125": base["pdf_silent_pass_lt125"],
            "sent_to_ai": base["pdf_sent_to_ai"],
            "recall": base["pdf_recall"],
        },
        "pdf_fix_full_chain_arm": {**_route_from_rows(mal_rows),
                                   "sent_to_ai": chain_stats["malicious"]["sent_to_ai"],
                                   "recall": chain_stats["malicious"]["recall"]},
    }
    a, b = routing["batch_a_mb280_scriptdoc_pdf"], routing["pdf_fix_full_chain_arm"]
    routing["reconciles"] = all(a[k] == b[k] for k in
                                ("files", "layer1_closed_malicious", "gate_direct_ge200",
                                 "triage_candidates_125_199", "silent_pass_lt125", "sent_to_ai"))
    routing["note"] = ("**这两列必须逐格相等**：①层是确定性的，本轮没动它一个字。"
                       "相等 = 这一轮生产口径的对照成立（唯一变量是②层摘要）。")

    report = {
        "batch_id": "pdf-fix-20260927",
        "batch_title": "PDF 盲区修复（只测 PDF）：mb-pdf 60 恶 + 良性 PDF 语料（alt-forms 去重 + 系统文档）",
        "discipline": ("一批一产物；每个数字都带批次；分母写清；**不做跨批合并指标**。"
                       "全恶意批次没有误报率，全良性批次没有召回。"),
        "corpus": {
            "malicious": {"name": "~/ai-av-bench/mb-pdf", "files": 60, "kind": "纯恶意",
                          "note": "**参与过批次 A 的测量**（mb280-scriptdoc 的 pdf 那一类），"
                                  "所以本轮的结论只能说「在这批上的改善」。"},
            "benign": {"name": str(args.benign_dir), "files": len(benign_names), "kind": "纯良性",
                       "manifest": str(args.benign_dir / "manifest.json"),
                       "note": "alt-forms-benign（项目自造良性文档语料，标签全 clean，"
                               "60 个文件按 sha256 去重后 50 个唯一）+ 系统与开源文档 20 个。"
                               "私人文档与 PoC 已刻意排除。"},
        },
        "baseline_batch_a": _batch_a_baseline(args.batch_a),
        "arm_old": arm_old,
        "arm_new": arm_new,
        "arm_diff": diff,
        "layer_pair": layer_pair,
        "full_chain": chain_stats,
        "routing_reconciliation": routing,
        "regression": regression,
        "cost_summary": {
            "triage_old_cny_all_files": round(
                (arm_old["labels"][MALICIOUS_LABEL]["cny"]
                 + arm_old["labels"][BENIGN_LABEL]["cny"]), 4),
            "triage_new_cny_all_files": round(
                (arm_new["labels"][MALICIOUS_LABEL]["cny"]
                 + arm_new["labels"][BENIGN_LABEL]["cny"]), 4),
            "triage_token_delta_per_file": round(
                arm_new["labels"][MALICIOUS_LABEL]["total_tokens_per_file"]
                - arm_old["labels"][MALICIOUS_LABEL]["total_tokens_per_file"], 1),
            "triage_prompt_token_delta_per_file": round(
                arm_new["labels"][MALICIOUS_LABEL]["prompt_tokens_per_file"]
                - arm_old["labels"][MALICIOUS_LABEL]["prompt_tokens_per_file"], 1),
            "price_note": ("¥/百万 token 取项目常量 budget.CNY_PER_MILLION_TOKENS = 8.0（偏高的一档 = 上界）。"),
        },
        "examples": [row for row in diff["recovered_detail"][:3]],
    }
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps({
        "baseline_batch_a": report["baseline_batch_a"],
        "arm_old_malicious": arm_old["labels"][MALICIOUS_LABEL]["recall_at_threshold"],
        "arm_new_malicious": arm_new["labels"][MALICIOUS_LABEL]["recall_at_threshold"],
        "arm_diff": {k: v for k, v in diff.items() if k not in ("recovered_detail", "lost_detail")},
        "layer_pair": layer_pair,
        "full_chain_malicious": chain_stats["malicious"],
        "full_chain_benign": chain_stats["benign"],
        "cost": report["cost_summary"],
    }, ensure_ascii=False, indent=1))
    print(f"产物: {args.out}")


if __name__ == "__main__":
    main()
