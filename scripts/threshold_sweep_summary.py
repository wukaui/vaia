#!/usr/bin/env python3
"""阈值扫描的汇总口径：把「同一批 320 个样本、六个闸门档、每档真跑 AI」拉成一条曲线。

为什么要有这个脚本
------------------
`--ai-threshold` 原来的值（300）是**照抄上游 `verdict.suspicious` 的**，不是数据定的。
实测那 320 个样本里只有 1 个过线 → AI 全程只判了 1 个文件。产品的定位是"AI 研判台"，
所以得扫一遍闸门，找那个"**AI 有实质贡献、成本还压得住**"的点。

输入（全部是产物，这里只读、不重算判定）
----------------------------------------
  · `--measure`      `scripts/measure_deterministic.py` 的 JSON —— ①层那一臂（无 AI，全量实测）
                     用来拿**逐文件分数 / 标签 / ①层处置**，也就是"闸门把谁放进来"
  · `--sweep-dir`    `scripts/threshold_sweep_run.sh` 的产物根目录（每档一个子目录）
  · `--runlog`       每档的墙钟秒数（驱动脚本写的 TSV）
  · `--full-ai-report`  `aiav scan --ai-threshold 0` 的历史全量轮 —— **0 档的实测参照**
  · `--sample`       `bench/real-dist-320/ai_arm_sample.json` —— 0 档的**正式口径**（分层 48 抽样）

每个数都带 `kind`
-----------------
  measured     真跑出来的（逐文件实测值）
  extrapolated 抽样均值 × 规模乘出来的（**不许当实测值用**）
  derived      由前两者算出来的

四个口径（写死，免得每次换说法）
--------------------------------
  1. **送审率** = ①层处置 `send_ai` 的文件数 / 语料总数（320）。与闸门一一对应。
  2. **召回（①层定性覆盖）** =（确定性判恶意 + 送 AI）覆盖到的恶意 / 恶意总数。
     口径是"①层认为这个文件要么是恶意的、要么得让人/AI 看一眼"。
  3. **召回（AI 判定覆盖）** =（确定性判恶意 + AI 判 malicious/suspicious）覆盖到的恶意 / 恶意总数。
  4. **AI 的增量** = 送审文件里 AI 判成 malicious/suspicious 的**逐个列出来**
     —— 这些是"只跑①层"时会停在"未结案"、现在被明确指出来的文件；
     顺带把 AI 在**良性**文件上多判出来的 flag 也列出来（增量有正有负）。

用法：

    .venv/bin/python scripts/threshold_sweep_summary.py \
        --measure "/tmp/final-out/measure_gate300_20260927_135213.json" \
        --sweep-dir /tmp/thr-sweep \
        --runlog /tmp/thr-sweep/runlog.tsv \
        --full-ai-report "/tmp/real-dist-ai-out/scan_*.json" \
        --sample bench/real-dist-320/ai_arm_sample.json \
        --out bench/real-dist-320/threshold_sweep.json
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

CORPUS_TOTAL = 320          # 语料总数（含 1 个被 50MB 上限挡掉的大文件）
FLAG_RISKS = ("malicious", "suspicious")


def load_one(pattern: str) -> dict:
    hits = [p for p in sorted(glob.glob(pattern)) if "audit" not in p]
    if not hits:
        raise SystemExit(f"找不到产物：{pattern}")
    return json.loads(Path(hits[-1]).read_text(encoding="utf-8"))


def load_many(pattern: str) -> dict[str, dict]:
    out = {}
    for p in sorted(glob.glob(pattern)):
        if "audit" in p:
            continue
        out[p] = json.loads(Path(p).read_text(encoding="utf-8"))
    return out


def deep_threshold_from_extra(extra: str) -> int:
    """从 runlog 的 extra 字段里抠出 `--deep-evidence-threshold` 的值（没有就是 0）。"""
    toks = (extra or "").split()
    for i, t in enumerate(toks):
        if t == "--deep-evidence-threshold" and i + 1 < len(toks):
            try:
                return int(toks[i + 1])
            except ValueError:
                return 0
        if t.startswith("--deep-evidence-threshold="):
            try:
                return int(t.split("=", 1)[1])
            except ValueError:
                return 0
    return 0


def read_runlog(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        rec = {"label": parts[0]}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                rec[k] = v
        out[parts[0]] = rec
    return out


# ---------------------------------------------------------------- 一档的核心计算

def analyze_tier(label: str, gate: int, reports: list[dict], layer1_by_path: dict,
                 layer1_rows: list[dict], unit_price: float, wall_s: float | None,
                 extra: str = "", doc: dict | None = None) -> dict:
    """把一档的 scan JSON 折成一条曲线上的一个点。

    `doc` 是整份 scan JSON —— 它顶上有 CLI 自己的账本（`aggregate.deterministic`
    的送审率/结案数、`token_budget` 的计费 token、`summary.files_degraded`），
    这些数比从逐文件行重算更权威，能对上就说明两套口径一致。
    """
    doc = doc or {}
    ledger = doc.get("aggregate", {}).get("deterministic", {}) or {}
    budget = doc.get("token_budget", {}) or {}
    cli_summary = doc.get("summary", {}) or {}
    scanned = doc.get("total") or len(reports)

    # 送审 = 真正被路由给 AI 的文件。**不能拿 `deterministic.disposition == "send_ai"` 当送审**
    # —— 本轮扫出来一个坑：那个字段是 `quick_prefilter` 用**硬编码的 AI_GATE(300)** 算的，
    # 不认 `--ai-threshold`（见报告里的"核验"一节）。所以这里按**路由规则本身**重算：
    # `scanner.py` 的路由是 `prefilter_score >= ai_threshold`，且确定性结案的文件在它之前就短路。
    CLOSED = ("closed_malicious", "closed_clean")
    routed = [r for r in reports
              if int(r.get("prefilter_score") or 0) >= gate
              and (r.get("deterministic") or {}).get("disposition") not in CLOSED]
    routed_declared = [r for r in reports
                       if (r.get("deterministic") or {}).get("disposition") == "send_ai"]
    used = [r for r in routed if r.get("agent_used")]
    degraded = [r for r in routed if not r.get("agent_used")]     # 送了但调用失败 → 降级到规则

    dist = {"malicious": 0, "suspicious": 0, "clean": 0}
    for r in used:
        risk = ((r.get("verdict") or {}).get("risk") or "clean")
        dist[risk if risk in dist else "clean"] += 1

    def label_of(path: str) -> str:
        row = layer1_by_path.get(path)
        return row["label"] if row else ("malicious" if "/malware/" in path else "benign")

    # ---- 召回：只认语料里带标签的那 20 个恶意 ----
    mal_rows = [r for r in layer1_rows if r["label"] == "malicious"]
    n_mal = len(mal_rows)
    closed_mal = {r["path"] for r in reports
                  if (r.get("deterministic") or {}).get("disposition") == "closed_malicious"}
    routed_paths = {r["path"] for r in routed}
    ai_flagged = {r["path"] for r in used
                  if ((r.get("verdict") or {}).get("risk")) in FLAG_RISKS}

    recall_layer1_hit = [r["path"] for r in mal_rows if r["path"] in closed_mal or r["path"] in routed_paths]
    recall_ai_hit = [r["path"] for r in mal_rows if r["path"] in closed_mal or r["path"] in ai_flagged]
    still_missed = [r["path"] for r in mal_rows
                    if r["path"] not in closed_mal and r["path"] not in routed_paths]

    # ---- AI 的增量：送审文件里 AI 判成 flag 的，逐个列出来 ----
    delta_mal = [r["path"] for r in used
                 if ((r.get("verdict") or {}).get("risk")) in FLAG_RISKS
                 and label_of(r["path"]) == "malicious"]
    delta_ben_fp = [r["path"] for r in used
                    if ((r.get("verdict") or {}).get("risk")) in FLAG_RISKS
                    and label_of(r["path"]) == "benign"]
    delta_mal_susp = [r["path"] for r in used
                      if ((r.get("verdict") or {}).get("risk")) == "suspicious"
                      and label_of(r["path"]) == "malicious"]

    # ---- 成本：AI 判决 vs 取证（capa/floss 预采集）分开报 ----
    tokens = [int(((r.get("agent_usage") or {}).get("tokens")) or 0) for r in used]
    total_tokens = sum(tokens)
    preload_ms = [float((r.get("evidence_preload") or {}).get("elapsed_ms") or 0) for r in used]
    deep_done = sum(1 for r in used
                    if (r.get("evidence_preload") or {}).get("deep_forensics") == "done")
    deep_skipped = sum(1 for r in used
                       if (r.get("evidence_preload") or {}).get("deep_forensics") == "skipped")

    from_cache = sum(1 for r in reports if (r.get("cache") or {}).get("from_cache"))
    errors = [r["path"] for r in reports if r.get("error")]

    # ---- AI 自调工具：分流档最怕的就是"AI 自己把跳过的 capa/floss 补回来" ----
    self_calls = sum(int(((r.get("agent_usage") or {}).get("tool_calls")) or 0) for r in used)
    deep_dive_files = sum(1 for r in used if (r.get("agent_usage") or {}).get("deep_dive"))

    return {
        "label": label,
        "gate": gate,
        "config": {
            "ai_threshold": gate,
            "deep_evidence_threshold": deep_threshold_from_extra(extra),
            "extra_args": extra.strip(),
            "workers": 6,
            "cache": "AI_AV_CACHE=0（关缓存，保证每档真跑）",
            "state_dir": f"/tmp/thr-sweep/state-{label}（每档独立，空缓存）",
        },
        "kind": "measured",
        "files_scanned": len(reports),
        "routed_to_ai": len(routed),
        "routed_declared_send_ai": len(routed_declared),
        "send_rate": round(len(routed) / CORPUS_TOTAL, 4),
        "send_rate_cli": ledger.get("send_rate"),
        "send_rate_denominator_note": f"脚本口径分母 = 语料 {CORPUS_TOTAL} 个；"
                                      f"CLI 口径分母 = 实际扫到的 {scanned} 个"
                                      f"（1 个 114.8MB 大文件被 50MB 上限挡掉）",
        "cli_ledger": {
            "kind": "measured",
            "send_rate": ledger.get("send_rate"),
            "sent": ledger.get("sent"),
            "closed_malicious": ledger.get("closed_malicious"),
            "closed_clean": ledger.get("closed_clean"),
            "closed_rate": ledger.get("closed_rate"),
            "unresolved": ledger.get("unresolved"),
            "unclassified_signals": len(ledger.get("unclassified_signals") or []),
            "unavailable_detections": ledger.get("unavailable_detections"),
            "tokens": cli_summary.get("tokens"),
            "requests": budget.get("requests"),
            "files_charged": budget.get("files_charged"),
            "files_skipped_by_budget": budget.get("files_skipped_by_budget"),
            "files_degraded": cli_summary.get("files_degraded"),
            "files_with_retry": cli_summary.get("files_with_retry"),
            "errors": (doc.get("aggregate") or {}).get("errors"),
            "scan_skips": doc.get("scan_skips"),
        },
        "ai_used": len(used),
        "ai_degraded_to_rules": len(degraded),
        "degraded_files": [r["path"] for r in degraded],
        "ai_verdict_dist": dist,
        "recall_layer1": round(len(recall_layer1_hit) / n_mal, 4),
        "recall_layer1_hits": len(recall_layer1_hit),
        "recall_ai": round(len(recall_ai_hit) / n_mal, 4),
        "recall_ai_hits": len(recall_ai_hit),
        "recall_delta_vs_layer1": round((len(recall_ai_hit) - len(recall_layer1_hit)) / n_mal, 4),
        "n_malicious": n_mal,
        "still_missed_malicious": still_missed,
        "ai_delta": {
            "kind": "measured",
            "malicious_flagged_by_ai": delta_mal,
            "malicious_flagged_suspicious": delta_mal_susp,
            "benign_false_flags": delta_ben_fp,
            "net_flagged_files": len(delta_mal) - len(delta_ben_fp),
        },
        "cost": {
            "ai_judgement": {
                "kind": "measured",
                "tokens": total_tokens,
                "cny": round(total_tokens / 1_000_000 * unit_price, 4),
                "tokens_per_ai_file": round(total_tokens / len(used), 1) if used else 0,
                "tokens_per_corpus_file": round(total_tokens / CORPUS_TOTAL, 1),
                "median_tokens": sorted(tokens)[len(tokens) // 2] if tokens else 0,
            },
            "evidence_preload": {
                "kind": "measured",
                "seconds_total": round(sum(preload_ms) / 1000, 1),
                "seconds_per_ai_file": round(sum(preload_ms) / 1000 / len(used), 1) if used else 0,
                "deep_forensics_done": deep_done,
                "deep_forensics_skipped": deep_skipped,
                "note": "capa/floss 等预采集的**逐文件实测**耗时，与模型调用分开计时",
            },
            "ai_self_tool_calls": {
                "kind": "measured",
                "calls": self_calls,
                "files_deep_dive": deep_dive_files,
                "note": "送审之后 AI **自己**又调了几次工具（分流档要看这个：跳过的 capa/floss "
                        "若被 AI 补回来，分流的收益就没了）",
            },
            "wall_clock_s": wall_s,
            "wall_s_per_ai_file": round(wall_s / len(used), 1) if (wall_s and used) else None,
            "wall_s_per_corpus_file": round(wall_s / CORPUS_TOTAL, 3) if wall_s else None,
        },
        "verification": {
            "from_cache": from_cache,
            "file_errors": len(errors),
            "error_files": errors[:5],
        },
    }


# ------------------------------------------------- 取证层分流的对照（补充指令那一档）

def build_deep_control(tiers: list[dict], by_label: dict[str, dict[str, dict]]) -> dict:
    """**同一个闸门**下，"所有送审文件都深挖" vs "只对高分文件深挖"。

    为什么必须测这一档（2026-09-27 补充指令）：阈值一调低，capa/floss 的取证时间就成了
    主要成本（实测 capa 4.9~7.5s、floss 8.3~8.7s，合计 14~16s/文件，大 PE 上更久）。
    不测它，曲线上会出现"送审率降了、总时间反而涨了"这种看不懂的形状。

    两臂之间**只差一个开关**：`--deep-evidence-threshold`。闸门、语料、workers、
    缓存口径全一样。所以要盯三件事：总时间（该降）、送审率与召回（**不该变**）、
    以及"AI 有没有自己把跳过的 capa/floss 补回来"（补回来就等于分流白做）。
    """
    by_gate: dict[int, list[dict]] = {}
    for t in tiers:
        by_gate.setdefault(t["gate"], []).append(t)

    def arm_view(t: dict) -> dict:
        c = t["cost"]
        return {
            "label": t["label"],
            "deep_evidence_threshold": t["config"]["deep_evidence_threshold"],
            "wall_s": c["wall_clock_s"],
            "routed_to_ai": t["routed_to_ai"],
            "send_rate": t["send_rate"],
            "recall_layer1": t["recall_layer1"],
            "recall_ai": t["recall_ai"],
            "ai_verdict_dist": t["ai_verdict_dist"],
            "tokens": c["ai_judgement"]["tokens"],
            "preload_s": c["evidence_preload"]["seconds_total"],
            "preload_s_per_ai_file": c["evidence_preload"]["seconds_per_ai_file"],
            "deep_done": c["evidence_preload"]["deep_forensics_done"],
            "deep_skipped": c["evidence_preload"]["deep_forensics_skipped"],
            "ai_self_tool_calls": c["ai_self_tool_calls"]["calls"],
            "ai_degraded_to_rules": t["ai_degraded_to_rules"],
        }

    pairs = []
    for gate, group in sorted(by_gate.items(), reverse=True):
        base = next((t for t in group if t["config"]["deep_evidence_threshold"] == 0), None)
        if base is None:
            continue
        for t in group:
            if t["config"]["deep_evidence_threshold"] <= 0:
                continue
            a, b = arm_view(base), arm_view(t)
            # 同一文件在两臂里的 AI 判定：分流**不该**改送审率，但可能改定性
            ra, rb = by_label.get(base["label"], {}), by_label.get(t["label"], {})
            common = sorted(p for p in ra
                            if ra[p].get("agent_used") and rb.get(p, {}).get("agent_used"))
            changes = []
            for p in common:
                x = (ra[p].get("verdict") or {}).get("risk")
                y = (rb[p].get("verdict") or {}).get("risk")
                if x != y:
                    changes.append({
                        "file": Path(p).name,
                        "deep_all": x,
                        "deep_gated": y,
                        "score": rb[p].get("prefilter_score"),
                        "size": rb[p].get("size"),
                        "deep_forensics_in_gated_arm":
                            (rb[p].get("evidence_preload") or {}).get("deep_forensics"),
                    })
            wall_delta = (round(b["wall_s"] - a["wall_s"], 1)
                          if (a["wall_s"] and b["wall_s"]) else None)
            pairs.append({
                "gate": gate,
                "kind": "measured",
                "deep_all_arm": a,                    # --deep-evidence-threshold 0
                "deep_gated_arm": b,                  # 只对高分文件深挖
                "delta": {
                    "kind": "derived",
                    "wall_s": wall_delta,
                    "wall_pct": (round(wall_delta / a["wall_s"] * 100, 1)
                                 if (wall_delta is not None and a["wall_s"]) else None),
                    "send_rate": round(b["send_rate"] - a["send_rate"], 4),
                    "recall_layer1": round(b["recall_layer1"] - a["recall_layer1"], 4),
                    "recall_ai": round(b["recall_ai"] - a["recall_ai"], 4),
                    "tokens": b["tokens"] - a["tokens"],
                    "preload_s": round(b["preload_s"] - a["preload_s"], 1),
                },
                "same_file_verdict_diff": {
                    "kind": "measured",
                    "common_ai_files": len(common),
                    "risk_agreement": (round((len(common) - len(changes)) / len(common), 4)
                                       if common else None),
                    "changes": changes,
                },
            })

    return {
        "question": "同一个闸门下，把深度取证（capa/floss）限制在高分文件上，"
                    "总时间/送审率/召回 各变多少？",
        "why": "capa 4.9~7.5s + floss 8.3~8.7s ≈ 14~16s/文件，且与文件大小强相关"
               "（24MB 的 edgehtml.dll / 18MB 的 mspdf.dll）；闸门调低后送审文件变多，"
               "取证时间会盖过模型时间。",
        "control_variable": "只有 --deep-evidence-threshold 一个：0 = 全部深挖；"
                            ">0 = 预筛分数低于它的文件只采轻量证据（PE 头/导入表/明文字符串/签名）",
        "pairs": pairs,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--measure", required=True)
    ap.add_argument("--sweep-dir", default="/tmp/thr-sweep")
    ap.add_argument("--runlog", default="/tmp/thr-sweep/runlog.tsv")
    ap.add_argument("--full-ai-report", default=None, help="gate 0 的历史全量轮（0 档的实测参照）")
    ap.add_argument("--sample", default=None, help="bench/real-dist-320/ai_arm_sample.json")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    from aiav.budget import CNY_PER_MILLION_TOKENS

    measure = load_one(args.measure)
    name = next(iter(measure["corpora"]))
    layer1 = measure["corpora"][name]
    layer1_rows = layer1["rows"]
    layer1_by_path = {r["path"]: r for r in layer1_rows}

    runlog = read_runlog(Path(args.runlog))

    # ---- 每一档 ----
    sweep = Path(args.sweep_dir)
    tiers = []
    for sub in sorted(sweep.iterdir()):
        if not sub.is_dir() or not sub.name.startswith("g"):
            continue
        hits = [p for p in sorted(glob.glob(str(sub / "scan_*.json"))) if "audit" not in p]
        if not hits:
            continue
        rep = json.loads(Path(hits[-1]).read_text(encoding="utf-8"))
        log = runlog.get(sub.name, {})
        gate = int(log.get("gate") or 0)
        tiers.append(analyze_tier(sub.name, gate, rep.get("reports") or [], layer1_by_path,
                                  layer1_rows, CNY_PER_MILLION_TOKENS,
                                  float(log["wall_s"]) if log.get("wall_s") else None,
                                  log.get("extra", ""), rep))
    tiers.sort(key=lambda t: -t["gate"])

    # ---- 0 档：抽样 + 外推（沿用上一轮那套：分层 48 / seed 20260927 / 清单入库） ----
    tier0: dict = {"label": "g0", "gate": 0, "kind": "sampled+extrapolated"}
    full_block = None
    if args.full_ai_report:
        ai = load_one(args.full_ai_report)
        reports = ai.get("reports") or []
        used = [r for r in reports if r.get("agent_used")]
        routed = [r for r in reports
                  if int(r.get("prefilter_score") or 0) >= 0
                  and (r.get("deterministic") or {}).get("disposition")
                  not in ("closed_malicious", "closed_clean")]
        closed_mal = {r["path"] for r in reports
                      if (r.get("deterministic") or {}).get("disposition") == "closed_malicious"}
        ai_flagged = {r["path"] for r in used
                      if ((r.get("verdict") or {}).get("risk")) in FLAG_RISKS}
        mal_rows = [r for r in layer1_rows if r["label"] == "malicious"]
        n_mal = len(mal_rows)
        tokens = [int(((r.get("agent_usage") or {}).get("tokens")) or 0) for r in used]
        preload = [float((r.get("evidence_preload") or {}).get("elapsed_ms") or 0) for r in used]
        dist = {"malicious": 0, "suspicious": 0, "clean": 0}
        for r in used:
            risk = ((r.get("verdict") or {}).get("risk") or "clean")
            dist[risk if risk in dist else "clean"] += 1

        def lab(p: str) -> str:
            row = layer1_by_path.get(p)
            return row["label"] if row else ("malicious" if "/malware/" in p else "benign")

        full_block = {
            "kind": "measured",
            "scope": "full-run（历史那一轮，本轮没有再调模型）",
            "files_scanned": ai.get("total"),
            "routed_to_ai": len(routed),
            "send_rate": round(len(routed) / CORPUS_TOTAL, 4),
            "ai_used": len(used),
            "ai_degraded_to_rules": len(routed) - len(used),
            "ai_verdict_dist": dist,
            # ⚠️ 这里必须拿**路径集合**去比，不能拿 `routed`（list[dict]）去比 ——
            # 字符串 in list[dict] 永远 False，会把 recall① 算成"只有 ClamAV 结案的那 17 个"
            # （0 档曾经就这么报出 0.850，而它其实是全送审、20/20）。
            "recall_layer1": round(len([r for r in mal_rows
                                        if r["path"] in closed_mal
                                        or r["path"] in {x["path"] for x in routed}]) / n_mal, 4),
            "recall_ai": round(len([r for r in mal_rows
                                    if r["path"] in closed_mal or r["path"] in ai_flagged]) / n_mal, 4),
            "n_malicious": n_mal,
            "ai_delta": {
                "kind": "measured",
                "malicious_flagged_by_ai": [r["path"] for r in used
                                            if ((r.get("verdict") or {}).get("risk")) in FLAG_RISKS
                                            and lab(r["path"]) == "malicious"],
                "malicious_flagged_suspicious": [r["path"] for r in used
                                                 if ((r.get("verdict") or {}).get("risk")) == "suspicious"
                                                 and lab(r["path"]) == "malicious"],
                "benign_false_flags": [r["path"] for r in used
                                       if ((r.get("verdict") or {}).get("risk")) in FLAG_RISKS
                                       and lab(r["path"]) == "benign"],
            },
            "cost": {
                "ai_judgement": {
                    "kind": "measured",
                    "tokens": sum(tokens),
                    "cny": round(sum(tokens) / 1_000_000 * CNY_PER_MILLION_TOKENS, 4),
                    "tokens_per_ai_file": round(sum(tokens) / len(used), 1) if used else 0,
                    "tokens_per_corpus_file": round(sum(tokens) / CORPUS_TOTAL, 1),
                },
                "evidence_preload": {
                    "kind": "measured",
                    "seconds_total": round(sum(preload) / 1000, 1),
                    "seconds_per_ai_file": round(sum(preload) / 1000 / len(used), 1) if used else 0,
                },
            },
        }
        tier0["full_run_reference"] = full_block

    if args.sample and full_block:
        smp = json.loads(Path(args.sample).read_text(encoding="utf-8"))
        m = (smp.get("sample_measured") or {})
        mean_tok = m.get("mean_tokens_per_ai_file") or 0
        routed_full = full_block["routed_to_ai"]
        tier0["sampling"] = {
            "kind": "extrapolated",
            "method": smp.get("method"),
            "sample_measured": m,
            "basis": f"分层 48 抽样实测均值 {mean_tok} token/文件（seed=20260927，与语料同为 6.25% 恶意）",
            "extrapolated": {
                "same_scope_x_routed": {
                    "scale": routed_full,
                    "tokens": round(mean_tok * routed_full),
                    "cny": round(mean_tok * routed_full / 1_000_000 * CNY_PER_MILLION_TOKENS, 2),
                },
                "upper_bound_x_corpus": {
                    "scale": CORPUS_TOTAL,
                    "tokens": round(mean_tok * CORPUS_TOTAL),
                    "cny": round(mean_tok * CORPUS_TOTAL / 1_000_000 * CNY_PER_MILLION_TOKENS, 2),
                },
            },
            "note": "0 档按纪律**不全量重跑**：用上一轮那套分层抽样 + 外推（0 token）；"
                    "上面 full_run_reference 是历史全量实测，用来核抽样代表性",
        }

    # ---- 一致性：同档两遍 / 跨档同文件 ----
    consistency = {"same_gate_repeats": [], "cross_tier_same_file": []}
    by_label = {}
    for sub in sorted(sweep.iterdir()):
        if not sub.is_dir() or not sub.name.startswith("g"):
            continue
        hits = [p for p in sorted(glob.glob(str(sub / "scan_*.json"))) if "audit" not in p]
        if not hits:
            continue
        rep = json.loads(Path(hits[-1]).read_text(encoding="utf-8"))
        by_label[sub.name] = {r["path"]: r for r in rep.get("reports") or []}

    for a, b in (("g200", "g200b"),):
        if a in by_label and b in by_label:
            ra, rb = by_label[a], by_label[b]
            used_a = {p: r for p, r in ra.items() if r.get("agent_used")}
            used_b = {p: r for p, r in rb.items() if r.get("agent_used")}
            common = sorted(set(used_a) & set(used_b))
            same_risk = [p for p in common
                         if ((used_a[p].get("verdict") or {}).get("risk")
                             == (used_b[p].get("verdict") or {}).get("risk"))]
            ta = [int(((used_a[p].get("agent_usage") or {}).get("tokens")) or 0) for p in common]
            tb = [int(((used_b[p].get("agent_usage") or {}).get("tokens")) or 0) for p in common]
            consistency["same_gate_repeats"].append({
                "pair": [a, b], "common_ai_files": len(common),
                "risk_agreement": round(len(same_risk) / len(common), 4) if common else None,
                "risk_disagreements": [
                    {"file": Path(p).name,
                     "a": (used_a[p].get("verdict") or {}).get("risk"),
                     "b": (used_b[p].get("verdict") or {}).get("risk")} for p in common
                    if p not in set(same_risk)],
                "tokens_mean_a": round(sum(ta) / len(ta), 1) if ta else None,
                "tokens_mean_b": round(sum(tb) / len(tb), 1) if tb else None,
            })

    # 跨档：同一文件出现在多档时，AI 判定是否一致（闸门不该改变同一个文件的判定）
    seen: dict[str, list[tuple[str, str]]] = {}
    for lab_name, rows in by_label.items():
        for p, r in rows.items():
            if r.get("agent_used"):
                seen.setdefault(p, []).append((lab_name, (r.get("verdict") or {}).get("risk")))
    multi = {p: v for p, v in seen.items() if len(v) > 1}
    agree = 0
    total_pairs = 0
    disagree_examples = []
    for p, v in multi.items():
        risks = {x[1] for x in v}
        total_pairs += 1
        if len(risks) == 1:
            agree += 1
        else:
            disagree_examples.append({"file": Path(p).name,
                                      "observations": [{"tier": t, "risk": k} for t, k in v]})
    consistency["cross_tier_same_file"] = {
        "files_in_multiple_tiers": len(multi),
        "all_agree": agree,
        "agreement_rate": round(agree / total_pairs, 4) if total_pairs else None,
        "disagreements": disagree_examples[:10],
    }

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "kind_note": "measured = 真跑出来的；extrapolated = 抽样均值乘规模（不许当实测）；"
                     "derived = 由前两者算出",
        "corpus": {
            "path": "/tmp/real-dist-320/files",
            "total": CORPUS_TOTAL,
            "n_malicious": len([r for r in layer1_rows if r["label"] == "malicious"]),
            "n_benign": len([r for r in layer1_rows if r["label"] == "benign"]),
            "note": "300 良性 + 20 恶意；1 个 114.8MB 的大文件被 CLI 的 50MB 上限挡掉，"
                    "所以每档实际扫到 319 个（闸门 0 那一轮同理）",
        },
        "score_distribution": layer1["summary"].get("score_histogram"),
        "unit_price_cny_per_million": CNY_PER_MILLION_TOKENS,
        "tiers": tiers,
        "tier_0": tier0,
        "deep_evidence_control": build_deep_control(tiers, by_label),
        "consistency": consistency,
        "layer1_reference": {
            "kind": "measured",
            "gate": measure.get("gate"),
            "summary": layer1["summary"],
            "elapsed_s": layer1["elapsed_s"],
            "elapsed_s_with_clamav": layer1["elapsed_s_with_clamav"],
            "consistency": measure.get("consistency"),
            "verification": measure.get("verification"),
        },
    }

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    # ---------------- 打印曲线 ----------------
    print(f"语料 {CORPUS_TOTAL}（300 良 + 20 恶）· 单价 ¥{CNY_PER_MILLION_TOKENS}/百万 token")
    print()
    hdr = (f"{'档':>5} {'送审':>5} {'送审率':>7} {'召回①':>6} {'召回AI':>7} "
           f"{'AI判恶':>6} {'AI疑':>5} {'AI净增':>6} {'token':>9} {'¥':>7} {'取证s':>7}")
    print(hdr)
    print("-" * len(hdr))
    for t in tiers:
        c = t["cost"]
        print(f"{t['gate']:>5} {t['routed_to_ai']:>5} {t['send_rate']:>7.4f} "
              f"{t['recall_layer1']:>6.3f} {t['recall_ai']:>7.3f} "
              f"{t['ai_verdict_dist']['malicious']:>6} {t['ai_verdict_dist']['suspicious']:>5} "
              f"{t['ai_delta']['net_flagged_files']:>6} "
              f"{c['ai_judgement']['tokens']:>9,} {c['ai_judgement']['cny']:>7.3f} "
              f"{c['evidence_preload']['seconds_total']:>7.1f}")
    if full_block:
        c = full_block["cost"]
        print(f"{'0*':>5} {full_block['routed_to_ai']:>5} {full_block['send_rate']:>7.4f} "
              f"{full_block['recall_layer1']:>6.3f} {full_block['recall_ai']:>7.3f} "
              f"{full_block['ai_verdict_dist']['malicious']:>6} "
              f"{full_block['ai_verdict_dist']['suspicious']:>5} "
              f"{len(full_block['ai_delta']['malicious_flagged_by_ai']) - len(full_block['ai_delta']['benign_false_flags']):>6} "
              f"{c['ai_judgement']['tokens']:>9,} {c['ai_judgement']['cny']:>7.3f} "
              f"{c['evidence_preload']['seconds_total']:>7.1f}")
        print("  * 0 档 = 历史全量轮实测（本轮没有再调模型）")
    print()

    # ---------------- 取证层分流对照 ----------------
    ctl = payload["deep_evidence_control"]
    if ctl["pairs"]:
        print("取证层分流对照（同一个闸门，只差 --deep-evidence-threshold）")
        hdr2 = (f"{'闸门':>5} {'臂':>14} {'深挖阈值':>8} {'墙钟s':>8} {'送审':>5} {'送审率':>7} "
                f"{'召回AI':>7} {'token':>9} {'取证s':>8} {'深挖/跳过':>10} {'AI自调':>6}")
        print(hdr2)
        print("-" * len(hdr2))
        for p in ctl["pairs"]:
            for key, name in (("deep_all_arm", "全部深挖"), ("deep_gated_arm", "只对高分深挖")):
                a = p[key]
                print(f"{p['gate']:>5} {name:>14} {a['deep_evidence_threshold']:>8} "
                      f"{a['wall_s']:>8.1f} {a['routed_to_ai']:>5} {a['send_rate']:>7.4f} "
                      f"{a['recall_ai']:>7.3f} {a['tokens']:>9,} {a['preload_s']:>8.1f} "
                      f"{str(a['deep_done']) + '/' + str(a['deep_skipped']):>10} "
                      f"{a['ai_self_tool_calls']:>6}")
            d = p["delta"]
            print(f"{'':>5} {'Δ':>14} {'':>8} {d['wall_s']:>8.1f} {'':>5} "
                  f"{d['send_rate']:>+7.4f} {d['recall_ai']:>+7.3f} {d['tokens']:>+9,} "
                  f"{d['preload_s']:>+8.1f} {'':>10} {'':>6}"
                  f"   （墙钟 {d['wall_pct']:+.1f}%）")
        print()

    if args.out:
        print(f"写入 {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
