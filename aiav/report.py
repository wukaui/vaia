from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from aiav.criteria import AI_GATE
from aiav.models import FileReport, RiskLevel

RISK_COLOR = {
    RiskLevel.clean: "#2e7d32",
    RiskLevel.suspicious: "#ef6c00",
    RiskLevel.malicious: "#c62828",
}

RISK_ORDER = {RiskLevel.clean: 0, RiskLevel.suspicious: 1, RiskLevel.malicious: 2}


def _band(score: int) -> str:
    """分数档位。**Assemblyline 刻度**（2026-09-27 换）：一条弱信号 125 分起，
    两条才够 300（送审闸门），500-999 是强可疑，≥1000 是确定性结案。"""
    if score == 0:
        return "0"
    if score < 300:
        return "1-299"
    if score < 500:
        return "300-499"
    if score < 1000:
        return "500-999"
    return ">=1000"


def build_summary(reports: list[FileReport]) -> dict[str, Any]:
    """报告聚合视图：风险 / 类型 / 处置 / 策略 / 采样 / 溯源 一屏看全。"""
    # 抬头那个"闸门"必须是**这一轮真正用的**那个（`--ai-threshold`），不是常量。
    # ⚠️ 2026-09-27 阈值扫描扫出来的坑：这里原来写死 `AI_GATE`(300)，于是
    # `--ai-threshold 100` 跑出来的报告抬头写着"闸门 300"，而 `sent` 是 105 ——
    # **产物自己看不出这一档用的什么配置**（扫阈值最不能忍的一条）。
    # 逐文件的 `deterministic.gate` 现在是运行时闸门，这里取众数；老报告（缓存里的）
    # 可能是满值 300，所以退化时才用常量兜底。
    gates = Counter((r.deterministic or {}).get("gate") for r in reports
                    if isinstance((r.deterministic or {}).get("gate"), int))
    gate = gates.most_common(1)[0][0] if gates else AI_GATE

    risk = Counter(r.verdict.risk.value for r in reports)
    ext = Counter((r.extension or "(none)") for r in reports)
    category = Counter((r.verdict.category or "unknown") for r in reports)
    disp = Counter((r.disposition or {}).get("status") or "none" for r in reports)
    band = Counter(_band(r.prefilter_score) for r in reports)
    yara = Counter(h for r in reports for h in (r.yara_hits or []))

    actions: Counter = Counter()
    bases: Counter = Counter()
    for r in reports:
        for a in r.policy_actions or []:
            actions[a.get("action", "?")] += 1
            bases[str(a.get("basis", ""))[:60]] += 1

    # 判决权归 AI 的审计面：策略想改判但没改成的提议（"规则和 AI 到底同不同意"）
    proposals = [p for r in reports for p in (r.policy_proposals or [])]
    disagreements = [p for p in proposals if p.get("disagreement")]

    # 溯源口径：**只在走过 AI 的文件上统计**。
    # 没走 AI 的文件是确定性判定（规则/哈希/低分放行），压根没有模型参与，
    # 把它们算进"有没有出处"的分母，等于拿规则档去拉低模型档的分数（实测：132 个文件里
    # 只有 1 个进 AI，旧口径给出 2.9% → 卡片四舍五入成 0%，看着像模型全在编，其实是口径错）。
    claims = [s for r in reports for s in (r.evidence_sources or [])]
    ai_claims = [s for r in reports if r.agent_used for s in (r.evidence_sources or [])]
    det_claims = [s for r in reports if not r.agent_used for s in (r.evidence_sources or [])]
    total_claims = len(claims)

    def _attribute(group: list[dict]) -> tuple[int, int]:
        attributed = sum(1 for s in group if s.get("support") in ("explicit", "overlap"))
        return attributed, len(group) - attributed

    attributed, unattributed = _attribute(ai_claims)
    det_claims_count, det_unattributed = len(det_claims), _attribute(det_claims)[1]
    ai_files = sum(1 for r in reports if r.agent_used)
    ai_claims_denominator = len(ai_claims)
    # 全确定性判定时**没有可统计的分子分母** → 必须是 None（报告显示 N/A），不许显示 0%。
    attributed_rate = (round(attributed / ai_claims_denominator, 4)
                       if ai_claims_denominator else None)
    warnings = [w for r in reports for w in (r.claim_warnings or [])]

    sampled = [r for r in reports if (r.sampling or {}).get("samples", 1) > 1]
    agreement = (sum((r.sampling or {}).get("agreement", 1.0) for r in sampled) / len(sampled)
                 if sampled else None)

    packed = [r for r in reports if (r.packing or {}).get("packed")]
    unpacked = [r for r in reports if ((r.packing or {}).get("unpack") or {}).get("ok")]
    payload_verdicts = Counter(
        ((r.packing or {}).get("unpack") or {}).get("verdict", "unknown") for r in unpacked)

    def _dimension(value_of) -> list[dict[str, Any]]:
        """按维度聚合成 [值, 计数, 占比, 失败数, 失败率]，供报告与测试直接核对。"""
        buckets: dict[str, dict[str, int]] = {}
        for r in reports:
            key = value_of(r) or "(none)"
            row = buckets.setdefault(key, {"count": 0, "errors": 0})
            row["count"] += 1
            if r.error:
                row["errors"] += 1
        out = []
        for key, row in sorted(buckets.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
            out.append({
                "value": key, "count": row["count"],
                "share": round(row["count"] / len(reports), 4) if reports else 0.0,
                "errors": row["errors"],
                "error_rate": round(row["errors"] / row["count"], 4) if row["count"] else 0.0,
            })
        return out

    dimensions = {
        "risk": _dimension(lambda r: r.verdict.risk.value),
        "extension": _dimension(lambda r: r.extension or "(none)"),
        "category": _dimension(lambda r: r.verdict.category or "unknown"),
    }

    # ---- ①层账本（2026-09-27）：产品的三个命数 ----
    #   送审率       = 真正交给 AI 的文件占比（旧架构是 100%）
    #   纯①层结案率  = 不送 AI 就把结论定下来的比例（确定性判恶意 + 确定性判干净）
    #   未结案率     = 没线索、不送 AI、也没结论（⚠️ 不是判白）
    n = len(reports) or 1
    dispositions = Counter((r.deterministic or {}).get("disposition") or "unknown" for r in reports)

    # ---- 两档送审的账（2026-09-27）----
    # 三类：`high`（≥高档，旧口径也送）/ `low`（[低档, 高档)，**新增**）/ `none`（静默放行）。
    # `ai_tier` 由 `quick_prefilter` 按运行时闸门写（确定性结案的文件记 `none`）。
    # 老产物（缓存里的、两档之前跑的）没有这个字段 —— 按 `send_ai` + 分数回推，
    # 免得读老报告时三档数加起来对不上总数。
    gates_low = Counter((r.deterministic or {}).get("gate_low") for r in reports
                        if isinstance((r.deterministic or {}).get("gate_low"), int))
    gate_low = gates_low.most_common(1)[0][0] if gates_low else 0

    def _tier_of(r: FileReport) -> str:
        det_r = r.deterministic or {}
        tier = det_r.get("ai_tier")
        if tier in ("high", "low", "triage", "none"):
            return str(tier)
        if det_r.get("disposition") == "send_ai" or r.agent_used:
            return "high" if int(r.prefilter_score or 0) >= gate else "low"
        return "none"

    tiers = Counter(_tier_of(r) for r in reports)
    low_files = [r for r in reports if _tier_of(r) == "low"]
    low_ai = [r for r in low_files if r.agent_used]
    low_flagged = [r for r in low_ai
                   if r.verdict.risk in (RiskLevel.suspicious, RiskLevel.malicious)]
    low_conf = [round(float(r.verdict.confidence), 3) for r in low_ai]
    low_degraded = [r for r in low_ai
                    if (r.agent_retry or {}).get("outcome") == "degraded_to_rules"]

    # ---- ②层 LLM 初筛的账（2026-09-27 接进流水线）----
    # 三类：`select`（初筛说值得看 → 送 ③）/ `drop`（初筛说算了 → 静默放行）/
    # `none`（没跑 / 没拿到分数）。**没拿到分数不许记成 drop** ——
    # 那会把一次调用故障伪装成一个判定（口径与 `criteria.triage_tier` 一致）。
    triage_rows = [(r, (r.deterministic or {}).get("triage") or {}) for r in reports]
    triage_cand = [r for r, t in triage_rows if t.get("candidate")]
    triage_select = [r for r, t in triage_rows if t.get("tier") == "select"]
    triage_drop = [r for r, t in triage_rows if t.get("tier") == "drop"]
    triage_no_score = [r for r, t in triage_rows
                       if t.get("candidate") and t.get("score") is None]
    triage_ai = [r for r in triage_select if r.agent_used]
    triage_flagged = [r for r in triage_ai
                      if r.verdict.risk in (RiskLevel.suspicious, RiskLevel.malicious)]
    triage_batch = next(((r.deterministic or {}).get("triage_batch") for r in reports
                         if (r.deterministic or {}).get("triage_batch")), None)
    triage_enabled_any = any(t.get("enabled") for _r, t in triage_rows)
    # ⚠️ 送审率看的是**①层处置**（send_ai），不是 `agent_used`。
    # `--no-ai` 跑的时候 `agent_used` 永远是 False —— 拿它当送审率会得到 0% 这种假数
    # （踩过一次：40 个文件里 13 个该送审，卡片上写着 0.0%）。
    sent = sum(1 for r in reports
               if (r.deterministic or {}).get("disposition") == "send_ai" or r.agent_used)
    unclassified = [r for r in reports if r.unclassified_signals]
    criteria_fired = Counter(
        h.get("heur_id", "?") for r in reports for h in (r.criteria_hits or []) if h.get("score")
    )
    criteria_zeroed = Counter(
        h.get("heur_id", "?") for r in reports for h in (r.criteria_hits or [])
        if h.get("safelisted")
    )

    return {
        "total": len(reports),
        "errors": sum(1 for r in reports if r.error),
        "deterministic": {
            "gate": gate,
            # 低档闸门与三档计数（两档送审，2026-09-27）。`gate_low=0` = 低档关掉。
            "gate_low": gate_low,
            "ai_tiers": {k: tiers.get(k, 0) for k in ("high", "low", "triage", "none")},
            "sent_high": tiers.get("high", 0),
            "sent_low": tiers.get("low", 0),
            # ②层挑出来送 ③ 的（**预筛分没到闸门**，靠初筛进来的）——
            # 与高档/低档并列成第三类送审，否则这些文件在报告里会被读成"未结案"。
            "sent_triage": tiers.get("triage", 0),
            "triage": {
                "enabled": triage_enabled_any,
                "batch": triage_batch,
                "candidates": len(triage_cand),
                "selected": len(triage_select),
                "dropped": len(triage_drop),
                "no_score": len(triage_no_score),
                "ai_files": len(triage_ai),
                "flagged": len(triage_flagged),
                "entry_gate": (triage_batch or {}).get("entry_gate"),
                "threshold": (triage_batch or {}).get("threshold"),
                "model": (triage_batch or {}).get("model"),
            },
            # 低档这一档的**可读账**：送了多少、AI 真判了几个、判 flag 几个、
            # AI 给的置信度（均值/区间）。目的就一个：让"AI 也看过这一档"有痕迹，
            # 而不是静默放行 —— 这是两档送审唯一容易被读错的地方。
            "low_tier": {
                "files": len(low_files),
                "ai_files": len(low_ai),
                "flagged": len(low_flagged),
                "degraded": len(low_degraded),
                "confidence_mean": (round(sum(low_conf) / len(low_conf), 3) if low_conf else None),
                "confidence_min": (min(low_conf) if low_conf else None),
                "confidence_max": (max(low_conf) if low_conf else None),
            },
            "send_rate": round(sent / n, 4),
            "sent": sent,
            "closed_malicious": dispositions.get("closed_malicious", 0),
            "closed_clean": dispositions.get("closed_clean", 0),
            "closed_rate": round(
                (dispositions.get("closed_malicious", 0) + dispositions.get("closed_clean", 0)) / n, 4),
            "unresolved": dispositions.get("pass", 0),
            "unresolved_rate": round(dispositions.get("pass", 0) / n, 4),
            "dispositions": dict(dispositions),
            "criteria_fired": dict(criteria_fired.most_common(20)),
            "criteria_safelisted": dict(criteria_zeroed),
            # 核验铁律：这个数**必须为 0**。不为 0 说明有信号加了分却没进判据表。
            "files_with_unclassified_signals": len(unclassified),
            "unclassified_signals": sorted({s for r in reports for s in (r.unclassified_signals or [])})[:10],
            # 工具可用性（核验铁律：先验"工具真跑了吗"）。未安装的检测项直接列在报告抬头，
            # 免得读报告的人把"没报 AV 命中"读成"AV 查过了没有"。
            "unavailable_detections": _unavailable_detections(reports),
            # ClamAV 这一步的**批次账本**（2026-09-27）：引擎/库版本、扫了几个、命中几个、
            # 静默跳过几个、批次报错。核验铁律要求"未安装 / 报错 / 静默降级计数不为 0"能一眼看见 ——
            # 实测踩过：整批 319 个文件超时没结果行，报告里当时一点痕迹都没有。
            "clamav": _clamav_summary(reports),
            "conclusive_producers": {
                "DET_KNOWN_BAD_HASH": "内置哈希库（aiav/data/known_bad_hashes.txt）",
                "DET_CLAMAV_SIGNATURE": "clamscan / clamdscan",
                "DET_EICAR": "内置常量",
                "DET_TRUSTED_SIGNATURE": "aiav.authenticode（纯 Python 验签）",
                "DET_SAFELIST_HIT": "运营白名单",
            },
        },
        "dimensions": dimensions,
        "risk": {k: risk.get(k, 0) for k in ("clean", "suspicious", "malicious")},
        "agent_used": sum(1 for r in reports if r.agent_used),
        "by_extension": dict(ext.most_common(12)),
        "by_category": dict(category.most_common(10)),
        "by_score_band": {b: band.get(b, 0) for b in
                          ("0", "1-299", "300-499", "500-999", ">=1000")},
        "yara_top": dict(yara.most_common(8)),
        "disposition": {k: disp.get(k, 0) for k in
                        ("none", "whitelisted", "quarantined", "quarantine_planned",
                         "previously_quarantined")},
        "policy_actions": dict(actions),
        "policy_basis_top": dict(bases.most_common(6)),
        # 判决权归 AI：策略提议数 / 其中"与 AI 结论不一致"的条数（分歧率按文件算）
        "policy_proposals": {
            "total": len(proposals),
            "disagreement": len(disagreements),
            "files_with_disagreement": sum(
                1 for r in reports if any(p.get("disagreement") for p in (r.policy_proposals or []))),
            "disagreement_rate": (
                round(sum(1 for r in reports
                          if any(p.get("disagreement") for p in (r.policy_proposals or [])))
                      / len(reports), 4) if reports else 0.0),
        },
        "evidence": {
            # `agent_used` 决定哪些文件进溯源统计（见上面的口径说明）
            "agent_used": ai_files,
            "ai_claims": ai_claims_denominator,
            "claims": ai_claims_denominator,
            "attributed": attributed,
            "unattributed": unattributed,
            "attributed_rate": attributed_rate,
            # 未走 AI 的确定性断言单独记账：不是"模型推断"，也不进上面的率
            "deterministic_claims": det_claims_count,
            "deterministic_unattributed": det_unattributed,
            "all_claims": total_claims,
            "claim_warnings": len(warnings),
            "warnings_per_1000_claims": (round(len(warnings) / total_claims * 1000, 1)
                                         if total_claims else 0.0),
        },
        "sampling": {
            "files_with_multiple_samples": len(sampled),
            "mean_agreement": round(agreement, 3) if agreement is not None else None,
        },
        "packing": {
            "packed": len(packed),
            "unpacked_ok": len(unpacked),
            "payload_verdicts": dict(payload_verdicts),
        },
        "cache": {
            "from_cache": sum(1 for r in reports if (r.cache or {}).get("from_cache")),
        },
        "archives": {
            "archives": sum(1 for r in reports if (r.archive or {}).get("is_archive") or (r.archive or {}).get("ok")),
            "children_scanned": sum(len((r.archive or {}).get("children") or []) for r in reports),
            "truncated": sum(1 for r in reports if (r.archive or {}).get("truncated")),
        },
        # 模型调用重试留痕（2026-09-26 修①）：用了重试几次、有几条最终降级到规则判定。
        # 旧实现失败即静默降级，报告里只有一句 error，看不出"这条 clean 其实是规则给的"。
        "retry": {
            "files_with_retry": sum(1 for r in reports if (r.agent_retry or {}).get("retried")),
            "retry_count": sum(int((r.agent_retry or {}).get("retry_count") or 0)
                               for r in reports),
            "files_degraded": sum(1 for r in reports
                                  if (r.agent_retry or {}).get("outcome") == "degraded_to_rules"),
            "failure_kinds": dict(Counter(
                f.get("kind", "?") for r in reports
                for f in ((r.agent_retry or {}).get("failures") or []))),
        },
        # 确定性证据前置 + 工具调用/token 留痕（2026-09-27）：回答两个问题 ——
        # "这次判定用了几次工具调用"、"有没有走按需深挖这条路"。
        # 口径：`tool_calls` 只数 AI 自己发起的（预采集是本地 0 token 的活，单独计）。
        "usage": {
            "tool_calls": sum(int((r.agent_usage or {}).get("tool_calls") or 0)
                              for r in reports),
            "files_deep_dive": sum(1 for r in reports if (r.agent_usage or {}).get("deep_dive")),
            "files_no_tool_call": sum(1 for r in reports if (r.agent_usage or {}).get("tool_calls") == 0
                                      and r.agent_used),
            "tokens": sum(int((r.agent_usage or {}).get("tokens") or 0) for r in reports),
            "by_tool": dict(Counter(
                name for r in reports
                for name, count in ((r.agent_usage or {}).get("by_tool") or {}).items()
                for _ in range(int(count)))),
        },
        "preload": {
            "files_preloaded": sum(1 for r in reports if (r.evidence_preload or {}).get("tools")),
            "tools": dict(Counter(
                name for r in reports
                for name in ((r.evidence_preload or {}).get("tools") or []))),
            "chars": sum(int((r.evidence_preload or {}).get("chars") or 0) for r in reports),
            "ms": round(sum(float((r.evidence_preload or {}).get("elapsed_ms") or 0)
                            for r in reports), 1),
            "truncated": sum(1 for r in reports if (r.evidence_preload or {}).get("truncated")),
            # 分流·取证层（2026-09-27）：这一轮有多少文件**跳过**了 capa/floss、
            # 有多少文件真跑了。跳过必须在报告里看得见 —— 否则读报告的人会把
            # "没报注入能力"读成"查过了、没有"。
            "deep_done": sum(1 for r in reports
                             if (r.evidence_preload or {}).get("deep_forensics") == "done"),
            "deep_skipped": sum(1 for r in reports
                                if (r.evidence_preload or {}).get("deep_forensics") == "skipped"),
        },
        "top_warnings": warnings[:5],
    }


# 报告分层：**判定结果与审计全文分两卷写**。
# 逐文件的 `agent_trace`（工具调用链）与 `evidence_sources`（证据原始片段）
# 实测占 JSON 的 ~64%，属于"要能核对"的审计材料，不是"要读"的判定材料 ——
# 混在一个文件里会让主报告读不动。拆开后主卷只剩判定与聚合，审计卷一字不少。
AUDIT_ONLY_FIELDS = ("agent_trace", "evidence_sources")


def write_reports(reports: list[FileReport], output_dir: Path,
                  extra: dict[str, Any] | None = None) -> tuple[Path, Path, Path]:
    """写三份产物：`scan_*.json`（判定）/ `scan_*.html`（阅读）/ `scan_*.audit.json`（审计全文）。"""
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = output_dir / f"scan_{stamp}.json"
    audit_path = output_dir / f"scan_{stamp}.audit.json"
    html_path = output_dir / f"scan_{stamp}.html"

    summary = build_summary(reports)
    full_reports = [r.model_dump(mode="json") for r in reports]
    light_reports = [{k: v for k, v in item.items() if k not in AUDIT_ONLY_FIELDS}
                     for item in full_reports]
    json_payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total": len(reports),
        # 兼容老字段（历史脚本/文档引用过这些键）
        "summary": {
            "clean": summary["risk"]["clean"],
            "suspicious": summary["risk"]["suspicious"],
            "malicious": summary["risk"]["malicious"],
            "agent_used": summary["agent_used"],
            "policy_escalations": summary["policy_actions"].get("escalate", 0),
            "policy_downgrades": summary["policy_actions"].get("downgrade", 0),
            "policy_no_escalation": summary["policy_actions"].get("no_escalation", 0),
            # 判决权归 AI：策略提议（未生效）与"规则不同意 AI"的文件数
            "policy_proposals": summary["policy_proposals"]["total"],
            "policy_disagreements": summary["policy_proposals"]["disagreement"],
            "files_with_policy_disagreement": summary["policy_proposals"]["files_with_disagreement"],
            "claim_warnings": summary["evidence"]["claim_warnings"],
            "evidence_unattributed": summary["evidence"]["unattributed"],
            "disposition": summary["disposition"],
            # 模型调用重试（2026-09-26 修①）：让脚本能直接读"重试了几个文件、降级了几个"
            "files_with_retry": summary["retry"]["files_with_retry"],
            "files_degraded": summary["retry"]["files_degraded"],
            # 确定性证据前置 + 工具调用/token（2026-09-27）：脚本直接读"平均几次调用/多少 token"
            "tool_calls": summary["usage"]["tool_calls"],
            "files_deep_dive": summary["usage"]["files_deep_dive"],
            "tokens": summary["usage"]["tokens"],
            "preloaded_files": summary["preload"]["files_preloaded"],
        },
        "aggregate": summary,
        # Assemblyline 形状的证据链（2026-09-27）：判据 / 依据 / 证据段 / 服务 / 血缘。
        # 结构由**装进 venv 的上游 `Result` 模型**校验过，校验不过会在这里抛出来（不静默）。
        "assemblyline": _assemblyline_payload(reports),
        # 逐文件溯源统计：报告正文里每条结论能不能对回工具输出，这里给出可核对的计数
        "attribution_by_file": {
            str(r.path): attribution_stats(r) for r in reports
        },
        "reports": light_reports,
        # 审计全文在同名 `*.audit.json`：逐文件工具调用链 + 证据原始片段
        "audit_file": audit_path.name,
        **(extra or {}),
    }
    audit_payload = {
        "generated_at": json_payload["generated_at"],
        "total": len(reports),
        "note": "审计全文：逐文件 Agent 工具调用链与证据来源原始片段。判定结果见同名 scan_*.json。",
        "attribution_by_file": json_payload["attribution_by_file"],
        "reports": full_reports,
    }

    json_path.write_text(json.dumps(json_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    audit_path.write_text(json.dumps(audit_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(_render_html(reports, summary), encoding="utf-8")
    return json_path, html_path, audit_path


def _assemblyline_payload(reports: list[FileReport]) -> dict[str, Any]:
    """Assemblyline 形状的那一份（提交级 + 逐文件），并**用上游模型校验**。

    校验失败不让扫描挂掉，但要在报告里留下 `schema_errors` —— 静默降级是核验铁律里
    明令禁止的（"看 not installed / error / 静默降级计数，不为 0 则该批数字直接作废"）。
    """
    from aiav.assemblyline_view import build_submission, criteria_catalog, validate_result

    stats = load_criteria_stats()
    submission = build_submission(reports, stats=stats)
    schema_errors: list[str] = []
    for item in submission["results"]:
        try:
            validate_result(item)
        except Exception as exc:  # noqa: BLE001
            schema_errors.append(f"{item.get('sha256', '?')[:16]}: {type(exc).__name__}: {exc}")
    return {
        "upstream": "CybercentreCanada/assemblyline",
        "upstream_version": "4.7.4.20",
        "licence": "MIT",
        "criteria_catalog": criteria_catalog(),
        "criteria_stats": stats,
        "schema_errors": schema_errors,
        "submission": submission,
    }


def _unavailable_detections(reports: list["FileReport"] | None = None) -> list[str]:
    """没装的检测项 + **跑失败了的**检测项。

    后半截是 2026-09-27 补的：ClamAV 装了、但这一批没扫成（超时 / 起不来）时，
    `DET_CLAMAV_SIGNATURE` 一条都不会命中，报告看上去跟"扫过且干净"一模一样 ——
    必须在这里显式说出来，否则核验铁律那一条就是空话。
    """
    out: list[str] = []
    try:
        from aiav.tools import unavailable_detections

        out += unavailable_detections()
    except Exception:  # noqa: BLE001
        pass
    failed = sorted({str((r.clamav or {}).get("error"))
                     for r in (reports or []) if (r.clamav or {}).get("error")})
    if failed:
        n = sum(1 for r in (reports or []) if (r.clamav or {}).get("error"))
        out.append(f"ClamAV 预扫**没跑成**：{n} 个文件没有结果行"
                   f"（{'；'.join(failed)[:200]}）—— 这批的 `DET_CLAMAV_SIGNATURE` 按「未产出」算，"
                   f"不是「扫过且干净」")
    return out


def _clamav_summary(reports: list["FileReport"]) -> dict[str, Any]:
    """把逐文件的 ClamAV 记录汇总成批次账本（报告抬头直接看）。"""
    recs = [r.clamav for r in reports if r.clamav]
    if not recs:
        return {"recorded": False,
                "note": "本轮没有 ClamAV 记录（没跑预扫，或引擎未安装）—— 不许读成「扫过且干净」"}
    kinds: dict[str, int] = {}
    for c in recs:
        if c.get("infected"):
            k = c.get("kind") or "malware"
            kinds[k] = kinds.get(k, 0) + 1
    errors: dict[str, int] = {}
    for c in recs:
        if c.get("error"):
            errors[str(c["error"])] = errors.get(str(c["error"]), 0) + 1
    return {
        "recorded": True,
        "files": len(recs),
        "available": sum(1 for c in recs if c.get("available")),
        "batched": sum(1 for c in recs if c.get("batch")),
        "infected": sum(1 for c in recs if c.get("infected")),
        "kinds": kinds,
        # 核验铁律：这两个数**必须为 0**
        "files_without_a_result_line": sum(
            1 for c in recs if c.get("available") and "静默跳过" in str(c.get("error") or "")),
        "files_with_a_batch_error": sum(1 for c in recs if c.get("error")),
        "errors": dict(sorted(errors.items(), key=lambda kv: -kv[1])[:3]),
        "engine": _clamav_engine_note(),
    }


def _clamav_engine_note() -> str:
    """引擎版本 / 库版本 —— "装了 ClamAV"不等于"库是新的、真加载了"。"""
    try:
        from aiav.tools import clamav_engine_info

        info = clamav_engine_info()
        if not info.get("available"):
            return ""
        return f"{info.get('exe')} · {info.get('version')}"
    except Exception:  # noqa: BLE001
        return ""


def load_criteria_stats() -> dict[str, Any]:
    try:
        from aiav.criteria import load_stats

        return load_stats()
    except Exception:  # noqa: BLE001
        return {}


SUPPORTED_SUPPORT = ("explicit", "overlap")


def attribution_stats(report: FileReport) -> dict[str, Any]:
    """单文件溯源统计：结论条数 / 有出处 / 无出处 / 告警数 / 溯源率。

    这份统计同时进 HTML（逐文件列 + 卡片）和 JSON（`attribution_by_file`），
    保证"每条结论都能溯源"这件事既可看也可核对。

    `agent_used=False` 的文件是确定性判定（规则/哈希/低分放行）：这里照样给计数，
    但 `attribution_rate` 固定为 None —— 没调用过模型的文件没有"出处率"可言，
    报 0.0 会被读成"模型全在编"（那是口径错，不是判断错）。
    """
    sources = list(report.evidence_sources or [])
    claims = len(report.verdict.evidence or [])
    attributed = sum(1 for s in sources if s.get("support") in SUPPORTED_SUPPORT)
    unattributed = sum(1 for s in sources if s.get("support") == "unattributed")
    name_only = sum(1 for s in sources if s.get("support") == "explicit_name_only")
    return {
        "claims": claims,
        "sources": len(sources),
        "agent_used": bool(report.agent_used),
        "attributed": attributed,
        "unattributed": unattributed,
        "name_only": name_only,
        "claim_warnings": len(report.claim_warnings or []),
        "policy_actions": len(report.policy_actions or []),
        "attribution_rate": (round(attributed / len(sources), 4)
                             if (sources and report.agent_used) else None),
    }


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _rate_text(rate: float | None, *, digits: int = 0) -> str:
    """出处率显示：没有可统计的 AI 断言时给 N/A，**绝不显示 0%**（0% 是结论，N/A 是没数据）。"""
    if rate is None:
        return "N/A"
    return f"{rate * 100:.{digits}f}%"


def _rate_cell_text(rate: float | None) -> str:
    return "N/A（无 AI 断言）" if rate is None else _rate_text(rate)


def _details(title: str, inner: str, open_: bool = False) -> str:
    return (f"<details{' open' if open_ else ''}><summary>{_esc(title)}</summary>{inner}</details>")


def _file_row(r: FileReport, index: int) -> str:
    color = RISK_COLOR.get(r.verdict.risk, "#555")
    trace_html = ""
    if r.agent_trace:
        items = "".join(
            f"<li><b>{_esc(i.get('tool'))}</b>"
            + (f" <span class='dim'>#{_esc(i.get('sample'))}</span>" if i.get("sample") else "")
            + f": <code>{_esc(i.get('summary'))}</code></li>"
            for i in r.agent_trace
        )
        trace_html = _details("Agent 工具调用链", f"<ul>{items}</ul>")

    # 证据：每条结论挂它的来源（工具名 + 支撑类型）。**原始片段不在这里展开** ——
    # 逐文件行里再贴几百字原文，一屏就全是代码块；全量片段统一进下面那个默认收起的折叠区。
    src_by_claim = {str(s.get("claim")): s for s in (r.evidence_sources or [])}
    evidence_items = []
    for e in r.verdict.evidence:
        src = src_by_claim.get(str(e))
        if src:
            support = src.get("support")
            cls = "" if support in ("explicit", "overlap") else " class='warn'"
            evidence_items.append(
                f"<li{cls}>{_esc(e)}<br><span class='src'>↳ 来源: {_esc(src.get('source'))}"
                f"（{_esc(support)}）</span></li>")
        else:
            evidence_items.append(f"<li>{_esc(e)}</li>")
    evidence_html = f"<ul>{''.join(evidence_items)}</ul>"

    if r.evidence_sources:
        src_items = []
        for item in r.evidence_sources:
            support = item.get("support")
            cls = "" if support in ("explicit", "overlap") else " class='warn'"
            src_items.append(
                f"<li{cls}>[{_esc(item.get('source'))} / {_esc(support)}] {_esc(item.get('claim'))}"
                + (f"<br><code>{_esc((item.get('raw_excerpt') or '')[:200])}</code>"
                   if item.get("raw_excerpt") else "")
                + "</li>")
        sources_html = _details(f"结论证据来源 {len(src_items)} 条（工具名 + 原始输出片段）",
                                f"<ul>{''.join(src_items)}</ul>")
    else:
        sources_html = ""

    policy_html = ""
    if r.policy_actions:
        pol_items = "".join(
            f"<li><b>{_esc(a.get('actor'))}</b> / {_esc(a.get('action'))}: "
            f"{_esc(a.get('from'))} → {_esc(a.get('to'))}｜依据: {_esc(a.get('basis'))}"
            + (f"｜{_esc(a.get('detail'))}" if a.get("detail") else "") + "</li>"
            for a in r.policy_actions)
        policy_html = _details("策略审计（谁把谁抬到哪、依据）", f"<ul>{pol_items}</ul>")

    proposals_html = ""
    props = list(r.policy_proposals or [])
    if props:
        prop_items = "".join(
            f"<li{' class=&quot;warn&quot;' if p.get('disagreement') else ''}>"
            f"<b>{_esc(p.get('actor'))}</b> 提议 {_esc(p.get('proposed'))}: "
            f"{_esc(p.get('from'))} → {_esc(p.get('to'))}"
            f"{'（<b>与 AI 结论不一致</b>）' if p.get('disagreement') else '（与 AI 结论一致）'}"
            f"｜未采纳（applied=False）｜依据: {_esc(p.get('basis'))}"
            + (f"｜{_esc(p.get('detail'))}" if p.get("detail") else "") + "</li>"
            for p in props)
        proposals_html = _details(
            f"策略提议 {len(props)} 条（判决权归 AI —— 提议不生效，只留痕）",
            f"<ul>{prop_items}</ul>", open_=any(p.get("disagreement") for p in props))

    warnings_html = ""
    if r.claim_warnings:
        warnings_html = _details(
            f"⚠ 断言告警 {len(r.claim_warnings)} 条（与确定性证据冲突 / 无支撑）",
            "<ul class='warn'>" + "".join(f"<li>{_esc(w)}</li>" for w in r.claim_warnings) + "</ul>",
            open_=True)

    pack_html = ""
    if r.packing:
        if r.packing.get("error"):
            pack_html = f"<div class='disp'>壳识别失败: {_esc(r.packing['error'])[:100]}</div>"
        elif r.packing.get("packed"):
            up = r.packing.get("unpack") or {}
            bits = [f"壳: {_esc(r.packing.get('packer') or '?')}"
                    f"（{_esc(r.packing.get('confidence') or '?')}）"]
            if up.get("skipped"):
                bits.append(f"脱壳: 跳过（{_esc(up['skipped'])}）")
            elif up.get("ok"):
                bits.append(f"脱壳: 成功 → 载荷判定 {_esc(up.get('verdict') or '?')}"
                            f"（score={up.get('prefilter_score')}）")
                bits.append(f"载荷: <code>{_esc(str(up.get('output')))}</code>")
            elif up.get("error"):
                bits.append(f"脱壳失败: {_esc(up['error'])[:90]}")
            ev = "；".join(str(x) for x in (r.packing.get("evidence") or [])[:3])
            pack_html = (f"<div class='disp'>{'<br>'.join(bits)}"
                         + (f"<br>依据: {_esc(ev)}" if ev else "") + "</div>")

    disp_html = ""
    disp_status = (r.disposition or {}).get("status")
    if disp_status:
        labels = {
            "whitelisted": ("已白名单", "#2e7d32"),
            "quarantined": (f"已隔离 {(r.disposition or {}).get('id', '')}", "#c62828"),
            "quarantine_planned": ("待隔离（dry-run）", "#ef6c00"),
            "previously_quarantined": (f"此前已隔离 {(r.disposition or {}).get('id', '')}", "#6a1b9a"),
        }
        text, color = labels.get(disp_status, (disp_status, "#555"))
        detail = _esc((r.disposition or {}).get("reason")
                      or (r.disposition or {}).get("quarantine_path") or "")
        disp_html = (f"<span class='badge' style='background:{color}'>{_esc(text)}</span>"
                     + (f"<div class='disp'>{detail}</div>" if detail else ""))

    sample_html = ""
    if (r.sampling or {}).get("samples", 1) > 1:
        s = r.sampling
        sample_html = (f"<div class='disp'>采样 {s.get('samples')} 次，一致性 "
                       f"{float(s.get('agreement', 1.0))*100:.0f}%<br>票型 {_esc(s.get('votes'))}"
                       f"{'（平票取更严）' if s.get('tie_break') else ''}</div>")

    stats = attribution_stats(r)
    if not r.agent_used:
        # 没走 AI：这些结论由规则/哈希/低分放行生成，没有"出处率"这回事，别拿 0% 冤枉它
        trace_cell = "<span class='dim'>确定性判定（未走 AI，不进出处率）</span>"
    elif stats["sources"]:
        rate = stats["attribution_rate"]
        cls = "" if (rate is not None and rate >= 0.99) else " class='warn'"
        trace_cell = (f"<span{cls}>有出处 {stats['attributed']}/{stats['sources']}"
                      f"（{_rate_cell_text(rate)}）</span>"
                      + (f"<div class='disp'>无出处 {stats['unattributed']}</div>"
                         if stats["unattributed"] else "")
                      + (f"<div class='disp'>告警 {stats['claim_warnings']}</div>"
                         if stats["claim_warnings"] else ""))
    else:
        trace_cell = "<span class='dim'>无模型断言</span>"

    error = f"<p class='error'>Error: {_esc(r.error)}</p>" if r.error else ""
    # 重试留痕（2026-09-26 修①）：一眼看出"这条结论是重试拿到的"还是"降级到规则的"
    retry_html = ""
    rt = r.agent_retry or {}
    if rt:
        outcome = rt.get("outcome")
        bits = [f"模型调用 {rt.get('attempts', '?')}/{rt.get('max_attempts', '?')} 次"]
        if rt.get("retried"):
            bits.append(f"<b>用过重试</b>（{rt.get('retry_count', 0)} 次）")
        else:
            bits.append("一次过")
        if outcome == "degraded_to_rules":
            bits.append("<b class='error'>最终降级到规则判定</b>")
        if rt.get("failures"):
            kinds = ", ".join(sorted({f.get("kind", "?") for f in rt["failures"]}))
            bits.append(f"错误: {_esc(kinds)}")
        cls = "disp" if outcome != "degraded_to_rules" else "disp warn"
        retry_html = f"<div class='{cls}'>{' · '.join(bits)}</div>"

    # 工具调用 / 深挖留痕（2026-09-27）：一眼看出这次判定是"纯读预采集证据就下结论"
    # 还是"自己又调了 N 次工具去深挖"。口径与 summary.usage.tool_calls 一致：
    # 只数 AI 自己发起的调用（预采集是本地 0 token 的活，单独列在 evidence_preload 里）。
    usage_html = ""
    au = r.agent_usage or {}
    if au:
        calls = int(au.get("tool_calls") or 0)
        bits = [f"工具调用 <b>{calls}</b> 次",
                "走了深挖路径" if calls else "纯读预采集证据"]
        if au.get("tokens"):
            bits.append(f"{int(au['tokens']):,} token")
        if au.get("by_tool"):
            bits.append("、".join(f"{_esc(k)}×{v}" for k, v in list(au["by_tool"].items())[:6]))
        if au.get("degraded"):
            bits.append("<b class='error'>调用失败已降级</b>")
        usage_html = f"<div class='disp'>{' · '.join(bits)}</div>"
    pl = r.evidence_preload or {}
    if pl.get("tools"):
        pl_bits = [f"预采集 {len(pl['tools'])} 项: " + "、".join(_esc(t) for t in pl["tools"]),
                   f"{int(pl.get('chars') or 0):,} 字符",
                   f"{float(pl.get('elapsed_ms') or 0) / 1000:.1f}s（本地，0 token）"]
        if pl.get("truncated"):
            pl_bits.append("<b class='warn'>证据块超预算已降级</b>")
        if pl.get("deep_forensics") == "skipped":
            pl_bits.append("<b class='warn'>深度取证已跳过（capa/floss 未跑）</b>")
        if pl.get("skipped"):
            pl_bits.append("按类型未跑: " + "、".join(_esc(s) for s in pl["skipped"][:6]))
        usage_html += f"<div class='disp'>{' · '.join(pl_bits)}</div>"
    # 送审档（两档送审，2026-09-27）：逐行把"这个文件走的是哪一档"写出来 ——
    # 低档送审的文件在旧口径下是"未结案"，报告里必须一眼能分出来它其实**送过 AI**。
    tier = (r.deterministic or {}).get("ai_tier")
    if tier not in ("high", "low", "triage", "none"):
        tier = ("high" if r.agent_used or (r.deterministic or {}).get("disposition") == "send_ai"
                else "none")
    triage_info = (r.deterministic or {}).get("triage") or {}
    # 逐文件把初筛失败也写出来（2026-10-08 修）：失败 ≠ 未达门槛，原来失败在 HTML 里
    # 只显示"未送（静默）"，读报告的人分不清"初筛说它不值得看"和"初筛没跑成"。
    triage_error = str(triage_info.get("error") or "")
    if triage_info.get("tier") == "drop":
        triage_none_extra = f"·初筛 {triage_info.get('score')} 未达门槛"
    elif triage_info.get("enabled") and triage_info.get("score") is None and triage_error:
        triage_none_extra = (f"·<b class='error'>初筛失败</b>"
                             f"<span class='dim'>（{_esc(triage_error[:120])}）</span>")
    else:
        triage_none_extra = ""
    tier_label = {"high": "高档送审", "low": "低档送审",
                  "triage": f"初筛送审（{triage_info.get('score')} 分）",
                  "none": "未送（静默）"}[tier]
    tier_html = ({"high": "<span style='color:#555'>高档送审</span>",
                  "low": "<b style='color:#ef6c00'>低档送审</b>",
                  "triage": (f"<b style='color:#6a1b9a'>初筛送审</b>"
                             f"<span class='dim'>（初筛 {triage_info.get('score')}/100 · "
                             f"门槛 {triage_info.get('threshold')}）</span>"),
                  "none": ("<span class='dim'>未送（静默" + triage_none_extra
                           + "）</span>")}[tier])
    # 置信度这一列：走 AI 的是**模型给的**置信度；没走 AI 的是规则兜底那几条
    # （0.65/0.75 这种常量），必须标出来 —— 否则读报告的人会把规则置信度当成 AI 置信度。
    conf_cell = (f"{r.verdict.confidence:.2f}" if r.agent_used
                 else f"<span class='dim'>{r.verdict.confidence:.2f} 规则</span>")

    search_text = " ".join([r.path, r.verdict.category or "", r.verdict.summary or "",
                            " ".join(r.yara_hits or []), tier_label])
    return f"""
            <tr data-risk="{_esc(r.verdict.risk.value)}" data-ext="{_esc(r.extension or '(none)')}"
                data-cat="{_esc(r.verdict.category or 'unknown')}" data-error="{1 if r.error else 0}"
                data-retried="{1 if rt.get('retried') else 0}"
                data-degraded="{1 if rt.get('outcome') == 'degraded_to_rules' else 0}"
                data-deepdive="{1 if au.get('deep_dive') else 0}"
                data-preloaded="{1 if pl.get('tools') else 0}"
                data-deepskipped="{1 if pl.get('deep_forensics') == 'skipped' else 0}"
                data-tier="{tier}"
                data-triagecand="{1 if triage_info.get('candidate') else 0}"
                data-text="{_esc(search_text.lower())}" data-idx="{index}">
              <td><code>{_esc(r.path)}</code>{error}</td>
              <td><span class="badge" style="background:{color}">{_esc(r.verdict.risk.value)}</span>
                  <div class="disp">score={r.prefilter_score} · {tier_html}</div></td>
              <td>{conf_cell}</td>
              <td>{_esc(r.verdict.category)}</td>
              <td>{_esc(r.verdict.summary)}</td>
              <td>{'是' if r.agent_used else '否'}{retry_html}{usage_html}</td>
              <td>{trace_cell}</td>
              <td>{disp_html or '-'}{pack_html}{sample_html}</td>
              <td>{evidence_html}{warnings_html}{sources_html}{policy_html}{proposals_html}{trace_html}</td>
            </tr>"""


def _dimension_table(title: str, dim: str, rows: list[dict[str, Any]]) -> str:
    """三维聚合表：计数 / 占比 / 失败数 / 失败率，表头可排序，点行可按该值筛选明细。"""
    body = "".join(
        f"<tr data-dim='{_esc(dim)}' data-value='{_esc(r['value'])}'>"
        f"<td><code>{_esc(r['value'])}</code></td>"
        f"<td>{r['count']}</td>"
        f"<td>{r['share']*100:.1f}%</td>"
        f"<td>{r['errors']}</td>"
        f"<td>{r['error_rate']*100:.1f}%</td></tr>"
        for r in rows
    )
    return (f"<div class='dimb'><h3>{_esc(title)}（{len(rows)} 类）</h3>"
            "<table class='dim'><thead><tr>"
            "<th onclick=\"sortDim(this,0)\">值</th><th onclick=\"sortDim(this,1)\">计数</th>"
            "<th onclick=\"sortDim(this,2)\">占比</th><th onclick=\"sortDim(this,3)\">失败数</th>"
            "<th onclick=\"sortDim(this,4)\">失败率</th></tr></thead>"
            f"<tbody>{body}</tbody></table></div>")


def _card(label: str, value: object, color: str = "#1565c0") -> str:
    return f"<div class='card'><span>{_esc(label)}</span><b style='color:{color}'>{_esc(value)}</b></div>"


def _kv_table(title: str, data: dict[str, Any]) -> str:
    if not data:
        return ""
    rows = "".join(f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in data.items())
    return f"<h3>{_esc(title)}</h3><table class='mini'>{rows}</table>"


def _render_html(reports: list[FileReport], summary: dict[str, Any] | None = None) -> str:
    summary = summary or build_summary(reports)
    total = summary["total"]
    risk = summary["risk"]
    ev = summary["evidence"]

    rows = "".join(_file_row(r, i) for i, r in enumerate(reports))

    from aiav.assemblyline_view import criteria_catalog

    catalog = criteria_catalog()
    catalog_html = (
        "<table><thead><tr><th>判据 ID</th><th>名字</th><th>分</th><th>上限</th>"
        "<th>适用类型</th><th>产出工具</th><th>ATT&amp;CK</th><th>档位</th></tr></thead><tbody>"
        + "".join(
            "<tr>"
            f"<td><code>{_esc(c['heur_id'])}</code></td>"
            f"<td>{_esc(c['name'])}<div class='meta'>{_esc(c['description'][:160])}</div></td>"
            f"<td>{c['score']}</td>"
            f"<td>{'' if c['max_score'] is None else c['max_score']}</td>"
            f"<td>{_esc(c['filetype'])}</td>"
            f"<td>{_esc(c['produced_by'])}</td>"
            f"<td>{_esc('、'.join(a['attack_id'] + ' ' + (a.get('name') or '') for a in c['attack']) or '-')}</td>"
            f"<td>{'确定性结案' if c['conclusive'] else ('强可疑' if c['score'] >= 500 else '弱信号')}"
            f"{'（判干净）' if c['direction'] == 'clean' else ''}</td>"
            "</tr>"
            for c in catalog)
        + "</tbody></table>"
    )

    warnings_block = ""
    if summary["top_warnings"]:
        warnings_block = _details(
            f"⚠ 全文断言告警 TOP {len(summary['top_warnings'])}",
            "<ul class='warn'>" + "".join(f"<li>{_esc(w)}</li>" for w in summary["top_warnings"]) + "</ul>",
            open_=True)

    sampling_note = ""
    if summary["sampling"]["files_with_multiple_samples"]:
        rate = float(summary["sampling"]["mean_agreement"] or 0) * 100
        sampling_note = (f"<div class='meta'>多次采样：{summary['sampling']['files_with_multiple_samples']} "
                         f"个文件，平均一致性 {rate:.0f}%</div>")

    # 重试/降级说明（2026-09-26 修①）：降级不是"没发生"，必须显式写在报告抬头
    retry_note = ""
    retry = summary["retry"]
    if retry["files_with_retry"] or retry["files_degraded"]:
        kinds = "、".join(f"{k}×{v}" for k, v in retry["failure_kinds"].items()) or "无"
        retry_note = (
            f"<div class='meta'>模型调用重试：{retry['files_with_retry']} 个文件用过重试"
            f"（共 {retry['retry_count']} 次）；<b class='error'>"
            f"{retry['files_degraded']} 个文件最终降级到规则判定</b>"
            f"（降级文件的 risk 不是 AI 结论，见明细行）。失败类型：{_esc(kinds)}</div>")

    # 证据前置 / 工具调用说明（2026-09-27）：让读报告的人一眼看出"这次判定用了几次工具调用、
    # 有没有走深挖路径"。平均调用次数是这套设计最核心的一个数，不能只藏在逐文件明细里。
    usage_note = ""
    usage = summary["usage"]
    preload = summary["preload"]
    if summary["agent_used"]:
        avg_calls = usage["tool_calls"] / max(1, summary["agent_used"])
        bits = [f"工具调用 {usage['tool_calls']} 次（平均 <b>{avg_calls:.1f}</b> 次/文件）",
                f"走深挖路径 {usage['files_deep_dive']} 个文件",
                f"纯读预采集证据 {usage['files_no_tool_call']} 个文件"]
        if usage["tokens"]:
            bits.append(f"模型消耗 {usage['tokens']:,} token"
                        f"（平均 {usage['tokens'] / max(1, summary['agent_used']):,.0f}/文件）")
        if usage["by_tool"]:
            bits.append("AI 自调工具：" + "、".join(
                f"{_esc(k)}×{v}" for k, v in sorted(usage["by_tool"].items(),
                                                    key=lambda kv: -kv[1])[:6]))
        usage_note = f"<div class='meta'>{' ｜ '.join(bits)}</div>"
    if preload["files_preloaded"]:
        pl_bits = [f"{preload['files_preloaded']} 个文件做过确定性证据前置",
                   f"共 {preload['chars']:,} 字符",
                   f"本地采集 {preload['ms'] / 1000:.1f}s（0 token）"]
        if preload["tools"]:
            pl_bits.append("预采集工具：" + "、".join(
                f"{_esc(k)}×{v}" for k, v in sorted(preload["tools"].items(),
                                                    key=lambda kv: -kv[1])))
        if preload["truncated"]:
            pl_bits.append(f"<b class='warn'>{preload['truncated']} 个文件的证据块超预算已降级</b>")
        if preload.get("deep_skipped"):
            # 分流·取证层：**必须在抬头就说**，否则"没报注入能力"会被读成"查过了没有"
            pl_bits.append(
                f"<b class='warn'>{preload['deep_skipped']} 个文件跳过深度取证"
                f"（capa/floss 未跑，只给轻量证据）</b>"
            )
            pl_bits.append(f"深度取证已跑 {preload.get('deep_done', 0)} 个文件")
        usage_note += f"<div class='meta'>{' ｜ '.join(pl_bits)}</div>"

    trace_table = {"结论条数（AI 档）": ev["ai_claims"],                   "有工具出处": ev["attributed"],
                   "无出处（模型推断）": ev["unattributed"],
                   "有出处率（AI 档口径）": _rate_text(ev["attributed_rate"], digits=1),
                   "确定性判定断言（未走 AI，不计入出处率）": ev["deterministic_claims"],
                   "全批结论条数": ev["all_claims"],
                   "断言告警": ev["claim_warnings"],
                   "告警/千条结论": ev["warnings_per_1000_claims"]}
    pack_table = {"检出加壳": summary["packing"]["packed"],
                  "成功脱壳": summary["packing"]["unpacked_ok"]}

    # ---- ①层账本（2026-09-27）----
    det = summary["deterministic"]
    low = det.get("low_tier") or {}
    tiers = det.get("ai_tiers") or {}
    if det.get("gate_low") and 0 < det["gate_low"] < det["gate"]:
        conf_txt = ("AI 置信度 " + (
            f"{low['confidence_min']:.2f}~{low['confidence_max']:.2f}"
            f"（均值 {low['confidence_mean']:.2f}）" if low.get("confidence_mean") is not None
            else "N/A"))
        low_note = (
            f"<div class='meta'><b>两档送审</b>：高档 <b>≥{det['gate']}</b> {det.get('sent_high', 0)} 个 · "
            f"低档 <b>{det['gate_low']}~{det['gate'] - 1}</b>（<b>也送 AI</b>）"
            f"{det.get('sent_low', 0)} 个 —— 其中 AI 真判了 {low.get('ai_files', 0)} 个、"
            f"判 flag {low.get('flagged', 0)} 个、{conf_txt}"
            f"{f'、<b class="error">降级到规则 {low["degraded"]} 个</b>' if low.get('degraded') else ''}"
            f" · 静默放行（<b>&lt;{det['gate_low']}</b>，不送、不下结论）{tiers.get('none', 0)} 个。"
            "低档与高档走的是**同一条送审路径**，只差报告字段 <code>ai_tier</code>。</div>")
    else:
        low_note = ("<div class='meta'>两档送审：<b>低档已关闭</b>（这一轮是单档闸门 "
                    f"≥{det['gate']}）—— 低档送审 {det.get('sent_low', 0)} 个。</div>")
    det_note = (
        "<div class='meta'>①层（确定性）闸门 <b>" + str(det["gate"]) + "</b> 分"
        "（Assemblyline 刻度，= 上游 verdict.suspicious）。"
        f"送审率 <b>{det['send_rate']*100:.1f}%</b>（{det['sent']}/{total}）· "
        f"纯①层结案 <b>{det['closed_rate']*100:.1f}%</b>"
        f"（判恶意 {det['closed_malicious']} + 判干净 {det['closed_clean']}）· "
        f"未结案 <b>{det['unresolved']}</b>（<b>未结案 ≠ 判白</b>，只是没线索、不值得花 token）。"
        + (f" <b class='error'>⚠ {det['files_with_unclassified_signals']} 个文件有未分类信号："
           f"{_esc('、'.join(det['unclassified_signals']))} —— 有信号加了分却没进判据表，"
           "这批数字按核验铁律作废。</b>" if det["files_with_unclassified_signals"] else "")
        + "</div>")
    det_note += low_note
    triage = det.get("triage") or {}
    if triage.get("enabled"):
        # ②层的抬头账：候选/选中/放行/没拿到分数，与它挑出来之后 ③ 判成什么。
        triage_note = (
            "<div class='meta'><b>②层 LLM 初筛</b>：入口 <b>≥"
            f"{triage.get('entry_gate')}</b>（未结案）· 门槛 <b>{triage.get('threshold')}</b> · "
            f"模型 <code>{_esc(str(triage.get('model') or ''))}</code> —— "
            f"候选 <b>{triage.get('candidates', 0)}</b> 个 → 选中送 ③ "
            f"<b>{triage.get('selected', 0)}</b> 个（其中 ③ 真判了 {triage.get('ai_files', 0)} 个、"
            f"判 flag {triage.get('flagged', 0)} 个）· 未达门槛静默放行 "
            f"{triage.get('dropped', 0)} 个 · <b>没拿到分数 {triage.get('no_score', 0)} 个</b>"
            "（没拿到分数 <b>不算没过门槛</b> —— 那是调用故障，不是判定）。"
            "⚠️ <b>送审率 ≠ 误报率</b>：初筛只回答『值不值得花钱看』，"
            "判白是 ③ 深度 AI 的事。</div>")
    else:
        triage_note = ("<div class='meta'>②层 LLM 初筛：<b>这一轮没开</b>"
                       "（默认关；打开用 <code>--triage</code> 或 <code>AI_AV_TRIAGE=1</code>）。</div>")
    det_note += triage_note
    unavailable = det.get("unavailable_detections") or []
    unavailable_note = (
        "<div class='meta'><b>未安装 / 未配置的检测项（这些判据在本批里是空的，不是『跑了没问题』）：</b>"
        + _esc("；".join(unavailable)) + "</div>"
    ) if unavailable else ""
    det_table = "".join(
        f"<tr><td><code>{_esc(k)}</code></td><td>{_esc(v)}</td></tr>"
        for k, v in sorted(det["criteria_fired"].items(), key=lambda kv: -kv[1]))

    def _options(rows: list[dict[str, Any]]) -> str:
        return "".join(f"<option value='{_esc(r['value'])}'>{_esc(r['value'])}（{r['count']}）</option>"
                       for r in rows)

    ext_options = _options(summary["dimensions"]["extension"])
    cat_options = _options(summary["dimensions"]["category"])

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>「第二意见」AI 恶意文件研判台 · 扫描报告</title>
  <style>
    body {{ font-family: "Segoe UI", Arial, "Microsoft YaHei", sans-serif; margin: 24px; color: #222; background: #fafafa; }}
    h1 {{ margin-bottom: 4px; }}
    h2 {{ margin: 22px 0 8px; font-size: 17px; }}
    h3 {{ margin: 14px 0 6px; font-size: 14px; }}
    .meta {{ color: #666; font-size: 13px; }}
    .cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 16px 0 8px; }}
    .card {{ padding: 10px 16px; border-radius: 8px; background: #fff; border: 1px solid #e5e5e5; min-width: 96px; }}
    .card span {{ display: block; font-size: 12px; color: #666; }}
    .card b {{ font-size: 22px; }}
    .panels {{ display: flex; flex-wrap: wrap; gap: 22px; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; }}
    th, td {{ border: 1px solid #e0e0e0; padding: 8px; vertical-align: top; text-align: left; font-size: 13px; }}
    th {{ background: #f0f0f0; cursor: pointer; }}
    table.mini {{ width: auto; min-width: 220px; }}
    table.mini td {{ font-size: 12px; padding: 4px 8px; }}
    code {{ word-break: break-all; font-size: 12px; }}
    ul {{ margin: 4px 0; padding-left: 18px; }}
    .badge {{ color: #fff; padding: 3px 8px; border-radius: 10px; font-size: 12px; }}
    .error {{ color: #c62828; }}
    .warn {{ color: #b71c1c; }}
    .dim {{ color: #999; }}
    .src {{ color: #666; font-size: 12px; }}
    .disp {{ font-size: 11px; color: #555; word-break: break-all; margin-top: 4px; }}
    details summary {{ cursor: pointer; font-size: 12px; color: #444; }}
    .toolbar {{ display: flex; gap: 8px; align-items: center; margin: 10px 0; flex-wrap: wrap; }}
    .toolbar input {{ padding: 6px 10px; border: 1px solid #ccc; border-radius: 6px; min-width: 260px; }}
    .toolbar button {{ padding: 6px 12px; border: 1px solid #ccc; background: #fff; border-radius: 6px; cursor: pointer; }}
    .toolbar button.on {{ background: #1565c0; color: #fff; border-color: #1565c0; }}
  </style>
</head>
<body>
  <h1>「第二意见」AI 恶意文件研判台</h1>
  <div class="meta">扫描报告（AI AV Agent）</div>
  <div class="meta">生成时间：{_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} ｜ 文件数：{total}
   ｜ 每条结论都标注证据来源（工具名 + 原始输出片段），可展开核对</div>
  {_details("统计口径说明（出处率为什么是 N/A）",
            "<p>「结论有出处率」只在 <b>AI 研判过的文件</b>（上卡「AI 研判 "
            f"{summary['agent_used']}」）上统计 —— 未走 AI 的文件是确定性判定"
            "（规则 / 哈希 / 低分放行），没有模型断言，不进这个分母；没走 AI 的结论标 "
            "<code>确定性判定</code>，不走 AI 的批次出处率显示 <b>N/A</b>（不是 0%）。</p>")}

  <div class="cards">
    {_card("总数", total)}
    {_card("安全", risk["clean"], "#2e7d32")}
    {_card("可疑", risk["suspicious"], "#ef6c00")}
    {_card("恶意", risk["malicious"], "#c62828")}
    {_card("AI 研判", summary["agent_used"])}
    {_card("已隔离", summary["disposition"]["quarantined"], "#c62828")}
    {_card("已白名单", summary["disposition"]["whitelisted"], "#2e7d32")}
    {_card("结论有出处率", _rate_text(ev["attributed_rate"]), "#1565c0")}
    {_card("断言告警", ev["claim_warnings"], "#b71c1c")}
    {_card("重试过", summary["retry"]["files_with_retry"], "#1565c0")}
    {_card("降级到规则", summary["retry"]["files_degraded"], "#c62828")}
    {_card("走深挖路径", summary["usage"]["files_deep_dive"], "#1565c0")}
    {_card("纯读预采集证据", summary["usage"]["files_no_tool_call"], "#2e7d32")}
    {_card("送审率", f"{det['send_rate']*100:.1f}%", "#c62828")}
    {_card("高档送审", det.get('sent_high', 0), "#c62828")}
    {_card("低档送审（也送 AI）", det.get('sent_low', 0), "#ef6c00")}
    {_card("初筛选中送 ③", det.get('sent_triage', 0), "#6a1b9a")}
    {_card("①层结案率", f"{det['closed_rate']*100:.1f}%", "#2e7d32")}
    {_card("确定性判恶意", det["closed_malicious"], "#c62828")}
    {_card("确定性判干净", det["closed_clean"], "#2e7d32")}
    {_card("未结案（≠判白）", det["unresolved"], "#ef6c00")}
  </div>
  {det_note}
  {unavailable_note}
  {sampling_note}
  {retry_note}
  {usage_note}
  {warnings_block}

  <h2>聚合视图</h2>
  <div class="meta">点击任意一行可按该值筛选下方明细；点表头排序。</div>
  <div class="panels">
    {_dimension_table("判定", "risk", summary["dimensions"]["risk"])}
    {_dimension_table("文件类型", "extension", summary["dimensions"]["extension"])}
  </div>
  {_details("更多聚合（家族 / 预筛分档 / 处置 / YARA / 策略 / 溯源 / 加壳）",
            "<div class='panels'>"
            + _dimension_table("家族（判定类别）", "category", summary["dimensions"]["category"])
            + "<div>" + _kv_table("按预筛分档", summary["by_score_band"])
            + _kv_table("处置状态", summary["disposition"])
            + _kv_table("YARA 命中 TOP", summary["yara_top"]) + "</div>"
            + "<div>" + _kv_table("策略动作", summary["policy_actions"])
            + _kv_table("证据溯源", trace_table)
            + _kv_table("加壳处理", pack_table)
            + _kv_table("载荷判定", summary["packing"]["payload_verdicts"]) + "</div>"
            + "</div>")}

  <h2>①层判据表（照 Assemblyline 三档语义）</h2>
  <div class="meta">判据表就是代码里的那张表（<code>aiav/criteria.py</code>），
  报告里原样列出来 —— 每条判据的名字 / 分数 / 上限 / 适用类型 / 产出工具 / ATT&amp;CK
  都能当场核对，不是"总分多少、来源不明"。</div>
  {_details("本批判据命中计数", "<table class='mini'>" + det_table + "</table>")}
  {_details("判据全表（" + str(len(catalog)) + " 条）", catalog_html)}

  <h2>逐文件结果</h2>
  <div class="toolbar">
    <input id="q" placeholder="过滤：文件名 / 类别 / 结论 / YARA…" oninput="applyFilter()">
    <button class="on" data-risk="all" onclick="setRisk(this)">全部</button>
    <button data-risk="malicious" onclick="setRisk(this)">只看恶意</button>
    <button data-risk="suspicious" onclick="setRisk(this)">只看可疑</button>
    <button data-risk="clean" onclick="setRisk(this)">只看安全</button>
    <select id="fExt" onchange="applyFilter()"><option value="">全部类型</option>{ext_options}</select>
    <select id="fCat" onchange="applyFilter()"><option value="">全部家族</option>{cat_options}</select>
    <button data-risk="__error__" onclick="setRisk(this)">只看失败</button>
    <button data-risk="__retried__" onclick="setRisk(this)">只看重试</button>
    <button data-risk="__degraded__" onclick="setRisk(this)">只看降级到规则</button>
    <button data-risk="__deepdive__" onclick="setRisk(this)">只看走了深挖</button>
    <button data-risk="__preloaded__" onclick="setRisk(this)">只看证据前置</button>
    <button data-risk="__deepskipped__" onclick="setRisk(this)">只看跳过深度取证</button>
    <button data-risk="__lowtier__" onclick="setRisk(this)">只看低档送审</button>
    <button data-risk="__triagetier__" onclick="setRisk(this)">只看初筛送审</button>
    <button data-risk="__triagecand__" onclick="setRisk(this)">只看跑过初筛</button>
    <button data-risk="__highorlow__" onclick="setRisk(this)">只看送过 AI（三档）</button>
    <span class="dim" id="cnt"></span>
  </div>
  <table id="t">
    <thead>
      <tr>
        <th onclick="sortBy(0)">文件</th><th onclick="sortBy(1)">风险</th><th onclick="sortBy(2)">置信度</th>
        <th onclick="sortBy(3)">类别</th><th onclick="sortBy(4)">结论</th><th onclick="sortBy(5)">AI</th>
        <th onclick="sortBy(6)">溯源</th>
        <th onclick="sortBy(7)">处置 / 加壳 / 采样</th><th>证据（含来源与策略审计）</th>
      </tr>
    </thead>
    <tbody id="tb">
      {rows}
    </tbody>
  </table>

  <script>
  var curRisk = 'all', curExt = '', curCat = '';
  function applyFilter() {{
    var q = (document.getElementById('q').value || '').toLowerCase();
    var fe = document.getElementById('fExt'), fc = document.getElementById('fCat');
    curExt = fe ? fe.value : '';
    curCat = fc ? fc.value : '';
    var rows = document.querySelectorAll('#tb tr');
    var shown = 0;
    for (var i = 0; i < rows.length; i++) {{
      var r = rows[i];
      var okRisk = (curRisk === 'all')
        || (curRisk === '__error__' ? r.getAttribute('data-error') === '1'
          : curRisk === '__retried__' ? r.getAttribute('data-retried') === '1'
          : curRisk === '__degraded__' ? r.getAttribute('data-degraded') === '1'
          : curRisk === '__deepdive__' ? r.getAttribute('data-deepdive') === '1'
          : curRisk === '__deepskipped__' ? r.getAttribute('data-deepskipped') === '1'
          : curRisk === '__preloaded__' ? r.getAttribute('data-preloaded') === '1'
          : curRisk === '__lowtier__' ? r.getAttribute('data-tier') === 'low'
          : curRisk === '__triagetier__' ? r.getAttribute('data-tier') === 'triage'
          : curRisk === '__triagecand__' ? r.getAttribute('data-triagecand') === '1'
          : curRisk === '__highorlow__' ? r.getAttribute('data-tier') !== 'none'
                                      : r.getAttribute('data-risk') === curRisk);
      var okExt = !curExt || r.getAttribute('data-ext') === curExt;
      var okCat = !curCat || r.getAttribute('data-cat') === curCat;
      var okText = !q || (r.getAttribute('data-text') || '').indexOf(q) >= 0;
      var vis = okRisk && okExt && okCat && okText;
      r.style.display = vis ? '' : 'none';
      if (vis) shown++;
    }}
    var c = document.getElementById('cnt');
    if (c) c.textContent = '显示 ' + shown + ' / ' + rows.length + ' 个文件';
  }}
  function filterBy(dim, value) {{
    if (dim === 'risk') {{ curRisk = value; }}
    else if (dim === 'extension') {{ var fe = document.getElementById('fExt'); if (fe) fe.value = value; }}
    else if (dim === 'category') {{ var fc = document.getElementById('fCat'); if (fc) fc.value = value; }}
    applyFilter();
  }}
  // 维度表筛选：只从 data-* 读值，**不做任何 JS 字符串拼接** ——
  // 表格值来自文件名后缀 / AI 自由填写的 category，属于不可信数据。
  // （旧实现把值内联进 onclick="filterBy('…')"，HTML 属性解码一次后能闭合 JS 字符串 → XSS）
  document.querySelectorAll('table.dim').forEach(function(tb) {{
    tb.addEventListener('click', function(e) {{
      var tr = e.target.closest('tr');
      if (!tr || !tr.dataset.dim) return;
      filterBy(tr.dataset.dim, tr.dataset.value || '');
    }});
  }});
  function sortDim(th, col) {{
    var tb = th.closest('table').querySelector('tbody');
    var rows = Array.prototype.slice.call(tb.querySelectorAll('tr'));
    var dir = th.getAttribute('data-dir') === 'asc' ? -1 : 1;
    th.setAttribute('data-dir', dir === 1 ? 'asc' : 'desc');
    rows.sort(function(a, b) {{
      var x = a.children[col].innerText.trim(), y = b.children[col].innerText.trim();
      var nx = parseFloat(x.replace('%', '')), ny = parseFloat(y.replace('%', ''));
      if (!isNaN(nx) && !isNaN(ny) && col > 0) return (nx - ny) * dir;
      return x.localeCompare(y) * dir;
    }});
    rows.forEach(function(r) {{ tb.appendChild(r); }});
  }}
  function setRisk(btn) {{
    curRisk = btn.getAttribute('data-risk');
    var btns = document.querySelectorAll('.toolbar button');
    for (var i = 0; i < btns.length; i++) btns[i].className = '';
    btn.className = 'on';
    applyFilter();
  }}
  applyFilter();
  var sortDir = {{}};
  function sortBy(col) {{
    var tb = document.getElementById('tb');
    var rows = Array.prototype.slice.call(tb.querySelectorAll('tr'));
    sortDir[col] = !sortDir[col];
    var dir = sortDir[col] ? 1 : -1;
    rows.sort(function(a, b) {{
      var x = a.children[col].innerText.trim(), y = b.children[col].innerText.trim();
      var nx = parseFloat(x), ny = parseFloat(y);
      if (!isNaN(nx) && !isNaN(ny)) return (nx - ny) * dir;
      return x.localeCompare(y) * dir;
    }});
    for (var i = 0; i < rows.length; i++) tb.appendChild(rows[i]);
  }}
  </script>
</body>
</html>"""
