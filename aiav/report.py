from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from aiav.models import FileReport, RiskLevel

RISK_COLOR = {
    RiskLevel.clean: "#2e7d32",
    RiskLevel.suspicious: "#ef6c00",
    RiskLevel.malicious: "#c62828",
}

RISK_ORDER = {RiskLevel.clean: 0, RiskLevel.suspicious: 1, RiskLevel.malicious: 2}


def _band(score: int) -> str:
    if score == 0:
        return "0"
    if score <= 4:
        return "1-4"
    if score <= 11:
        return "5-11"
    return ">=12"


def build_summary(reports: list[FileReport]) -> dict[str, Any]:
    """报告聚合视图：风险 / 类型 / 处置 / 策略 / 采样 / 溯源 一屏看全。"""
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

    return {
        "total": len(reports),
        "errors": sum(1 for r in reports if r.error),
        "dimensions": dimensions,
        "risk": {k: risk.get(k, 0) for k in ("clean", "suspicious", "malicious")},
        "agent_used": sum(1 for r in reports if r.agent_used),
        "by_extension": dict(ext.most_common(12)),
        "by_category": dict(category.most_common(10)),
        "by_score_band": {b: band.get(b, 0) for b in ("0", "1-4", "5-11", ">=12")},
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
        },
        "aggregate": summary,
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
    search_text = " ".join([r.path, r.verdict.category or "", r.verdict.summary or "",
                            " ".join(r.yara_hits or [])])
    return f"""
            <tr data-risk="{_esc(r.verdict.risk.value)}" data-ext="{_esc(r.extension or '(none)')}"
                data-cat="{_esc(r.verdict.category or 'unknown')}" data-error="{1 if r.error else 0}"
                data-text="{_esc(search_text.lower())}" data-idx="{index}">
              <td><code>{_esc(r.path)}</code>{error}</td>
              <td><span class="badge" style="background:{color}">{_esc(r.verdict.risk.value)}</span>
                  <div class="disp">score={r.prefilter_score}</div></td>
              <td>{r.verdict.confidence:.2f}</td>
              <td>{_esc(r.verdict.category)}</td>
              <td>{_esc(r.verdict.summary)}</td>
              <td>{'是' if r.agent_used else '否'}</td>
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

    trace_table = {"结论条数（AI 档）": ev["ai_claims"],
                   "有工具出处": ev["attributed"],
                   "无出处（模型推断）": ev["unattributed"],
                   "有出处率（AI 档口径）": _rate_text(ev["attributed_rate"], digits=1),
                   "确定性判定断言（未走 AI，不计入出处率）": ev["deterministic_claims"],
                   "全批结论条数": ev["all_claims"],
                   "断言告警": ev["claim_warnings"],
                   "告警/千条结论": ev["warnings_per_1000_claims"]}
    pack_table = {"检出加壳": summary["packing"]["packed"],
                  "成功脱壳": summary["packing"]["unpacked_ok"]}

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
  </div>
  {sampling_note}
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
