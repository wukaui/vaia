"""报告结构 —— 照 Assemblyline 的 `Result` 模型摆证据链。

我们照它的模型摆证据不是为了好看，是为了让报告**能过它的 schema**：
`build_result()` 的产物会被**上游包里那个真的** `assemblyline.odm.models.result.Result`
校验一遍，校验不过就是 bug（`tests/test_assemblyline_view.py` 盯着这条）。

字段对应关系（左边是我们的，右边是上游的）：

    判据            → `result.sections[].heuristic`：名字 + 说明 + ATT&CK + `signature[]`
    依据            → `heuristic.signature[].frequency`（命中**次数**）
                      + `signature[].safe`（**是否白名单**）
    证据段          → `result.sections[]`：`title_text` + 结构化 `body` + `tags`
                      + `safelisted_tags`（写清这段为什么没算分）
    服务            → `response.service_name` + `service_tool_version`（工具版本 = 可复现）
    文件血缘        → `response.extracted[].parent_relation`（ROOT/EXTRACTED/DOWNLOADED…）
    分数            → `result.score`（各段求和）+ 提交级取最高文件分

`tags` 用的是上游 `Tagging` 模型里的**真实字段**（266 个字段的那份），
不是我们自己造的键 —— 否则校验过不去，也就谈不上"照它改"。
"""

from __future__ import annotations

import importlib.metadata as md
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aiav.criteria import CRITERIA, band_label
from aiav.models import FileReport

#: 上游 `File.parent_relation` 的取值：ROOT / EXTRACTED / INFORMATION / DYNAMIC / MEMDUMP / DOWNLOADED
PARENT_ROOT = "ROOT"
PARENT_EXTRACTED = "EXTRACTED"
PARENT_DOWNLOADED = "DOWNLOADED"

SERVICE_NAME = "aiav-deterministic"

#: 工具版本要写进报告，否则"这条证据是哪个版本的工具产出的"说不清 = 不可复现。
_TOOL_PACKAGES = (
    ("capa", "flare-capa"),
    ("yara-python", "yara-python"),
    ("pefile", "pefile"),
    ("oletools", "oletools"),
    ("pypdf", "pypdf"),
    ("floss", "flare-floss"),
    ("asn1crypto", "asn1crypto"),
    ("cryptography", "cryptography"),
)


def tool_versions() -> dict[str, str]:
    out: dict[str, str] = {}
    for label, pkg in _TOOL_PACKAGES:
        try:
            out[label] = md.version(pkg)
        except md.PackageNotFoundError:
            out[label] = "not installed"
    return out


def service_tool_version() -> str:
    return "; ".join(f"{k} {v}" for k, v in tool_versions().items())


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _aiav_version() -> str:
    try:
        from aiav import __version__ as v  # noqa: PLC0415

        return str(v)
    except Exception:  # noqa: BLE001
        return "0.0.0"


# --------------------------------------------------------------------------------------
# tags：只用上游 Tagging 模型里真实存在的字段
# --------------------------------------------------------------------------------------
def _tags_for(report: FileReport, hits: list[dict]) -> dict[str, Any]:
    tags: dict[str, Any] = {}

    extracted = [
        f.get("name")
        for f in ((report.archive or {}).get("children") or [])
        if f.get("name")
    ]
    if extracted:
        tags.setdefault("file", {})["name"] = {"extracted": extracted[:20]}

    yara = [h for r in hits for h in (r.get("signature") or []) if r["heur_id"] in
            ("STRONG_YARA", "WEAK_YARA")]
    if yara:
        tags.setdefault("file", {})["rule"] = {"yara": [s["name"] for s in yara][:20]}

    av = [s["name"] for r in hits if r["heur_id"] in ("DET_CLAMAV_SIGNATURE", "DET_EICAR")
          for s in (r.get("signature") or [])]
    if av:
        tags["av"] = {"virus_name": av[:20]}

    ids = {h["heur_id"] for h in hits}
    technique: list[str] = []
    if "PACKING" in ids:
        technique.append("packer")
    if ids & {"MACRO_PRESENT", "MACRO_PATTERN", "XLM_PRESENT", "XLM_EXEC_PATTERN"}:
        technique.append("macro")
    if ids & {"XLM_CHAR_CELLS", "STRUCT_TEXT_RATIO", "STRUCT_EP_NOT_EXECUTABLE"}:
        technique.append("obfuscation")
    if "STRONG_YARA" in ids:
        technique.append("string")
    if technique:
        tags["technique"] = {t: [t] for t in technique}

    return tags


def _safelisted_tags(report: FileReport, hits: list[dict]) -> dict[str, list[str]]:
    """写清"这一段为什么没算分"。

    上游语义：一条判据下的签名全部 safe → 该判据分数归零。
    我们照抄这个形状，把"归零的原因"逐条写出来，而不是让读者自己猜为什么分数是 0。
    """
    out: dict[str, list[str]] = {}
    for h in hits:
        if h.get("safelisted"):
            out.setdefault("file.rule.yara", []).append(
                f"{h['heur_id']}（{h['name']}）：命中的签名全部在白名单，按上游 Signature.safe 语义分数归零"
            )
    disposition = (report.deterministic or {}).get("disposition")
    if disposition == "closed_clean":
        for h in hits:
            if h.get("conclusive") and h.get("direction") == "clean":
                out.setdefault("file.behavior", []).append(
                    f"{h['heur_id']}（{h['name']}）：确定性结案判干净，本文件所有段分数归零、不送 AI"
                )
    return out


# --------------------------------------------------------------------------------------
# sections：一条判据 = 一段证据
# --------------------------------------------------------------------------------------
def _section_for(hit: dict, *, stats: dict[str, Any] | None, depth: int = 0) -> dict[str, Any]:
    # 上游 `Heuristic` 展开出来的形状是 {attack_id, pattern, categories}；
    # `pattern` 就是技术名（老版本我们自己的 lookup 给的是 `name`，两个都认）。
    attack = [
        {
            "attack_id": a.get("attack_id", ""),
            "pattern": a.get("pattern") or a.get("name") or a.get("attack_id", ""),
            "categories": a.get("categories", []),
        }
        for a in (hit.get("attack") or [])
    ]
    signature = [
        {"name": s["name"], "frequency": int(s.get("frequency", 1)), "safe": bool(s.get("safe"))}
        for s in (hit.get("signature") or [])
    ]
    st = (stats or {}).get(hit["heur_id"]) or {}
    body_lines = [
        hit.get("description") or "",
        "",
        f"判据 ID：{hit['heur_id']}",
        f"本条得分：{hit['score']}"
        + (f"（上限 {hit['max_score']}）" if hit.get("max_score") is not None else ""),
        f"适用文件类型：{hit.get('filetype') or '*'}",
        f"产出工具：{hit.get('produced_by') or '（未登记）'}",
        f"方向：{'判恶意' if hit.get('direction') == 'malicious' else ('判干净' if hit.get('direction') == 'clean' else '可疑')}"
        + ("（确定性结案级）" if hit.get("conclusive") else ""),
    ]
    if st:
        body_lines.append(
            "历史统计：命中 {count} 次 · 均分 {avg} · 区间 [{min}, {max}] · 首次 {first_hit} · 最近 {last_hit}".format(
                count=st.get("count", 0), avg=st.get("avg", 0), min=st.get("min", 0),
                max=st.get("max", 0), first_hit=(st.get("first_hit") or "")[:19],
                last_hit=(st.get("last_hit") or "")[:19],
            )
        )
    return {
        "title_text": f"{hit['name']}（{hit['heur_id']}）",
        "body": "\n".join(body_lines),
        "body_format": "KEY_VALUE",
        "classification": "UNRESTRICTED",
        "depth": depth,
        "auto_collapse": False,
        "heuristic": {
            "heur_id": hit["heur_id"],
            "name": hit["name"],
            "score": int(hit["score"]),
            "attack": attack,
            "signature": signature,
        },
    }


# --------------------------------------------------------------------------------------
# 文件血缘
# --------------------------------------------------------------------------------------
def _extracted_entries(report: FileReport) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    children = (report.archive or {}).get("children") or []
    for child in children:
        out.append({
            "name": child.get("name") or "?",
            "sha256": child.get("sha256") or ("0" * 64),
            "description": child.get("detail") or child.get("kind") or "压缩包/容器解出的文件",
            "classification": "UNRESTRICTED",
            "parent_relation": PARENT_EXTRACTED,
        })
    unpack = ((report.packing or {}).get("unpack") or {})
    if unpack.get("ok") and unpack.get("path"):
        out.append({
            "name": Path(unpack["path"]).name,
            "sha256": unpack.get("sha256") or ("0" * 64),
            "description": f"静态脱壳产物（{unpack.get('packer') or '未知壳'}）",
            "classification": "UNRESTRICTED",
            "parent_relation": PARENT_EXTRACTED,
        })
    return out


# --------------------------------------------------------------------------------------
# 主入口
# --------------------------------------------------------------------------------------
def build_result(
    report: FileReport,
    *,
    stats: dict[str, Any] | None = None,
    parent_sha256: str | None = None,
) -> dict[str, Any]:
    """把一个 `FileReport` 摆成 Assemblyline `Result` 的形状（纯 dict，可直接进 JSON）。"""
    hits = list(report.criteria_hits or [])
    # `safelisted_tags` 是上游 `Section` 的字段：写清**这一段为什么没算分**。
    # 归零的判据自己也要进报告 —— "分数 0"必须带原因，否则读者会以为是漏算。
    safelisted = _safelisted_tags(report, hits)
    sections = [_section_for(h, stats=stats) for h in hits if h.get("score")]
    for section in sections:
        section["safelisted_tags"] = safelisted

    # 分数为 0 的判据（比如"XLM 信息类模式，不计分"）也进报告 —— 它是**留痕**，
    # 不是结论。不写进去，读者就不知道我们看过这一面。
    zero_sections = [
        _section_for(h, stats=stats)
        for h in hits
        if not h.get("score") and not h.get("safelisted")
    ]
    for section in zero_sections:
        section["safelisted_tags"] = safelisted
    # 上游 `Section` 不允许空 tags 之外的怪东西，但允许 sections 为空列表；
    # 一条判据都没命中的文件也要有结论段，否则报告里这个文件是"空白"，看不出跑没跑。
    if not sections and not zero_sections:
        sections = [{
            "title_text": "①层无判据命中",
            "body": "确定性层没有任何判据命中，也没有走 AI（未结案）。"
                    "⚠️ 这不等于判白 —— 只是『没线索，不值得花 token』。",
            "body_format": "TEXT",
            "classification": "UNRESTRICTED",
            "depth": 0,
            "heuristic": {"heur_id": "NO_CRITERION_HIT", "name": "无判据命中", "score": 0,
                          "attack": [], "signature": []},
        }]

    score = int(report.prefilter_score or 0)
    disposition = (report.deterministic or {}).get("disposition") or "unknown"

    payload: dict[str, Any] = {
        "sha256": report.sha256,
        "classification": "UNRESTRICTED",
        "created": _now_iso(),
        "type": (report.extension or "").lstrip(".") or "unknown",
        "size": int(report.size or 0),
        "response": {
            "milestones": {"service_started": _now_iso(), "service_completed": _now_iso()},
            "service_name": SERVICE_NAME,
            "service_version": _aiav_version(),
            "service_tool_version": service_tool_version(),
            "service_context": f"①层处置={disposition}",
            "extracted": _extracted_entries(report),
            "supplementary": [],
        },
        "result": {
            "score": score,
            "sections": sections + zero_sections,
        },
    }
    if parent_sha256:
        payload["response"]["service_context"] += f"；父文件 {parent_sha256[:16]}…"
    return payload


def build_submission(
    reports: list[FileReport],
    *,
    stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """提交级视图：**提交分 = 所有文件里最高的那个**（上游 `Submission.max_score`）。

    另外给出送审率/结案率的账 —— 这三个数才是产品的命，报告抬头必须先看见它们。
    """
    files = [build_result(r, stats=stats) for r in reports]
    file_scores = [int(f["result"]["score"]) for f in files]
    dispositions: dict[str, int] = {}
    for r in reports:
        d = (r.deterministic or {}).get("disposition") or "unknown"
        dispositions[d] = dispositions.get(d, 0) + 1

    n = len(reports) or 1
    # 同 `report.build_summary`：送审率 = ①层处置为 send_ai（或真的走过 AI）。
    # 用 `agent_used` 单独算会在 `--no-ai` 下得到 0%。
    sent = sum(1 for r in reports
               if (r.deterministic or {}).get("disposition") == "send_ai" or r.agent_used)
    # 两档送审（2026-09-27）：高档 / 低档分开数（口径与 `report.build_summary` 同一套字段）
    tiers: dict[str, int] = {"high": 0, "low": 0, "none": 0}
    for r in reports:
        t = (r.deterministic or {}).get("ai_tier")
        if t not in tiers:
            t = ("high" if ((r.deterministic or {}).get("disposition") == "send_ai"
                            or r.agent_used) else "none")
        tiers[t] = tiers.get(t, 0) + 1
    closed_mal = dispositions.get("closed_malicious", 0)
    closed_clean = dispositions.get("closed_clean", 0)
    passed = dispositions.get("pass", 0)

    return {
        "max_score": max(file_scores) if file_scores else 0,
        "file_count": len(reports),
        "files": [{"sha256": f["sha256"], "score": f["result"]["score"]} for f in files],
        "results": files,
        "deterministic": {
            "dispositions": dispositions,
            "ai_tiers": tiers,
            "sent_high": tiers.get("high", 0),
            "sent_low": tiers.get("low", 0),
            "send_rate": round(sent / n, 4),
            "closed_malicious_rate": round(closed_mal / n, 4),
            "closed_clean_rate": round(closed_clean / n, 4),
            "unresolved_rate": round(passed / n, 4),
            "band": band_label(max(file_scores) if file_scores else 0),
        },
    }


def validate_result(payload: dict[str, Any]) -> None:
    """用**上游包里那个模型**校验报告结构。校验不过就说明"照它改"没改到位。"""
    from assemblyline.odm.models.result import Result  # noqa: PLC0415

    Result(payload)


def criteria_catalog() -> list[dict[str, Any]]:
    """判据表本身，报告里要能查 —— 读者得知道每条判据的名字/上限/工具/ATT&CK。"""
    from aiav.assemblyline_core.attack_ids import describe  # noqa: PLC0415

    rows = []
    for crit in CRITERIA.values():
        rows.append({
            "heur_id": crit.heur_id,
            "name": crit.name,
            "description": crit.description,
            "score": crit.score,
            "max_score": crit.max_score,
            "filetype": crit.filetype,
            "produced_by": crit.produced_by,
            "direction": crit.direction.value,
            "conclusive": crit.conclusive,
            "attack": [
                {"attack_id": a, **(describe(a) or {})} for a in crit.attack_ids
            ],
        })
    return rows
