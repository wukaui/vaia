"""确定性证据前置：送审前把确定性工具的输出**一次采齐**，渲染进送审上下文。

════ 为什么要有这个模块（2026-09-27 实测） ════

同一批 40 个 Dike pilot 样本（20 恶意 + 20 良性）从报告 JSON 里数出来的事实：

  · **平均 8.0 次工具调用/文件**（320 次 / 40 文件）。各工具的调用率精确接近
    1.00/文件（capa 40/40、pe_analyze 40/40、floss 39/40、strings 41/40）——
    等于**把工具清单从头到尾刷了一遍**，而提示词里自己写着"不要按固定顺序把工具跑一遍"。
    其中 `signature_verify` 1.88 次/文件（同一个文件验两遍）、`script_analyze` 对 .exe
    也跑（36/40，绝大多数直接返回 "binary/non-script file, skipped"）。
  · **每文件 2.3 万 token**（93 万 / 40）。大头不是工具输出本身（审计链里逐文件
    工具输出中位数只有 6.3k 字符），而是**每一轮都把整个上下文重发一遍**：
    8 次工具调用 ≈ 9 次模型请求，每次请求都要重发系统提示词 + 送审提示词 + 全部历史。

也就是说：送审上下文当时是"一半预置一半靠调"——YARA 命中与预筛信号是预置的，
PE / strings / 签名 / capa / floss / 脚本 / 宏全靠 AI 一轮轮调回来。

════ 做法 ════

**采集本身 0 token**（本地跑，不是让 AI 调用），把输出直接渲染进送审提示词：

  1. 按文件类型**按需挑工具**：非 PE 不跑 capa/floss；非脚本文本不跑 script_analyze；
     Office 容器里没有宏存储就不跑宏反混淆。
  2. **每个文件只算一次**：`signature_verify` 复用预筛已经采好的签名证据块
     （`PreliminaryEvidence.signature`），不重复采集。
  3. 渲染口径**与现有 YARA 段一致**：给事实、不给判断；**不给**预筛分数、
     **不给** strong/weak 分档 —— "该信多少"留给 AI。
  4. 工具仍然**全部保留**给 AI 可用（`tools.available_tools()` 不动）——
     这是"按需深挖"的口子，不是删工具。提示词改成"证据已经给全，除非你有具体怀疑点，
     否则不必再调工具"。
  5. 每条证据都带**来源工具名**，并原样进 `deps.tool_calls`（`source="preload"`），
     让 `scanner.attribute_evidence` 的证据溯源能对得上 —— 与 AI 自己调用的工具
     用同一个 `summary` 字段，溯源逻辑不用改。

采集用的是**真工具函数**（`tools.pe_analyze` 等），只喂一个 `ctx.deps` 的壳子，
所以送审里看到的载荷与 AI 自己调用时拿到的**逐字一致**，不存在两套实现漂移。
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from aiav.models import ScanDeps
from aiav.tools import (
    _cap_for_record,
    _find_exe,
    OLE_DOC_EXTENSIONS,
    OOXML_DOC_EXTENSIONS,
    RTF_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    capa_ready,
    capa_scan,
    floss_scan,
    office_macro_analyze,
    pdf_analyze,
    pe_analyze,
    script_analyze,
    strings_ioc,
)

# ---- 文件类型识别用的魔数（比扩展名可信：投递样本经常挂着文档扩展名却是 PE）----
PE_MAGIC = b"MZ"
PDF_MAGIC = b"%PDF"
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"      # CFBF（.doc/.xls/.ppt/.ole/.msi）
ZIP_MAGIC = b"PK\x03\x04"                              # OOXML（.docm/.xlsm…）
RTF_MAGIC = b"{\\rtf"

# PE 扩展名（拿不到魔数时的兜底）。.msi 不在内 —— 它是 OLE 复合文档，不是 PE。
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".pif",
                 ".pyd", ".efi", ".ax", ".mui", ".acm", ".drv", ".tsp"}

# `script_analyze` 真正能处理（读成文本做正则）的扩展名，比 tools.SCRIPT_EXTENSIONS 宽一点：
# 后者的 `.py/.sh` 之类也在，前者额外包含纯文本容器。这里只列"按类型该跑"的。
SCRIPT_KIND_EXTENSIONS = SCRIPT_EXTENSIONS | {
    ".txt", ".xml", ".html", ".htm", ".lnk", ".json", ".csv", ".ini", ".reg", ".inf",
}

# 渲染时的工具顺序 = 优先级顺序：预算不够时从后往前降级（结构化裁剪 → 整个不纳入）。
# 签名与 PE 结构是"平反"最常用的两样，排前面。
TOOL_PRIORITY = (
    "signature_verify",
    "pe_analyze",
    "strings_ioc",
    "capa_scan",
    "floss_scan",
    "script_analyze",
    "office_macro_analyze",
    "pdf_analyze",
)

# 每个工具的载荷上限（字符）。超了走 `_cap_for_record` 的**结构化裁剪**（仍是合法 JSON
# 且留痕"这里被截了"），绝不裸切 JSON 字符串 —— 腰斩的 JSON 比少几条详情更糟。
PER_TOOL_CHARS = {
    "signature_verify": 4000,
    "pe_analyze": 5000,
    "strings_ioc": 3000,
    "capa_scan": 6000,
    "floss_scan": 4000,
    "script_analyze": 4000,
    "office_macro_analyze": 3000,
    "pdf_analyze": 3000,
}
DEFAULT_PER_TOOL_CHARS = 3000

# 整个证据块的字符预算。实测比例约 0.32~0.35 token/字符（cl100k 近似），
# 14000 字符 ≈ 4600 token；加上系统提示词（约 1900 token）与送审骨架（约 500 token），
# 单文件总上下文约 7000 token，留足输出空间，也留足"AI 忍不住调两次工具"的余量。
DEFAULT_MAX_CHARS = 14000


def _env_flag(name: str, default: str = "1") -> bool:
    return os.getenv(name, default).strip().lower() not in ("0", "false", "no", "off")


def preload_enabled() -> bool:
    """总开关。`AI_AV_PRELOAD=0` 退回旧行为（证据全靠 AI 自己调）。"""
    return _env_flag("AI_AV_PRELOAD", "1")


def _max_chars() -> int:
    try:
        return max(0, int(os.getenv("AI_AV_PRELOAD_MAX_CHARS", str(DEFAULT_MAX_CHARS))))
    except ValueError:
        return DEFAULT_MAX_CHARS


def _per_tool_chars(tool: str) -> int:
    try:
        override = int(os.getenv("AI_AV_PRELOAD_PER_TOOL_CHARS", "0"))
    except ValueError:
        override = 0
    if override > 0:
        return override
    return PER_TOOL_CHARS.get(tool, DEFAULT_PER_TOOL_CHARS)


def _magic(path: Path) -> bytes:
    try:
        with path.open("rb") as f:
            return f.read(8)
    except OSError:
        return b""


def detect_kind(path: Path) -> str:
    """按**魔数优先、扩展名兜底**判文件类型，返回 pe / pdf / ole / script / other。

    魔数优先是因为投递样本的扩展名不可信（`.pdf.exe` 这类双扩展就是靠这个骗人的），
    而"该跑哪些工具"必须跟着**真实类型**走 —— 给一个 .exe 跑 `script_analyze`
    只会拿回一句 "binary/non-script file, skipped"（实测 36/40 次都是这个结果）。
    """
    ext = path.suffix.lower()
    head = _magic(path)
    if head.startswith(PE_MAGIC):
        return "pe"
    if head.startswith(PDF_MAGIC):
        return "pdf"
    if head.startswith(OLE_MAGIC):
        return "ole"
    if head.startswith(RTF_MAGIC) or ext in RTF_EXTENSIONS:
        return "ole" if ext in OLE_DOC_EXTENSIONS else "other"
    if head.startswith(ZIP_MAGIC):
        # OOXML 文档（.docm/.xlsm）与普通 zip 都可能是宏载体，交给宏探针再定
        return "ole" if ext in OOXML_DOC_EXTENSIONS else "other"
    if ext in PE_EXTENSIONS:
        return "pe"
    if ext == ".pdf":
        return "pdf"
    if ext in OLE_DOC_EXTENSIONS | OOXML_DOC_EXTENSIONS:
        return "ole"
    if ext in SCRIPT_KIND_EXTENSIONS:
        return "script"
    return "other"


# ---- "容器里到底有没有宏"的结构探针 ------------------------------------------
# 目的：**无宏的容器不跑宏反混淆**。oletools 解压 + 反混淆一个 2.4MB 的 OLE 要几百毫秒，
# 而绝大多数文档容器压根没有 VBA 存储。先做一次廉价的结构检查：
#   True  = 明确看到 VBA/宏存储 → 跑宏分析
#   False = 明确没有 → 不跑，但**把这条事实写进送审**（"容器内无 VBA 宏存储"，
#           这比"宏分析没跑"信息量大，也符合本项目"没跑 ≠ 跑了没问题"的口径）
#   None  = 判断不了（没有 olefile / 解析失败 / RTF 内嵌 OLE 对象）→ 保守起见跑
MACRO_STORAGE_NEEDLES = ("vba", "_vba_project", "macros", "macro")


def _macro_storage_probe(path: Path) -> bool | None:
    ext = path.suffix.lower()
    head = _magic(path)
    try:
        if head.startswith(OLE_MAGIC):
            import olefile  # type: ignore

            with olefile.OleFileIO(str(path)) as ole:
                names = ["/".join(entry).lower() for entry in ole.listdir(streams=True, storages=True)]
            return any(n for n in names if any(k in n for k in MACRO_STORAGE_NEEDLES))
        if head.startswith(ZIP_MAGIC) or ext in OOXML_DOC_EXTENSIONS:
            import zipfile

            with zipfile.ZipFile(path) as zf:
                names = [n.lower() for n in zf.namelist()]
            return any("vbaproject" in n or n.endswith("vba.bin") for n in names)
    except Exception:  # noqa: BLE001 - 探针失败就保守地跑真分析
        return None
    if ext in RTF_EXTENSIONS:
        return None       # RTF 的宏是内嵌 OLE 对象，结构探针看不出来
    return None


def plan_tools(kind: str, path: Path) -> tuple[list[str], list[str]]:
    """按文件类型挑工具，返回 (要跑的工具名, 跳过原因)。

    跳过原因会**写进送审**，不是静默省略 —— 但**措辞必须是"不适用"而不是"没跑"**。
    2026-09-27 实测教训：第一版把按类型跳过的工具写成「script_analyze（.exe 不是脚本文本，
    **按类型未跑**）」，结果 AI 老老实实去把这些"没跑"的补上 —— 40 个文件里
    `script_analyze` 被补调 6 次（每次都只拿回 `binary/non-script file, skipped`）、
    `office_macro_analyze` 5 次、`pe_analyze` 对 .ole 3 次（`not a PE file`）。
    每补一次就是**一整个模型往返**（≈5k token），28 次调用里有 14 次是这么来的。

    所以这里改成「与类型无关」+ 明确的"不必再调"，并在渲染时把这条规则说透
    （见 `render_section`）：**"没跑"（本机不可用）与"不适用"（类型对不上）是两回事** ——
    前者该告诉 AI（它也无能为力），后者告诉 AI 只会诱使它去补一个必然返回"不适用"的调用。
    """
    ext = path.suffix.lower()
    tools: list[str] = []
    skipped: list[str] = []

    if kind == "pe":
        tools += ["pe_analyze", "strings_ioc"]
        # 签名证据块由预筛采（`quick_prefilter(with_signature=True)`），这里只渲染，
        # 不重复采集 —— 旧口径实测 signature_verify 1.88 次/文件，同一个文件验两遍。
        tools.append("signature_verify")
        if capa_ready()[0]:
            tools.append("capa_scan")
        else:
            skipped.append("capa_scan（本机不可用，见下方『未执行的检测』）")
        if _find_exe("floss", env_var="FLOSS_EXE"):
            tools.append("floss_scan")
        else:
            skipped.append("floss_scan（本机不可用，见下方『未执行的检测』）")
    elif kind == "script":
        tools += ["script_analyze", "strings_ioc"]
    elif kind == "ole":
        tools.append("strings_ioc")
        probe = _macro_storage_probe(path)
        if probe is False:
            # 明确没有宏存储：不跑反混淆，但把"没有宏存储"这条**事实**给出去 ——
            # 以一条 `office_macro_analyze` 证据的形式给（见 collect 里的 probe 条目），
            # 而不是丢进"没跑"清单：AI 要的是答案，不是"这里有个洞"。
            pass
        else:
            tools.append("office_macro_analyze")
    elif kind == "pdf":
        tools += ["pdf_analyze", "strings_ioc"]
    else:
        tools.append("strings_ioc")

    # 类型对不上的工具：写成"不适用"，不写成"没跑"
    if kind != "pe":
        skipped.append(f"capa_scan（{ext or '无扩展名'} 不是 PE，能力识别不适用）")
        skipped.append(f"floss_scan（{ext or '无扩展名'} 不是 PE，解混淆串不适用）")
    if kind != "script":
        skipped.append(f"script_analyze（{ext or '无扩展名'} 不是脚本文本，读成文本无意义）")
    if kind != "pdf":
        skipped.append(f"pdf_analyze（{ext or '无扩展名'} 不是 PDF，可执行面解析不适用）")
    if kind != "ole":
        skipped.append(f"office_macro_analyze（{ext or '无扩展名'} 不是 Office 容器，宏分析不适用）")

    order = {name: i for i, name in enumerate(TOOL_PRIORITY)}
    tools = sorted(dict.fromkeys(tools), key=lambda t: order.get(t, 99))
    return tools, skipped


class _Ctx:
    """给真工具函数喂一个只带 `deps` 的壳子。

    工具只从 `ctx.deps` 取 `file_path` / `sha256`，并靠 `_record(ctx, …)` 写调用链。
    用它而不是重写一份采集逻辑，保证**送审里看到的载荷与 AI 自己调用时逐字一致**。
    """

    __slots__ = ("deps",)

    def __init__(self, deps: ScanDeps) -> None:
        self.deps = deps


_TOOL_FUNCS = {
    "pe_analyze": pe_analyze,
    "strings_ioc": strings_ioc,
    "capa_scan": capa_scan,
    "floss_scan": floss_scan,
    "script_analyze": script_analyze,
    "office_macro_analyze": office_macro_analyze,
    "pdf_analyze": pdf_analyze,
}


def _run_tool(name: str, path: Path, sha256: str) -> tuple[str, str | None, str]:
    """跑一个工具，返回 (工具名, 载荷, 失败说明)。

    每个工具给**自己的一份 deps**：采集是并发跑的（capa / floss 各要 15~25s，
    串起来一个 PE 就是 40s），共享一个 `deps.tool_calls` 会让 `_record` 的写入交错，
    分不清哪条是谁的。工具返回的字符串就是它交给 AI 的原文，不需要再从调用链里取。
    """
    deps = ScanDeps(file_path=path, sha256=sha256)
    try:
        payload = _TOOL_FUNCS[name](_Ctx(deps))       # type: ignore[arg-type]
    except Exception as exc:  # noqa: BLE001 - 单个工具炸掉不该拖垮送审
        return name, None, f"{name}（采集失败: {type(exc).__name__}: {exc}）"
    return name, payload, ""


def collect(
    path: Path,
    sha256: str,
    signature: dict[str, Any] | None = None,
    kind: str | None = None,
) -> dict[str, Any]:
    """本地采集确定性证据（0 token）。

    返回：
      {
        "kind": "pe",
        "tools": ["signature_verify", "pe_analyze", …],       # 真跑了的
        "entries": [{"tool": …, "payload": …}, …],            # 供送审渲染 + 证据溯源
        "skipped": ["script_analyze（… 不是脚本文本，按类型未跑）", …],
        "chars": 12345, "elapsed_ms": 210.5, "truncated": False,
      }

    `entries` 的 `payload` 就是工具返回给 AI 的原文（超预算时走结构化裁剪并留痕），
    原样写进 `deps.tool_calls` 就能被 `scanner.attribute_evidence` 对上。
    """
    kind = kind or detect_kind(path)
    tools, skipped = plan_tools(kind, path)

    started = time.monotonic()
    entries: list[dict[str, Any]] = []
    failed: list[str] = []

    # 签名不重复采集：用预筛已经采好的那一份（同一份数据，只是换个来源标签）
    if "signature_verify" in tools:
        tools.remove("signature_verify")
        if signature:
            entries.append({
                "tool": "signature_verify",
                "payload": _cap_for_record(json.dumps(signature, ensure_ascii=False),
                                           _per_tool_chars("signature_verify")),
                "source": "prefilter",     # 与旧口径一致：签名证据由预筛采
            })
        else:
            failed.append("signature_verify（本次未采集到签名证据块）")

    # OLE 容器且结构探针明确没看到宏存储：**不跑宏反混淆**，但把探针结果当成一条
    # `office_macro_analyze` 证据给出去（而不是丢进"没跑"清单）。
    # 理由见 plan_tools 的注释：只报"没跑"，AI 会自己去补一个必然返回"没有"的调用。
    if kind == "ole" and "office_macro_analyze" not in tools and not failed:
        if _macro_storage_probe(path) is False:
            entries.append({
                "tool": "office_macro_analyze",
                "payload": json.dumps({
                    "has_macros": False,
                    "checked": "VBA 宏存储（OLE 目录结构探针：olefile.listdir）",
                    "note": ("OLE 目录里没有 VBA/宏存储，因此未做宏反混淆（oletools）。"
                             "Excel 4.0 (XLM) 宏表**不在**这个探针范围内 —— 它住在 workbook "
                             "流里，要看『其它预筛信号』里的 XLM 条目。"),
                }, ensure_ascii=False),
                "source": "preload",
            })

    # 并发跑（capa / floss 是子进程，天然放 GIL；纯 Python 的那几个本来就毫秒级）。
    # 上限 4 是为了不跟外层"4 个文件并发"叠成十几路 subprocess。
    if tools:
        with ThreadPoolExecutor(max_workers=min(len(tools), 4)) as pool:
            results = list(pool.map(lambda n: _run_tool(n, path, sha256), tools))
        for name, payload, err in results:
            if err:
                failed.append(err)
                continue
            entries.append({
                "tool": name,
                "payload": _cap_for_record(payload or "", _per_tool_chars(name)),
                "source": "preload",
            })

    entries.sort(key=lambda e: TOOL_PRIORITY.index(e["tool"])
                 if e["tool"] in TOOL_PRIORITY else 99)
    entries, budget_note = _apply_total_budget(entries)

    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    return {
        "kind": kind,
        "tools": [e["tool"] for e in entries],
        "entries": entries,
        # 原样进 deps.tool_calls，供证据溯源（`source` 区分预采集 / 预筛 / AI 自调）
        "calls": [{"tool": e["tool"], "summary": e["payload"], "source": e["source"]}
                  for e in entries],
        "skipped": skipped + failed,
        "chars": sum(len(e["payload"]) for e in entries),
        "elapsed_ms": elapsed_ms,
        "truncated": budget_note is not None,
        "budget_note": budget_note or "",
        "policy": "by_type",
    }


def _apply_total_budget(entries: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str | None]:
    """整块字符预算：超了从**优先级最低**的条目开始降级（裁剪 → 整个不纳入），并留痕。"""
    limit = _max_chars()
    if limit <= 0 or not entries:
        return entries, None
    total = sum(len(e["payload"]) for e in entries)
    if total <= limit:
        return entries, None

    kept: list[dict[str, Any]] = []
    used = 0
    dropped: list[str] = []
    for entry in entries:                     # 已按优先级排序
        size = len(entry["payload"])
        if used + size <= limit:
            kept.append(entry)
            used += size
            continue
        room = limit - used
        if not kept:
            # 预算再紧也要留住**优先级最高**的那条（硬裁到 limit）——一份证据都不给，
            # AI 就只能凭预筛理由猜，那是把"证据前置"做成了"证据消失"。
            shrunk = _cap_for_record(entry["payload"], max(1, limit))
            kept.append({**entry, "payload": shrunk})
            used += len(shrunk)
            dropped.append(f"{entry['tool']}（裁剪到 {limit} 字符）")
        elif room >= 600:
            shrunk = _cap_for_record(entry["payload"], room)
            kept.append({**entry, "payload": shrunk})
            used += len(shrunk)
            dropped.append(f"{entry['tool']}（裁剪到 {room} 字符）")
        else:
            dropped.append(f"{entry['tool']}（整条未纳入）")
    note = ("证据块超出预算 %d 字符，按优先级降级：" % limit) + "、".join(dropped)
    return kept, note


def render_section(result: dict[str, Any]) -> str:
    """把采集结果渲染成送审提示词里的一段（**给事实，不给判断**）。

    与现有 YARA 段同一口径：只列工具在本机跑出来的原始输出，不写分数、不写分档、
    不写"这说明什么"。判断留给 AI。
    """
    if not result or not result.get("entries"):
        # 空结果也要**显式说明为什么空**（关掉了 / 预算裁光了），不能留白让 AI 以为"没证据"
        if result and result.get("budget_note"):
            return f"（本次未预采集确定性证据：{result['budget_note']}）"
        if result and result.get("policy") == "disabled":
            return "（本次未做确定性证据前置：预采集被显式关闭，证据需要你自己调工具取）"
        return "（本次未预采集确定性证据）"

    lines = [
        "【确定性证据（本地预采集 · 事实，不是判断）】",
        "以下每一项都是工具在**本机**对**这个文件**跑出来的原始输出（与你自己调工具拿到的是"
        "**同一份输出** —— 同一个函数、同一份输入），采集不消耗模型 token，也不含任何结论：",
        "没有预筛分数、没有 strong/weak 分档。怎么解读由你决定。",
        "按文件类型挑工具（%s），每项标注来源工具名，可直接用于证据溯源。" % result.get("kind", "?"),
    ]
    for entry in result["entries"]:
        lines.append("")
        lines.append(f"  ▸ 来源工具: {entry['tool']}")
        for raw_line in str(entry["payload"]).splitlines():
            lines.append(f"    {raw_line}")
    if result.get("skipped"):
        lines.append("")
        lines.append("  与本次文件类型无关、未执行的工具（不是『跑了没问题』，是『对这个文件"
                     "没有可分析的面』）：")
        for item in result["skipped"]:
            lines.append(f"    · {item}")
        lines.append("    ⚠ 上面这几项**不需要再调** —— 它们对这个文件只会返回同一句『不适用』，"
                     "白白多花一整个模型往返（实测每多一轮 ≈ 多 5k token）。")
    if result.get("budget_note"):
        lines.append("")
        lines.append(f"  ⚠ {result['budget_note']}")
    return "\n".join(lines)


def preload_tool_calls(result: dict[str, Any]) -> list[dict[str, Any]]:
    """采集结果 → 可直接塞进 `deps.tool_calls` 的条目（带 `source` 标签）。

    `source` 有两个值：
      · `preload`   本地预采集（**不算 AI 的工具调用次数**，报告里单独计）
      · `prefilter` 预筛阶段就采好的（签名证据块，旧口径沿用）
    """
    return [dict(c) for c in (result or {}).get("calls") or []]


def ai_tool_calls(tool_calls: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """从调用链里挑出**AI 自己发起的**工具调用（排除预采集/预筛注入的条目）。

    报告里"用了几次工具调用"用的是这个口径 —— 预采集是本地 0 token 的活，
    把它算进 AI 的轮数会把"砍轮数"这件事算糊。
    """
    return [c for c in (tool_calls or [])
            if str(c.get("source") or "") not in ("preload", "prefilter")]
