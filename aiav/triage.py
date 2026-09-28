"""LLM 初筛层：**最小摘要 → 便宜档模型 → 0~100 可疑度分**（独立的第二层，不是深度 AI）。

════ 为什么要有这一层（2026-09-27 实测） ════

Dike 400（200 恶意 + 200 良性）上的预筛分数分布：

    分数    恶意   良性   良:恶
      0       0     51     —
    125       6    137   22.8 : 1   ← 主战场
    225       2      2    1.0 : 1
    250       0      1     —
    275       7      4    0.6 : 1

125 分这一档里，恶意和良性命中的是**同一条判据**（`HIGH_RISK_EXTENSION`，"它是个 .exe"）——
**判据分不开、门槛也分不开**（捞 6 个恶意要吃进 137 个良性）。
这一档只能靠"看内容"分：规则层已经用尽了，深度 AI 又太贵。
所以补一层**便宜的内容初筛**：喂最小摘要，输出一个可排序的分数，把"该不该花钱送深度 AI"变成
一个**算得出来的门槛**问题。

════ 三条设计红线 ════

1. **输入是最小摘要，不是全证据**（成本控制的关键）。全证据（预采集的 capa/floss/字符串原文）
   是 10k token/文件量级；这里的目标是 **≤1000 token/文件**，差 10 倍。
   摘要只给：文件名 + 大小 + 扩展名 + 熵 + 布局（段表/流表）摘要 + 前 N 个字符串
   + 导入表摘要。**不给任何规则分数、不给判据名** —— 给了就是泄题，LLM 会去复述规则
   （预筛分数与它自己的分数高度共线，等于白花钱）。
   **例外且只有一处（2026-09-27）**：`kind == "pdf"` 走**单独一条解析路径**
   （`_pdf_summary`）—— PDF 正文是压缩流，"前 20 条字符串"全是乱码，摘要等于没给
   信息（实测批次 A：PDF 召回 0.283，同批 vbs/js 是 1.000）。PDF 改给结构面 +
   动作 + 内嵌文件 + 外链 + **解压后可读的 JS 代码**；其它类型的摘要渲染一个字没改。
2. **输出是 0~100 的分数，不是三分类**。分数才能排序、才能算 AUC、才能"用数据定门槛"。
   理由只是一句话，用来事后解释，不参与路由。
3. **预算守门**：摘要渲染后按 token 计数，超预算就**从字符串尾部往前砍**，
   并把 `summary_truncated` 记进结果 —— 不静默超支。

════ 核验纪律 ════

结果里逐文件记 `ok / error / degraded`、`usage_source`（provider 报的还是本地估的）、
`from_cache`。**降级/报错计数不为 0 的批次要作废**（照项目铁律：先验"模型真被调用了"）。
"""

from __future__ import annotations

import json
import math
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import httpx
from dotenv import load_dotenv

# 与 `cli.py` 同款的环境加载。放在模块级（而不是只放在 CLI 里）是有意的：
# `TriageClient` 会被脚本/测试直接构造，配置入口只能有一处，否则"脚本里没 key、
# CLI 里有 key"这种差异会变成只在某一条路径上复现的故障。
load_dotenv()
load_dotenv(Path.cwd() / ".env")
load_dotenv(Path.home() / ".config" / "aiav" / ".env")

# ---------------------------------------------------------------- 调参常量
#: 摘要结构版本。改摘要字段/提示词/解析口径都要 +1，让旧缓存整体失效。
#: v2（2026-09-27）：PDF 走**单独一条解析路径**（结构面 + 解压后的 JS 代码 +
#: 动作/内嵌文件/URI），字符串档位从 20 收到 8。其它类型的摘要渲染**一个字没改**。
TRIAGE_VERSION = "2"
#: 摘要里最多给几条字符串（任务给的 N，目标 ≤20 条）。
MAX_STRINGS = 20
#: **PDF 专用**：字符串只给 8 条。PDF 正文是压缩流，"前 20 条字符串"几乎全是
#: 解压后的二进制碎片 —— 实测（批次 A，mb-pdf 60 个全恶意）②层在 PDF 上召回
#: 0.283，而同一批 vbs/js 是 1.000。预算要让给结构面与**解压后的 JS 代码**。
MAX_STRINGS_PDF = 8
#: PDF 摘要里 JS 代码片段 / URI / 内嵌文件 / 可疑模式的条数上限。
PDF_JS_SNIPPETS = 3
PDF_URI_MAX = 5
PDF_EMBEDDED_MAX = 5
#: 单条 JS 片段最长字符数（一条 base64 blob 能吃掉整份预算）。
PDF_JS_CHARS = 240
#: 单文件提示词的 token 目标（硬上限靠 `TRIAGE_MAX_PROMPT_TOKENS` 覆盖）。
TARGET_PROMPT_TOKENS = 1000
#: 摘要最多读进内存的字节数（熵/字符串只在前 1MB 上算 —— 成本与代表性之间取的档）。
SUMMARY_READ_BYTES = 1024 * 1024
#: 字符串最短长度。
MIN_STRING_LEN = 6
#: 单条字符串最长保留字符数（超长直接截断，避免一条 base64 吃掉整个预算）。
MAX_STRING_CHARS = 120
#: 字符串噪声黑名单：PE 装订板/通用编译器产物，**每个 PE 都一样**，白占预算。
STRING_SKIP_EXACT = frozenset({
    "!This program cannot be run in DOS mode.",
    "!This program cannot be run in DOS mode",
    "Rich",
    "This program cannot be run in DOS mode.",
})
#: 导入表里"值得点名"的 API（按行为族分组）。**注意**：这些 API 在良性软件里也常见，
#: 所以它们只是"给模型看的线索"，不是判据、不计分 —— 判据层（criteria.py）另有口径。
NOTABLE_APIS: dict[str, tuple[str, ...]] = {
    "内存/注入": (
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "CreateRemoteThreadEx", "NtUnmapViewOfSection", "SetThreadContext",
        "QueueUserAPC", "RtlMoveMemory", "ZwProtectVirtualMemory", "NtWriteVirtualMemory",
        "OpenProcess", "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
        "WinExec", "CreateThread",
    ),
    "动态解析": (
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
        "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    ),
    "网络": (
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW",
        "InternetReadFile", "HttpSendRequestA", "HttpSendRequestW", "URLDownloadToFileA",
        "URLDownloadToFileW", "WinHttpOpen", "WinHttpConnect", "WSAStartup", "socket",
        "connect", "send", "recv", "WSASocketA", "gethostbyname", "inet_addr",
    ),
    "持久化/注册表": (
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "RegOpenKeyExA", "RegOpenKeyExW", "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW", "OpenSCManagerA", "OpenSCManagerW",
        "SHSetValueA", "SHSetValueW",
    ),
    "加密/勒索": (
        "CryptEncrypt", "CryptGenKey", "CryptAcquireContextA", "CryptAcquireContextW",
        "CryptStringToBinaryA", "CryptStringToBinaryW", "BCryptEncrypt", "CryptUnprotectData",
    ),
    "反分析/发现": (
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "GetTickCount", "QueryPerformanceCounter", "OutputDebugStringA", "OutputDebugStringW",
        "GetSystemInfo", "GetComputerNameA", "GetComputerNameW", "GetVolumeInformationA",
        "GetVolumeInformationW", "FindFirstFileA", "FindFirstFileW", "CreateToolhelp32Snapshot",
        "Process32First", "Process32Next", "EnumProcesses",
    ),
    "键盘/截屏/窃密": (
        "GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
        "GetForegroundWindow", "BitBlt", "GetDC", "CreateCompatibleDC", "OpenClipboard",
        "GetClipboardData",
    ),
    "文件/自删": (
        "DeleteFileA", "DeleteFileW", "MoveFileExA", "MoveFileExW", "CopyFileA", "CopyFileW",
        "SetFileAttributesA", "SetFileAttributesW", "CreateFileA", "CreateFileW",
    ),
}
#: 扁平化的"值得点名"集合（大小写敏感，PE 导入名就是这个名字）。
NOTABLE_API_SET: frozenset[str] = frozenset(
    api for group in NOTABLE_APIS.values() for api in group
)

SYSTEM_PROMPT = """你是一个恶意文件**初筛**器。你只看到一份**最小摘要**（不是文件本体、不是完整证据），
请据此给出一个 0~100 的**可疑度分数**，用于排序和定门槛。

评分口径（照这个来，别自创刻度）：
- 0~19：从摘要看就是正常软件（有正常厂商名/版本资源、导入表丰富且常规、字符串像通用程序）。
- 20~49：有点反常但解释得通（加壳、导入表稀疏、大量非常规字符串、无版本信息）。
- 50~69：多项特征一起指向可疑（稀疏导入 + 动态解析 API；小代码段 + 高熵载荷；可疑脚本/宏片段）。
- 70~89：强可疑（明确的下载/注入/持久化/窃密行为串，混淆明显的脚本或宏）。
- 90~100：摘要本身就构成恶意证据（勒索提示、明确 C2 地址 + 落地执行链、已知恶意工具特征串）。

硬要求：
- **只输出 JSON**，格式 {"score": <0-100 的整数>, "reason": "<一句话中文理由>"}，不要输出别的任何东西。
- reason 必须**指到摘要里的具体事实**（哪个字段、哪条字符串），不许写"看起来可疑"这种空话。
- 你只看到摘要，**看不到的东西不能说"没有"**。摘要里没有签名信息 ≠ 未签名。
- 加壳本身不是恶意证据；文件是 .exe 本身也不是。
"""


# ---------------------------------------------------------------- 熵 / 字符串
def shannon_entropy(data: bytes) -> float:
    """字节级 Shannon 熵（0~8）。空数据返回 0。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / total
            entropy -= p * math.log2(p)
    return round(entropy, 3)


_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)
# UTF-16LE：可打印 ASCII 后跟 \x00，至少 MIN_STRING_LEN 个字符
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LEN)


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> list[str]:
    """按**文件偏移顺序**取前 `limit` 条字符串（ASCII + UTF-16LE 合并去重）。

    口径说明（有意为之，不是随手写的）：
      · "前 N 条"是任务给的口径 —— 偏移顺序的头部信息量最大（PE 头部/资源目录/早期代码段），
        按"出现频率"或"随机采样"排序都会把这条简单口径变成需要调参的东西。
      · 去掉 PE 装订板（`!This program cannot be run in DOS mode.` / `Rich`）——
        它们在**每个** PE 里都一样，留着只是白烧 20% 的字符串预算。
      · 单条截到 `MAX_STRING_CHARS`：一条 base64 blob 能吃掉整份摘要。
    """
    found: list[tuple[int, str]] = []
    for match in _ASCII_RE.finditer(data):
        found.append((match.start(), match.group().decode("ascii", errors="replace")))
    for match in _UTF16_RE.finditer(data):
        found.append((match.start(), match.group().decode("utf-16-le", errors="replace")))
    found.sort(key=lambda item: item[0])

    out: list[str] = []
    seen: set[str] = set()
    for _offset, text in found:
        text = text.strip()
        if len(text) < MIN_STRING_LEN or text in STRING_SKIP_EXACT:
            continue
        if len(set(text)) <= 2:          # "AAAAAAA" 这类填充
            continue
        if text in seen:
            continue
        seen.add(text)
        out.append(text[:MAX_STRING_CHARS])
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- 摘要构建
def _pe_summary(path: Path, summary: dict[str, Any]) -> None:
    """PE：段表摘要 + 导入表摘要（只解析头部，不执行任何东西）。"""
    try:
        import pefile  # type: ignore
    except ImportError:  # pragma: no cover - pefile 是硬依赖
        return
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:  # noqa: BLE001 - 不是 PE / 解析失败：摘要里留空，不猜
        return
    try:
        try:
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"],
                ]
            )
        except Exception:  # noqa: BLE001
            pass

        sections: list[str] = []
        for s in list(getattr(pe, "sections", []) or [])[:12]:
            name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace") or "?"
            ch = int(getattr(s, "Characteristics", 0) or 0)
            flags = "".join([
                "X" if ch & 0x20000000 else "-",
                "W" if ch & 0x80000000 else "-",
                "R" if ch & 0x40000000 else "-",
            ])
            try:
                ent = round(float(s.get_entropy()), 2)
            except Exception:  # noqa: BLE001
                ent = -1.0
            sections.append(
                f"{name} raw={int(getattr(s, 'SizeOfRawData', 0) or 0) // 1024}KB ent={ent} {flags}"
            )
        summary["layout"] = sections

        dlls: list[str] = []
        apis: set[str] = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            try:
                dlls.append(entry.dll.decode("utf-8", errors="replace").lower())
            except Exception:  # noqa: BLE001
                continue
            for imp in getattr(entry, "imports", []) or []:
                if getattr(imp, "name", None):
                    apis.add(imp.name.decode("utf-8", errors="replace"))
        if dlls or apis:
            summary["imports"] = {
                "dll_count": len(set(dlls)),
                "api_count": len(apis),
                "dlls": sorted(set(dlls))[:8],
                "key_apis": sorted(apis & NOTABLE_API_SET)[:15],
            }
        else:
            summary["imports"] = {"dll_count": 0, "api_count": 0, "dlls": [], "key_apis": []}

        try:
            entry_rva = int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0) or 0)
        except Exception:  # noqa: BLE001
            entry_rva = 0
        try:
            import pefile as _pf

            com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                _pf.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
            ]
            is_dotnet = bool(int(getattr(com, "VirtualAddress", 0) or 0))
        except Exception:  # noqa: BLE001
            is_dotnet = False
        summary["pe_flags"] = {
            "entry_rva": entry_rva,
            "dotnet": is_dotnet,
            "machine": hex(int(getattr(pe.FILE_HEADER, "Machine", 0) or 0)),
        }
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001
            pass


def _ole_summary(path: Path, summary: dict[str, Any]) -> None:
    """OLE / OOXML：只列流名（这一层不做宏反混淆 —— 那是深度 AI 的活）。"""
    ext = path.suffix.lower()
    try:
        if ext in {".docm", ".xlsm", ".docx", ".xlsx", ".pptx", ".zip"}:
            import zipfile

            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
            summary["layout"] = [f"zip:{n} ({zf.getinfo(n).file_size // 1024}KB)"
                                 for n in names[:12]]
            summary["macro_store"] = any(
                "vbaproject" in n.lower() or n.lower().endswith("vba.bin") for n in names
            )
            return
        import olefile  # type: ignore

        with olefile.OleFileIO(str(path)) as ole:
            entries = ["/".join(e) for e in ole.listdir(streams=True, storages=True)]
        summary["layout"] = entries[:12]
        summary["macro_store"] = any(
            k in e.lower() for e in entries for k in ("vba", "_vba_project", "macros")
        )
    except Exception:  # noqa: BLE001 - 容器解析失败：留空，不猜
        return


# ---------------------------------------------------------------- PDF 专用摘要
#: 从①层（pypdf 走对象树）拿到的字典 repr 里把 JS 正文抠出来。
#: 例：`{'/JS': 'app.alert("x");', '/S': '/JavaScript'}` → `app.alert("x");`
#: 两种引号都要认（repr 里单双引号都可能出现），**不能按第一个引号截断** ——
#: JS 正文自己就带引号（`{cName:"e.exe"}`），截断会把代码切坏。
_JS_FROM_REPR_RE = re.compile(
    r"""['"]/JS['"]\s*:\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")"""
)
#: 判"这段解出来的是不是**可读的 JS 代码**"（解压失败的流是二进制碎片，喂给模型
#: 只会制造噪声 —— 那正是旧摘要在 PDF 上失效的原因）。
_JS_HINT_TOKENS = ("(", "=", ";", "{", "}", ".", "function", "var ", "this")
#: JS 片段的**可疑度**排序（与 `pdfscan.PDF_PATTERNS` 同一套信号的强档）。
#: 注意：这只是"先给模型看哪几条"的排序，不是判据、不计分。
_JS_SUSPICIOUS_TOKENS = (
    "app.launchURL", "exportDataObject", "submitForm", "eval(", "unescape",
    "String.fromCharCode", "getURL", "util.printf", "this.exportDataObject",
    "%u9090", "com.adobe.acrobat", "Collab.getIcon",
)


def _clean_js_blob(text: str) -> str:
    """把①层解出来的东西洗成"像 JS 代码"的样子。**只做字符串处理，不 eval、不执行。**"""
    text = (text or "").strip()
    match = _JS_FROM_REPR_RE.search(text)
    if match:
        text = match.group(1) if match.group(1) is not None else match.group(2)
    # 解压出来的 JS 里 `\n` 常是**两个字符**（反斜杠 + n）而不是真换行
    for escaped, plain in (("\\r\\n", " "), ("\\n", " "), ("\\r", " "), ("\\t", " ")):
        text = text.replace(escaped, plain)
    return re.sub(r"\s+", " ", text).strip()


def _readable_js(text: str) -> bool:
    """这段解出来的东西**可读**吗（可读才值得喂给模型）。"""
    if len(text) < 12:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\t\n ")
    if printable / len(text) < 0.9:
        return False
    return any(tok in text for tok in _JS_HINT_TOKENS)


def _js_snippets(blobs: Iterable[str],
                 limit: int = PDF_JS_SNIPPETS) -> tuple[list[str], int, int]:
    """从①层解出来的 JS 里挑几条**真正可读的代码**。

    返回 `(片段, 可读段数, 原始块数)` —— 三个数都要留痕：只报"挑了几条"会把
    "根本没有 JS" 和 "有 JS 但全解不开" 混成同一件事（后者对研判有意义）。

    挑选口径（为什么这么排）：
      ① 先按可读度过滤 —— 解压失败的流是二进制碎片；
      ② 再按可疑度排序 —— 带 `app.launchURL` / `exportDataObject` / `eval` 这些串的
         片段优先（与 `pdfscan.PDF_PATTERNS` 同一套信号）；
      ③ 剩下的按**原文顺序**兜底，保证"有 JS 但没命中模式"的文件也能给出代码；
      ④ 折叠空白 + 截断 —— 一条 base64 blob 能吃掉整份摘要预算。
    """
    seen: set[str] = set()
    readable: list[tuple[int, int, str]] = []
    raw_total = 0
    for index, blob in enumerate(blobs):
        raw_total += 1
        text = _clean_js_blob(blob)
        if not _readable_js(text) or text in seen:
            continue
        seen.add(text)
        score = sum(1 for token in _JS_SUSPICIOUS_TOKENS if token in text)
        readable.append((-score, index, text[:PDF_JS_CHARS]))
    readable.sort(key=lambda item: (item[0], item[1]))
    return [text for _score, _index, text in readable[:limit]], len(seen), raw_total


def _pdf_summary(path: Path, summary: dict[str, Any]) -> None:
    """PDF：**单独一条解析路径**（只在 `kind == "pdf"` 时走，别的类型一个字不改）。

    为什么必须单列：PDF 的正文是压缩流，`extract_strings()` 在前 1MB 上捞到的
    "字符串"几乎全是解压后的二进制碎片 —— 摘要等于没给信息。而①层其实**认识** PDF
    （`criteria.py` 有 `PDF_JS` / `PDF_EMBEDDED_FILE` / `PDF_URI` 等 7 条判据，
    `pdfscan.analyze_pdf()` 会把 JS 解压出来），**只是②层的摘要没把这些喂进去** ——
    这就是"①层看得到、②层看不见"的错配。

    这里做的事：把①层已经算过的东西（动作 / 内嵌文件 / URI / XFA / 解压后的 JS）
    取过来，再补一层①层没给的结构面（对象数 / 流数 / 加密 / ObjStm / 版本），
    整理成②层看得懂的摘要。**只读静态：不渲染、不打开、不执行 PDF。**
    """
    try:
        from aiav.pdfscan import (
            RISKY_EMBEDDED_EXTS,
            analyze_pdf,
            raw_js_literals,
            structure_info,
        )
    except Exception as exc:  # noqa: BLE001 - 模块不可用：如实记账，不猜
        summary["pdf"] = {"errors": [f"pdfscan 不可用: {type(exc).__name__}: {exc}"[:120]]}
        return

    pdf: dict[str, Any] = {"errors": []}
    try:
        structure = structure_info(path)
        pdf["structure"] = {
            "engine": structure.get("engine"),
            "version": structure.get("version") or "",
            "header": structure.get("header") or "",
            "objects": structure.get("objects", 0),
            "streams": structure.get("streams", 0),
            "encrypted": bool(structure.get("encrypted")),
            "objstm": structure.get("objstm", 0),
            "pages": structure.get("pages", 0),
            "counts": structure.get("counts") or {},
        }
        pdf["errors"].extend(structure.get("errors") or [])
    except Exception as exc:  # noqa: BLE001
        pdf["errors"].append(f"结构面解析失败: {type(exc).__name__}: {exc}"[:120])

    try:
        info = analyze_pdf(path)
        pdf["errors"].extend(info.get("errors") or [])
        pdf["pages"] = info.get("pages") or 0
        # 页数两个来源：pdfid 数 `/Page` 关键字（未解压），pypdf 走对象树。
        # 任一拿到就用，两个都拿到取大的 —— 写 0 是**错的**（405 个对象的 PDF 不是 0 页）。
        if pdf.get("structure") is not None and not pdf["structure"].get("pages"):
            pdf["structure"]["pages"] = pdf["pages"]
        pdf["actions"] = list(info.get("actions") or [])
        pdf["uris"] = list(dict.fromkeys(info.get("uris") or []))[:PDF_URI_MAX]
        pdf["patterns"] = list(info.get("patterns") or [])
        pdf["xfa"] = bool(info.get("xfa"))

        embedded: list[dict[str, Any]] = []
        for item in (info.get("embedded_files") or [])[:PDF_EMBEDDED_MAX]:
            name = str(item.get("name") or "")
            suffix = Path(name).suffix.lower()
            embedded.append({
                "name": name[:80],
                "size": int(item.get("size") or 0),
                "risky": suffix in RISKY_EMBEDDED_EXTS,
            })
        pdf["embedded_files"] = embedded

        # JS 有两个来源，**互补**（实测 mb-pdf 60 个）：
        #   · pypdf 走对象树能解压 ObjStm 里的 JS（12/60 拿到）—— pdfid 数不到这些；
        #   · 原始 `/JS (…)` 字面量在"xref 坏了"的投递样本上仍然可读（7/60）。
        blobs: list[str] = list(info.get("javascript") or [])
        try:
            blobs.extend(raw_js_literals(path.read_bytes(), limit=8))
        except OSError as exc:
            pdf["errors"].append(f"原始字节读取失败: {type(exc).__name__}: {exc}"[:120])
        snippets, readable_total, raw_total = _js_snippets(blobs)
        pdf["js_snippets"] = snippets
        pdf["js_total"] = readable_total
        pdf["js_blocks"] = raw_total
    except Exception as exc:  # noqa: BLE001
        pdf["errors"].append(f"可执行面解析失败: {type(exc).__name__}: {exc}"[:120])

    pdf["errors"] = sorted(set(str(e) for e in pdf["errors"] if e))[:4]
    summary["pdf"] = pdf


def build_summary(path: Path, sha256: str = "") -> dict[str, Any]:
    """构建**最小摘要**（这是喂给模型的东西，也是成本的全部来源）。

    字段刻意保持"事实"口径：没有预筛分数、没有判据名、没有 strong/weak 分档 ——
    那些是"该信多少"的判断，给出去等于泄题（实测：把分数写进提示词，模型会去复述它）。
    """
    from aiav.preload import detect_kind

    summary: dict[str, Any] = {
        "name": path.name,
        "sha256_prefix": (sha256 or "")[:16],
        "size": 0,
        "extension": path.suffix.lower(),
        "kind": "other",
        "entropy": 0.0,
    }
    try:
        summary["size"] = path.stat().st_size
    except OSError:
        summary["size"] = 0

    try:
        with path.open("rb") as f:
            blob = f.read(SUMMARY_READ_BYTES)
    except OSError as exc:
        summary["read_error"] = f"{type(exc).__name__}: {exc}"
        blob = b""

    summary["entropy"] = shannon_entropy(blob)
    try:
        summary["kind"] = detect_kind(path)
    except Exception:  # noqa: BLE001
        summary["kind"] = "other"

    if summary["kind"] == "pe":
        _pe_summary(path, summary)
    elif summary["kind"] in ("ole",) or path.suffix.lower() in {
        ".docm", ".xlsm", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".rtf", ".lnk"
    }:
        _ole_summary(path, summary)
    elif summary["kind"] == "pdf":
        # PDF **单独一条解析路径**（2026-09-27）。走这条分支的只有 kind == "pdf" ——
        # vbs/js/bat（script）、rtf/xls（ole / other）的摘要渲染与字段**一个字没改**。
        _pdf_summary(path, summary)

    # PDF 的字符串档位单独收窄（见 `MAX_STRINGS_PDF`）：PDF 正文是压缩流，
    # 20 条乱码字符串白占预算，而预算要留给结构面与解压后的 JS。别的类型仍走 20。
    strings_limit = MAX_STRINGS_PDF if summary["kind"] == "pdf" else MAX_STRINGS
    summary["strings"] = extract_strings(blob, strings_limit)
    summary["strings_total_seen"] = len(summary["strings"])
    return summary


# ---------------------------------------------------------------- 渲染 / 计数
def _count_tokens(text: str) -> int:
    """token 计数：有 tiktoken 就用它（cl100k_base 是**近似**，本机没装就退到 chars/4）。

    口径写清楚：这是**估算**，答案里的"每文件 token"最终以 provider 报的 usage 为准，
    估算只用来**事前**守预算。
    """
    try:
        import tiktoken  # type: ignore

        return len(tiktoken.get_encoding("cl100k_base").encode(text))
    except Exception:  # noqa: BLE001
        return max(1, len(text) // 4)


def _render_pdf_block(pdf: dict[str, Any]) -> list[str]:
    """PDF 事实块（**只印事实**：没有判据名、没有分数、没有规则命中 —— 给了就是泄题）。

    ⚠️ 有意不印 `pdf["patterns"]`：那几条（`PDF JS: eval` 之类）就是 `criteria.py`
    里 `PDF_PATTERN` 判据的命中标签，印出来等于把①层的规则结论喂回去，
    与"不给判据名"这条设计红线冲突。模型要看的是**原始事实**（JS 代码本身、
    动作、外链、内嵌文件、结构面），不是我们的规则怎么说。
    """
    out: list[str] = []
    structure = pdf.get("structure") or {}
    if structure:
        out.append(
            "PDF 结构: "
            f"版本={structure.get('version') or '?'} "
            f"对象={structure.get('objects', 0)} 流={structure.get('streams', 0)} "
            f"页={structure.get('pages', 0)} "
            f"加密={'是' if structure.get('encrypted') else '否'} "
            f"ObjStm={structure.get('objstm', 0)}"
            f"（结构面引擎: {structure.get('engine') or '?'}）"
        )
        counts = structure.get("counts") or {}
        named = {
            "js": "/JS", "javascript": "/JavaScript", "openaction": "/OpenAction",
            "aa": "/AA", "launch": "/Launch", "embeddedfile": "/EmbeddedFile",
            "richmedia": "/RichMedia", "xfa": "/XFA", "acroform": "/AcroForm",
        }
        hits = [f"{named[key]}×{value}" for key, value in counts.items()
                if key in named and value]
        if hits:
            out.append("PDF 明文关键字计数（未解压口径）: " + ", ".join(hits))
    actions = pdf.get("actions") or []
    if actions:
        out.append("PDF 动作（解引用对象树后）: " + ", ".join(str(a) for a in actions[:12]))
    if pdf.get("xfa"):
        out.append("PDF 含 XFA 表单（可脚本化）")
    embedded = pdf.get("embedded_files") or []
    if embedded:
        out.append("PDF 内嵌文件: " + " | ".join(
            f"{item.get('name')}({item.get('size')}B"
            f"{'，可执行/脚本类型' if item.get('risky') else ''})"
            for item in embedded))
    uris = pdf.get("uris") or []
    if uris:
        out.append(f"PDF 外链动作(URI) {len(uris)} 条:")
        out.extend(f"  · {uri}" for uri in uris)
    snippets = pdf.get("js_snippets") or []
    readable_total = int(pdf.get("js_total") or 0)
    raw_total = int(pdf.get("js_blocks") or 0)
    if snippets:
        out.append(
            f"PDF JavaScript 片段（解压后可读 {readable_total} 段 / 原始 JS 块 {raw_total} 个，"
            f"下面是最可疑的 {len(snippets)} 段）:"
        )
        out.extend(f"  · {snippet}" for snippet in snippets)
    elif raw_total:
        out.append(
            f"PDF JavaScript: 解出 {raw_total} 个 JS 块但**都不可读**（解压失败 / 二进制碎片）"
        )
    errors = pdf.get("errors") or []
    if errors:
        out.append("PDF 解析异常（**解不开 ≠ 安全**）: " + "; ".join(str(e) for e in errors[:3]))
    return out


def render_user_prompt(summary: dict[str, Any]) -> str:
    """把摘要渲染成提示词正文。只印事实，每一行都能在摘要里找到出处。"""
    lines = [
        f"文件名: {summary.get('name')}",
        f"类型: {summary.get('kind')}  扩展名: {summary.get('extension') or '(无)'}",
        f"大小: {summary.get('size')} bytes",
        f"整体熵(前1MB): {summary.get('entropy')}",
    ]
    if summary.get("read_error"):
        lines.append(f"读取错误: {summary['read_error']}（读不到内容，不等于安全）")
    if summary.get("layout"):
        lines.append("布局: " + " | ".join(summary["layout"]))
    if summary.get("macro_store") is not None:
        lines.append(f"容器内宏存储: {'有' if summary['macro_store'] else '无'}")
    imports = summary.get("imports")
    if imports:
        lines.append(
            f"导入表: DLL {imports['dll_count']} 个 / API {imports['api_count']} 条；"
            f"DLL: {', '.join(imports['dlls']) or '(无)'}"
        )
        lines.append(f"值得点名的 API: {', '.join(imports['key_apis']) or '(无)'}")
    if summary.get("pe_flags"):
        flags = summary["pe_flags"]
        lines.append(
            f"PE: 入口点 RVA={flags['entry_rva']} machine={flags['machine']} "
            f".NET={'是' if flags['dotnet'] else '否'}"
        )
    pdf = summary.get("pdf")
    if pdf:
        lines.extend(_render_pdf_block(pdf))
    strings = summary.get("strings") or []
    if pdf:
        lines.append(
            f"字符串（文件偏移顺序前 {len(strings)} 条；PDF 正文多数是压缩流，"
            "这一段是**未解压的原始字节**，不代表文件内容）:"
        )
    else:
        lines.append(f"字符串（文件偏移顺序前 {len(strings)} 条）:")
    for s in strings:
        lines.append(f"  · {s}")
    return "\n".join(lines)


@dataclass
class RenderedPrompt:
    system: str
    user: str
    est_tokens: int
    strings_used: int
    truncated: bool
    dropped: int = 0
    summary: dict[str, Any] = field(default_factory=dict)
    #: 砍光字符串、瘦完骨架之后**仍然**超预算（系统提示词 + 骨架自己就装不下）。
    #: **必须显式记账**：不能因为"砍无可砍"就静默交一份超预算的提示词出去 ——
    #: 那样预算闸就是假的（下游看到的 token 数比预算大，而没人知道）。
    over_budget: bool = False


def render_prompt(
    summary: dict[str, Any], max_tokens: int = TARGET_PROMPT_TOKENS
) -> RenderedPrompt:
    """渲染提示词并**在预算内**收敛。

    收敛顺序（从"最贵且最不影响结构判断"开始砍）：
      ① 字符串（20 条能占 60% token）；
      ② 骨架瘦身：布局条目砍到 8 条、DLL 名单砍到 4 个；
      ③ 还超就置 `over_budget=True` 原样交出去 —— 系统提示词自身的长度是硬底，
         再砍就没有摘要可言。这时候的正确做法是**让下游看得见**，不是假装没超。
    """
    system = SYSTEM_PROMPT
    base_cost = _count_tokens(system)
    working = dict(summary)
    strings = list(working.get("strings") or [])
    dropped = 0
    truncated = False
    over_budget = False
    user = ""
    total = 0

    while True:
        working["strings"] = strings
        user = render_user_prompt(working)
        total = base_cost + _count_tokens(user)
        if total <= max_tokens:
            break
        if strings:
            # 一次砍掉 1/4，比逐条砍少跑十几轮渲染
            cut = max(1, len(strings) // 4)
            dropped += cut
            strings = strings[:-cut]
            truncated = True
            continue
        # PDF 分支（只在 `summary["pdf"]` 存在时进入，别的类型走不到这里）：
        # 字符串砍光还超预算时，先收 URI / 内嵌文件，**至少留 1 段 JS 代码** ——
        # 那是这一层在 PDF 上最值钱的东西（见 `_pdf_summary`）。再超才退到骨架瘦身。
        if working.get("pdf") and not working.get("_pdf_trimmed"):
            pdf = dict(working["pdf"])
            changed = False
            for key, keep in (("uris", 2), ("embedded_files", 2), ("js_snippets", 1)):
                items = list(pdf.get(key) or [])
                if len(items) > keep:
                    pdf[key] = items[:keep]
                    changed = True
            working["_pdf_trimmed"] = True
            if changed:
                working["pdf"] = pdf
                truncated = True
                continue
        if not working.get("_skeleton_trimmed"):
            layout = list(working.get("layout") or [])
            if len(layout) > 8:
                working["layout"] = layout[:8]
                working["layout_more"] = len(layout) - 8
            imports = working.get("imports")
            if isinstance(imports, dict) and len(imports.get("dlls") or []) > 4:
                working["imports"] = {**imports, "dlls": imports["dlls"][:4]}
            working["_skeleton_trimmed"] = True
            truncated = True
            continue
        over_budget = total > max_tokens
        break

    working.pop("_skeleton_trimmed", None)
    working.pop("_pdf_trimmed", None)
    return RenderedPrompt(
        system=system,
        user=user,
        est_tokens=total,
        strings_used=len(strings),
        truncated=truncated,
        dropped=dropped,
        summary=working,
        over_budget=over_budget,
    )


# ---------------------------------------------------------------- 模型调用
_BAD_ESCAPE_RE = re.compile(r'\\(?!["\\/bfnrtu])')
_SCORE_RE = re.compile(r'"score"\s*:\s*(-?\d{1,3})')
_REASON_RE = re.compile(r'"reason"\s*:\s*"((?:[^"\\]|\\.)*)"')


def _parse_score(text: str) -> tuple[int | None, str, str, str]:
    """从模型输出里抽 {"score": int, "reason": str}。

    返回 `(score, reason, 错误说明, parse_mode)`。`parse_mode` 逐条留痕 ——
    报告里必须能分开"严格 JSON"和"修复后才解析出来的"，否则修好的坏输出会被当成正常输出。

    为什么需要修复档（实测，不是预防性代码）：模型会把摘要里那条乱码字符串原样引到 reason 里
    （`vqtMFpulT\\anMxeW1` 这种），一旦它写成**单个反斜杠**，产出的就是**非法 JSON**
    （`Invalid \\escape`）。Dike 灰区试水里 16 个文件踩了 1 个。
    这类失败**不能靠重试解决**（temperature=0，重发得到同一个坏字节），
    只能把"明显是转义写错"的地方修回来再解析 —— 修不动就如实报失败。
    """
    if not text or not text.strip():
        return None, "", "empty_output", "none"
    raw = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", raw, re.S)
    if fence:
        raw = fence.group(1).strip()
    candidate = raw
    if not candidate.startswith("{"):
        brace = re.search(r"\{.*\}", raw, re.S)
        if not brace:
            return None, "", "no_json_object", "none"
        candidate = brace.group()

    try:
        obj = json.loads(candidate)
        mode = "strict_json"
    except json.JSONDecodeError:
        # 修复档①：把非法转义（单个反斜杠）补成合法的 `\\`
        repaired = _BAD_ESCAPE_RE.sub(r"\\\\", candidate)
        try:
            obj = json.loads(repaired)
            mode = "repaired_escape"
        except json.JSONDecodeError:
            # 修复档②：只在能**明确**抓到 score 时用正则兜底（抓不到就报失败，不倒推分数）
            match = _SCORE_RE.search(candidate)
            if not match:
                return None, "", "json_decode_error_unrecoverable", "none"
            score = int(match.group(1))
            if not 0 <= score <= 100:
                return None, "", f"score_out_of_range:{score}", "none"
            reason_match = _REASON_RE.search(candidate)
            reason = reason_match.group(1) if reason_match else ""
            return score, reason, "", "regex_fallback"

    if not isinstance(obj, dict):
        return None, "", "json_not_object", mode
    score = obj.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        if isinstance(score, str) and score.strip().lstrip("-").isdigit():
            score = int(score.strip())
        else:
            return None, "", "score_missing_or_not_number", mode
    score = int(round(float(score)))
    if not 0 <= score <= 100:
        return None, "", f"score_out_of_range:{score}", mode
    reason = str(obj.get("reason") or "").strip()
    return score, reason, "", mode


@dataclass
class TriageCall:
    """一次模型调用的原始留痕（成功与失败都写）。"""

    ok: bool
    score: int | None
    reason: str
    error: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    usage_source: str = "none"      # provider / estimate / none
    elapsed_ms: int = 0
    attempts: int = 0
    model: str = ""
    # 解析档位：strict_json / repaired_escape / regex_fallback / none。
    # 必须留痕 —— 修复过的坏输出不能被当成正常输出（见 `_parse_score`）。
    parse_mode: str = "none"


class TriageClient:
    """便宜档模型的极简调用器（直接走 OpenAI-compatible /chat/completions）。

    为什么不用 `agent.build_agent` 那套 PydanticAI：深度 AI 那一层要工具调用、
    要重试策略、要证据溯源；初筛层**一次请求、一个 JSON、没有工具**——
    走 pydantic_ai 只会把这层的成本抬上去（它会把工具表、结构化输出重试全带上）。
    同样的 `AGENT_BASE_URL` / `AGENT_API_KEY`，少一层开销。
    """

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float | None = None,
        max_tokens: int = 4000,
        retries: int = 2,
    ) -> None:
        self.model = model or os.getenv("AGENT_MODEL", "deepseek-chat")
        self.base_url = (base_url or os.getenv("AGENT_BASE_URL", "https://api.deepseek.com/v1")).rstrip("/")
        self.api_key = (
            api_key
            or os.getenv("AGENT_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or os.getenv("DEEPSEEK_API_KEY")
        )
        if not self.api_key:
            raise RuntimeError("缺少 API Key（AGENT_API_KEY / OPENAI_API_KEY / DEEPSEEK_API_KEY）")
        self.timeout = timeout or float(os.getenv("AGENT_HTTP_TIMEOUT", "120"))
        # 输出预算：flash 是**推理模型**，reasoning token 也算在 max_tokens 里 ——
        # 实测（Dike 灰区试水）给 2000 时 20 个文件里 3 个把预算烧在 reasoning 上、
        # 正文字段为空（finish_reason=length）。默认放到 4000（用不完不计费），
        # 可用 TRIAGE_MAX_OUTPUT_TOKENS 覆盖。
        self.max_tokens = int(os.getenv("TRIAGE_MAX_OUTPUT_TOKENS", str(max_tokens)))
        self.retries = max(0, retries)
        # 网关要求每个会话一个稳定 ID（缺了直接 4xx）。复用 `agent._provider_headers`
        # —— 这一层与深度 AI 走的是同一个网关，头必须一致，不能各写一份。
        from aiav.agent import _provider_headers

        self.session_id = os.getenv("AGENT_SESSION_ID") or uuid.uuid4().hex
        self.headers = _provider_headers(self.base_url, self.session_id)

    def _client(self) -> httpx.Client:
        return httpx.Client(
            timeout=self.timeout,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                **self.headers,
            },
        )

    @staticmethod
    def _retryable(exc: BaseException) -> bool:
        if isinstance(exc, httpx.TransportError):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            code = exc.response.status_code
            return code in {408, 409, 425, 429} or code >= 500
        return False

    def classify(
        self,
        prompt: RenderedPrompt,
        client: httpx.Client | None = None,
    ) -> TriageCall:
        """跑一次初筛。**失败就是失败**：不猜分数、不倒推、不留 -1 之类的假值。"""
        started = time.time()
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
            "temperature": 0.0,
            "max_tokens": self.max_tokens,
        }
        own = client is None
        http = client or self._client()
        attempts = 0
        last_error = ""
        spent_tokens = 0
        try:
            data: dict[str, Any] = {}
            # 两类可重试失败：
            #   ① 传输/网关抖动（见 `_retryable`）；
            #   ② **空输出 / 被 max_tokens 截断** —— flash 是推理模型，reasoning token
            #      也算在 max_tokens 里。实测（Dike 灰区试水）：20 个文件里 3 个
            #      把预算烧在 reasoning 上、`content` 是空的（约 2.8k token 白花）。
            #      这类失败**重发一次往往就正常**（与 `agent.EmptyAgentResponse` 同款判断），
            #      所以这里和网络错误一样重试；重试仍失败才作废。
            for attempt in range(1, self.retries + 2):
                attempts = attempt
                data = {}
                try:
                    resp = http.post(f"{self.base_url}/chat/completions", json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as exc:  # noqa: BLE001 - 分类后决定重试还是放弃
                    last_error = f"{type(exc).__name__}: {exc}"[:300]
                    if attempt > self.retries or not self._retryable(exc):
                        return TriageCall(
                            ok=False, score=None, reason="", error=last_error,
                            elapsed_ms=int((time.time() - started) * 1000),
                            attempts=attempts, model=self.model,
                            prompt_tokens=spent_tokens or prompt.est_tokens,
                            total_tokens=spent_tokens or prompt.est_tokens,
                            usage_source="estimate",
                        )
                    time.sleep(min(8.0, 0.5 * 2 ** (attempt - 1)))
                    continue

                usage = data.get("usage") or {}
                spent_tokens += int(usage.get("total_tokens") or 0)
                text = ""
                try:
                    text = data["choices"][0]["message"]["content"] or ""
                except (KeyError, IndexError, TypeError) as exc:
                    last_error = f"bad_response_shape: {exc}"
                if not text.strip():
                    finish = ""
                    try:
                        finish = str(data["choices"][0].get("finish_reason") or "")
                    except (KeyError, IndexError, TypeError):
                        pass
                    last_error = f"empty_output(finish_reason={finish or '?'})"
                    if attempt <= self.retries:
                        time.sleep(min(8.0, 0.5 * 2 ** (attempt - 1)))
                        continue
                    return TriageCall(
                        ok=False, score=None, reason="", error=last_error,
                        prompt_tokens=int(usage.get("prompt_tokens") or prompt.est_tokens),
                        completion_tokens=int(usage.get("completion_tokens") or 0),
                        total_tokens=spent_tokens or prompt.est_tokens,
                        usage_source="provider",
                        elapsed_ms=int((time.time() - started) * 1000),
                        attempts=attempts, model=self.model,
                    )
                break
            else:  # pragma: no cover - 循环必然 break 或 return
                return TriageCall(ok=False, score=None, reason="", error=last_error)

            usage = data.get("usage") or {}
            prompt_tokens = int(usage.get("prompt_tokens") or 0)
            completion_tokens = int(usage.get("completion_tokens") or 0)
            total_tokens = int(usage.get("total_tokens") or (prompt_tokens + completion_tokens))
            source = "provider"
            if not total_tokens:
                # provider 没报 usage：退到本地估算并**显式标出来**（别让报告分不清实测与估算）
                prompt_tokens = prompt.est_tokens
                completion_tokens = _count_tokens(text)
                total_tokens = prompt_tokens + completion_tokens
                source = "estimate"
            # 重试过的尝试也要算钱：把前几次白烧的 token 加进去，否则成本被系统性低估
            total_tokens += max(0, spent_tokens - int(usage.get("total_tokens") or 0))

            score, reason, err, parse_mode = _parse_score(text)
            return TriageCall(
                ok=err == "",
                score=score,
                reason=reason,
                error=err or last_error,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                usage_source=source,
                elapsed_ms=int((time.time() - started) * 1000),
                attempts=attempts,
                model=self.model,
                parse_mode=parse_mode,
            )
        finally:
            if own:
                http.close()


# ---------------------------------------------------------------- 单文件入口
def triage_cached(
    path: Path,
    sha256: str,
    client: TriageClient,
    http: httpx.Client | None = None,
    max_prompt_tokens: int = TARGET_PROMPT_TOKENS,
    cache: Any | None = None,
    samples: int = 1,
) -> dict[str, Any]:
    """单文件初筛 + 缓存（**缓存口径只在这一处**）。

    命中 `TriageCache` 就不重算（同 sha256 + 同模型 + 同摘要版本），`from_cache=True`
    原样写进结果。流水线（`scanner`）与脚本（`run_batch`）都走这个函数 ——
    两边各写一份缓存判断，就会出现"脚本吃了缓存、流水线没吃"这种只在一条路径上
    复现的差异（与 `TriageClient` 构造只留一处是同一类理由）。
    """
    if cache is not None:
        hit = cache.get_triage(sha256, model=client.model, samples=samples)
        if hit:
            record = dict(hit["result"])
            record["from_cache"] = True
            record["path"] = str(path)
            record["name"] = path.name
            return record
    record = triage_one(path, sha256, client, http=http,
                        max_prompt_tokens=max_prompt_tokens)
    if cache is not None and record["ok"]:
        cache.put_triage(sha256, record, model=client.model, samples=samples)
    return record


def triage_one(
    path: Path,
    sha256: str,
    client: TriageClient,
    http: httpx.Client | None = None,
    max_prompt_tokens: int = TARGET_PROMPT_TOKENS,
) -> dict[str, Any]:
    """单文件初筛：构建摘要 → 渲染 → 调用 → 组装结果记录（含成本与留痕）。"""
    summary = build_summary(path, sha256)
    prompt = render_prompt(summary, max_tokens=max_prompt_tokens)
    call = client.classify(prompt, client=http)
    return {
        "path": str(path),
        "name": path.name,
        "sha256": sha256,
        "score": call.score,
        "reason": call.reason,
        "ok": call.ok,
        "error": call.error,
        "prompt_tokens": call.prompt_tokens,
        "completion_tokens": call.completion_tokens,
        "total_tokens": call.total_tokens,
        "usage_source": call.usage_source,
        "parse_mode": call.parse_mode,
        "elapsed_ms": call.elapsed_ms,
        "attempts": call.attempts,
        "model": call.model,
        "est_tokens": prompt.est_tokens,
        "strings_used": prompt.strings_used,
        "summary_truncated": prompt.truncated,
        "summary_over_budget": prompt.over_budget,
        "strings_dropped": prompt.dropped,
        "summary": {
            k: v for k, v in prompt.summary.items()
            if k in ("name", "size", "extension", "kind", "entropy", "layout",
                     "imports", "pe_flags", "macro_store", "read_error", "pdf")
        },
        "from_cache": False,
    }


def run_batch(
    items: Iterable[tuple[Path, str]],
    client: TriageClient,
    workers: int = 6,
    max_prompt_tokens: int = TARGET_PROMPT_TOKENS,
    cache: Any | None = None,
    samples: int = 1,
    on_result: Any | None = None,
) -> list[dict[str, Any]]:
    """并发跑一批。**只做静态读取**：不执行样本、不上传、不落地。

    缓存口径见 `triage_cached`（唯一一处）：命中 `TriageCache` 就不重算，
    `from_cache=True` 原样写进结果 —— 报告里能分开"这次真跑了"和"吃了缓存"。
    """
    items = list(items)
    results: list[dict[str, Any]] = []

    with httpx.Client(
        timeout=client.timeout,
        headers={
            "Authorization": f"Bearer {client.api_key}",
            "Content-Type": "application/json",
            **client.headers,
        },
    ) as shared:
        def bound(item: tuple[Path, str]) -> dict[str, Any]:
            path, sha256 = item
            return triage_cached(path, sha256, client, http=shared,
                                 max_prompt_tokens=max_prompt_tokens,
                                 cache=cache, samples=samples)

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for record in pool.map(bound, items):
                results.append(record)
                if on_result is not None:
                    on_result(record)
    return results


def summarize_cost(results: list[dict[str, Any]]) -> dict[str, Any]:
    """成本口径（**只有这一处**定义，报告与脚本都从这里取）。

    · `tokens` 全部来自 provider 报的 usage；没有 usage 的条目退到本地估算，
      并把条数记在 `estimated_entries` 里 —— 报告里必须能分开实测与估算。
    · 金额用 `aiav.budget.CNY_PER_MILLION_TOKENS`（全项目唯一定义处，偏高的一档）。
    """
    from aiav.budget import CNY_PER_MILLION_TOKENS

    ok = [r for r in results if r.get("ok")]
    failed = [r for r in results if not r.get("ok")]
    cached = [r for r in results if r.get("from_cache")]
    charged = [r for r in results if not r.get("from_cache")]
    total = sum(int(r.get("total_tokens") or 0) for r in charged)
    prompt = sum(int(r.get("prompt_tokens") or 0) for r in charged)
    completion = sum(int(r.get("completion_tokens") or 0) for r in charged)
    estimated = sum(1 for r in charged if r.get("usage_source") == "estimate")
    parse_modes: dict[str, int] = {}
    for r in charged:
        key = str(r.get("parse_mode") or "none")
        parse_modes[key] = parse_modes.get(key, 0) + 1
    n = len(charged) or 0
    return {
        "files": len(results),
        "ok": len(ok),
        "failed": len(failed),
        "from_cache": len(cached),
        "charged_files": n,
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": total,
        "avg_tokens_per_file": round(total / n, 1) if n else 0.0,
        "avg_prompt_tokens": round(prompt / n, 1) if n else 0.0,
        "estimated_entries": estimated,
        "parse_modes": parse_modes,
        "repaired_or_fallback": sum(
            v for k, v in parse_modes.items() if k in ("repaired_escape", "regex_fallback")),
        "summary_over_budget": sum(1 for r in charged if r.get("summary_over_budget")),
        "usage_source": "provider" if estimated == 0 else "mixed",
        "cny_per_million_tokens": CNY_PER_MILLION_TOKENS,
        "cost_cny": round(total / 1_000_000 * CNY_PER_MILLION_TOKENS, 4),
        "price_source": "project constant (budget.CNY_PER_MILLION_TOKENS) — upper bound for flash tier",
    }
