from __future__ import annotations

import functools
import json
import locale
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from pydantic_ai import RunContext

from aiav.models import ScanDeps


def _resource_root() -> Path:
    """包内数据目录：YARA 规则（rules/）与已知恶意 hash 表（known_bad_hashes.txt）都从这里找。

    源码运行 = `aiav/data/`；PyInstaller 打包后 = 解包目录下的 `aiav/data/`（兼容摊平的 `data/`）。
    """
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
        for cand in (base / "aiav" / "data", base / "data"):
            if cand.is_dir():
                return cand
        return base / "aiav" / "data"
    return Path(__file__).resolve().parent / "data"


BASE_DIR = _resource_root()
# 仓库根（源码运行时 = 项目根）。capa 的规则/签名是外部大语料，不进包，放这里按需拉取。
PROJECT_ROOT = Path(__file__).resolve().parent.parent
# 只做提示、不允许抬升定级的启发式规则（通用子串，误报率高）
WEAK_YARA_RULES = {"Suspicious_Process_Injection_APIs"}
# 只有这类"高置信恶意"规则才允许把 clean 抬到 suspicious（策略兜底白名单）。
# 其余规则（通用 PowerShell/Office 特征）只能作为送 AI 复筛的理由，不能单独定性 ——
# 2026-09-19 实测：Suspicious_PowerShell_Download 会在微软签名系统 DLL 上命中，
# 而 enforce_policy 的旧实现把 AI 的 clean 顶回 suspicious，造成无法平反的误报。
HIGH_CONFIDENCE_YARA_RULES = {"EICAR_Test_File", "Suspicious_LNK_Execution", "Suspicious_RTF_Remote_Object"}
RULES_DIR = BASE_DIR / "rules"
KNOWN_BAD_HASHES_FILE = BASE_DIR / "known_bad_hashes.txt"

SUSPICIOUS_SCRIPT_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\bInvoke-Expression\b|\bIEX\b", "PowerShell Invoke-Expression"),
    (r"(?i)\bDownloadString\b", "PowerShell DownloadString"),
    (r"(?i)\bDownloadFile\b", "PowerShell DownloadFile"),
    (r"(?i)\bFromBase64String\b", "PowerShell FromBase64String"),
    (r"(?i)-enc(odedcommand)?\s", "PowerShell encoded command"),
    (r"(?i)-nop|noprofile|-w\s+hidden|-windowstyle\s+hidden", "PowerShell hidden window"),
    (r"(?i)New-Object\s+Net\.WebClient", "PowerShell WebClient"),
    (r"(?i)Start-Process", "PowerShell Start-Process"),
    (r"(?i)WScript\.Shell|Shell\.Application", "COM shell execution"),
    (r"(?i)CreateObject\s*\(", "VBScript/JS CreateObject"),
    (r"(?i)AutoOpen|Document_Open|Workbook_Open", "Office 自动执行入口"),
    (r"(?i)URLDownloadToFile|WinHttpOpen|InternetOpen", "Windows 下载 API"),
    (r"(?i)\beval\s*\(", "eval execution"),
    (r"(?i)\batob\s*\(|fromCharCode", "JS base64/char decode"),
    (r"(?i)ActiveXObject|XMLHttpRequest", "JS ActiveX/HTTP"),
    (r"(?i)cmd\.exe|powershell\.exe|mshta\.exe|rundll32\.exe|regsvr32\.exe", "常见 LOLBin 调用"),
    (r"(?i)schtasks|bitsadmin|certutil\s+-urlcache", "持久化/下载命令"),
    (r"(?i)vssadmin|wbadmin|bcdedit|wevtutil", "系统安全相关命令"),
    # ---- 2026-09-19 补强：脚本类混淆的静态特征（PowerShell / VBS / JS / BAT）----
    # 只加"结构上可判定"的特征；「是不是恶意」仍由模型/策略看上下文，
    # 这些标签的作用是把混淆脚本送进复核并让规则档也能抓到最粗的那一档。
    (r"(?i)(?:^|[\s\"'])-?e(nc(odedcommand)?)?\s*[\"']?[A-Za-z0-9+/=]{40,}", "PowerShell 编码命令载荷(base64)"),
    (r"(?i)powershell(\.exe)?[^\n]{0,60}\s-e\s+[A-Za-z0-9+/=]{20,}", "PowerShell -e 短编码参数"),
    (r"(?i)\[Convert\]::FromBase64String|\[System\.Text\.Encoding\]::\w+\.GetString",
     "PowerShell 解码链(Convert/Encoding)"),
    (r"(?i)\[char\]\s*\d+|\[char\]\s*0x", "PowerShell [char] 字符码构造"),
    (r"(?i)-bxor|\s-join\s*\(|\s-join\s*\$", "PowerShell 逐字节拼装(-bxor/-join)"),
    (r"(?i)Set-MpPreference|Add-MpPreference[^\n]{0,40}Exclusion|DisableRealtimeMonitoring",
     "PowerShell 关闭/绕过 Defender"),
    (r"(?i)Invoke-WebRequest|\bIWR\b|Invoke-RestMethod|DownloadData\b", "PowerShell 远程下载"),
    (r"(?i)Reflection\.Assembly|\[\s*System\.Reflection\.Assembly\s*\]|Add-Type\s+-TypeDefinition",
     "PowerShell 内存加载程序集"),
    (r"(?i)\bExecute(Global)?\s*\(", "VBS 动态执行(Execute/ExecuteGlobal)"),
    (r"(?i)\bChrW?\s*\(\s*(\d+|&H)", "VBS Chr() 字符码构造"),
    (r"(?i)MSXML2\.(XMLHTTP|ServerXMLHTTP)|WinHttp\.WinHttpRequest", "VBS HTTP 下载对象"),
    (r"(?i)ADODB\.Stream|\.SaveToFile\b|\.Open\s+.*adodb", "VBS 落盘(ADODB.Stream/SaveToFile)"),
    (r"(?i)unescape\s*\(|decodeURIComponent\s*\(", "JS 解码函数"),
    (r"(?i)new\s+Function\s*\(", "JS 动态构造函数"),
    (r"(?i)(\\x[0-9a-fA-F]{2}){4,}", "JS 十六进制转义串"),
    (r"(?i)(%u[0-9a-fA-F]{4}){4,}", "JS Unicode 转义串"),
    (r"(?i)certutil\s+(-decode|-urlcache|-f\s+-)", "certutil 解码/下载"),
    (r"(?i)bitsadmin\s+/transfer", "bitsadmin 下载"),
    (r"(?i)regsvr32[^\n]{0,20}/i:\s*https?", "regsvr32 远程脚本(Squiblydoo)"),
    (r"(?i)copy\s+/b\s+[^\n]{0,60}\+", "copy /b 拼接文件"),
    (r"(?i)%\w+:~", "BAT 变量切片混淆"),
]

SUSPICIOUS_PE_APIS = {
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "SetWindowsHookEx",
    "QueueUserAPC",
    "CreateProcessA",
    "CreateProcessW",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "RegCreateKeyExA",
    "RegSetValueExA",
    "RegSetValueExW",
}

HIGH_RISK_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".pif",
    ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".jar", ".lnk", ".msi",
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".ole",
}


RECORD_MAX_CHARS = int(os.getenv("AI_AV_RECORD_MAX_CHARS", "2000"))


def _shrink_json(value: Any, budget: int) -> Any:
    """递归裁剪 JSON 结构：优先砍长列表、再砍长字符串，不砍掉字段本身。

    这样裁完仍是**合法 JSON 且字段齐全**，读报告的人能看出"这个列表被截了"，
    而不是面对一个腰斩的字符串。
    """
    if isinstance(value, dict):
        return {k: _shrink_json(v, budget) for k, v in value.items()}
    if isinstance(value, list):
        out: list[Any] = []
        used = 0
        for item in value:
            piece = _shrink_json(item, max(64, budget // 2))
            size = len(json.dumps(piece, ensure_ascii=False))
            if used + size > budget and out:
                out.append(f"…[此处省略 {len(value) - len(out)} 项]")
                break
            out.append(piece)
            used += size
        return out
    if isinstance(value, str) and len(value) > budget:
        return value[:budget] + f"…[字符串截断，原长 {len(value)}]"
    return value


def _cap_for_record(summary: str, limit: int | None = None) -> str:
    """审计存档用的截断：**结构化裁剪 + 显式标注**，绝不裸切 JSON 字符串。

    旧实现是 `summary[:2000]` —— 对 `json.dumps` 的结果裸切字符串，结果存档里
    13/65 条工具输出是**非法 JSON**（尾部字符串被腰斩）。而且它是静默的：
    读报告的人分不清"工具只返回了这些"和"这里被截了"。
    （对照 IntelOwl 的做法：a truncated list is never silent。）

    注意：这里截的只是**审计存档副本**，返回给 AI 的是各工具自己的 `summary[:N]`。
    """
    limit = limit or RECORD_MAX_CHARS
    if len(summary) <= limit:
        return summary
    try:
        data = json.loads(summary)
    except Exception:  # noqa: BLE001 - 非 JSON（少数工具返回纯文本）
        head = limit // 2
        return (summary[:head]
                + f"\n…[审计存档截断：完整输出 {len(summary)} 字符，此处留头尾]…\n"
                + summary[-(limit - head):])
    shrunk = json.dumps(_shrink_json(data, limit), ensure_ascii=False)
    if len(shrunk) > limit:
        # 收紧预算再来一轮（列表项数会进一步减少）
        shrunk = json.dumps(_shrink_json(data, max(64, limit // 3)), ensure_ascii=False)
    if len(shrunk) > limit:
        # 最后兜底：**包成合法 JSON 信封**，别裸切字符串 ——
        # 裸切会让存档变成非法 JSON，读报告的人只能看到一段腰斩的文本。
        shrunk = json.dumps(
            {
                "_truncated": True,
                "_original_chars": len(summary),
                "_note": f"结构裁剪后仍超出存档上限 {limit} 字符，仅保留片段",
                "_preview": shrunk[: max(0, limit - 200)],
            },
            ensure_ascii=False,
        )
    return shrunk


def _record(ctx: RunContext[ScanDeps], tool_name: str, summary: str) -> None:
    ctx.deps.tool_calls.append({"tool": tool_name, "summary": _cap_for_record(summary)})


def _decode_output(data: bytes) -> str:
    """外部命令输出解码：先 UTF-8，再退回本地代码页（Windows 上是 cp936/mbcs）。

    Windows 下 cmd / PowerShell / capa 的输出常是 OEM 代码页，用 UTF-8 硬解会变乱码。
    """
    if not data:
        return ""
    for enc in ("utf-8", locale.getpreferredencoding(False), "cp936", "latin-1"):
        if not enc:
            continue
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def _script_dirs() -> list[Path]:
    """候选的「pip 装出来的可执行文件」目录。

    ⚠️ **不能用 `Path(sys.executable).resolve().parent`。**
    venv 里 `bin/python` 是指向系统解释器的**符号链接**，`.resolve()` 会跟过去，
    parent 变成 `/usr/bin` —— 于是 venv 里 pip 装的 capa/floss **永远找不到**。
    实测：干净 venv 里装好 capa 后 `_find_exe("capa")` 仍返回 None，
    只能靠 `CAPA_EXE` 手动指路；这也是为什么之前调 capa 必须显式设环境变量。

    `sysconfig.get_path("scripts")` 是标准做法，它认 venv。
    """
    dirs: list[Path] = []
    try:
        import sysconfig

        scripts = sysconfig.get_path("scripts")
        if scripts:
            dirs.append(Path(scripts))
    except Exception:  # noqa: BLE001 - 取不到就走兜底
        pass
    # 兜底：**不 resolve**，保留 venv 路径；Windows 的 venv 是 Scripts/，POSIX 是 bin/
    exe_dir = Path(sys.executable).parent
    dirs += [exe_dir / "Scripts", exe_dir / "bin", exe_dir]
    seen: set[Path] = set()
    out: list[Path] = []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _find_exe(*names: str, env_var: str | None = None) -> str | None:
    """查找外部工具：环境变量覆盖 → PATH → 当前 venv 的 Scripts/bin 目录。

    Windows 下 pip 装的 capa/floss 落在 `Scripts\\*.exe`，若不在 PATH 里也能找到。
    """
    if env_var:
        override = os.getenv(env_var)
        if override and Path(override).exists():
            return override
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    for name in names:
        for d in _script_dirs():
            for suffix in ("", ".exe", ".cmd", ".bat"):
                p = d / f"{name}{suffix}"
                if p.exists():
                    return str(p)
    return None


def _text_preview(text: str, max_chars: int = 8000) -> str:
    return text[:max_chars]


def _read_bytes(path: Path, max_bytes: int = 2 * 1024 * 1024) -> bytes:
    with path.open("rb") as f:
        return f.read(max_bytes)


def _read_text_safe(path: Path, max_bytes: int = 256 * 1024) -> str:
    data = _read_bytes(path, max_bytes)
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        # 带 BOM 的纯 UTF-16 文本，整体解码
        return data.decode("utf-16", errors="ignore")
    if b"\x00" in data[:200]:
        # 二进制容器（LNK / OLE / PE 等）：只抽字符串。
        # 整体按 UTF-16 解码会因为二进制头导致字节错位，把 "Windows" 读成 "圀椀渀搀漀眀猀"，
        # 关键字和 URL 全部匹配不上。
        return extract_container_strings(data)
    return data.decode("utf-8", errors="ignore")


@functools.lru_cache(maxsize=1)
def load_yara_rules() -> Any | None:
    """加载 rules/ 目录下的所有 .yar / .yara 规则。"""
    try:
        import yara  # type: ignore
    except ImportError:
        return None

    rule_files = sorted(list(RULES_DIR.glob("*.yar")) + list(RULES_DIR.glob("*.yara")))
    if not rule_files:
        return None

    namespaces: dict[str, str] = {}
    for f in rule_files:
        namespaces[f.stem] = str(f)
    try:
        return yara.compile(filepaths=namespaces)
    except Exception:
        return None


def run_yara(path: Path) -> list[str]:
    """给预筛用的 YARA 包装：**只要规则名**（预筛只拿它算分）。"""
    rules = load_yara_rules()
    if rules is None:
        return []
    try:
        matches = rules.match(str(path))
    except Exception:
        return []
    return [m.rule for m in matches]


# =========================
# YARA 命中详情（送 AI 的证据，不是结论）
# =========================
# 为什么有这个东西（2026-09-26 审查结论）：
#   旧设计把 YARA 结果做成 `yara_scan` 工具，返回 `strong_hits` / `weak_hits` 两档 ——
#   那个分档是**本模块自己硬编码的判定口径**（WEAK_YARA_RULES），既不是 YARA 引擎给的，
#   也不是规则作者声明的。而 YARA 引擎真正算出来的东西（命中在哪个偏移、命中了什么字节）
#   和规则作者真正声明的东西（severity / tuning / benign_expectation）**全被扔了**。
#   结果 AI 拿到一个光秃秃的规则名 + 一份别人的加权口径，只能复读。
#
#   现在改成：预筛结果直接进送审提示词，给的是**可解读的证据**：
#     · 命中偏移 + 命中字节 + 前后上下文  → AI 能判"这是真载荷还是源码里的字符串字面量"
#     · 规则自己的 meta                   → AI 知道这条规则什么时候会错（作者写的误报史）
#   不给分数、不给分档 —— 那是判断，留给 AI 做。
YARA_DETAIL_MAX_RULES = 8          # 最多列几条规则
YARA_DETAIL_MAX_PER_RULE = 5       # 每条规则最多列几个命中位置
YARA_DETAIL_MAX_TOTAL = 20         # 全文最多列几个命中位置
YARA_DETAIL_CONTEXT_BYTES = 60     # 每个命中位置前后各取多少字节上下文
YARA_DETAIL_READ_LIMIT = 16 * 1024 * 1024  # 读文件取上下文的上限，超了不取上下文


def yara_match_details(path: Path) -> list[dict[str, Any]]:
    """取出 YARA 命中的证据：规则 meta + 每个命中标识符的偏移/字节/上下文。

    返回一个列表，每条对应一条命中的规则：
        {rule, severity, description, tuning, benign_expectation,
         instances: [{identifier, offset, matched, context}],
         instances_shown, instances_total, truncated}
    截断**显式记账**（truncated / instances_total），不让"只列了 5 处"被读成"只有 5 处"。
    """
    rules = load_yara_rules()
    if rules is None:
        return []
    try:
        matches = rules.match(str(path))
    except Exception:
        return []

    # 取上下文要读原文件；读不动就不给上下文，但偏移和命中字节照给
    raw = b""
    try:
        if path.is_file() and path.stat().st_size <= YARA_DETAIL_READ_LIMIT:
            raw = path.read_bytes()
    except OSError:
        raw = b""

    def _context(offset: int, length: int) -> str:
        if not raw:
            return ""
        lo = max(0, offset - YARA_DETAIL_CONTEXT_BYTES)
        hi = min(len(raw), offset + length + YARA_DETAIL_CONTEXT_BYTES)
        text = raw[lo:hi].decode("utf-8", errors="replace")
        # 按字节切片会把多字节字符切一半，解出 U+FFFD。对提示词来说那是噪音，
        # 直接去掉（宁可少一个字，也不要给 AI 一串看不懂的替换符）。
        text = text.replace("\ufffd", "")
        # 换行压成可见符号，免得提示词里出现真假难辨的空行
        return text.replace("\r\n", "\n").replace("\n", "⏎")

    out: list[dict[str, Any]] = []
    total_shown = 0
    for m in matches:
        if len(out) >= YARA_DETAIL_MAX_RULES:
            break
        meta = dict(getattr(m, "meta", {}) or {})
        instances: list[dict[str, Any]] = []
        total_for_rule = 0
        for sm in getattr(m, "strings", []) or []:
            ident = getattr(sm, "identifier", "") or ""
            for inst in getattr(sm, "instances", []) or []:
                total_for_rule += 1
                if len(instances) >= YARA_DETAIL_MAX_PER_RULE:
                    continue
                if total_shown >= YARA_DETAIL_MAX_TOTAL:
                    continue
                offset = int(getattr(inst, "offset", 0) or 0)
                matched = getattr(inst, "matched_data", b"") or b""
                instances.append(
                    {
                        "identifier": ident,
                        "offset": offset,
                        "matched": matched.decode("utf-8", errors="replace")[:120],
                        "context": _context(offset, len(matched)),
                    }
                )
                total_shown += 1
        out.append(
            {
                "rule": getattr(m, "rule", ""),
                "severity": meta.get("severity"),
                "description": meta.get("description"),
                "tuning": meta.get("tuning"),
                "benign_expectation": meta.get("benign_expectation"),
                "instances": instances,
                "instances_shown": len(instances),
                "instances_total": total_for_rule,
                "truncated": total_for_rule > len(instances),
            }
        )
    return out


def _user_data_root() -> Path:
    """跨平台用户数据目录 —— pip 装出来的包找不到项目根时的落点。"""
    if sys.platform == "win32":
        base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
        if base:
            return Path(base) / "aiav"
    base = os.getenv("XDG_DATA_HOME", "").strip()
    if base:
        return Path(base) / "aiav"
    return Path.home() / ".local" / "share" / "aiav"


def capa_data_root() -> Path:
    """capa 语料根目录，`CAPA_DATA` 可覆盖。源码运行用仓库 third_party/；
    装出来的包 PROJECT_ROOT 是 site-packages，改用用户数据目录。
    """
    override = os.getenv("CAPA_DATA", "").strip()
    if override:
        return Path(override)
    if (PROJECT_ROOT / "pyproject.toml").is_file():
        return PROJECT_ROOT / "third_party"
    return _user_data_root()


def _pick_capa_dir(env_var: str, name: str) -> Path:
    """挑一个**真的有内容**的 capa 语料目录；都没有就返回默认落点（供报错信息指路）。"""
    override = os.getenv(env_var, "").strip()
    if override:
        return Path(override)
    target = capa_data_root() / name
    for cand in (target, _user_data_root() / name, PROJECT_ROOT / "third_party" / name):
        if cand.is_dir() and any(cand.iterdir()):
            return cand
    return target


def capa_rules_dir() -> Path:
    """capa 规则集目录，`CAPA_RULES` 可覆盖。pip 包不自带，由 `aiav capa-setup` 拉取。"""
    return _pick_capa_dir("CAPA_RULES", "capa-rules")


def capa_sigs_dir() -> Path:
    """capa 签名集目录，`CAPA_SIGS` 可覆盖。v9.4.0 有 3 个 `.sig`；少一个不报错，只是少认一批编译器签名。"""
    return _pick_capa_dir("CAPA_SIGS", "capa-sigs")


def _capa_timeout() -> int:
    """capa 单文件超时秒数，`CAPA_TIMEOUT` 可覆盖。"""
    try:
        return max(10, int(os.getenv("CAPA_TIMEOUT", "180")))
    except ValueError:
        return 180


def capa_ready() -> tuple[bool, str]:
    """capa 能不能真的跑起来，返回 (可用, 原因)。二进制 + 规则集 + 签名集三样都要：
    缺规则报 "embedded rules not found" 退出码 10，缺签名直接退出码 1 零输出。
    """
    if not _find_exe("capa", env_var="CAPA_EXE"):
        return False, "未安装（拿不到能力识别与 ATT&CK 映射）"
    rules = capa_rules_dir()
    if not rules.is_dir() or not any(rules.iterdir()):
        return False, (
            f"已装但缺少规则集（{rules} 不存在或为空；pip 装的 capa 不自带规则，"
            "跑 `aiav capa-setup` 拉取）"
        )
    sigs = capa_sigs_dir()
    if not sigs.is_dir() or not any(sigs.iterdir()):
        return False, (
            f"已装但缺少签名集（{sigs} 不存在或为空；capa 没有签名集会直接报错退出，"
            "跑 `aiav capa-setup` 拉取）"
        )
    return True, ""


# 跑不了的检测项：不是"没发现问题"，是"根本没跑"。这两件事必须分开告诉 AI，
# 否则它会把"缺上下文"读成"没风险"（对照 beenuar/AiSOC 的教训）。
# ClamAV：传统 AV 引擎的签名库命中。上游明说 ≥1000 档（单条即可定恶意、几乎无误报）的
# 分数就来自这类**签名服务** —— 所以 `DET_CLAMAV_SIGNATURE` 是①层里最有价值的一条判据。
#
# ⚠️ 本机没装 ClamAV（`aiav tools` 里明写"未安装"）。这条判据因此在本轮实测里命中 0，
# 报告里必须显式标出 —— "没装"不等于"查过了没有"。
CLAMAV_TIMEOUT = 120


def clamav_evidence(path: Path, runner=None) -> dict[str, Any]:
    """跑一次 ClamAV（只读扫描，不上传、不联网）。

    返回 `{available, infected, signature, raw, error}`。
    `available=False` 表示**本机没有 ClamAV** —— 调用方据此把这条判据记成"未产出"，
    不许当成"扫过且干净"。

    `runner` 只给测试注入用（默认走 subprocess）。
    """
    exe = _find_exe("clamscan", "clamdscan", env_var="CLAMAV_EXE")
    if not exe:
        return {"available": False, "infected": False, "signature": "",
                "raw": "", "error": "ClamAV 未安装（clamscan / clamdscan 都不在 PATH 里）"}

    cmd = [exe, "--no-summary", "--stdout", str(path)]
    try:
        if runner is not None:
            proc = runner(cmd)
        else:
            proc = subprocess.run(cmd, capture_output=True, timeout=CLAMAV_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": True, "infected": False, "signature": "", "raw": "",
                "error": f"{type(exc).__name__}: {exc}"}

    out = ((proc.stdout or b"") + (proc.stderr or b"")).decode("utf-8", errors="replace")
    # clamscan 命中时退出码 1，输出形如 `/path/file: Win.Trojan.Agent-123 FOUND`
    infected = "FOUND" in out
    signature = ""
    if infected:
        line = next((ln for ln in out.splitlines() if "FOUND" in ln), "")
        signature = line.split(":", 1)[1].replace("FOUND", "").strip() if ":" in line else line.strip()
    return {"available": True, "infected": infected, "signature": signature,
            "raw": out.strip()[:500], "error": ""}


def unavailable_detections() -> list[str]:
    """返回本次环境不可用的检测项及原因（写进送审提示词）。"""
    items: list[str] = []
    if not _find_exe("clamscan", "clamdscan", env_var="CLAMAV_EXE"):
        items.append("ClamAV —— 未安装（没有传统 AV 基线可对照）")
    capa_ok, capa_why = capa_ready()
    if not capa_ok:
        items.append(f"capa —— {capa_why}")
    if not _find_exe("floss", env_var="FLOSS_EXE"):
        items.append("FLOSS —— 未安装（拿不到解混淆/解码字符串）")
    if not os.getenv("VT_API_KEY", "").strip():
        items.append("VirusTotal —— 未配置 API Key（拿不到外部多引擎票数）")
    return items


def find_script_patterns(text: str) -> list[str]:
    """返回命中的可疑脚本模式。"""
    found: list[str] = []
    for pattern, label in SUSPICIOUS_SCRIPT_PATTERNS:
        if re.search(pattern, text, re.MULTILINE):
            found.append(label)
    return sorted(set(found))


# 脚本类扩展名：这些文件的"可执行面"就是文本本身，所以预筛要多读一点。
SCRIPT_EXTENSIONS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
                     ".wsf", ".wsh", ".hta", ".py", ".sh"}
SCRIPT_READ_LIMIT = 256 * 1024   # 脚本是文本，多读不会爆内存；旧实现只看前 4KB 会漏掉尾部载荷

# 结构性混淆信号：单个关键词看不出来，要数"密度"才判得动。
# 阈值故意保守（宁可漏一点，也不要把正常脚本的路径拼接算成混淆）。
_QUOTED_CONCAT_RE = re.compile(r"""["']\s*(?:\+|&)\s*["']""")
_LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_CHARCODE_RE = re.compile(r"(?i)\bChrW?\s*\(\s*(?:\d+|&H[0-9a-f]+)\s*\)|String\.fromCharCode|\[char\]")
_REVERSE_STRING_RE = re.compile(r"(?i)-join\s*\[char\[\]\]|\[array\]::Reverse|StrReverse\s*\(")


def script_obfuscation_signals(text: str) -> list[str]:
    """结构性混淆信号（拼接密度 / 长 base64 / 字符码密度 / 字符串反转）。

    这些是"形状"特征而不是关键词：单个 `Chr(` 在正常 VBS 里也有，
    但十几个字符码拼一句命令就只有混淆器会这么写。
    """
    signals: list[str] = []
    # 数"引号字面量之间的拼接符"：6 段字面量 = 5 个边界。正常脚本几乎不会这么写。
    if len(_QUOTED_CONCAT_RE.findall(text)) >= 5:
        signals.append("字符串拼接混淆(≥6 段字面量)")
    if _LONG_BASE64_RE.search(text):
        signals.append("长 Base64 载荷串(≥200 字符)")
    if len(_CHARCODE_RE.findall(text)) >= 4:
        signals.append("字符码构造密集(≥4 处)")
    if _REVERSE_STRING_RE.search(text):
        signals.append("字符串反转拼装(StrReverse/-join [char[]])")
    return signals


# 弱特征：单个出现时在正常脚本里很常见（下载、启动进程、COM 对象、变量切片…）。
# 它们只用来"送 AI 复核"，不该单独把规则结论推到可疑 —— 这一档直接决定误报率。
WEAK_SCRIPT_LABELS = {
    "PowerShell DownloadString",
    "PowerShell DownloadFile",
    "PowerShell WebClient",
    "PowerShell Start-Process",
    "PowerShell 远程下载",
    "PowerShell hidden window",
    "VBScript/JS CreateObject",
    "COM shell execution",
    "JS 解码函数",
    "JS ActiveX/HTTP",
    "VBS 落盘(ADODB.Stream/SaveToFile)",
    "BAT 变量切片混淆",
    "常见 LOLBin 调用",
    "持久化/下载命令",
    "系统安全相关命令",
    "Windows 下载 API",
    "Office 自动执行入口",
    # 2026-09-19 实测收窄：结构性信号在**合法复杂脚本**里也会成片出现 ——
    # Windows 自带的 PSDesiredStateConfiguration.psm1（DSC 模块）同时命中
    # "编码命令载荷(base64) / 字符串反转 / 拼接混淆 / 字符码密集"，被规则档推到 20 分（suspicious）。
    # 这些"形状"特征降为弱特征：仍然会把文件送 AI 复核，但不单独把规则结论推成可疑。
    "字符串拼接混淆(≥6 段字面量)",
    "字符码构造密集(≥4 处)",
    "字符串反转拼装(StrReverse/-join [char[]])",
    "PowerShell 编码命令载荷(base64)",
}


def script_signal_tiers(text: str) -> tuple[list[str], list[str]]:
    """把脚本特征分成（强, 弱）两档：强特征才是"混淆/执行"的形状，弱特征是正常脚本也会有的用法。"""
    labels = find_script_patterns(text) + script_obfuscation_signals(text)
    strong = sorted({x for x in labels if x not in WEAK_SCRIPT_LABELS})
    weak = sorted({x for x in labels if x in WEAK_SCRIPT_LABELS})
    return strong, weak


def find_script_signals(text: str) -> list[str]:
    """脚本预筛总入口：关键词模式 + 结构性混淆信号（不分档，供展示与工具层使用）。"""
    return sorted(set(find_script_patterns(text) + script_obfuscation_signals(text)))


# ---------------------------------------------------------------------------
# 容器类文件（LNK / RTF / OLE 文档）的启发式模式
#
# 这些容器的字符串常常是 UTF-16LE，或者被塞在二进制结构里，
# 所以预筛不能只看按 UTF-8 解码的文件头（这正是 LNK 曾经整类漏掉的原因）。
# ---------------------------------------------------------------------------

LNK_EXTENSIONS = {".lnk"}
RTF_EXTENSIONS = {".rtf"}
OLE_DOC_EXTENSIONS = {".doc", ".xls", ".ppt", ".ole", ".msi"}
OOXML_DOC_EXTENSIONS = {".docm", ".docx", ".xlsm", ".xlsx", ".pptm", ".pptx"}
OFFICE_DOC_EXTENSIONS = OLE_DOC_EXTENSIONS | OOXML_DOC_EXTENSIONS
# 需要走 oletools 解压宏的扩展名（.docm/.xlsm 这类 OOXML 也要，否则整类漏检）
MACRO_SCAN_EXTENSIONS = OFFICE_DOC_EXTENSIONS | RTF_EXTENSIONS
CONTAINER_EXTENSIONS = LNK_EXTENSIONS | RTF_EXTENSIONS | OFFICE_DOC_EXTENSIONS

# 这些命中只说明「结构上存在什么」，不能说明恶意，因此不计分：
#   - 有入口名（AutoOpen / Document_Open）是宏的正常写法
#   - 有 VBA 存储只说明文档带宏
NEUTRAL_PATTERN_LABELS = {
    "Office 自动执行入口",
    "OLE 内含 VBA 宏存储",
}

LNK_SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)powershell(\.exe)?", "LNK 调用 PowerShell"),
    (r"(?i)mshta|rundll32|regsvr32|certutil|bitsadmin|wmic", "LNK 调用系统 LOLBin"),
    (r"(?i)cmd\.exe", "LNK 调用 cmd.exe"),
    (r"(?i)-enc(odedcommand)?\s|-w\s+hidden|-windowstyle\s+hidden|-nop\b", "LNK 隐藏窗口/编码命令"),
    (r"(?i)https?://", "LNK 指向远程 URL"),
    (r"\\\\[A-Za-z0-9._-]+\\", "LNK 指向 UNC 共享路径"),
    # 2026-09-19 实测收窄（合成矩阵 940 个样本暴露）：
    # 旧写法把「.exe」也算作载荷证据，可快捷方式的**目标本来就是 .exe**
    # （notepad.exe / WINWORD.EXE / EXCEL.EXE），于是 50 个良性快捷方式里 50 个被推成可疑。
    # 拆成三条结构上站得住的：
    #   ① 载荷是脚本文件（脚本扩展名当参数/目标是投递手法，本地文档参数不算）
    #   ② 从**远程位置**（UNC / URL）加载可执行体 —— 本地 .exe 目标不算证据
    #   ③ 双扩展名可执行体（invoice.pdf.exe 这类），要求两个扩展名**相邻**
    (r"(?i)\.(ps1|vbs|vbe|js|jse|hta|bat|cmd|scr)\b", "LNK 载荷为脚本文件"),
    (r"(?i)(?:\\\\[\w.$-]+\\|https?://)[^\s\"']*\.(?:exe|scr|bat|cmd|com|pif|ps1|vbs|js|hta)\b",
     "LNK 从远程位置加载可执行体"),
    (r"(?i)\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip)\.(?:exe|scr|bat|cmd|com|pif|ps1|vbs|js|hta)\b",
     "LNK 双扩展名可执行体"),
]

RTF_SUSPICIOUS_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\\obj(link|aut|ocx)\b", "RTF 远程/自动更新对象"),
    (r"(?i)\\objupdate\b", "RTF 强制更新对象"),
    (r"(?i)\\objdata\b", "RTF 内嵌对象数据"),
    (r"(?i)https?://", "RTF 引用远程 URL"),
    (r"(?i)equation\.3|eqn\.exe|\bpackage\b", "RTF 公式编辑器/包对象"),
]

# 宏**源码**（oletools 解压后）里值得计分的内容模式。
# 2026-09-19 实测暴露的缺口：`Sub AutoOpen(): Shell "cmd /c start http://…"` 这类宏
# 在 .xls 容器里因为裸字节里能搜到 URL 而得分，在 .doc/.docm 里（宏被 MS-OVBA 压缩）
# 就只剩「有宏」+5，整类掉到阈值以下 —— 同一个宏、换个容器结论就变了。
# 这里补的是"压缩与否都应在乎"的内容级证据：远程 URL 与 UNC 路径。
MACRO_SOURCE_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)https?://", "宏内含远程 URL"),
    (r"\\\\[A-Za-z0-9._-]+\\", "宏内引用 UNC 路径"),
]


OLE_MACRO_MARKERS: list[tuple[str, str]] = [
    (r"Macros/VBA|_VBA_PROJECT|VBA/ThisDocument|VBA/dir", "OLE 内含 VBA 宏存储"),
    (r"(?i)AutoOpen|Document_Open|Workbook_Open|Auto_Open", "OLE 内含自动执行入口"),
    (r"(?i)URLDownloadToFile|WinHttpOpen|InternetOpen|WScript\.Shell", "OLE 内含下载/命令执行 API"),
]

# 常见壳的节区名
PACKER_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata", "MPRESS1", "MPRESS2",
    ".themida", ".vmp0", ".vmp1", ".petite", ".nsp0", "FSG!", ".packed",
}


def extract_container_strings(data: bytes, min_len: int = 5) -> str:
    """从二进制容器中抽出 ASCII + UTF-16LE 字符串，供启发式规则匹配。

    注意 UTF-16 命中必须按 utf-16-le 解码：按 utf-8 解会得到 "p\\x00o\\x00w..."，
    关键字和 URL 正则都匹配不上。
    """
    ascii_strings = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
    parts = [raw.decode("utf-8", errors="ignore") for raw in ascii_strings]
    parts += [raw.decode("utf-16-le", errors="ignore") for raw in utf16_strings]
    return "\n".join(parts)


def find_embed_patterns(text: str, extension: str) -> list[str]:
    """按扩展名选择 LNK / RTF / OLE 的容器模式。"""
    ext = extension.lower()
    if ext in LNK_EXTENSIONS:
        patterns = LNK_SUSPICIOUS_PATTERNS
    elif ext in RTF_EXTENSIONS:
        patterns = RTF_SUSPICIOUS_PATTERNS
    elif ext in OLE_DOC_EXTENSIONS:
        patterns = OLE_MACRO_MARKERS
    else:
        return []
    found = [label for rx, label in patterns if re.search(rx, text, re.MULTILINE)]
    return sorted(set(found))


# 同一处证据被「通用脚本模式」和「容器专用模式」各抓一次时会重复计分（各 +5）。
# 2026-09-19 实测：良性 LNK 里的 cmd.exe 同时命中 `常见 LOLBin 调用` 与 `LNK 调用 cmd.exe`，
# 白拿 10 分，离 12 分阈值只差 2 分。规则：有更具体的容器标签时，通用标签不再单独计分。
CONTAINER_LABEL_ALIASES: dict[str, set[str]] = {
    "常见 LOLBin 调用": {"LNK 调用 PowerShell", "LNK 调用系统 LOLBin", "LNK 调用 cmd.exe"},
}


def merge_container_patterns(text: str, extension: str) -> list[str]:
    """容器（LNK/RTF/OLE）命中的模式集合，**去掉重复计分的通用标签**。"""
    embed = set(find_embed_patterns(text, extension))
    script = set(find_script_patterns(text))
    for generic, specifics in CONTAINER_LABEL_ALIASES.items():
        if generic in script and (specifics & embed):
            script.discard(generic)
    return sorted(embed | script)


# ---------------------------------------------------------------- Excel 4.0 / XLM 宏表
#
# 2026-09-19 实测的盲区：`oletools` 只认 VBA 工程（`_VBA_PROJECT_CUR` / `Macros`），
# **看不到 Excel 4.0 宏表**（BIFF 的 BOUNDSHEET dt=0x01 指向的那种工作表）。
# 于是 XLM 投递型样本在预筛里只会拿到「高风险扩展名 +5」，整类掉在阈值以下
# （实测：60 个合成 XLM 恶意样本，预筛命中 15 个 = 0.250，且分数与良性完全同分）。
# XLM 的宏体是 BIFF 的 FORMULA(0x0006) 记录里的 ptg 标记 + 字符串，**确定性可读**，
# 所以这里自己解 BIFF，不依赖 oletools。

# XLM 宏函数**分档**（2026-09-19 实测后收紧）：
# 第一版把所有"提到就计分"的关键字放一起，结果良性宏表（财务表常见的 =URL(...) 取数、
# =GET.DOCUMENT(88) 读工作表名）被一起打成可疑 —— 60 个良性里误报 24 个（FPR 0.400）。
# 现在拆开：
#   · **执行类**：宏表直接发起执行/联网落盘/写注册表/自毁 —— 语义上就是投递行为；
#   · **信息类**：只说明"这段宏在读环境/取数"，正常业务表同样会用，**不能当恶意证据**。
# 说明：EXEC/CALL/HALT/REGISTER 这类**名字本身中性**（"CALL" 在任何英文文本里都可能出现），
# 因此要求带左括号（`EXEC(` / `CALL(` / `HALT(`）才算执行类证据；
# 而 `cmd.exe`、`powershell`、`URLDownloadToFile`、`RegWrite` 这些**本身就是投递标记**，按裸词匹配。
XLM_EXEC_KEYWORDS: list[tuple[str, str]] = [
    (r"(?i)\bEXEC\s*\(|\bEXEC\b(?=[^A-Za-z])", "XLM 调用 EXEC（执行外部程序）"),
    (r"(?i)\bCALL\s*\(|\bCALL\b(?=[^A-Za-z])", "XLM 调用 CALL（外部 DLL 函数）"),
    (r"(?i)URLDownloadToFile|URLMON|WinHttp|InternetOpen", "XLM 联网下载 API"),
    (r"(?i)\bREGISTER\s*\(|RegWrite", "XLM 注册/写注册表"),
    (r"(?i)\bHALT\s*\(|\bHALT\b(?=[^A-Za-z])", "XLM 调用 HALT（隐藏痕迹）"),
    (r"(?i)cmd\.exe|powershell|mshta|rundll32|regsvr32|wscript|cscript", "XLM 命令行/LOLBin 目标"),
    (r"(?i)-enc(odedcommand)?\b|-nop\b|-w(indowstyle)?\s+hidden", "XLM 隐藏窗口/编码命令"),
]
XLM_INFO_KEYWORDS: list[tuple[str, str]] = [
    (r"(?i)GET\.WORKSPACE|GET\.DOCUMENT|GET\.CELL", "XLM 读取环境/单元格信息"),
    (r"(?i)\bDIR\b|FILES\s*\(", "XLM 列目录/枚举文件"),
    (r"(?i)https?://|\\\\[A-Za-z0-9._-]+\\", "XLM 内含远程 URL / UNC 路径"),
]
# 兼容旧名（有外部引用/测试按这个名字取列表）
XLM_RISKY_KEYWORDS = XLM_EXEC_KEYWORDS + XLM_INFO_KEYWORDS

XLM_MACRO_SHEET_DT = 0x01          # BOUNDSHEET.dt：1 = Excel 4.0 macro sheet
BIFF_BOF = 0x0809
BIFF_BOUNDSHEET = 0x0085
BIFF_FORMULA = 0x0006
BIFF_LABEL = 0x0204
BIFF_EOF = 0x000A
# BIFF8 单条记录体上限。**这是上限，不是"异常阈值"**：真实工作簿里的
# MSODRAWINGGROUP(0x00EB) 等记录合法地就能顶到 8224 字节（0x2020）。
BIFF_MAX_RECORD_BYTES = 0x2020


def _iter_biff_records(stream: bytes) -> tuple[list[tuple[int, int, bytes]], bool]:
    """线性遍历 BIFF 记录，返回 ([(offset, type, body)], 是否偏移跑飞)。

    ⚠️ 不要用"记录很长就当跑飞"的启发式提前 `break`：那会在**第一条合法大记录**
    处截断整条流，把后面的 sheet substream 全部丢掉（见 `extract_xlm_macro_info` 的说明）。
    只有超过 BIFF8 上限（0x2020）才说明偏移真的跑飞了。
    """
    records: list[tuple[int, int, bytes]] = []
    i, n, desync = 0, len(stream), False
    while i + 4 <= n:
        rt = int.from_bytes(stream[i:i + 2], "little")
        ln = int.from_bytes(stream[i + 2:i + 4], "little")
        if ln > BIFF_MAX_RECORD_BYTES:
            desync = True
            break
        records.append((i, rt, stream[i + 4:i + 4 + ln]))
        i += 4 + ln
    return records, desync


def _biff_substreams(records: list[tuple[int, int, bytes]]) -> list[tuple[int, list[tuple[int, bytes]]]]:
    """按 BOF/EOF 把记录切成 substream。

    返回 [(BOF 偏移, [(记录类型, 记录体), …]), …]：`[0]` 是 Workbook Globals，
    其后各 substream **按 BOUNDSHEET 出现顺序**对应各张工作表。
    """
    out: list[tuple[int, list[tuple[int, bytes]]]] = []
    depth = 0
    for off, rt, body in records:
        if rt == BIFF_BOF:
            if depth == 0:
                out.append((off, []))
                depth = 1
            else:
                depth += 1
            continue
        if not out:
            continue
        out[-1][1].append((rt, body))
        if rt == BIFF_EOF:
            depth = max(0, depth - 1)
    return out


def _biff_strings(blob: bytes, limit: int = 4000) -> list[str]:
    """从 BIFF 字节流里抽可读字符串（ptgStr 0x17 / XLUnicodeString / 裸 ASCII 串）。

    不追求完整还原公式语义：只要能把 `EXEC`、`cmd.exe`、`URLDownloadToFileA` 这类
    **宏函数名与参数**读出来，就足以让预筛做确定性判定。
    """
    found: list[str] = []
    # ① ptgStr(0x17)：cch(2) + grbit(1) + 字符
    for m in re.finditer(rb"\x17([\x00-\xff]{2})([\x00\x01])", blob):
        cch = int.from_bytes(m.group(1), "little")
        grbit = m.group(2)[0]
        start = m.end()
        if grbit == 0x01:                       # 宽字符
            raw = blob[start:start + cch * 2]
            text = raw.decode("utf-16-le", "ignore")
        else:                                   # 压缩（单字节）
            raw = blob[start:start + cch]
            text = raw.decode("latin-1", "ignore")
        text = text.strip("\x00\r\n\t ")
        if 2 <= len(text) <= 400:
            found.append(text)
        if len(found) >= limit:
            return found
    # ② 裸 ASCII（含 1 字节长度前缀的 XLUnicodeString）与宽字符串
    for m in re.finditer(rb"[\x20-\x7e]{4,200}", blob):
        found.append(m.group().decode("latin-1", "ignore"))
        if len(found) >= limit:
            return found
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){4,200}", blob):
        found.append(m.group().decode("utf-16-le", "ignore"))
        if len(found) >= limit:
            return found
    return found


def extract_xlm_macro_info(path: Path, max_size_mb: int = 30) -> dict[str, Any]:
    """确定性解析 Excel 4.0 宏表（XLM）：有没有宏表、宏表里有什么。

    返回 {available, has_xlm, macro_sheets, patterns, preview, error}。
    只读 `Workbook`/`Book` 流，不做任何执行；解析失败一律优雅降级。
    """
    info: dict[str, Any] = {"available": True, "has_xlm": False, "macro_sheets": 0,
                            "hidden_macro_sheets": 0, "formula_cells": 0, "char_cells": 0,
                            "patterns": [], "preview": "", "error": None}
    try:
        import olefile  # type: ignore
    except ImportError:
        info["available"] = False
        info["error"] = "olefile not installed"
        return info
    try:
        if path.stat().st_size > max_size_mb * 1024 * 1024:
            info["error"] = f"file larger than {max_size_mb}MB, skipped"
            return info
        if not olefile.isOleFile(str(path)):
            return info
        with olefile.OleFileIO(str(path)) as ole:
            stream = None
            for name in ("Workbook", "Book"):
                if ole.exists(name):
                    stream = ole.openstream(name).read()
                    break
            if stream is None:
                return info
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"cannot read OLE stream: {exc}"
        return info

    # 扫记录。⚠️ 2026-09-19 实测的第二个盲区（**合成语料看不见，只有真实样本能暴露**）：
    # 原实现把「记录体 > 0x2000」当成"偏移跑飞"直接 break —— 但 BIFF8 的记录体上限是
    # 0x2020(8224)，真实工作簿里的 MSODRAWINGGROUP(0x00EB) 等记录**合法地**就有 8224 字节。
    # 于是线性遍历在第一条大记录处被截断（实测 288 条记录处停住），后面的 sheet substream
    # 一条都没读到，宏表永远定位不到 → `has_xlm=false`。极简的合成 XLM 没有大记录，
    # 所以一直没暴露；3 个真实在野 Excel 4.0 样本（`BOUNDSHEET.dt=1` 确实存在）上全部漏判。
    records, desync = _iter_biff_records(stream)

    sheet_types: list[int] = []
    macro_sheet_offsets: set[int] = set()
    hidden_macro_sheets = 0
    for _off, rt, body in records:
        if rt == BIFF_BOUNDSHEET and len(body) >= 6:
            sheet_types.append(body[5])
            if body[5] == XLM_MACRO_SHEET_DT:
                macro_sheet_offsets.add(int.from_bytes(body[0:4], "little"))
                # hsState（body[4]）：0 可见 / 1 隐藏 / 2 **深度隐藏**。
                # 真实在野 XLM（ZLoader 系）实测 3/3 的宏表都是 2（深度隐藏），
                # 正常业务宏表极少深度隐藏 —— 这是纯结构信号，不依赖任何明文。
                if body[4] in (1, 2):
                    hidden_macro_sheets += 1

    substreams = _biff_substreams(records)
    # 两条定位路线（先规范、后兜底）：
    #   ① `BOUNDSHEET.lbPlyPos` 精确指向宏表 substream 的 BOF —— 规范写法；
    #   ② 按 substream 出现顺序与 BOUNDSHEET 顺序对齐 —— 个别生产工具写的 lbPlyPos 不可靠。
    targets: set[int] = {idx for idx, (bof, _r) in enumerate(substreams)
                         if bof in macro_sheet_offsets}
    if not targets:
        for idx in range(1, len(substreams)):
            sheet_index = idx - 1                      # substreams[0] 是 Workbook Globals
            if 0 <= sheet_index < len(sheet_types) and sheet_types[sheet_index] == XLM_MACRO_SHEET_DT:
                targets.add(idx)

    if not targets:
        # 读不到就说清"读不到"，别让它静默变成"没有宏表"
        if desync:
            info["error"] = "BIFF 记录流偏移跑飞，未能定位宏表（未检出 ≠ 没有）"
        return info

    macro_formula_bytes = bytearray()
    formula_cells = 0
    char_cells = 0
    for idx in sorted(targets):
        for rt, body in substreams[idx][1]:
            if rt not in (BIFF_FORMULA, BIFF_LABEL):
                continue
            macro_formula_bytes += body
            if rt != BIFF_FORMULA or len(body) < 22:
                continue
            formula_cells += 1
            cce = int.from_bytes(body[20:22], "little")
            rgce = body[22:22 + cce]
            # `=CHAR(<常量>)` 的字节形态：ptgInt(0x1e)+int16 紧跟 ptgFunc(0x21–0x5F)
            # 且函数号 0x006f = CHAR（对照 xlrd.formula.func_defs[111] == 'CHAR'）。
            # 实测这些样本的 STRING 缓存记录里就是 "="，与 CHAR(61) 吻合。
            if (len(rgce) == 6 and rgce[0] == 0x1E and 0x21 <= rgce[3] <= 0x5F
                    and rgce[4:6] == b"\x6f\x00"):
                char_cells += 1

    if not macro_formula_bytes:
        info["error"] = "已定位宏表 substream，但没读到 FORMULA/LABEL 记录"
        return info

    strings = _biff_strings(bytes(macro_formula_bytes))
    exec_hits = sorted({label for rx, label in XLM_EXEC_KEYWORDS
                        if any(re.search(rx, s) for s in strings)})
    info_hits = sorted({label for rx, label in XLM_INFO_KEYWORDS
                        if any(re.search(rx, s) for s in strings)})
    info.update({
        "has_xlm": True,
        "macro_sheets": len(targets),
        # 结构化信号（不依赖明文，真实在野样本里靠这两个才看得见）
        "hidden_macro_sheets": hidden_macro_sheets,
        "formula_cells": formula_cells,
        "char_cells": char_cells,
        "exec_patterns": exec_hits,
        "info_patterns": info_hits,
        # patterns 保持"全部命中的标签"，供报告展示；计分只用 exec_patterns
        "patterns": sorted(set(exec_hits) | set(info_hits)),
        "preview": _text_preview("\n".join(strings[:80]), 1500),
    })
    return info


def extract_ole_macro_info(path: Path, max_size_mb: int = 20) -> dict[str, Any]:
    """用 oletools 解压并抽取 Office 文档里的 VBA 宏。

    返回 {available, has_macros, patterns, preview, error}，供预筛和 Agent 工具共用。
    宏源码在 OLE 里是压缩存储的，只有解压后才能做模式匹配。

    注意：**oletools 看不到 Excel 4.0 宏表（XLM）**，那条线在 `extract_xlm_macro_info()`。
    """
    if path.suffix.lower() not in MACRO_SCAN_EXTENSIONS:
        return {"available": True, "has_macros": False, "patterns": [], "preview": "",
                "error": "not an Office document"}

    try:
        if path.stat().st_size > max_size_mb * 1024 * 1024:
            return {"available": True, "has_macros": False, "patterns": [], "preview": "",
                    "error": f"file larger than {max_size_mb}MB, skipped"}
    except OSError as exc:
        return {"available": True, "has_macros": False, "patterns": [], "preview": "",
                "error": f"stat failed: {exc}"}

    try:
        from oletools.olevba import VBA_Parser  # type: ignore
    except ImportError:
        return {"available": False, "has_macros": False, "patterns": [], "preview": "",
                "error": "oletools not installed"}

    try:
        parser = VBA_Parser(str(path))
    except Exception as exc:  # noqa: BLE001 - 解析失败要优雅降级
        return {"available": True, "has_macros": False, "patterns": [], "preview": "",
                "error": f"cannot parse office file: {exc}"}

    try:
        if not parser.detect_vba_macros():
            return {"available": True, "has_macros": False, "patterns": [], "preview": "",
                    "error": None}

        patterns: set[str] = set()
        code = ""
        for _filename, _stream, _vba_name, vba_code in parser.extract_macros():
            code += "\n" + (vba_code or "")
            src = vba_code or ""
            patterns.update(find_script_patterns(src))
            patterns.update(label for rx, label in MACRO_SOURCE_PATTERNS if re.search(rx, src, re.MULTILINE))
        return {
            "available": True,
            "has_macros": True,
            "patterns": sorted(patterns),
            "preview": _text_preview(code, 2500),
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {"available": True, "has_macros": False, "patterns": [], "preview": "",
                "error": f"macro extraction failed: {exc}"}
    finally:
        try:
            parser.close()
        except Exception:
            pass


def pe_packing_signals(path: Path) -> list[str]:
    """PE 加壳信号：壳的节区名（**用 `unpack.py` 的同一张签名表**）+ 高熵可执行节区。

    注意：加壳本身不等于恶意（正常软件也加壳），所以调用方只应把它
    当作「值得送去 AI 复核」的弱信号，不能单独定性。

    ⚠️ 2026-09-19 修掉的一处**内部不一致**：本函数原来只认 `PACKER_SECTION_NAMES`
    里那 14 个手写节名（`UPX0/.aspack/.vmp0/…`），而报告侧的 `unpack.detect_packer()`
    用的是 24 条 `SECTION_SIGNATURES` 表 —— 于是 `PEC2`（PECompact）、`.enigma1`（Enigma）
    这类样本**报告里写着"已加壳"，预筛理由里却一个字都没有**（实测：同一个文件
    `detect_packer` 判 PECompact、本函数返回空）。现在两张表合并成一张（以 `unpack` 为准），
    预筛与报告口径一致。
    """
    try:
        import pefile  # type: ignore
    except ImportError:
        return []

    from aiav.unpack import SECTION_SIGNATURES, NON_PACKER_NOTES  # 延迟导入，避免与 unpack 形成环

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return []

    signals: list[str] = []
    try:
        for section in list(getattr(pe, "sections", []))[:16]:
            name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            low = name.lower()
            # 非壳节名（如 MSVC 的 .rich）先排除：它不是壳，不能当加壳证据
            if any(k in low for k in NON_PACKER_NOTES):
                continue
            for packer, needles in SECTION_SIGNATURES:
                if any(needle in low for needle in needles):
                    signals.append(f"加壳节区名: {name}（{packer}）")
                    break
            try:
                executable = bool(section.Characteristics & 0x20000000)
                if executable and float(section.get_entropy()) >= 7.2:
                    signals.append(f"高熵可执行节区: {name}")
            except Exception:
                continue
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return sorted(set(signals))


@functools.lru_cache(maxsize=1)
def load_known_bad_hashes() -> frozenset[str]:
    hashes: set[str] = set()
    if not KNOWN_BAD_HASHES_FILE.exists():
        return hashes
    for line in KNOWN_BAD_HASHES_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        # 支持 "hash,label" 格式
        h = line.split(",")[0].strip()
        if re.fullmatch(r"[0-9a-f]{32,64}", h):
            hashes.add(h)
    return frozenset(hashes)


# =========================
# 数字签名：确定性证据块（不花 token）
# =========================
# 为什么要有这块：
#   pe_analyze 只检查 PE 里有没有「内嵌签名目录」，而 Windows 系统文件绝大多数是靠
#   **目录签名（catalog signing）** 覆盖的 —— 实测本机 System32/SysWOW64 的 1153 个 PE 里，
#   834 个（72.3%）内嵌签名目录为空但 Windows 验签为 Valid（SignatureType=Catalog）。
#   只看内嵌目录会把「正常」读成「未签名」，2026-09-19 的良性语料评测里，模型正是据此
#   把 iphlpsvc.dll / msdtcwmi.dll / pnrmc.sys 判成 suspicious（假证据）。
#   这块用 Windows 自己的验签结果兜底，并把「无内嵌签名 ≠ 未签名」写进证据本身。

SIGNATURE_CACHE: dict[str, dict[str, Any]] = {}
# 缓存键里带 mtime/size，所以同一个文件被改写一次就多一条**永不淘汰**的条目；
# 全量扫描几千个文件就是几千条（每条还带 windows_verify 的 JSON 片段）。
# 上限 + FIFO 淘汰：进程内复用够用，不涨成泄漏。
SIGNATURE_CACHE_MAX = int(os.getenv("AI_AV_SIGNATURE_CACHE_MAX", "4096"))
SIGNATURE_TIMEOUT_SECONDS = float(os.getenv("AI_AV_SIGNATURE_TIMEOUT", "30"))
TRUSTED_SIGNER_SUBSTR = os.getenv("AI_AV_TRUSTED_SIGNER_SUBSTR", "Microsoft")

# ⚠️ 血泪教训（2026-09-19 + 2026-09-26 两次实测）：
# 从 WSL 调 Windows 的 Get-AuthenticodeSignature 验签，会让 **Windows Defender
# 实时防护**顺手打开每个文件 —— 目录里只要有真恶意样本，Defender 就直接隔离/删除。
#   2026-09-19：吃掉 Dike 恶意集 19 个 + 定向集 2 个样本
#   2026-09-26：吃掉验证集 21 个样本（时间戳与 AI 扫描窗口一一对应）
# 当时的对策是 `AI_AV_NO_WIN_TOUCH_DIRS` 保护目录 —— 但那只是把问题挪走：
# 保护目录内验签一律跳过（53 次调用 53 次 unknown），保护目录外照样丢样本。
#
# 2026-09-26 起**根治**：验签改走 `aiav.authenticode`（asn1crypto + cryptography），
# 全程在本地完成，不再有任何跨到 Windows 的动作。于是
# `NO_WIN_TOUCH_DIRS` / `windows_touch_blocked()` / `_embedded_signature()` /
# `_windows_verify()` 全部删除 —— 没有 Windows 侧访问，就不需要保护目录。

def signature_evidence(path: Path, use_cache: bool = True) -> dict[str, Any]:
    """签名状态的确定性证据块 —— **纯 Python 验签，不碰 Windows**。

    2026-09-26 换的实现。旧版调 `powershell.exe Get-AuthenticodeSignature`，是个死结：
      · 路径在 `AI_AV_NO_WIN_TOUCH_DIRS` 内 → 跳过 → 53 次调用 53 次 unknown
      · 路径在外 → 真的递给 Windows → **Defender 顺手隔离样本**（实测吃掉 21 个）
      · Linux 机器 / 独立虚拟机里根本没有 powershell.exe → 直接不可用
    现在改走 `aiav.authenticode`（asn1crypto + cryptography），四件事全在本地做完：
    解析签名表、取签名者与证书链、重算 Authenticode 摘要比对、验签 + 链验证。

    字段沿用旧名，`status` 仍取 `Valid` / `HashMismatch` / `NotTrusted` / `unknown`
    —— `apply_claim_guard` 与 `find_claim_warnings` 都读它，别改名。
    """
    try:
        st = path.stat()
        cache_key = f"{path}|{st.st_mtime_ns}|{st.st_size}"
    except OSError:
        cache_key = str(path)

    if use_cache and cache_key in SIGNATURE_CACHE:
        return SIGNATURE_CACHE[cache_key]

    from aiav import authenticode

    raw = authenticode.analyze(path)

    # conclusion → status 映射。**"没有内嵌签名"不能映射成 not_signed**：
    # Windows 系统文件大量用目录签名（Catalog），其签名在 CatRoot 里，Linux 侧拿不到，
    # 所以只能落 unknown —— 这样 claim_guard 才会拦住"无签名"这类断言。
    conclusion = raw.get("conclusion") or "unknown"
    status = {
        "valid_signed_embedded": "Valid",
        "tampered": "HashMismatch",
        "signature_invalid": "NotTrusted",
    }.get(conclusion, "unknown")

    signer = raw.get("signer") or ""
    chain_ok = raw.get("chain_valid")
    # trusted_signer 的语义与旧版一致：**签名有效 + 签发者名字匹配**。
    # 不把 chain_valid 并进来 —— 微软的代码签名根不在 Linux CA 库里，
    # 并进来会让所有微软签名文件在 Linux 上一律 trusted=False，白白丢掉信号。
    # 链的可信度单独用 chain_valid 三态表达（True/False/None）。
    trusted = bool(status == "Valid") and (
        TRUSTED_SIGNER_SUBSTR.lower() in signer.lower()
    )

    info: dict[str, Any] = {
        # 兼容旧字段名：外部（报告/守卫/提示词）读的是这几个
        "embedded_signature_directory": bool(raw.get("has_signature")),
        "status": status,
        "signature_type": "embedded" if raw.get("has_signature") else None,
        "signer": signer or None,
        "trusted_signer": trusted,
        "conclusion": conclusion,
        # 新增：纯 Python 验签的具体结果（AI 判断"签名可不可信"要看这些）
        "signer_cn": raw.get("signer_cn") or _signer_cn(signer),
        "chain": raw.get("chain") or [],
        "digest_algorithm": raw.get("digest_algorithm"),
        "digest_match": raw.get("digest_match"),
        "signature_valid": raw.get("signature_valid"),
        "chain_valid": chain_ok,
        "timestamped": bool(raw.get("timestamped")),
        "verify_method": "authenticode-python",
        "note": raw.get("note") or SIGNATURE_NOTE,
    }
    if raw.get("error"):
        info["error"] = raw["error"]
    if use_cache:
        _signature_cache_put(cache_key, info)
    return info


def _signer_cn(signer: str) -> str | None:
    """从证书 DN 里抠出 CN（兜底路径；正常情况下 authenticode 已经给了 signer_cn）。

    要同时认两种格式：RFC4514 的 `CN=xxx` 和 asn1crypto human_friendly 的
    `Common Name: xxx` —— 只认前者会一直返回 None（踩过一次）。
    """
    for part in (signer or "").split(","):
        part = part.strip()
        low = part.lower()
        if low.startswith("cn="):
            return part[3:].strip() or None
        if low.startswith("common name:"):
            return part[len("common name:"):].strip() or None
    return None


def _signature_cache_put(key: str, info: dict[str, Any]) -> None:
    """写签名缓存，并做**有界**淘汰（dict 保序，按插入顺序 FIFO）。

    旧实现直接 `SIGNATURE_CACHE[key] = info`：键含 mtime，文件一改就多一条僵尸条目，
    全量扫描下只涨不消。淘汰一半（不是只弹一条）是为了避免每次插入都触发一轮清理。
    """
    SIGNATURE_CACHE[key] = info
    if len(SIGNATURE_CACHE) > SIGNATURE_CACHE_MAX:
        for stale in list(SIGNATURE_CACHE)[: max(1, len(SIGNATURE_CACHE) - SIGNATURE_CACHE_MAX // 2)]:
            SIGNATURE_CACHE.pop(stale, None)


def yara_scan(ctx: RunContext[ScanDeps]) -> str:
    """对当前文件运行 YARA 规则，返回命中的规则名。"""
    hits = run_yara(ctx.deps.file_path)
    strong = [h for h in hits if h not in WEAK_YARA_RULES]
    weak = [h for h in hits if h in WEAK_YARA_RULES]
    summary = json.dumps({
        "yara_hits": hits,
        "strong_hits": strong,
        "weak_hits": weak,
        "note": "weak_hits 只是通用启发式信号，不足以单独定性；strong_hits 可信度更高",
    }, ensure_ascii=False)
    _record(ctx, "yara_scan", summary)
    return summary


def pe_analyze(ctx: RunContext[ScanDeps]) -> str:
    """解析当前 PE 文件，返回区段、熵、导入表等静态特征。"""
    try:
        import pefile  # type: ignore
    except ImportError:
        result = {"error": "pefile not installed"}
        _record(ctx, "pe_analyze", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    path = ctx.deps.file_path
    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception as exc:
        result = {"error": f"not a PE file: {exc}"}
        _record(ctx, "pe_analyze", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    info: dict[str, Any] = {}
    try:
        try:
            pe.parse_data_directories()
        except Exception:
            pass

        info["machine"] = hex(getattr(pe.FILE_HEADER, "Machine", 0) or 0)
        info["timestamp"] = int(getattr(pe.FILE_HEADER, "TimeDateStamp", 0) or 0)
        info["is_dll"] = bool(getattr(pe.FILE_HEADER, "Characteristics", 0) & 0x2000)
        info["subsystem"] = int(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0) or 0)
        info["entrypoint_rva"] = hex(int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0) or 0))

        sections: list[dict[str, Any]] = []
        for s in getattr(pe, "sections", [])[:20]:
            name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            sections.append(
                {
                    "name": name,
                    "virtual_size": int(s.Misc_VirtualSize),
                    "raw_size": int(s.SizeOfRawData),
                    "entropy": round(float(s.get_entropy()), 3),
                    "executable": bool(s.Characteristics & 0x20000000),
                    "writable": bool(s.Characteristics & 0x80000000),
                }
            )
        info["sections"] = sections
        info["high_entropy_sections"] = [s["name"] for s in sections if s["entropy"] >= 7.2]

        dlls: list[str] = []
        api_hits: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("utf-8", errors="replace")
                dlls.append(dll_name)
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("utf-8", errors="replace")
                        if name in SUSPICIOUS_PE_APIS:
                            api_hits.append(f"{dll_name}!{name}")
        info["imports"] = sorted(set(dlls))[:40]
        info["suspicious_apis"] = sorted(set(api_hits))[:50]

        security = None
        try:
            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ]
            security = int(getattr(directory, "VirtualAddress", 0) or 0)
        except Exception:
            pass
        info["has_authenticode"] = bool(security)

        has_exports = hasattr(pe, "DIRECTORY_ENTRY_EXPORT")
        info["has_exports"] = bool(has_exports)
    finally:
        try:
            pe.close()
        except Exception:
            pass

    summary = json.dumps(info, ensure_ascii=False)
    _record(ctx, "pe_analyze", summary)
    return summary[:6000]


def script_analyze(ctx: RunContext[ScanDeps]) -> str:
    """读取当前文件中的脚本/文本，做正则规则分析。"""
    path = ctx.deps.file_path
    suffix = path.suffix.lower()
    scriptish = suffix in {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".py", ".sh", ".txt", ".xml", ".html", ".htm", ".lnk"}
    data = _read_bytes(path, 256 * 1024)
    if not scriptish and b"\x00" in data[:200]:
        result = {"error": "binary/non-script file, skipped"}
        _record(ctx, "script_analyze", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    text = _read_text_safe(path)
    patterns = find_script_patterns(text)
    urls = re.findall(r"https?://[^\s\"'<>]{6,200}", text, flags=re.IGNORECASE)

    result = {
        "suspicious_patterns": patterns,
        "urls": sorted(set(urls))[:20],
        "preview": _text_preview(text, 3000),
    }
    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "script_analyze", summary)
    return summary[:6000]


def office_macro_analyze(ctx: RunContext[ScanDeps]) -> str:
    """检查 Office 文件是否包含恶意宏或可疑宏关键字。"""
    info = extract_ole_macro_info(ctx.deps.file_path)
    if info.get("error") and not info.get("available"):
        result: dict[str, Any] = {"error": info["error"]}
    elif info.get("error") and info["error"] == "not an Office document":
        result = {"skipped": "not an Office document"}
    elif not info.get("has_macros"):
        result = {"has_macros": False, "suspicious_patterns": [], "note": info.get("error")}
    else:
        result = {
            "has_macros": True,
            "suspicious_patterns": info["patterns"],
            "macro_preview": info["preview"],
        }
    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "office_macro_analyze", summary)
    return summary[:6000]


def strings_ioc(ctx: RunContext[ScanDeps]) -> str:
    """提取当前文件中的高价值字符串、URL、IP 和可疑关键字。"""
    data = _read_bytes(ctx.deps.file_path, 2 * 1024 * 1024)

    ascii_strings = re.findall(rb"[\x20-\x7e]{5,}", data)
    utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){5,}", data)

    strings: list[str] = []
    for raw in ascii_strings:
        strings.append(raw.decode("utf-8", errors="ignore"))
    # UTF-16 命中必须按 utf-16-le 解，否则拿到的是夹 NUL 的字符串，关键字匹配不上
    for raw in utf16_strings:
        strings.append(raw.decode("utf-16-le", errors="ignore"))

    keywords = (
        "http://", "https://", "powershell", "cmd.exe", "wscript", "cscript",
        "mshta", "rundll32", "regsvr32", "download", "invoke", "base64",
        "frombase64string", "start-process", "createobject", "autoopen",
        "bitcoin", "wallet", "onion", ".exe", ".dll", ".ps1", ".vbs",
    )
    interesting: list[str] = []
    for s in strings:
        low = s.lower()
        if any(k in low for k in keywords):
            interesting.append(s)
    interesting = sorted(set(interesting))[:80]

    urls = sorted(set(re.findall(r"https?://[^\s\"'<>]{6,200}", "\n".join(strings), flags=re.IGNORECASE)))[:30]
    ips = sorted(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "\n".join(strings))))[:30]

    result = {
        "interesting_strings": interesting[:40],
        "urls": urls,
        "ips": ips,
    }
    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "strings_ioc", summary)
    return summary[:6000]


def signature_verify(ctx: RunContext[ScanDeps]) -> str:
    """验证当前 PE 文件的 Authenticode 数字签名（纯本地解析，不联网、不碰 Windows）。

    返回签名者、完整证书链、重算的 PE 摘要是否与签名时一致（判断有没有被改）、
    签名本身是否验过、证书链是否可信。

    **只对 PE（.exe / .dll / .sys / .pyd / .ocx / .cpl 等）有意义。**
    脚本（.js/.vbs/.bat/.ps1）、文档（.doc*/.xls*/.pdf）、容器（.lnk/.rtf/.wsf）
    没有 Authenticode 签名这个概念 —— 对这些文件调用它只会拿到「不是 PE 文件」，
    纯属浪费一次往返。**判断"这个文件是谁签的"之前，先确认它是 PE。**
    签名信息用来给 PE 平反（例如"Qt 官方签名的组件"），不能反过来当恶意证据。

    **无内嵌签名 ≠ 未签名**：Windows 系统文件大量使用目录签名（Catalog），
    其签名存放在 CatRoot 里，非 Windows 环境取不到 —— 这种情况返回 unknown，
    不得据此断言文件「无数字签名」。
    """
    info = signature_evidence(ctx.deps.file_path)
    summary = json.dumps(info, ensure_ascii=False)
    _record(ctx, "signature_verify", summary)
    return summary[:4000]


def pdf_analyze(ctx: RunContext[ScanDeps]) -> str:
    """解析当前 PDF 的"可执行面"：JavaScript / 动作 / URI / 内嵌文件 / XFA（只读，不打开执行）。"""
    from aiav.pdfscan import analyze_pdf, summary_text

    info = analyze_pdf(ctx.deps.file_path)
    if not info.get("is_pdf"):
        result = {"skipped": "not a PDF file"}
    else:
        result = {k: v for k, v in info.items() if k != "javascript"}
        result["javascript_excerpts"] = [t[:400] for t in (info.get("javascript") or [])[:5]]
        result["summary"] = summary_text(info)
    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "pdf_analyze", summary)
    return summary[:6000]


def hash_lookup(ctx: RunContext[ScanDeps]) -> str:
    """查询本地已知恶意哈希库，返回是否命中。"""
    known = load_known_bad_hashes()
    hit = ctx.deps.sha256.lower() in known
    result = {"sha256": ctx.deps.sha256, "known_bad_hash": hit, "local_db_size": len(known)}
    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "hash_lookup", summary)
    return summary


def vt_lookup(ctx: RunContext[ScanDeps]) -> str:
    """用 SHA256 查询 VirusTotal，不上传样本。需要设置 VT_API_KEY。"""
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        result = {"error": "VT_API_KEY not set"}
        _record(ctx, "vt_lookup", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    url = f"https://www.virustotal.com/api/v3/files/{ctx.deps.sha256}"
    request = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore"))
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        result = {
            "sha256": ctx.deps.sha256,
            "last_analysis_stats": stats,
            "meaningful_name": attributes.get("meaningful_name"),
            "type_description": attributes.get("type_description"),
        }
    except urllib.error.HTTPError as exc:
        result = {"error": f"VT HTTP {exc.code}"}
    except Exception as exc:
        result = {"error": f"VT request failed: {exc}"}

    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "vt_lookup", summary)
    return summary



def clamav_scan(ctx: RunContext[ScanDeps]) -> str:
    """调用本机 ClamAV 扫描当前文件，作为传统 AV 基线/补充工具。"""
    exe = _find_exe("clamscan", "clamdscan", env_var="CLAMAV_EXE")
    if not exe:
        result = {"error": "ClamAV not installed or not in PATH"}
        _record(ctx, "clamav_scan", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    cmd = [exe, "--no-summary", "--infected", str(ctx.deps.file_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=60)
        result = {
            "exit_code": proc.returncode,
            "stdout": _decode_output(proc.stdout or b"")[:3000],
            "stderr": _decode_output(proc.stderr or b"")[:1000],
            "infected": proc.returncode == 1,
        }
    except subprocess.TimeoutExpired:
        result = {"error": "ClamAV timeout"}
    except Exception as exc:
        result = {"error": f"ClamAV failed: {exc}"}

    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "clamav_scan", summary)
    return summary[:5000]


def _capa_detail_budget() -> tuple[int, int, int]:
    """capa 送审注解的三个预算：最多列几条详情 / 每条 description 截多长 / 整段上限字符。

    为什么要预算：capa 规则库 1000+ 条，恶意样本动辄命中上百条；把 description 全带上
    会把提示词撑爆。宁可**少列几条并显式标注省略**，也不裸切 JSON。
    """

    def _int(name: str, default: int) -> int:
        try:
            return max(1, int(os.getenv(name, str(default))))
        except ValueError:
            return default

    return (_int("CAPA_DETAIL_RULES", 40),
            _int("CAPA_DESC_CHARS", 200),
            _int("CAPA_OUTPUT_CHARS", 12000))


# capa 送审注解：**关于规则的事实，不是关于被检文件的判断**（2026-09-26 修②）。
# 背景：良性误报 3 → 5，根因是规则名（allocate or change RWX memory /
# execute shellcode via indirect call / run PowerShell expression）对 MinGW 伪重定位
# 与 SEH 运行时的正常产物也会命中 —— 只给规则名，模型会照着名字判可疑。
# 修法不是加白名单硬压误报，而是把"这条规则在描述什么能力"和"这个文件是否真有该能力"
# 所需的上下文一并给出：namespace + 规则自带的 description + 这句显式声明。
CAPA_FACTS_NOTE = (
    "以下内容全部是「关于 capa 规则的事实」，不是「关于被检文件的判断」。"
    "rule = 规则名（规则作者起的名字，描述这条规则在找什么代码模式，不是这个文件做了什么）；"
    "namespace = 该规则在 capa 规则库里的能力分类路径；"
    "description = 规则作者自带的检测意图说明（null 表示规则库没写，不代表该规则没有行为）；"
    "scope = 规则生效的粒度。capa 是**模式匹配**：同一段代码模式在编译器运行时"
    "（CRT 启动、SEH/unwind 展开、MinGW 伪重定位）、语言运行时库、打包器等**正常产物**里"
    "同样会出现。所以命中只说明「文件的代码与这条模式相符」，"
    "**不等于文件真的具备该能力** —— 是否具备，要结合命中上下文、导入表、"
    "其它工具输出和文件整体形态自行判断。"
)


def _capa_rule_details(rules: dict, shown: int, desc_chars: int) -> list[dict]:
    """把 capa 的规则命中摊成"带 namespace + description 的事实条目"。"""
    details: list[dict] = []
    for name in sorted(rules)[:shown]:
        meta = (rules[name].get("meta") or {})
        desc = (meta.get("description") or "").strip()
        entry: dict = {
            "rule": name,
            "namespace": meta.get("namespace") or None,
            "description": desc[:desc_chars] if desc else None,
        }
        scope = (meta.get("scopes") or {}).get("static")
        if scope:
            entry["scope"] = scope
        details.append(entry)
    return details


def _capa_result(rules: dict, attack: list[str], mbc: list[str]) -> dict:
    """组装 capa 送审载荷，并保证**合法 JSON + 有界大小**。

    降级顺序（每一步都在字段里留痕，读报告的人能看出"这里被截了"）：
      1) 详情只列前 N 条（其余只在 capabilities 里留名字）
      2) 仍超预算 → 砍 description（标注 descriptions_omitted）
      3) 仍超预算 → 详情只留前若干条（标注 rule_details_omitted）
    """
    shown, desc_chars, budget = _capa_detail_budget()
    names = sorted(rules)
    payload: dict = {
        "_about_this_output": CAPA_FACTS_NOTE,
        "rule_details": _capa_rule_details(rules, shown, desc_chars),
        "rules_total": len(rules),
        "capabilities": names[:120],       # 旧字段保留：纯规则名清单（脚本/兼容用）
        "attack": attack[:80],
        "mbc": mbc[:80],
        "rule_count": len(rules),
    }
    payload["rule_details_shown"] = len(payload["rule_details"])
    if len(names) > shown:
        payload["rule_details_omitted"] = len(names) - shown
    if len(json.dumps(payload, ensure_ascii=False)) <= budget:
        return payload
    # 2) 砍 description
    payload["rule_details"] = [
        {k: v for k, v in d.items() if k != "description"} for d in payload["rule_details"]
    ]
    payload["descriptions_omitted"] = True
    if len(json.dumps(payload, ensure_ascii=False)) <= budget:
        return payload
    # 3) 砍详情条数
    while len(payload["rule_details"]) > 5 and len(json.dumps(payload, ensure_ascii=False)) > budget:
        keep = max(5, len(payload["rule_details"]) // 2)
        payload["rule_details"] = payload["rule_details"][:keep]
    payload["rule_details_shown"] = len(payload["rule_details"])
    payload["rule_details_omitted"] = len(names) - len(payload["rule_details"])
    return payload


def capa_scan(ctx: RunContext[ScanDeps]) -> str:
    """调用 mandiant/capa，提取恶意能力和 ATT&CK 映射。

    返回给模型的不只是规则名：每条命中带上 namespace 与规则自带的 description，
    并在 `_about_this_output` 里显式声明"这些是关于规则的事实，不是对本文件的判断"。
    """
    exe = _find_exe("capa", env_var="CAPA_EXE")
    if not exe:
        result = {"error": "capa not installed or not in PATH"}
        _record(ctx, "capa_scan", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    # capa 通过 pip 安装时不自带 rules/sigs，需要显式指定（默认找仓库根的 third_party/）
    rules_dir = capa_rules_dir()
    sigs_dir = capa_sigs_dir()

    cmd = [exe, "-j"]
    if rules_dir.is_dir():
        cmd += ["-r", str(rules_dir)]
    if sigs_dir.is_dir():
        cmd += ["-s", str(sigs_dir)]
    cmd.append(str(ctx.deps.file_path))

    try:
        # 大文件上 capa 会超时（cpack.exe 13.5MB 跑 6 分钟未完、内存 2.8GB），要放宽设 CAPA_TIMEOUT
        proc = subprocess.run(cmd, capture_output=True, timeout=_capa_timeout())
        capa_stdout = _decode_output(proc.stdout or b"")
        capa_stderr = _decode_output(proc.stderr or b"")
        if proc.returncode != 0 or not capa_stdout.strip():
            result = {
                "error": "capa did not return JSON",
                "exit_code": proc.returncode,
                "stderr": capa_stderr[:1200],
            }
        else:
            data = json.loads(capa_stdout)
            rules = data.get("rules", {})
            attack: set[str] = set()
            mbc: set[str] = set()
            for meta in rules.values():
                rule_meta = meta.get("meta") or {}
                for item in rule_meta.get("attack") or []:
                    if isinstance(item, dict):
                        tid = item.get("id") or ""
                        technique = item.get("technique") or ""
                        attack.add(f"{tid} {technique}".strip())
                    else:
                        attack.add(str(item))
                for item in rule_meta.get("mbc") or []:
                    if isinstance(item, dict):
                        mid = item.get("id") or ""
                        behavior = item.get("behavior") or ""
                        mbc.add(f"{mid} {behavior}".strip())
                    else:
                        mbc.add(str(item))
            result = _capa_result(rules, sorted(attack), sorted(mbc))
    except subprocess.TimeoutExpired:
        result = {"error": "capa timeout"}
    except Exception as exc:
        result = {"error": f"capa failed: {exc}"}

    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "capa_scan", summary)
    # 载荷已由 _capa_result 按 CAPA_OUTPUT_CHARS 保证合法且有界，这里只做兜底，
    # 且绝不裸切 JSON（腰斩的 JSON 会让模型看到半个字段，比少几条详情更糟）
    return summary[: int(os.getenv("CAPA_OUTPUT_CHARS", "12000"))]


def floss_scan(ctx: RunContext[ScanDeps]) -> str:
    """调用 mandiant/flare-floss，提取混淆/解码/栈上字符串。"""
    exe = _find_exe("floss", env_var="FLOSS_EXE")
    if not exe:
        result = {"error": "FLOSS not installed or not in PATH"}
        _record(ctx, "floss_scan", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    try:
        proc = subprocess.run(
            [exe, "-q", "-j", str(ctx.deps.file_path)],
            capture_output=True,
            timeout=180,
        )
        floss_stdout = _decode_output(proc.stdout or b"")
        if proc.returncode != 0 or not floss_stdout.strip():
            result = {
                "error": "FLOSS did not return JSON",
                "exit_code": proc.returncode,
                "stderr": _decode_output(proc.stderr or b"")[:1000],
            }
        else:
            data = json.loads(floss_stdout)
            strings = data.get("strings", {}) or {}
            decoded = [item.get("string") for item in (strings.get("decoded_strings") or []) if isinstance(item, dict)]
            stack = [item.get("string") for item in (strings.get("stack_strings") or []) if isinstance(item, dict)]
            tight = [item.get("string") for item in (strings.get("tight_strings") or []) if isinstance(item, dict)]
            static = [item.get("string") for item in (strings.get("static_strings") or []) if isinstance(item, dict)]

            keywords = ("http://", "https://", "powershell", "cmd.exe", "wscript", "mshta",
                        "rundll32", "download", "invoke", "base64", "frombase64", "inject",
                        "bitcoin", "wallet", "onion", ".exe", ".dll", ".ps1", ".vbs")
            interesting_static = [
                s for s in static
                if isinstance(s, str) and any(k in s.lower() for k in keywords)
            ]
            interesting = [s for s in (decoded + stack + tight) if isinstance(s, str) and s]
            interesting += interesting_static

            result = {
                "decoded_count": len(decoded),
                "stack_count": len(stack),
                "tight_count": len(tight),
                "interesting_strings": interesting[:80],
                # 必须 decode：proc.stderr 是 bytes，直接 json.dumps 会抛 TypeError，
                # 异常冒出工具 → 整轮 Agent 失败 → 静默降级判 clean（实测 7 个恶意 PE 中招）
                "stderr": _decode_output(proc.stderr or b"")[:500],
            }
    except subprocess.TimeoutExpired:
        result = {"error": "FLOSS timeout"}
    except Exception as exc:
        result = {"error": f"FLOSS failed: {exc}"}

    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "floss_scan", summary)
    return summary[:7000]




# =========================
# Shell 工具：给 AI 自由组合命令的能力
# 安全边界在环境策略层，不写死在提示词里
# =========================
SHELL_DENY_PATTERNS: list[tuple[str, str]] = [
    # Unix 破坏性
    (r"\brm\s+(-[a-z]*[rf][a-z]*\s+)+", "destructive rm"),
    (r"\brm\s+-[a-z]*[rf][a-z]*\s+/", "destructive rm on root"),
    (r"\brmdir\b|\brm\s+-r\b|\brm\s+-f\b", "rm/rmdir"),
    (r"\bdel\s+/[a-z]*[sqf][a-z]*", "Windows del"),
    (r"\berase\b|\bformat\s+[a-z]:", "Windows erase/format"),
    (r"\bmkfs\.|\bmkfs\b|\bdd\s+if=", "mkfs/dd"),
    (r"\bshred\b|\bwipe\b|\bdiskpart\b", "disk destroy"),
    (r"\bshutdown\b|\breboot\b|\bpoweroff\b|\bhalt\b", "system power"),
    # Windows 系统修改
    (r"set-content|remove-item|clear-content|out-file\s+[a-z]:", "Windows file modification"),
    (r"reg\s+(add|delete|copy|restore)", "registry modification"),
    (r"schtasks\s+/create|schtasks\s+/delete|schtasks\s+/change", "scheduled task modification"),
    (r"\bnet\s+(user|localgroup)\b", "account modification"),
    (r"takeown|icacls|attrib\s+[+\-]|bcdedit|vssadmin|wbadmin|wevtutil\s+cl", "system modification"),
    # 网络
    (r"\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bnetcat\b|\bssh\b|\bscp\b|\bftp\b|\btelnet\b",
     "network command"),
    (r"invoke-webrequest|invoke-restmethod|start-bitstransfer|bitsadmin|certutil\s+-urlcache",
     "network download"),
    (r"\bping\b|\btracert\b|\bnslookup\b|resolve-dnsname", "network probe"),
    # ---- 文件落地（外部审查 P1-3：黑名单实测可绕过的三类之一）----
    # 只读分析不需要写任何文件；能写文件的命令一律拦。
    (r"certutil\s+(-decode|-decodehex|-f\s+-decode)", "certutil 落地解码产物"),
    (r"\[\s*(io\.)?file\s*\]\s*::\s*(writealltext|writeallbytes|writealllines|appendalltext|"
     r"create|createtext|appendtext|openwrite)",
     "PowerShell .NET 直写文件"),
    (r"\bfile\s*::\s*(writealltext|writeallbytes|appendalltext|create)", ".NET 直写文件"),
    (r"\bfileinfo\s*::|\[\s*system\.io\.file", ".NET 文件 API"),
    (r"\b(copy|move|xcopy|robocopy|installutil)\b", "文件复制/移动"),
    (r"\b(type|more)\s+[^|<>]*>", "读取并落地到文件"),
    (r"(?<![0-9])>>?(?!=)", "输出重定向（写文件）"),
    (r"\btee\b", "tee 写文件"),
    (r"\bupx\s+-o\b|\b7z\s+(x|e)\b|\bunzip\s+-o|\bunrar\s+x|\bexpand\s+-\w*\s*[a-z]:"
     r"|\btar\b[^|<>]*\s-[a-z]*c[a-z]*f|\btar\s+[a-z]*c[a-z]*f",
     "解压/打包产物到磁盘"),
    (r"\bmkdir\b|\bmd\s+[a-z]:|\btouch\b", "创建目录/文件"),
    # ---- 间接执行（绕过"只读"的实际路径）----
    (r"\bmshta\b|\brundll32\b|\bregsvr32\b|\bwscript\b|\bcscript\b", "间接执行宿主"),
    (r"\bstart\s+/|\bcall\s+[a-z]:|(?:^|[\s;&|])\.[\\/]", "间接启动"),
    (r"add-type\b|\[reflection\.assembly\]|invoke-expression|\biex\b|\bicm\b|invoke-command\b",
     "内存加载/执行"),
    (r"-encodedcommand\b|\s-enc(?![a-z0-9_-])", "编码命令（可隐藏任意载荷）"),
    (r"\bwmic\s+.*\bcall\s+create|\bwmic\s+/node:", "WMI 远程执行"),
    # ---- 脚本层联网（cmd/PowerShell 原生下载通道）----
    (r"webclient|downloadfile|downloadstring|\.downloaddata\b", "脚本层下载"),
    (r"\burlmon\b|\bwinhttp\b|new-object\s+net\.", "脚本层网络对象"),
    (r"certutil\s+(-urlcache|-verifyctl)", "certutil 联网"),
    (r"\bftp\s+-s:|\btftp\b", "网络下载通道"),
    (r"\bnet\s+use\b|\bnet\s+view\b|\bnet\s+share\b", "网络共享访问"),
]

SHELL_SENSITIVE_ENV_KEYS = ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AUTH")


def _clean_shell_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in list(env.keys()):
        upper = key.upper()
        if any(word in upper for word in SHELL_SENSITIVE_ENV_KEYS):
            env.pop(key, None)
    env["AI_AV_SHELL"] = "1"
    return env


def _shell_policy_check(command: str) -> str | None:
    cmd = command.strip()
    if not cmd:
        return "empty command"
    if len(cmd) > 2000:
        return "command too long"
    lower = cmd.lower()
    for pattern, label in SHELL_DENY_PATTERNS:
        if re.search(pattern, lower):
            return f"blocked by policy: {label}"
    return None


def shell_exec(ctx: RunContext[ScanDeps], command: str, timeout_seconds: int = 30) -> str:
    """在受控 shell 中运行只读分析命令。破坏性/联网/系统修改命令会被环境策略拦截。

    Windows 下走 cmd.exe（可用 PowerShell 内置命令探测）：`dir` `findstr` `certutil -dump`
    `powershell -c "Get-AuthenticodeSignature '<file>'"` `Get-FileHash`；
    Linux/WSL 下走 /bin/bash -lc：`file` `strings` `xxd` `objdump` `7z l` `upx -l` `readelf`。"""
    blocked = _shell_policy_check(command)
    if blocked:
        result = {"blocked": True, "reason": blocked, "command": command}
        _record(ctx, "shell_exec", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)

    # 环境级防循环：同一命令重复执行没有意义，拦截并提示换方法或输出结论
    normalized = re.sub(r"\s+", " ", command.strip())[:500]
    if normalized in ctx.deps.shell_history:
        ctx.deps.shell_history.append(normalized)
        result = {
            "blocked": True,
            "reason": "repeated command; output would not change. Try a different command or finalize verdict.",
            "command": command,
        }
        _record(ctx, "shell_exec", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)
    if len(ctx.deps.shell_history) >= 20:
        result = {
            "blocked": True,
            "reason": "shell command budget exceeded for this file; use existing evidence and finalize verdict.",
            "command": command,
        }
        _record(ctx, "shell_exec", json.dumps(result, ensure_ascii=False))
        return json.dumps(result, ensure_ascii=False)
    ctx.deps.shell_history.append(normalized)

    cwd = str(ctx.deps.file_path.parent)
    env = _clean_shell_env()
    timeout_seconds = max(1, min(int(timeout_seconds), 60))
    try:
        if os.name == "nt":
            proc = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                capture_output=True,
                timeout=timeout_seconds,
                env=env,
            )
        else:
            proc = subprocess.run(
                ["/bin/bash", "-lc", command],
                cwd=cwd,
                capture_output=True,
                timeout=timeout_seconds,
                env=env,
            )
        result = {
            "command": command,
            "shell": "cmd" if os.name == "nt" else "bash",
            "exit_code": proc.returncode,
            "stdout": _decode_output(proc.stdout or b"")[:8000],
            "stderr": _decode_output(proc.stderr or b"")[:2000],
        }
    except subprocess.TimeoutExpired:
        result = {"command": command, "error": f"timeout after {timeout_seconds}s"}
    except Exception as exc:
        result = {"command": command, "error": f"shell failed: {exc}"}

    summary = json.dumps(result, ensure_ascii=False)
    _record(ctx, "shell_exec", summary)
    return summary[:9000]


# 暴露给 AI 的工具（2026-09-26 从 12 个收到 8 个）。
#
# 删掉 4 个，理由分两类：
#
# ① 信息已经在送审提示词里了 —— 再给工具就是让 AI 复述把它叫来的理由：
#      yara_scan   YARA 命中（规则名 / severity / 偏移 / 命中字节 / 上下文 / 规则 meta）
#                  现在由 yara_match_details() 直接写进提示词。
#                  实测教训：旧版提示词里本来就有「YARA 命中」，AI 还是调了 8 次工具
#                  （10 个文件里 8 个）—— 光把信息塞提示词不够，工具在它就会调。
#      hash_lookup 本地哈希表只有 1 条（EICAR），而命中就在 scanner 短路层判掉了，
#                  根本进不到 AI。所以 AI 调它**必然返回 false** —— 9 次调用 9 次 false，
#                  是个逻辑死胡同。哈希是"身份"，不是"特征"，不该做成工具。
#
# ② 本环境跑不了，给了就是让它空转 —— 改为在提示词里标「未执行」：
#      clamav_scan 未安装（被调 10 次，10 次全返回 "not installed"）
#      vt_lookup   未配置 API Key（被调 2 次，全返回 "not set"）
#      合起来 15 次空转 = 当时全部 AI 工具调用的 23%。
#
# 注意：**不能只是"不暴露"就完事**。藏掉工具会让 AI 以为"这项查过了、没问题"，
# 而真相是"根本没跑"。所以提示词里必须显式写「以下检测未执行」（unavailable_detections()）。
#
# ── 2026-09-26 第二轮实测补的坑 ──
# 上面这条只做了一半：`clamav_scan` / `vt_lookup` 从表里摘了，但 `capa_scan` / `floss_scan`
# 留着没摘 —— 于是提示词写着「capa 未安装」，工具表里却摆着 `capa_scan`。
# AI 的选择很合理：它不信提示词，直接调。63 个文件的验证跑里
# capa_scan 被调 22 次、floss_scan 被调 23 次，**每一次都返回 "not installed"**。
# 提示词和工具表打架时，AI 信工具表。
#
# 所以：**工具表必须按本机环境过滤**，由 `available_tools()` 生成，跟
# `unavailable_detections()` 用同一套探测逻辑 —— 一边不提供工具，一边明说它没跑，两边一致。
ALL_TOOLS = [
    pe_analyze,
    signature_verify,
    pdf_analyze,
    script_analyze,
    office_macro_analyze,
    strings_ioc,
    capa_scan,
    floss_scan,
]


def available_tools() -> list:
    """按本机环境过滤后的工具表 —— 交给 Agent 的就是这一份。

    跑不了的工具不暴露（否则 AI 会调它，拿回一句"没装"，白烧一次往返）。
    配套要求：这些工具对应的检测项必须出现在 `unavailable_detections()` 里，
    让 AI 知道"这个维度没查"，而不是"查了没问题"。
    """
    tools = [pe_analyze, signature_verify, pdf_analyze, script_analyze,
             office_macro_analyze, strings_ioc]
    # capa 要**二进制 + 规则集 + 签名集**三样齐了才暴露 —— 缺一样每次调用都必然报错
    if capa_ready()[0]:
        tools.append(capa_scan)
    if _find_exe("floss", env_var="FLOSS_EXE"):
        tools.append(floss_scan)
    # 默认不把 shell 放进全量扫描，防止 Agent 在难样本上反复调命令烧 token。
    # 需要深度分析时显式设置 AI_AV_ENABLE_SHELL=1。
    if os.getenv("AI_AV_ENABLE_SHELL") == "1":
        tools.insert(0, shell_exec)
    return tools

