from __future__ import annotations

import hashlib
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from pydantic_ai import Agent

from aiav.agent import analyze_file_with_agent
from aiav.budget import TokenBudget
from aiav.cache import ScanCache, cache_enabled, report_from_cache
from aiav.criteria import (
    AI_GATE,
    CRITERIA,
    CriterionHit,
    band_label,
    classify_reason,
    decide as decide_deterministic,
    file_score,
    update_stats as update_criteria_stats,
)
from aiav.disposition import StateStore, default_store
from aiav.models import FileReport, PreliminaryEvidence, RiskLevel, ScanDeps, Verdict
from aiav.preload import (
    ai_tool_calls,
    collect as collect_preload,
    deep_evidence_threshold as preload_deep_threshold,
    detect_kind,
    preload_enabled,
    preload_tool_calls,
)
from aiav.tools import (
    CONTAINER_EXTENSIONS,
    HIGH_CONFIDENCE_YARA_RULES,
    HIGH_RISK_EXTENSIONS,
    MACRO_SCAN_EXTENSIONS,
    OLE_DOC_EXTENSIONS,
    NEUTRAL_PATTERN_LABELS,
    SCRIPT_EXTENSIONS,
    SCRIPT_READ_LIMIT,
    WEAK_YARA_RULES,
    extract_container_strings,
    extract_ole_macro_info,
    extract_xlm_macro_info,
    find_embed_patterns,
    find_script_patterns,
    merge_container_patterns,
    find_script_signals,
    script_signal_tiers,
    load_known_bad_hashes,
    pe_packing_signals,
    run_yara,
    clamav_evidence,
    classify_clamav_signature,
    signature_evidence,
    unavailable_detections,
)
from aiav.structural import structure_signals

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
# EICAR 判定只认"文件本身就是测试标记"。真正的 EICAR 文件 68 字节；
# 放宽到 256 是给带换行/尾注的变体留余量，同时把"源码里定义了这个常量"的文件排除掉。
# 设成 0 可以退回旧的子串匹配行为（不推荐，见 quick_prefilter 里的说明）。
EICAR_MAX_BYTES = 256

#: ClamAV 签名名 → 判据 ID / 理由前缀。三档分开成三条判据，因为 `decide()` 认的是
#: 判据 ID 上的 `conclusive` 标记而不是分数 —— 共用一个 ID 会把启发式命中一起结案。
_CLAMAV_KIND_CRITERIA: dict[str, tuple[str, str]] = {
    "malware": ("DET_CLAMAV_SIGNATURE", "ClamAV 命中"),
    "heuristic": ("DET_CLAMAV_HEUR", "ClamAV 启发式命中"),
    "pua": ("DET_CLAMAV_PUA", "ClamAV PUA 命中"),
}

#: **单文件兜底路径**的扩展名白名单（批量路径不看这个，见 quick_prefilter 里的说明）。
#: 这是"每次起进程 6.3 秒"时代留下的省时间手段：批量之后每文件零点几秒，过滤只会漏样本。
_CLAMAV_SINGLE_FILE_EXTS = {
    ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".pif", ".pyd", ".efi",
    ".doc", ".docm", ".xls", ".xlsm", ".pdf", ".js", ".vbs", ".ps1", ".lnk", ".rtf",
    ".jar", ".zip", ".rar", ".7z",
}


def _file_size(path: Path) -> int:
    """取文件大小；取不到返回 0（宁可不判 EICAR，也不要因为 stat 失败而漏判）。"""
    try:
        return path.stat().st_size
    except OSError:
        return 0


# 预筛分数阈值：达到它就该交人工/AI 复核。单独抽成常量是因为"读不了"这条路径
# 必须能**明确**顶到阈值上（见 quick_prefilter 的 read_error 分支），
# 散在代码里的字面量 12 会让那处改动看起来很随意。
#
# 2026-09-27 换刻度：从"老口径 12 分"换成"Assemblyline 刻度 300 分"。
# **语义没变** —— `criteria.SIGNAL_UNIT = 25` 就是把老口径的 12 分映射到上游
# `verdict.suspicious = 300` 上（300 / 12 = 25），老口径每条权重一个都没调。
# 保留这个名字是因为报告/测试/外部脚本都在读它。
SUSPICIOUS_SCORE_THRESHOLD = AI_GATE

# XLM 宏表里「`=CHAR(<常量>)` 单字符单元格」超过这个数就算异常形态。
# 依据：真实在野 ZLoader 系 Excel 4.0 样本实测 526 / 569 / 569 个；
# 现有 120 个合成 XLM（恶 60 + 良 60）全是 0 个。取 50 是留一个数量级的余量，
# **不是**从分布上拟合出来的（样本只有 3 个，见 docs/ALT_FORMS_RESULTS.md 的口径说明）。
XLM_CHAR_CELL_MIN = 50

DEFAULT_SKIP_DIRS = {
    "$recycle.bin",
    "system volume information",
    "windows",
    "winsxs",
    "program files",
    "program files (x86)",
    "programdata",
    "appdata",
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
}

DOUBLE_EXTENSIONS = {
    ".pdf.exe", ".doc.exe", ".docx.exe", ".jpg.exe", ".jpeg.exe", ".png.exe",
    ".txt.exe", ".xls.exe", ".xlsx.exe", ".zip.exe", ".rar.exe",
    # 2026-09-19 补：投递用的"文档壳 + 脚本/快捷方式"双扩展
    # （实测 invoice_2026.pdf.lnk 这类样本，载荷名在**文件名**里，内容里看不到 —— YARA 看不见文件名）
    ".pdf.lnk", ".doc.lnk", ".docx.lnk", ".jpg.lnk", ".xls.lnk", ".txt.lnk", ".zip.lnk",
    ".pdf.js", ".pdf.vbs", ".doc.hta", ".pdf.scr", ".txt.bat", ".pdf.cmd", ".pdf.ps1",
}


#: 运营白名单的进程内缓存。白名单是"确定性结案"判据（`DET_SAFELIST_HIT`），
#: 每个文件都去读一次 JSON 在全量扫描（几千个文件）下是纯浪费；进程内缓存一次即可。
#: 代价：扫描**过程中**往白名单里加条目，本进程不会立刻生效 —— 记在这里免得被当 bug。
_WHITELIST_CACHE: set[str] | None = None
_WHITELIST_LOCK = threading.Lock()


def load_whitelisted_hashes() -> set[str]:
    """运营白名单里的 sha256 集合（进程内缓存一次）。"""
    global _WHITELIST_CACHE
    if _WHITELIST_CACHE is not None:
        return _WHITELIST_CACHE
    with _WHITELIST_LOCK:
        if _WHITELIST_CACHE is not None:
            return _WHITELIST_CACHE
        try:
            store = default_store()
            _WHITELIST_CACHE = {
                str(item.get("sha256", "")).lower()
                for item in store.whitelist()
                if item.get("sha256")
            }
        except Exception:  # noqa: BLE001 - 白名单读不到不该让扫描挂掉
            _WHITELIST_CACHE = set()
        return _WHITELIST_CACHE


def reset_whitelist_cache() -> None:
    """测试用：清掉白名单缓存。"""
    global _WHITELIST_CACHE
    _WHITELIST_CACHE = None


def compute_sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def iter_files(
    root: Path,
    max_size_mb: int = 50,
    include_system: bool = False,
    skip_stats: dict[str, int] | None = None,
) -> Iterator[Path]:
    """遍历待扫文件。**默认行为不变**：yield 的文件集合与 `skip_stats=None` 时逐字节相同。

    `skip_stats` 是可选出口：传一个 dict 进来，本函数会把"跳过了什么、各多少"累加进去，
    让报告能说清"有多少东西根本没进扫描"。

    为什么需要（外部审查 P4）：>50MB 的文件与点开头目录原先被**静默**跳过 ——
    报告里只看得到"扫了几个"，看不出"还有几个没扫、为什么"。对"只读研判台"来说这是
    口径风险：用户以为覆盖了整个目录，其实有东西被悄悄放过了。
    这里只加**计数**，不改判决、不改默认过滤规则。
    """
    max_size = max_size_mb * 1024 * 1024
    skip_dirs = set() if include_system else DEFAULT_SKIP_DIRS

    def _tally(reason: str) -> None:
        if skip_stats is not None:
            skip_stats[reason] = skip_stats.get(reason, 0) + 1

    def _on_walk_error(_exc: OSError) -> None:
        _tally("walk_error")

    for dirpath, dirnames, filenames in os.walk(root, onerror=_on_walk_error):
        keep = []
        for d in dirnames:
            if d.lower() in skip_dirs:
                _tally("system_dir")
            elif d.startswith("."):
                _tally("hidden_dir")
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in filenames:
            path = Path(dirpath) / name
            try:
                if not path.is_file():
                    _tally("not_regular_file")
                    continue
                if path.stat().st_size > max_size:
                    _tally("too_large")
                    continue
            except OSError:
                _tally("stat_failed")
                continue
            yield path


def quick_prefilter(path: Path, sha256: str, with_signature: bool = False,
                    clamav_batch: Mapping[str, Any] | None = None) -> PreliminaryEvidence:
    """规则预筛，不调用 LLM。

    with_signature=True 时附带确定性签名证据块（要调 Windows 验签，约 0.5s/文件），
    只在会进 AI 的路径上用；纯规则全量扫描默认关掉以免变慢。

    `clamav_batch` 是 `tools.clamav_scan_batch()` 的返回值（**整批一次进程**的 ClamAV 结果）。
    传了就用它查表，不传才走单文件兜底 —— 单文件一次要重新加载 362 万条签名（6.3 s）。
    """
    ext = path.suffix.lower()
    name_lower = path.name.lower()
    reasons: list[str] = []
    # 判据命中（2026-09-27）：分数**不再**由这里的字面量决定，而是每条信号先落成一条
    # `CriterionHit`（判据 ID + 理由 + 命中次数 + 签名名），最后由 `criteria.score_hits`
    # 按判据表算分。好处：每条分都能追到判据表里那一行（名字/上限/工具/ATT&CK），
    # 报告里能说清"这 375 分是谁给的"，而不是"总分 375，来源不明"。
    hits: list[CriterionHit] = []
    unclassified: list[str] = []

    def _hit(heur_id: str, reason: str, *, frequency: int = 1,
             signatures: Sequence[str] = (), safelisted: bool = False) -> None:
        hits.append(CriterionHit(heur_id, reason, frequency, tuple(signatures), safelisted))
        reasons.append(reason)

    def _hit_reason(reason: str, *, signatures: Sequence[str] = ()) -> None:
        """产出方只给了一句理由文本时走这里：分类不出来的**显式记账**，不许吞。"""
        heur_id = classify_reason(reason)
        if heur_id is None:
            unclassified.append(reason)
            reasons.append(reason)
            return
        _hit(heur_id, reason, signatures=signatures)

    yara_hits = run_yara(path)

    read_error = ""
    try:
        with path.open("rb") as f:
            head = f.read(4096)
    except OSError as exc:
        # 「读不了 ≠ 安全」在**预筛层**也要成立：旧实现把 OSError 吞成 `head=b""`，
        # 于是 EICAR/脚本特征一个都不命中、分数停在 0 → 判 clean。
        # 入口那层（compute_sha256 失败）是判 suspicious+review 的，两层口径必须一致。
        head = b""
        read_error = f"{type(exc).__name__}: {exc}"
        _hit("READ_ERROR", f"读取失败（无法排除，按需人工复核）: {read_error[:160]}")

    # EICAR：判"文件**就是** EICAR 测试文件"，不是"文件**含有** EICAR 字符串"。
    #
    # ⚠️ 2026-09-26 实测教训：旧实现是 `eicar = EICAR in head`（前 4KB 子串匹配），
    # 于是**定义了这个常量的源码文件自己中招** —— `aiav/scanner.py` 第 44 行写着
    # `EICAR = rb"X5O!P%..."`，落在前 4KB 内，被判 malicious(0.99)。
    # 而且 EICAR 在短路集合里，AI **根本没机会看它**（对照 `demo.yar` 那次：
    # 同样是自指命中，但走的是特征路径，被 AI 正确平反成 clean）。
    #
    # 这违反本项目自己定的短路原则（见下方 `evidence.eicar or known_bad_hash` 处的注释）：
    #   · SHA256 精确匹配 = 这个文件**就是**那个恶意样本 → 身份，可以短路
    #   · 字符串/规则命中  = 这个文件**含有**某种特征   → 特征，必须交给 AI 看语境
    # EICAR 的子串匹配属于后者。真正的 EICAR 文件只有 68 字节、内容就是这个字符串本身，
    # 所以用"体积 + 内容"把它和"含这个字符串的大文件"分开。
    eicar = EICAR_MAX_BYTES > 0 and _file_size(path) <= EICAR_MAX_BYTES and EICAR in head
    known_bad_hash = sha256.lower() in load_known_bad_hashes()

    if eicar:
        _hit("DET_EICAR", "EICAR 测试文件")
    if known_bad_hash:
        _hit("DET_KNOWN_BAD_HASH", "命中本地恶意哈希库")
    strong_yara = [h for h in yara_hits if h not in WEAK_YARA_RULES]
    if strong_yara:
        _hit("STRONG_YARA", "YARA 命中: " + ", ".join(strong_yara), signatures=strong_yara)
    elif yara_hits:
        _hit("WEAK_YARA", "弱 YARA 命中: " + ", ".join(yara_hits), signatures=yara_hits)

    if ext in HIGH_RISK_EXTENSIONS:
        _hit("HIGH_RISK_EXTENSION", f"高风险扩展名: {ext}")

    for double_ext in DOUBLE_EXTENSIONS:
        if name_lower.endswith(double_ext):
            _hit("DOUBLE_EXTENSION", f"可疑双扩展名: {double_ext}")

    suspicious_name_words = ("crack", "keygen", "hack", "inject", "loader", "trojan", "ransom", "miner", "stealer")
    for word in suspicious_name_words:
        if word in name_lower:
            _hit("SUSPICIOUS_NAME_WORD", f"文件名包含可疑词: {word}")

    # 文本/脚本类快速检查：脚本的"可执行面"就是文本，所以要多读一段（旧实现只看前 4KB，
    # 混淆脚本把载荷放在尾部就能整段躲过预筛）。上限 256KB，纯文本不会拖慢扫描。
    if ext in SCRIPT_EXTENSIONS:
        try:
            with path.open("rb") as f:
                blob = f.read(SCRIPT_READ_LIMIT)
            text = blob.decode("utf-8", errors="ignore")
            strong, weak = script_signal_tiers(text)
            if strong:
                _hit("SCRIPT_STRONG", "脚本强特征: " + ", ".join(strong[:6]),
                     frequency=min(len(strong), 4), signatures=strong[:6])
            if weak:
                _hit("SCRIPT_WEAK", "脚本弱特征: " + ", ".join(weak[:6]),
                     frequency=min(len(weak), 2), signatures=weak[:6])
        except Exception:  # noqa: BLE001 - 脚本解析失败不影响其它信号
            pass

    # 容器类（LNK / RTF / OLE / OOXML 文档）：字符串多为 UTF-16，必须重新抽字符串再匹配，
    # 否则整个类别在预筛阶段是盲的。
    if ext in CONTAINER_EXTENSIONS:
        try:
            with path.open("rb") as f:
                blob = f.read(512 * 1024)
            text = extract_container_strings(blob)
            # 通用脚本标签与容器专用标签会重复计分，统一走去重入口（见 tools.CONTAINER_LABEL_ALIASES）
            patterns = [
                p for p in merge_container_patterns(text, ext)
                if p not in NEUTRAL_PATTERN_LABELS
            ]
            # XLM 宏表存在时，容器字节里的 URL/LOLBin 子串已经由 XLM 分支按档计分，
            # 这里再算一次等于同一处证据记两遍（实测会把良性表顶过阈值）。
            if patterns and ext not in OLE_DOC_EXTENSIONS:
                _hit("CONTAINER_PATTERN", "容器可疑模式: " + ", ".join(patterns[:8]),
                     frequency=min(len(patterns), 4), signatures=patterns[:8])
            elif patterns and ext in OLE_DOC_EXTENSIONS:
                try:
                    _xlm = extract_xlm_macro_info(path)
                except Exception:  # noqa: BLE001
                    _xlm = {}
                if not _xlm.get("has_xlm"):
                    _hit("CONTAINER_PATTERN", "容器可疑模式: " + ", ".join(patterns[:8]),
                         frequency=min(len(patterns), 4), signatures=patterns[:8])
        except Exception:
            pass

    # OLE / OOXML 文档的宏源码是压缩存储的，只有解压后才能按内容打分。
    # 这是确定性检测（oletools），不消耗 token，所以放在预筛而不是 Agent 里。
    if ext in MACRO_SCAN_EXTENSIONS:
        try:
            info = extract_ole_macro_info(path)
            if info.get("has_macros"):
                _hit("MACRO_PRESENT", "包含 VBA 宏")
                # 入口名（AutoOpen 等）不算可疑特征，否则正常宏文档全是误报
                macro_patterns = [
                    p for p in (info.get("patterns") or []) if p not in NEUTRAL_PATTERN_LABELS
                ]
                if macro_patterns:
                    _hit("MACRO_PATTERN", "宏内可疑模式: " + ", ".join(macro_patterns[:8]),
                         frequency=min(len(macro_patterns), 4), signatures=macro_patterns[:8])
        except Exception:
            pass

    # Excel 4.0 / XLM 宏表：oletools 看不见（它只认 VBA 工程），2026-09-19 实测整类掉在阈值下。
    # 计分口径（收紧后）：宏表存在 +5；**执行类**宏函数每类 +10（上限 20）；
    # **信息类**（读环境/取数/列目录）**不计分**、只在理由里留痕 —— 业务宏表里这是常态。
    # 宏表存在时，本分支**不再**叠加容器字节子串的分数（同一处证据重复计分会让良性表越界）。
    if ext in OLE_DOC_EXTENSIONS:
        try:
            xlm = extract_xlm_macro_info(path)
            if xlm.get("has_xlm"):
                _hit("XLM_PRESENT", f"包含 Excel 4.0 (XLM) 宏表 ×{xlm.get('macro_sheets', 1)}")
                exec_hits = [p for p in (xlm.get("exec_patterns") or [])
                             if p not in NEUTRAL_PATTERN_LABELS]
                info_hits = [p for p in (xlm.get("info_patterns") or [])
                             if p not in NEUTRAL_PATTERN_LABELS]
                if exec_hits:
                    _hit("XLM_EXEC_PATTERN", "XLM 宏内执行类模式: " + ", ".join(exec_hits[:4]),
                         frequency=min(len(exec_hits), 2), signatures=exec_hits[:4])
                # 信息类**不计分**：读环境/取数/列目录在业务宏表里是常态
                # （实测：计分会让 60 个良性宏表里 24 个越界）。只在理由里留痕，供人工复核。
                if info_hits:
                    reasons.append("XLM 宏内信息类模式（不计分）: " + ", ".join(info_hits[:4]))
                # 2026-09-19 真实在野语料（3 个 ZLoader 系 Excel 4.0 样本）暴露的事：
                # 上面那两条**关键词**档在真实样本上一条都不响 —— 它们的宏体是几百个
                # `=CHAR(<常量>)` 单元格逐字符拼出来的，**明文为 0**。所以补两个**纯结构**信号：
                #   · 宏表被隐藏/深度隐藏（BOUNDSHEET.hsState，实测真实样本 3/3 是深度隐藏 2）
                #   · 宏表里大量 `=CHAR(常量)` 单字符单元格（实测 526–569 个，合成良性 0 个）
                # 两者都是弱信号：单独一个到不了阈值（5 / 10 < 12），合起来才送人工复核。
                hidden = int(xlm.get("hidden_macro_sheets") or 0)
                if hidden:
                    _hit("XLM_HIDDEN", f"XLM 宏表被隐藏 ×{hidden}", frequency=hidden)
                char_cells = int(xlm.get("char_cells") or 0)
                if char_cells >= XLM_CHAR_CELL_MIN:
                    _hit("XLM_CHAR_CELLS", f"XLM 宏表内 CHAR() 逐字符拼装 ×{char_cells}（明文为零）")
        except Exception:  # noqa: BLE001 - XLM 解析失败不影响其它信号
            pass

    # PDF：脚本/动作/内嵌文件是"可执行面"，用 pypdf 确定性解析（0 token），
    # 与 Office 宏同一个思路：能在预筛看清的，就不该靠模型猜。
    if ext == ".pdf":
        try:
            from aiav.pdfscan import analyze_pdf

            pdf_info = analyze_pdf(path)
            if pdf_info.get("is_pdf") and pdf_info.get("scores"):
                for pdf_reason in pdf_info["reasons"]:
                    _hit_reason(pdf_reason)
        except Exception:  # noqa: BLE001 - PDF 解析失败不影响其它信号
            pass

    # PE 加壳弱信号：正常软件也会加壳，所以权重故意压低（4 分），
    # 只够把它送进 AI 复核，不足以单独把结论推成 suspicious（阈值 12）。
    if ext in {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"}:
        try:
            packing = pe_packing_signals(path)
            if packing:
                _hit("PACKING", "疑似加壳: " + ", ".join(packing[:4]), signatures=packing[:4])
        except Exception:
            pass

    # 确定性**结构**信号（2026-09-27）：段表/流表本身长得不对（小 stub + 大载荷、
    # 可写可执行段、导入表稀疏、资源段占比异常、容器内嵌对象…）。全部本地可算、0 token。
    #
    # 动机（40 个 Dike pilot 实测）：补之前 35/40 个文件**同分 5**（那 5 分只来自
    # 「高风险扩展名」），恶意与良性分布完全重合（AUC 0.625）—— 分数既不能分流，
    # 也不能给 AI 提供任何信号。
    #
    # 每条理由都写成 `结构信号 +N: <事实>（<读数>）`，报告里能看出这条分是谁给的；
    # 与上面 `pe_packing_signals`（加壳节名 / 高熵可执行段）**不是同一处证据**：
    # 那边量的是"节名与熵"，这边量的是"原始数据分布与导入表形态"，不重复计分。
    try:
        struct_score, struct_reasons = structure_signals(path, ext)
        if struct_score:
            for struct_reason in struct_reasons:
                _hit_reason(struct_reason)
    except Exception:  # noqa: BLE001 - 结构解析失败不影响其它信号
        pass

    signature: dict = {}
    if with_signature:
        try:
            signature = signature_evidence(path)
        except Exception as exc:  # noqa: BLE001
            signature = {"status": "unknown", "conclusion": "unknown",
                         "error": f"签名证据获取失败: {exc}"}

    # ---- ClamAV（≥1000 档，确定性结案判恶意）----
    # 装了才跑；没装就**显式记成"未产出"**，不记成"扫过且干净"。
    #
    # 2026-09-27 改成**批量优先**：批次由调用方（`aiav scan` / 实测脚本）用
    # `tools.clamav_scan_batch(files)` 一次性建好，这里只查表 —— 一个文件起一次 clamscan
    # 每次都要重新加载 362 万条签名（6.3 s/文件），批量摊到每文件 0.1~0.4 s。
    # 没有批次（单文件调用）才走 `clamav_evidence()` 兜底，并在报告里标 `batch=False`。
    #
    # 批次里**不按扩展名过滤**：那个过滤是"每次进程 6.3 秒"时代留下的省时间手段，
    # 批量之后每文件只有零点几秒，而过滤会实打实地漏样本（Dike 的 `.ole` 就不在旧白名单里，
    # ClamAV 对它们是能出 `Doc.Dropper.Emotet` 这种命中的）。过滤只保留在单文件兜底路径上。
    clamav: dict[str, Any] = {"available": False, "infected": False, "signature": "",
                              "kind": "", "batch": False, "error": ""}
    if clamav_batch is not None:
        if not clamav_batch.get("available"):
            clamav["error"] = (clamav_batch.get("error")
                               or "ClamAV 未安装（clamscan / clamdscan 都不在 PATH 里）")
        else:
            batch_hit = (clamav_batch.get("results") or {}).get(str(path))
            if batch_hit is None:
                # 传进去了却没出现在输出里 = **静默跳过**。不是"扫过且干净"。
                clamav = {**clamav, "available": True, "batch": True,
                          "error": "本批 ClamAV 没有这个文件的结果（静默跳过，不是扫过且干净）"}
            else:
                clamav = {"available": True, "batch": True,
                          "infected": bool(batch_hit.get("infected")),
                          "signature": batch_hit.get("signature") or "",
                          "kind": batch_hit.get("kind") or "", "error": ""}
    elif ext in _CLAMAV_SINGLE_FILE_EXTS or ext == "":
        try:
            clamav = clamav_evidence(path)
        except Exception as exc:  # noqa: BLE001 - AV 跑不动不影响其它信号
            clamav = {"available": False, "infected": False, "signature": "",
                      "kind": "", "batch": False, "error": f"{type(exc).__name__}: {exc}"}

    if clamav.get("infected"):
        sig = clamav.get("signature") or ""
        # 签名名分三档：真病毒 → 1000 结案；启发式 → 300 送审；PUA/adware → 0 只留痕。
        # 签名名**原样**进判据的 `signature.name`（报告的证据链，也是复核时要看的东西）。
        heur_id, label = _CLAMAV_KIND_CRITERIA.get(
            clamav.get("kind") or classify_clamav_signature(sig),
            _CLAMAV_KIND_CRITERIA["malware"])
        _hit(heur_id, f"{label}: {sig or '(未取到签名名)'}", signatures=(sig or "clamav",))

    # ---- 确定性结案判据（2026-09-27）----
    # 这两条不进"弱信号累加"，它们各自就是结论：
    #   · 签名有效且签发者可信 → 确定性判干净（上游 safelist 语义：签名安全则分数归零）
    #   · 白名单命中           → 确定性判干净
    # 判白优先于判恶意：一条可信签名不会因为别处有弱信号而失效。
    if signature.get("status") == "Valid" and signature.get("trusted_signer"):
        _hit("DET_TRUSTED_SIGNATURE",
             f"内嵌签名有效且签发者可信: {signature.get('signer_cn') or signature.get('signer')}")
    if sha256.lower() in load_whitelisted_hashes():
        _hit("DET_SAFELIST_HIT", "命中运营白名单")

    # 分数由判据表算出来（每条夹自己的 max_score），不再由散落的字面量累加。
    # 判干净方向的结案判据命中时**归零**（上游 safelist 语义），所以分数与结论同源。
    score, scored, clean_ids = file_score(hits)
    verdict_now = decide_deterministic(hits)

    return PreliminaryEvidence(
        path=str(path),
        sha256=sha256,
        size=path.stat().st_size if path.exists() else 0,
        extension=ext,
        prefilter_score=score,
        reasons=reasons,
        yara_hits=yara_hits,
        eicar=eicar,
        known_bad_hash=known_bad_hash,
        read_error=read_error,
        signature=signature,
        criteria_hits=[_hit_record(s) for s in scored],
        unclassified_signals=unclassified,
        clamav={"available": bool(clamav.get("available")),
                "infected": bool(clamav.get("infected")),
                "signature": clamav.get("signature") or "",
                "kind": clamav.get("kind") or "",
                "batch": bool(clamav.get("batch")),
                "error": clamav.get("error") or ""},
        deterministic={
            "disposition": verdict_now.disposition.value,
            "tier": verdict_now.tier.value,
            "band": verdict_now.band.value,
            "band_label": band_label(verdict_now.score),
            "score": verdict_now.score,
            "sends_to_ai": verdict_now.sends_to_ai,
            "reasons": verdict_now.reasons,
            "gate": AI_GATE,
        },
    )


def _hit_record(scored) -> dict:
    """一条判据命中的**报告形状** —— 字段对齐上游 `odm/models/result.py::Heuristic`。"""
    crit = CRITERIA.get(scored.heur_id)
    return {
        "heur_id": scored.heur_id,
        "name": crit.name if crit else scored.name,
        "description": crit.description if crit else "",
        "score": scored.score,
        "max_score": crit.max_score if crit else None,
        "frequency": scored.frequency,
        "filetype": crit.filetype if crit else "*",
        "produced_by": crit.produced_by if crit else "",
        "attack": scored.attack,
        "signature": [
            {"name": name, "frequency": freq, "safe": bool(scored.signature_safe.get(name))}
            for name, freq in scored.signatures.items()
        ],
        "safelisted": scored.zeroed_by_safelist,
        "direction": crit.direction.value if crit else "suspect",
        "conclusive": bool(crit.conclusive) if crit else False,
    }


def heuristic_verdict(evidence: PreliminaryEvidence) -> Verdict:
    """AI 不可用时的降级策略，也用于预筛证据定级。

    2026-09-27：**确定性结案的结论优先** —— 一条"AV 库命中"或"签名可信"是结案，
    不是"降级到规则判定"。旧实现只认 eicar/known_bad_hash 两个布尔量，
    新增的结案判据（ClamAV 命中 / 白名单 / 可信签名）会被降级路径覆盖掉。
    """
    disposition = (evidence.deterministic or {}).get("disposition")
    if disposition == "closed_malicious":
        hits = [h for h in evidence.criteria_hits if h.get("conclusive") and h.get("direction") == "malicious"]
        return Verdict(
            risk=RiskLevel.malicious,
            confidence=0.99,
            category="deterministic_malicious",
            summary="确定性判据结案："
                    + "、".join(f"{h['name']}({h['heur_id']})" for h in hits),
            evidence=[f"{h['heur_id']}: {h['name']} +{h['score']}" for h in hits] or evidence.reasons,
            mitre=sorted({a["attack_id"] for h in hits for a in h.get("attack", [])}),
            recommended_action="isolate",
        )
    if disposition == "closed_clean":
        hits = [h for h in evidence.criteria_hits if h.get("conclusive") and h.get("direction") == "clean"]
        return Verdict(
            risk=RiskLevel.clean,
            confidence=0.99,
            category="deterministic_clean",
            summary="确定性判据结案（判干净）："
                    + "、".join(f"{h['name']}({h['heur_id']})" for h in hits),
            evidence=[f"{h['heur_id']}: {h['name']}" for h in hits],
            mitre=[],
            recommended_action="ignore",
        )
    if evidence.eicar or evidence.known_bad_hash:
        return Verdict(
            risk=RiskLevel.malicious,
            confidence=0.99,
            category="known_malware",
            summary="命中已知恶意特征。",
            evidence=evidence.reasons,
            mitre=[],
            recommended_action="isolate",
        )
    strong_yara = [h for h in evidence.yara_hits if h not in WEAK_YARA_RULES]
    if strong_yara:
        return Verdict(
            risk=RiskLevel.suspicious,
            confidence=0.75,
            category="yara_hit",
            summary="命中 YARA 规则，需要进一步确认。",
            evidence=evidence.reasons,
            mitre=[],
            recommended_action="review",
        )
    if evidence.prefilter_score >= SUSPICIOUS_SCORE_THRESHOLD:
        return Verdict(
            risk=RiskLevel.suspicious,
            confidence=0.65,
            category="heuristic",
            summary="多项静态特征可疑，但缺少直接恶意证据。",
            evidence=evidence.reasons,
            mitre=[],
            recommended_action="review",
        )
    return Verdict(
        risk=RiskLevel.clean,
        confidence=0.6,
        category="clean",
        summary="预筛未发现明显恶意特征。",
        evidence=evidence.reasons or ["无异常特征"],
        mitre=[],
        recommended_action="ignore",
    )


# =========================
# 证据溯源 / 断言校验（确定性，不花 token）
# =========================
# 证据溯源用的工具名表。
# 注意：`yara_scan` / `hash_lookup` / `vt_lookup` / `clamav_scan` 已于 2026-09-26
# 从 `tools.ALL_TOOLS` 摘除（前两个信息已进送审提示词，后两个本环境跑不了），
# 名字保留在这里只为能正确解析**历史报告**的 tool_calls，新扫描不会出现。
TOOL_NAMES_FOR_ATTRIBUTION = (
    "prefilter", "yara_scan", "pe_analyze", "signature_verify", "script_analyze",
    "office_macro_analyze", "strings_ioc", "hash_lookup", "vt_lookup", "clamav_scan",
    "capa_scan", "floss_scan", "shell_exec",
)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_.\-]{3,}|[\u4e00-\u9fff]{2,}")
# 「否定性签名断言」：工具/验签没说没有签名时，不许写这种话
SIGNATURE_DENIAL_RE = re.compile(
    r"(无|没有|缺少|未|不含)[^。；,，]{0,8}(数字签名|签名|Authenticode)"
    r"|unsigned|not\s+signed|no\s+(digital\s+)?signature|has_authenticode\s*[=:]\s*false",
    re.IGNORECASE,
)


def _claim_tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "")}


# 没有 source 的 claim 要按"这句话是谁说的"分开标：
#   走过 AI 的 → 模型推断（模型没给工具依据）；
#   没走 AI 的 → 确定性判定（规则/哈希/低分放行），压根没有模型参与，扣"模型推断"是错标签。
UNATTRIBUTED_LABEL_AI = "无工具输出支撑（模型推断）"
UNATTRIBUTED_LABEL_DETERMINISTIC = "确定性判定（规则档，未调用模型）"


# 送审提示词里给出的事实，作为证据溯源的一个**合法来源**。
# 理由：提示词里的 YARA 命中偏移/字节/上下文就是文件里的真实内容，
# AI 引用它是有依据的；把它和"凭空推断"混为一谈会让检查误报。
PROMPT_FACT_SOURCE = "送审事实"


def prompt_fact_texts(
    yara_details: Sequence[dict] | None,
    unavailable: Sequence[str] | None = None,
    extra_facts: Sequence[str] | None = None,
) -> list[str]:
    """把送审提示词里给出的事实拍平成可匹配的文本，供证据溯源使用。

    包含三部分，因为它们都是**提示词里明确写了的**：
      · YARA 命中位置与规则作者声明
      · 本次**未执行**的检测项 —— AI 说"ClamAV 没跑，所以这个维度没查"是有依据的，
        不该被标成"凭空推断"（对照 beenuar/AiSOC：缺上下文必须显式说明，
        说明它也是提示词给的）。
      · `extra_facts`：其它**写进了提示词**的事实（2026-09-27 起主要是预筛信号 ——
        它以前是伪装成一次 `prefilter` 工具调用进调用链的，现在直接进提示词事实表）。

    注意：**预采集的确定性工具输出不在这里** —— 它们以 `source=preload` 的条目进
    `deps.tool_calls`，走 `explicit` / `overlap` 两条常规溯源路径，
    和 AI 自己调用的工具输出享受同等待遇（这正是"证据前置"要的效果）。
    """
    facts: list[str] = []
    for d in yara_details or []:
        rule = str(d.get("rule") or "")
        if rule:
            facts.append(rule)
        for key in ("description", "benign_expectation", "tuning"):
            val = d.get(key)
            if val:
                facts.append(f"{rule} {val}")
        for inst in d.get("instances") or []:
            facts.append(
                f"{rule} {inst.get('identifier', '')} {inst.get('matched', '')} "
                f"偏移 {inst.get('offset', '')} {inst.get('context', '')}"
            )
    for item in unavailable or []:
        facts.append(f"未执行的检测 {item}")
    if unavailable:
        # 中文分词是按"连续汉字段"切的（见 _TOKEN_RE），所以「本环境未安装 ClamAV」
        # 和「未安装」对不上。这里把检测项名字单独聚成一条，让"我提到了 ClamAV/capa/
        # FLOSS/VT 但没跑"这类声明能对上 —— 名字是 ASCII 标识符，token 匹配稳定。
        names = [str(x).split("——")[0].strip() for x in unavailable]
        facts.append("未执行的检测 " + " ".join(n for n in names if n))
    for item in extra_facts or []:
        text = str(item)
        if text.strip():
            facts.append(text)
    return [f for f in facts if f.strip()]


def attribute_evidence(
    claims: Sequence[str],
    tool_calls: Sequence[dict] | None,
    agent_used: bool | None = None,
    prompt_facts: Sequence[str] | None = None,
) -> list[dict]:
    """把每条结论对到工具输出上，标注来源与原始输出片段。

    support 取值：
      explicit          结论里写明了工具名，且该工具这次真的被调用过
      explicit_name_only 写了工具名，但该工具这次没被调用（可疑）
      overlap           没写工具名，但与某次工具输出有 ≥2 个 token 重合
      prompt_fact       没对到工具，但对到了**送审提示词里给出的事实**（如 YARA 命中位置）
      unattributed      找不到任何工具支撑 —— 谁说的按 `agent_used` 分开标：
                        走过 AI 的算模型推断；没走 AI 的算确定性判定（规则档）。

    `agent_used` 省略时按"这次有没有工具调用"推断（有调用链 → 走过 AI）；
    调用方知情时应当显式传，别让"模型一句话没说"被误标成"模型推断"。
    """
    ai_ran = bool(tool_calls) if agent_used is None else bool(agent_used)
    fallback_label = UNATTRIBUTED_LABEL_AI if ai_ran else UNATTRIBUTED_LABEL_DETERMINISTIC
    calls = [(str(c.get("tool") or ""), str(c.get("summary") or "")) for c in (tool_calls or [])]
    facts = [str(f) for f in (prompt_facts or [])]
    out: list[dict] = []
    for claim in claims or []:
        text = str(claim)
        low = text.lower()
        source: str | None = None
        support = "unattributed"
        excerpt = ""
        named = [t for t in TOOL_NAMES_FOR_ATTRIBUTION if t in low]
        if named:
            source = named[0]
            support = "explicit_name_only"
            for tool, summary in calls:
                if tool == source:
                    excerpt, support = summary, "explicit"
                    break
        if source is None:
            claim_tokens = _claim_tokens(text)
            best = (0, "", "")
            for tool, summary in calls:
                inter = len(claim_tokens & _claim_tokens(summary))
                if inter > best[0]:
                    best = (inter, summary, tool)
            if best[0] >= 2:
                source, excerpt, support = best[2], best[1], "overlap"
        if source is None and facts:
            # 没对到工具，但可能对到了送审事实（YARA 命中位置/规则声明）
            claim_tokens = _claim_tokens(text)
            best_fact = (0, "")
            for fact in facts:
                inter = len(claim_tokens & _claim_tokens(fact))
                if inter > best_fact[0]:
                    best_fact = (inter, fact)
            if best_fact[0] >= 2:
                source, excerpt, support = PROMPT_FACT_SOURCE, best_fact[1], "prompt_fact"
        out.append({
            "claim": text,
            "source": source or fallback_label,
            "support": support,
            "raw_excerpt": (excerpt or "")[:600],
        })
    return out


def find_claim_warnings(claims: Sequence[str], evidence: PreliminaryEvidence) -> list[str]:
    """找出与确定性证据冲突、或没有工具支撑的断言（当前专盯『无签名』）。"""
    warnings: list[str] = []
    signature = (evidence.signature or {}) if evidence else {}
    status = str(signature.get("status") or "unknown").lower()
    for claim in claims or []:
        text = str(claim)
        if SIGNATURE_REWORD_SUFFIX in text:
            continue      # 已经过落库前守卫降级+留痕，不再重复算作冲突
        if not SIGNATURE_DENIAL_RE.search(text):
            continue
        if status == "valid":
            warnings.append(
                "[证据冲突] 结论声称『无签名』，但确定性验签为 Valid"
                f"（类型={signature.get('signature_type')}，签发者={signature.get('signer')}）：{text[:160]}"
            )
        elif status in ("", "unknown"):
            warnings.append(
                f"[无支撑断言] 结论声称『无签名』，但没有任何工具给出签名结论（不得据此断言缺失）：{text[:160]}"
            )
    seen: set[str] = set()
    uniq: list[str] = []
    for w in warnings:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    return uniq


SIGNATURE_REWORD_SUFFIX = "（签名状态未知：本次未完成 Windows 验签，不能据此断言『无签名』）"


def find_autonomy_warnings(sources: Sequence[dict]) -> list[str]:
    """AI 档硬约束：结论必须至少有一条有依据 —— 工具输出或送审事实。

    判定权交给 AI 的前提是它没在空转。如果全部结论都 `unattributed`，说明它既没取证、
    也没引用送审提示词里给出的事实，只可能是凭空推断，必须标出来。

    `prompt_fact` 算合格来源：送审提示词里的 YARA 命中偏移/字节/上下文就是文件里的真实
    内容，引用它是有依据的（对照 beenuar/AiSOC 的做法：平台预取上下文，agent 消费它，
    而不是自己去发发现类调用）。但**光复述送审理由不算干活** —— 那种情况会被
    `find_repetition_warnings` 单独标出来。
    """
    if not sources:
        return []
    if any(str(s.get("support")) in ("explicit", "overlap", "prompt_fact") for s in sources):
        return []
    return [f"未自主取证：{len(sources)} 条结论没有一条能对到 AI 自己调用的工具输出或送审事实"]


def find_repetition_warnings(
    sources: Sequence[dict],
    tool_calls: Sequence[dict] | None,
) -> list[str]:
    """AI 只复述送审理由、没做自己的取证时标出来。

    送审理由（YARA 命中位置、脚本特征）是"为什么叫你"，把它换个说法写进 evidence
    不算完成了分析。这正是旧的「复读机」问题 —— 实测：提示词里本来就有 YARA 命中，
    AI 还是调了 8 次 `yara_scan` 把同一批命中复述一遍。

    与 `find_autonomy_warnings` 的分工：那个管"完全没依据"，这个管"有依据但依据全是
    送审理由、自己一次都没取证"。

    2026-09-27 口径调整（证据前置）：预采集的确定性工具输出以 `source=preload` 进
    `deps.tool_calls`，溯源结果同样是 `explicit` / `overlap` —— 也就是**引用预采集证据
    算"有依据"**，不再逼 AI 去把工具重跑一遍。这个警告因此只在"结论全部落在预筛理由
    （YARA 命中这类"为什么叫你"）上"时才响，与设计意图一致。
    """
    if not sources:
        return []
    own = [s for s in sources if str(s.get("support")) in ("explicit", "overlap")]
    if own:
        return []
    if not any(str(s.get("support")) == "prompt_fact" for s in sources):
        return []          # 全无依据的情况由 find_autonomy_warnings 负责，不重复报
    ai_calls = ai_tool_calls(tool_calls)
    return [
        f"只复述送审理由：{len(sources)} 条结论全部来自提示词给定的事实，"
        f"没有一条对到自己取证的工具输出（本次 AI 实际调用工具 {len(ai_calls)} 次）"
    ]


def apply_claim_guard(
    verdict: Verdict,
    evidence: PreliminaryEvidence,
    audit: list[dict] | None = None,
) -> tuple[list[str], int]:
    """落库前的一致性守卫：验签 unknown/未采集时，禁止把「无签名」写进结论。

    与 `find_claim_warnings` 的分工：
      · find_claim_warnings 只**标出来**（校验用）；
      · 本守卫负责**改写措辞 + 留痕**，保证有冲突措辞的断言不流入报告正文。

    行为：
      · 验签 status=valid  → 不动（冲突已由 find_claim_warnings 记为「证据冲突」）
      · status=notsigned   → 不动（工具确实判定"未签名"，此时断言合法）
      · unknown / 未采集    → 在原句后追加降级说明，并记一条 `[措辞降级]` 告警 + 审计条目
    幂等：已追加过降级说明的句子不再重复追加。
    """
    sig = (evidence.signature or {}) if evidence else {}
    status = str(sig.get("status") or "unknown").lower()
    if status in ("valid", "notsigned"):
        return [], 0

    warnings: list[str] = []
    actions = audit if audit is not None else []
    rewritten: list[str] = []
    changed = 0
    for claim in verdict.evidence or []:
        text = str(claim)
        if SIGNATURE_DENIAL_RE.search(text) and SIGNATURE_REWORD_SUFFIX not in text:
            rewritten.append(text + SIGNATURE_REWORD_SUFFIX)
            warnings.append(
                "[措辞降级] 原断言含『无签名』类措辞，但验签状态为 "
                f"{status or 'unknown'}（不构成签名缺失的证据），已降级为『签名状态未知』：{text[:160]}"
            )
            changed += 1
        else:
            rewritten.append(text)
    if changed:
        verdict.evidence = rewritten
        actions.append({
            "actor": "claim_guard", "action": "reword", "from": f"{changed} 条断言",
            "to": "签名状态未知", "basis": "consistency_guard: signature status unknown",
            "detail": "验签未完成时禁止断言『无签名』；原句保留并追加降级说明",
        })
    return warnings, changed


PACKER_ONLY_REASON_PREFIXES = ("高风险扩展名:", "疑似加壳:", "弱 YARA 命中:")


def packer_only_downgrade(
    verdict: Verdict,
    evidence: PreliminaryEvidence,
    packing: dict | None,
    audit: list[dict] | None = None,
    record_only: bool = False,
) -> Verdict:
    """「仅因加壳就判可疑」的确定性纠正（2026-09-19 修复项）。

    背景：良性加壳程序（UPX 等）在静态下信息极少，模型倾向"稳妥起见判可疑" ——
    实测一组良性 UPX 样本被稳定误报（见 `docs/STABILITY_GRAY_ZONE.md` §3、`docs/PACKER_HANDLING.md`）。
    加壳在合法软件里极其常见，**加壳本身不是恶意证据**：只有"脱壳后载荷达到恶意"或
    "存在其它非加壳信号（YARA/哈希/容器/脚本特征…）"才允许把结论停在可疑/恶意。

    规则：
      · 只对 `suspicious` 生效（`malicious` 不动，避免放过真恶意）；
      · 排除强信号（EICAR / 已知哈希 / 高置信 YARA）；
      · 非加壳信号必须为空（把"高风险扩展名 / 疑似加壳 / 弱 YARA"这三类非定性理由剔除后无剩余）；
      · 载荷已脱壳且判为 **clean** → 降级为 `clean`，但 `recommended_action=review` 并留审计（供人工复核）；
      · 载荷判为 **suspicious / malicious** → **不降级**（"脱壳后载荷可疑"已经是加壳之外的证据，
        实测踩过：条件写宽成"载荷未达恶意"时，一个恶意 UPX 样本被判成 clean —— 该分支必须有单测盯住）；
      · 载荷未判（没脱壳/非 UPX 壳）→ 保留 `suspicious`，但把置信度压到 ≤0.35 并标注
        "仅因加壳，低置信"（这一步不改风险级别，只改可信度与说明）。

    **审计链（record_only 档）**：只要文件确实加壳、AI 又把它判成可疑，策略的反对意见
    就必须**同时**进 `policy_proposals`（报告"策略提议"栏）与审计链 —— 与 `enforce_policy._emit`
    对齐。旧实现只有走到函数末尾的那条分支才写 `policy_proposals`，前四条 `return` 直接返回，
    于是"策略认为仅凭加壳不足以定性"这条**最需要人复核**的分歧沉在 `policy_actions` 里，
    报告的"策略提议"栏看不见 —— 直接违背 README「判决可溯源」的声明。

    `AI_AV_PACKER_ONLY_DOWNGRADE=0` 可关闭（消融/对照实验用）。
    """
    if os.getenv("AI_AV_PACKER_ONLY_DOWNGRADE", "1").lower() in ("0", "false", "no"):
        return verdict

    actions = audit if audit is not None else []
    before = verdict.risk.value
    packed = bool((packing or {}).get("packed")) or any(
        str(r).startswith("疑似加壳:") for r in (evidence.reasons or []))

    def _propose(proposed: str, basis: str, detail: str, disagreement: bool) -> None:
        """record_only 档记一条提案：审计链 + `verdict.policy_proposals`（报告可见）。

        只在**确实加壳**时才记 —— 没加壳的文件根本没进这条策略的射程，
        记"反对意见"会变成无依据的噪音（`test_non_packed_file_untouched` 盯着这条）。
        """
        if not (record_only and packed):
            return
        entry = {
            "actor": "packer_policy", "action": "proposal",
            "from": before, "to": before, "proposed": proposed,
            "basis": basis, "detail": detail,
            "applied": False, "disagreement": disagreement,
        }
        actions.append(entry)
        verdict.policy_proposals = list(verdict.policy_proposals) + [
            {k: v for k, v in entry.items() if k != "action"}]

    if verdict.risk != RiskLevel.suspicious:
        return verdict
    if evidence.eicar or evidence.known_bad_hash:
        strong = "EICAR 测试文件" if evidence.eicar else "命中本地已知恶意哈希库"
        _propose("keep", f"packer_only: 存在强信号（{strong}），策略不介入",
                 f"packer={packing.get('packer')}; 强信号={strong}; AI 定级 {before} 未改动",
                 disagreement=False)
        return verdict
    if any(h in HIGH_CONFIDENCE_YARA_RULES for h in (evidence.yara_hits or [])):
        _propose("keep", "packer_only: 命中高置信恶意 YARA，策略不介入",
                 f"packer={packing.get('packer')}; yara={evidence.yara_hits}; AI 定级 {before} 未改动",
                 disagreement=False)
        return verdict

    other_signals = [
        r for r in (evidence.reasons or [])
        if not str(r).startswith(PACKER_ONLY_REASON_PREFIXES)
    ]
    if not packed:
        return verdict
    if other_signals:
        # 加壳 + 其它信号 → 不属于"仅因加壳"，策略不改判；但分歧仍要进报告：
        # 策略认为**单凭加壳不足以定性**，而这次定级还额外依赖了别的信号。
        _propose("keep",
                 "packer_only: 加壳之外还有其它信号，仅凭加壳不足以定性（本次定级不依赖加壳）",
                 f"packer={packing.get('packer')}; 其它信号={'; '.join(str(s) for s in other_signals[:3])}",
                 disagreement=True)
        return verdict

    unpack = ((packing or {}).get("unpack") or {})
    payload_risk = unpack.get("verdict")
    if record_only:
        # 判决权归 AI：AI 判可疑是它自己的结论，策略只记录"我认为仅凭加壳不足以定性"，
        # 不改风险级别（置信度调整也不做 —— 那同样是在改 AI 的结论强度）。
        _propose(("keep_low_confidence" if payload_risk not in
                  (RiskLevel.clean.value, RiskLevel.suspicious.value,
                   RiskLevel.malicious.value)
                  else "keep"),
                 "packer_only: 仅命中加壳特征、无非加壳信号（加壳本身不是恶意证据）",
                 f"packer={packing.get('packer')} payload={payload_risk}; "
                 f"AI 置信度 {verdict.confidence} 未改动",
                 disagreement=False)
        return verdict
    if payload_risk == RiskLevel.clean.value:
        verdict.risk = RiskLevel.clean
        verdict.confidence = min(verdict.confidence, 0.6)
        verdict.recommended_action = "review"
        verdict.evidence = list(dict.fromkeys(list(verdict.evidence) + [
            f"[策略] 仅命中加壳特征（{packing.get('packer') or '未识别壳'}），"
            f"脱壳载荷判定 {payload_risk}（未达恶意）→ 不再因加壳判可疑；建议人工复核",
        ]))
        actions.append({
            "actor": "packer_policy", "action": "downgrade", "from": before,
            "to": verdict.risk.value,
            "basis": "packer_only: 加壳本身不是恶意证据，脱壳载荷未达恶意",
            "detail": f"packer={packing.get('packer')} payload={payload_risk}",
        })
    elif payload_risk in (RiskLevel.suspicious.value, RiskLevel.malicious.value):
        actions.append({
            "actor": "packer_policy", "action": "keep", "from": before, "to": before,
            "basis": "packer_only: 但脱壳载荷本身可疑 —— 这已不是「仅因加壳」，保持原判",
            "detail": f"packer={packing.get('packer')} payload={payload_risk}",
        })
    else:
        verdict.confidence = min(verdict.confidence, 0.35)
        verdict.evidence = list(dict.fromkeys(list(verdict.evidence) + [
            f"[策略] 仅命中加壳特征（{packing.get('packer') or '未识别壳'}）、载荷未判出 → 保留可疑但降为低置信",
        ]))
        actions.append({
            "actor": "packer_policy", "action": "low_confidence", "from": before,
            "to": verdict.risk.value, "basis": "packer_only: 载荷未判出，仅凭加壳不足以定性",
            "detail": f"packer={packing.get('packer')} confidence→{verdict.confidence}",
        })
    return verdict


def enforce_policy(
    verdict: Verdict,
    evidence: PreliminaryEvidence,
    audit: list[dict] | None = None,
    record_only: bool = False,
) -> Verdict:
    """确定性策略层：**判决权归 AI**，这一层只做「表达意见 + 留痕」。

    两种工作模式（由 `record_only` 决定）：

    · `record_only=True`（**有 AI 结论的线上档**）：本函数**绝不改动 verdict.risk**。
      规则/YARA/预筛照跑，作用是「给证据 + 提速」；它们与 AI 结论不一致时，把
      「策略本来想做什么」原样写进 `verdict.policy_proposals`（`applied=False`）
      和审计链（`action="proposal"`），报告里能看到"规则和 AI 到底同不同意"。
      这就是「AI 是判决者」的落点：最终 risk 只能由 AI 自主下。

    · `record_only=False`（**纯规则档 / AI 不可用**）：保留旧的确定性兜底语义 ——
      没有人能判决时才由规则判决。抬升仍**只允许来自强信号**：
        1) EICAR 测试文件 / 本地已知恶意哈希库命中 → malicious
        2) 高置信恶意 YARA 规则（`tools.HIGH_CONFIDENCE_YARA_RULES`）→ suspicious
      泛化 YARA 子串与「预筛分数 ≥ 12」这类通用启发式**不抬升**，只作送 AI 复核的理由
      （旧实现会把 AI 的 clean 顶回 suspicious：实测 doclient.dll / cmdl32.exe /
      en-GB.pak 三个微软签名文件因此产生不可平反的误报）。
      反向：Windows 验签 Valid + 签发者可信 + 无强信号时，suspicious → clean
      （`AI_AV_TRUSTED_SIGNER_DOWNGRADE=0` 可关闭）。

    无论哪种模式，强信号本身**不丢**：`record_only` 下会把强信号作为证据行写进结论，
    由 AI 的复卷与人工复核去消化，而不是由策略越权改判。
    """
    actions = audit if audit is not None else []
    threat_yara = [h for h in evidence.yara_hits if h in HIGH_CONFIDENCE_YARA_RULES]
    heuristic_yara = [
        h for h in evidence.yara_hits
        if h not in HIGH_CONFIDENCE_YARA_RULES and h not in WEAK_YARA_RULES
    ]
    before = verdict.risk.value
    target = verdict.risk          # 提议生效后的定级（record_only 下不改 verdict）

    def _emit(proposed: str, new_risk: RiskLevel | None, basis: str, detail: str,
              evidence_lines: Sequence[str] = ()) -> None:
        """记一条提案：record_only 只写审计、不改判；否则照旧生效。"""
        if record_only:
            to = (new_risk.value if new_risk is not None else before)
            entry = {
                "actor": "enforce_policy", "action": "proposal", "from": before, "to": to,
                "proposed": proposed, "basis": basis, "detail": detail,
                "applied": False, "disagreement": to != before,
            }
            actions.append(entry)
            verdict.policy_proposals = list(verdict.policy_proposals) + [
                {k: v for k, v in entry.items() if k != "action"}]
            if evidence_lines:
                # 强信号不许丢：记录成证据行，交给 AI 复卷/人工复核消化
                verdict.evidence = list(dict.fromkeys(list(verdict.evidence) + list(evidence_lines)))
            return
        if new_risk is not None:
            verdict.risk = new_risk
            target = new_risk
        actions.append({
            "actor": "enforce_policy", "action": proposed, "from": before,
            "to": (new_risk.value if new_risk is not None else before),
            "basis": basis, "detail": detail,
        })

    # ---- 1) 强信号：EICAR / 已知恶意哈希 → malicious ----
    if evidence.eicar or evidence.known_bad_hash:
        basis = "EICAR 测试文件" if evidence.eicar else "命中本地已知恶意哈希库"
        if not record_only:
            verdict.confidence = max(verdict.confidence, 0.99)
            verdict.evidence = list(dict.fromkeys(verdict.evidence + evidence.reasons))
            verdict.recommended_action = "isolate"
        _emit("escalate", RiskLevel.malicious, f"strong_signal: {basis}",
              "; ".join(evidence.reasons[:4]),
              evidence_lines=[f"[强信号] {basis}（规则层检出，最终定级仍由 AI 自主作出）"])
        return verdict

    # ---- 2) 强信号：高置信恶意 YARA ----
    if threat_yara:
        if not record_only:
            verdict.confidence = max(verdict.confidence, 0.6)
            verdict.evidence = list(dict.fromkeys(
                verdict.evidence + ["YARA 命中（高置信）: " + ", ".join(threat_yara)]))
            verdict.recommended_action = "review"
        _emit("escalate", RiskLevel.suspicious, "strong_signal: 高置信恶意 YARA",
              ", ".join(threat_yara),
              evidence_lines=["[强信号] YARA 命中（高置信）: " + ", ".join(threat_yara)])

    # ---- 3) 通用启发式：只作送 AI 复核的理由 ----
    if record_only or verdict.risk == RiskLevel.clean:
        if heuristic_yara or evidence.prefilter_score >= SUSPICIOUS_SCORE_THRESHOLD:
            _emit("no_escalation", None,
                  "heuristic_signal: 通用 YARA/预筛分数（2026-09-19 起不再抬升定级）",
                  f"score={evidence.prefilter_score}; "
                  f"yara={heuristic_yara or list(evidence.yara_hits)}")

    # ---- 4) 可信签名 + 无强信号：旧语义降级 / 新语义记录反对意见 ----
    signature = evidence.signature or {}
    trusted = bool(signature.get("trusted_signer"))
    downgrade_enabled = os.getenv("AI_AV_TRUSTED_SIGNER_DOWNGRADE", "1").lower() not in ("0", "false", "no")
    if trusted and downgrade_enabled and not threat_yara:
        if record_only:
            if before != RiskLevel.clean.value:
                denial = [c for c in verdict.evidence if SIGNATURE_DENIAL_RE.search(str(c))]
                _emit("downgrade", RiskLevel.clean,
                      "trusted_signature: Windows 验签 Valid + 可信签发者 + 无强信号",
                      (f"被否定的模型断言: {str(denial[0])[:160]}" if denial else ""))
        elif verdict.risk == RiskLevel.suspicious:
            denial = [c for c in verdict.evidence if SIGNATURE_DENIAL_RE.search(str(c))]
            verdict.recommended_action = "ignore"
            verdict.evidence = list(dict.fromkeys(verdict.evidence + [
                "[策略] 通过 Windows 验签（Valid"
                f"{'/' + str(signature.get('signature_type')) if signature.get('signature_type') else ''}"
                f"，签发者 {signature.get('signer')}），且无强信号，suspicious → clean"
            ]))
            _emit("downgrade", RiskLevel.clean,
                  "trusted_signature: Windows 验签 Valid + 可信签发者 + 无强信号",
                  (f"被否定的模型断言: {str(denial[0])[:160]}" if denial else ""))

    return verdict



def _signature_check_enabled(agent_present: bool) -> bool:
    """签名证据块要不要采集（纯 Python 验签，约 0.5s/文件，结果按 mtime 缓存）。

    2026-09-27 起签名不只是"给 AI 看的证据"，它自己就是一条**确定性结案判据**
    （`DET_TRUSTED_SIGNATURE`：签名有效且签发者可信 → 判干净、不送 AI）。
    所以 `auto` 模式下除了"会进 AI"之外，**只要①层要出结论**就该采。

    AI_AV_SIGNATURE_CHECK 三档：
      `auto`（默认）  会进 AI，或开了①层结案（默认开）→ 采
      `1`             纯规则扫描也采（全量机器扫描会明显变慢，0.5s/文件）
      `0`             一律不采（这一档下 `DET_TRUSTED_SIGNATURE` 永远不命中，
                      送审率会明显变高 —— 报告里必须写清是哪一档）
    """
    mode = os.getenv("AI_AV_SIGNATURE_CHECK", "auto").strip().lower()
    if mode in ("0", "false", "no", "off"):
        return False
    if mode in ("1", "true", "yes", "on"):
        return True
    return agent_present or os.getenv("AI_AV_DETERMINISTIC_CLOSE", "1").strip().lower() not in (
        "0", "false", "no", "off"
    )


def _risk_rank(risk: RiskLevel) -> int:
    return {RiskLevel.clean: 0, RiskLevel.suspicious: 1, RiskLevel.malicious: 2}[risk]


def _collect_preload(path: Path, sha256: str, evidence: PreliminaryEvidence,
                     deep: bool = True, threshold: int = 0) -> dict:
    """确定性证据前置的入口（可关：`AI_AV_PRELOAD=0` 退回"全靠 AI 自己调"）。

    关掉时也返回一份**结构完整**的结果 —— 报告里的 `evidence_preload` 不能因为
    "没采集"就变成空对象，那样读报告的人分不清"关掉了"和"采了但没东西"。

    `deep=False` = 分流·取证层（B 档）：capa/floss 适用但按策略跳过，只采轻量证据。
    """
    if not preload_enabled():
        return {
            "kind": detect_kind(path), "tools": [], "entries": [], "calls": [],
            "skipped": ["全部工具（预采集已关闭：AI_AV_PRELOAD=0，证据由 AI 自己按需调用）"],
            "chars": 0, "elapsed_ms": 0.0, "truncated": False, "budget_note": "",
            "policy": "disabled", "deep_forensics": "disabled", "deep_note": "",
        }
    return collect_preload(path, sha256, evidence.signature,
                           deep=deep, score=evidence.prefilter_score, threshold=threshold)


def merge_retry_infos(infos: list[dict]) -> dict:
    """把多次采样各自的模型调用留痕合并成一条报告字段。

    口径：`attempts` 取各样本之和（一共发了几次请求），`retried` 任一为真即真
    （只要有一条结论是重试拿到的，这次判定就该标"用过重试"），
    `outcome` 任一降级即降级 —— 采样里有一路掉到规则判定，就不能说"全是 AI 判的"。
    """
    infos = [i for i in infos if i]
    if not infos:
        return {}
    if len(infos) == 1:
        return infos[0]
    failures = [f for i in infos for f in (i.get("failures") or [])]
    return {
        "attempts": sum(int(i.get("attempts") or 0) for i in infos),
        "max_attempts": sum(int(i.get("max_attempts") or 0) for i in infos),
        "retried": any(i.get("retried") for i in infos),
        "retry_count": sum(int(i.get("retry_count") or 0) for i in infos),
        "outcome": ("degraded_to_rules" if any(
            i.get("outcome") == "degraded_to_rules" for i in infos) else "ok"),
        "final_error": next((i.get("final_error") for i in infos
                             if i.get("outcome") == "degraded_to_rules"), None),
        "failures": failures,
        "policy": infos[0].get("policy") or {},
        "samples": len(infos),
        "per_sample_outcome": [i.get("outcome") for i in infos],
    }


def _degrade_note(exc: BaseException, retry: dict) -> str:
    """降级说明：**必须写清试了几次、重试了几次、为什么停**。

    旧实现只有一句 `Agent 调用失败，已降级到规则判断: <err>` —— 读报告的人看不出
    这是"一次过就失败"还是"重试两次都失败"，也看不出底下那条 clean 是规则给的。
    """
    attempts = int(retry.get("attempts") or 0)
    max_attempts = int(retry.get("max_attempts") or 0)
    retry_count = int(retry.get("retry_count") or 0)
    kinds = sorted({f.get("kind", "?") for f in (retry.get("failures") or [])})
    if attempts <= 1 and not retry_count:
        how = "未重试（首次调用即失败"
        how += "，错误判定为不可重试" if kinds and kinds != ["?"] else ""
        how += "）"
    else:
        how = f"已尝试 {attempts}/{max_attempts} 次（重试 {retry_count} 次）后放弃"
    detail = f"；错误类型: {', '.join(kinds)}" if kinds else ""
    return (f"Agent 调用失败，已降级到规则判定（{how}{detail}）：{exc}"
            f" —— 本条 risk 由规则/启发式给出，不是 AI 结论")


def merge_sampled_verdicts(verdicts: list[Verdict]) -> tuple[Verdict, dict]:
    """多次采样的结论合并：多数票；平票取更严的一档。

    返回 (合并后的 Verdict, 采样统计)。采样统计进报告，用来量化"判定稳定性"：
    `agreement` 越低说明模型在该文件上越不稳，评审时可直接说"这个文件 5 次里 3 次判可疑"。
    """
    if not verdicts:
        raise ValueError("verdicts 不能为空")
    if len(verdicts) == 1:
        return verdicts[0], {"samples": 1, "votes": {verdicts[0].risk.value: 1},
                             "agreement": 1.0, "tie_break": False, "winner": verdicts[0].risk.value,
                             "per_sample": [verdicts[0].risk.value]}
    counts: dict[RiskLevel, int] = {}
    for v in verdicts:
        counts[v.risk] = counts.get(v.risk, 0) + 1
    top = max(counts.values())
    tied = [risk for risk, c in counts.items() if c == top]
    winner = max(tied, key=_risk_rank)          # 平票取更严
    winners = [v for v in verdicts if v.risk == winner]
    representative = max(winners, key=lambda v: v.confidence)
    merged = representative.model_copy(deep=True)
    merged.confidence = round(sum(v.confidence for v in winners) / len(winners), 3)
    merged.evidence = list(dict.fromkeys(
        [e for v in verdicts for e in (v.evidence or [])]))
    votes = {r.value: c for r, c in sorted(counts.items(), key=lambda kv: -kv[1])}
    merged.summary = (f"{representative.summary}（{len(verdicts)} 次采样，{top}/{len(verdicts)} 一致，"
                      f"票型 {votes}）")
    stats = {
        "samples": len(verdicts),
        "votes": votes,
        "agreement": round(top / len(verdicts), 3),
        "tie_break": len(tied) > 1,
        "winner": winner.value,
        "per_sample": [v.risk.value for v in verdicts],
    }
    return merged, stats


def _agent_samples() -> int:
    try:
        n = int(os.getenv("AI_AV_AGENT_SAMPLES", "1"))
    except ValueError:
        n = 1
    return max(1, min(n, 5))


def _archives_enabled() -> bool:
    return os.getenv("AI_AV_ARCHIVES", "1").strip().lower() not in ("0", "false", "no", "off")


def _archive_ai_children_cap() -> int:
    """容器样本里最多几个**内嵌子样本**可以送 AI（默认 3）。

    背景（2026-09-20 成本实测）：`.docm/.xlsm` 就是 ZIP，会被 `detect_archive()` 当成压缩包递归，
    默认 `AI_AV_ARCHIVE_MAX_CHILDREN=20` → 一个 docm 最多起 **21 次完整 agent**
    （父文件 1 + 子样本 20），实测 docm 单文件成本是普通样本的 **12~18 倍**，
    而**这些子样本的 AI 结论改不了父文件 risk**（判决权归 AI 之后只能记为 proposal + 一条证据行，
    见本文件末尾的 archive 段）。也就是说那部分是"没有判决权重"的开销。

    做法：按**可疑度（预筛分）降序**排序后只把前 N 个送 AI —— 保留最可疑的，
    砍掉成批的零分子样本（实测某 docm 的 36 个子样本**没有一个**达到预筛阈值）。
    想回到旧行为：`AI_AV_ARCHIVE_AI_CHILDREN=0`（不限）。
    """
    try:
        raw = int(os.getenv("AI_AV_ARCHIVE_AI_CHILDREN", "3"))
    except ValueError:
        raw = 3
    return raw if raw > 0 else 10 ** 9      # ≤0 视为不限


def _unpack_escalate_from() -> RiskLevel:
    """脱壳载荷要在什么级别才允许抬升父文件定级。

    默认 `malicious`：实测（2026-09-19）6 个**良性** UPX 样本的载荷都被 AI 判 suspicious，
    若按 suspicious 抬升，父文件会被整体推成可疑（误报）；而 6 个恶意样本的载荷也大多是
    suspicious，父文件本身已被 AI 判 suspicious/malicious，不抬升也不丢召回。
    想回到旧行为：AI_AV_UNPACK_ESCALATE_FROM=suspicious。
    """
    raw = os.getenv("AI_AV_UNPACK_ESCALATE_FROM", "malicious").strip().lower()
    return {"suspicious": RiskLevel.suspicious, "clean": RiskLevel.clean}.get(raw, RiskLevel.malicious)


def _unpack_enabled() -> bool:
    return os.getenv("AI_AV_UNPACK", "1").strip().lower() not in ("0", "false", "no", "off")


def scan_file(
    path: Path,
    agent: Agent | None = None,
    ai_threshold: int = AI_GATE,
    store: StateStore | None = None,
    allow_unpack: bool = True,
    agent_samples: int | None = None,
    allow_archives: bool = True,
    cache: "ScanCache | None" = None,
    budget: TokenBudget | None = None,
    deterministic: bool = True,
    deep_evidence_threshold: int | None = None,
    clamav_batch: Mapping[str, Any] | None = None,
) -> FileReport:
    """扫描单个文件。

    `deterministic=False` 是**消融/研究用**开关：关掉全部确定性后处理
    （策略兜底 `enforce_policy` + 脱壳载荷抬升 + 压缩包最严者抬升），
    最终结论完全等于模型原始输出（壳内载荷/子样本仍会被扫描，只是不参与定级）。
    线上默认 `True`；消融实验靠它隔离"确定性层"的边际贡献，见 `docs/ABLATION.md`。

    `deep_evidence_threshold` 是**分流·取证层**（2026-09-27）：预筛分数 < 它的文件
    只采轻量证据，不跑 capa/floss。`None` 时读环境变量（默认 0 = 不分流，全部深挖）。

    `clamav_batch` 是 `tools.clamav_scan_batch(files)` 的返回值：**整批只起一次 clamscan**
    的 ClamAV 结果，①层查表用。不传 = 单文件兜底（每次重新加载库，6.3 s/文件）。
    """
    try:
        sha256 = compute_sha256(path)
    except OSError as exc:
        # 「读不了」不等于「安全」：文件可能被占用、被权限挡住，或被安全软件实时防护拦截
        # （Windows 上读 EICAR 就会拿到 Errno 22）。这种文件必须交人工复核，不能静默判 clean。
        return FileReport(
            path=str(path),
            sha256="",
            size=0,
            extension=path.suffix.lower(),
            prefilter_score=0,
            verdict=Verdict(
                risk=RiskLevel.suspicious,
                confidence=0.0,
                category="unreadable",
                summary=f"无法读取文件（可能被占用、无权限或被安全软件拦截），无法判定：{exc}",
                evidence=[f"读取失败: {type(exc).__name__}: {exc}"],
                recommended_action="review",
            ),
            error=str(exc),
            policy_actions=[{
                "actor": "scan_file", "action": "no_escalation",
                "from": "unknown", "to": RiskLevel.suspicious.value,
                "basis": "read_error: 无法读取即无法排除，按需人工复核处理（不判 clean）",
                "detail": f"{type(exc).__name__}: {exc}",
            }],
        )

    # ---- 处置闭环第一步：白名单（同 sha256 不再送 AI、不再报可疑，省 token 也省噪音）----
    try:
        store = store or default_store()
    except Exception:  # noqa: BLE001 - 状态目录不可用时不影响扫描
        store = None
    if store is not None:
        try:
            wl = store.whitelist_lookup(sha256)
        except Exception:  # noqa: BLE001
            wl = None
        if wl:
            return FileReport(
                path=str(path),
                sha256=sha256,
                size=path.stat().st_size if path.exists() else 0,
                extension=path.suffix.lower(),
                prefilter_score=0,
                verdict=Verdict(
                    risk=RiskLevel.clean,
                    confidence=1.0,
                    category="whitelisted",
                    summary=f"已在白名单，跳过研判（理由：{wl.get('reason') or '未填写'}）",
                    evidence=[f"whitehash={sha256[:16]}…", f"加入时间={wl.get('added_at')}"],
                    recommended_action="ignore",
                ),
                agent_used=False,
                disposition={"status": "whitelisted", "reason": wl.get("reason", ""),
                             "added_at": wl.get("added_at", "")},
            )
        # 之前隔离过的同一内容，报告里标出来（不重复处置）
        try:
            prev = store.find(sha256)
        except Exception:  # noqa: BLE001
            prev = None
    else:
        prev = None

    # ---- 断点续扫：命中缓存就直接复用分析结论（处置状态仍按当下重算）----
    if cache is not None:
        scan_cache = cache
    elif cache_enabled():
        # 缓存目录跟随状态目录：不同 --state-dir 之间不许串味（实测踩过跨 store 命中）
        scan_cache = (ScanCache(root=Path(store.root) / "cache", store_root=Path(store.root))
                      if store is not None else ScanCache())
    else:
        scan_cache = None
    if scan_cache is not None:
        requested_samples = agent_samples if agent_samples is not None else _agent_samples()
        cached = scan_cache.get(sha256, agent_available=agent is not None,
                                samples=requested_samples,
                                unpack=allow_unpack and _unpack_enabled(),
                                archives=allow_archives and _archives_enabled(),
                                deterministic=deterministic)
        if cached:
            fresh_disp = ({"status": "previously_quarantined", "id": prev.get("id")}
                          if prev and prev.get("status") == "quarantined" else {})
            return report_from_cache(cached, path=path, disposition=fresh_disp)

    # 是否走 AI：决定要不要先采集确定性签名证据块
    evidence = quick_prefilter(
        path, sha256, with_signature=_signature_check_enabled(agent is not None),
        clamav_batch=clamav_batch,
    )

    # 分流·取证层阈值（2026-09-27）：≤0 = 不分流（全部文件都跑 capa/floss，旧行为）。
    # 由 `--deep-evidence-threshold` / `AI_AV_DEEP_EVIDENCE_THRESHOLD` 设定。
    deep_threshold = (deep_evidence_threshold if deep_evidence_threshold is not None
                      else preload_deep_threshold())

    # 确定层直接结案，不消耗 API（消融三档里都一样，实验单独统计短路文件数）。
    #
    # ⚠️ 2026-09-24 实测教训：**短路集合只允许放"身份"信号，不允许放"特征"信号。**
    # 本轮曾把 `HIGH_CONFIDENCE_YARA_RULES` 也加进短路，结果 `data/rules/demo.yar`
    # （我们自己的规则文件，因为定义了 EICAR 规则而含有 EICAR 模式串）被自己的规则命中，
    # 短路后判 suspicious —— 而送 AI 时它会被正确平反成 clean。
    # 结论：SHA256 精确匹配 = 这个文件**就是**那个恶意样本，语境无法改变它；
    # 而字符串/规则命中 = 这个文件**含有**某种特征，规则文件、安全工具源码、测试样本
    # 都会命中，只有语境能定性 —— 那正是"第二意见"要干的活，不能短路掉。
    # （EICAR 保留短路：完整测试标记是标准测试产物，不属于"特征命中"这一类。）
    # 确定性结案短路（2026-09-27）：判恶意（哈希/EICAR/AV 库）与判干净（签名可信/白名单）
    # 都**不送 AI** —— 这是送审率的主要闸门。旧实现只短路 eicar/known_bad_hash 两条。
    if (evidence.deterministic or {}).get("disposition") in ("closed_malicious", "closed_clean"):
        audit: list[dict] = []
        verdict = heuristic_verdict(evidence)
        if deterministic:
            verdict = enforce_policy(verdict, evidence, audit)
        return FileReport(
            path=str(path),
            sha256=sha256,
            size=evidence.size,
            extension=evidence.extension,
            prefilter_score=evidence.prefilter_score,
            prefilter_reasons=evidence.reasons,
            yara_hits=evidence.yara_hits,
            criteria_hits=evidence.criteria_hits,
            unclassified_signals=evidence.unclassified_signals,
            deterministic=evidence.deterministic,
            clamav=evidence.clamav,
            verdict=verdict,
            agent_used=False,
            policy_actions=audit,
            evidence_sources=attribute_evidence(verdict.evidence, [], agent_used=False),
            disposition=({"status": "previously_quarantined", "id": prev.get("id")}
                         if prev and prev.get("status") == "quarantined" else {}),
        )

    agent_used = False
    # 判决权归 AI：这一轮定级是不是 AI 自主下的？是 → 任何确定性后处理都不许再改 risk。
    ai_verdict_taken = False
    agent_trace: list[dict] = []
    # 模型调用重试留痕（2026-09-26 修①）：默认空 = 这条路压根没走 AI（规则档/缓存/低分放行）
    agent_retry: dict = {}
    # 确定性证据前置 / 工具调用与 token 留痕（2026-09-27）：同样默认空 = 没走 AI
    evidence_preload: dict = {}
    agent_usage: dict = {}
    error: str | None = None
    audit = []
    evidence_sources: list[dict] = []
    claim_warnings: list[str] = []

    # ---- 加壳处理：先识别壳；UPX 就静态脱壳，脱壳产物再进一遍完整流程 ----
    packing: dict = {}
    if allow_unpack and _unpack_enabled():
        try:
            from aiav.unpack import default_work_dir, prepare_unpacked

            packing = prepare_unpacked(path, default_work_dir(), enable=True)
        except Exception as exc:  # noqa: BLE001 - 壳处理失败不影响主流程
            packing = {"error": f"壳识别失败: {exc}"}

    samples = agent_samples if agent_samples is not None else _agent_samples()
    sampling: dict = {}

    # ---- 压缩包递归：解出内嵌样本，各自进一遍完整流程，取最严结论 ----
    archive_info: dict = {}
    child_reports: list[FileReport] = []
    if allow_archives and _archives_enabled():
        try:
            from aiav.archive import detect_archive, extract_archive, work_dir_for

            ainfo = detect_archive(path)
            if ainfo.get("is_archive"):
                if not ainfo.get("supported"):
                    archive_info = {**ainfo, "ok": False, "error": "格式在当前环境不支持（缺 7z）"}
                else:
                    ext = extract_archive(path, work_dir_for(path, sha256))
                    archive_info = ext.as_dict()
                    children = [Path(f) for f in ext.files]
                    cap = int(os.getenv("AI_AV_ARCHIVE_MAX_CHILDREN", "20"))
                    # 先按可疑度排序再截断（旧实现按 zip 目录顺序取前 N 个，
                    # 实测会把 20 次 agent 花在零分子样本上，而 30 分的 vbaProject.bin 只是碰巧排第 10）
                    scored: list[tuple[int, Path, str]] = []
                    for child in children:
                        try:
                            child_evidence = quick_prefilter(child, compute_sha256(child),
                                                             with_signature=False)
                            scored.append((child_evidence.prefilter_score, child,
                                           child_evidence.sha256))
                        except OSError:
                            scored.append((-1, child, ""))     # 读不了排最后，也不静默丢
                    scored.sort(key=lambda item: (-item[0], str(item[1])))
                    archive_info["children"] = []
                    # 只有"会进 AI"的路径才受 AI 子样本上限约束；
                    # 纯规则档（agent=None）不受限 —— 规则档是 0 token 的，别把检出能力砍掉
                    ai_cap = _archive_ai_children_cap() if agent is not None else 10 ** 9
                    for rank, (score, child, _child_sha) in enumerate(scored[:cap]):
                        # 可疑度最高的那几个才真进 AI；其余子样本只留清单（不静默丢）
                        if rank >= ai_cap:
                            archive_info["children"].append({
                                "name": child.name, "risk": None, "score": score,
                                "skipped_reason": f"AI 子样本上限 {ai_cap}（按可疑度排序后截断）",
                            })
                            continue
                        cr = scan_file(child, agent=agent, ai_threshold=ai_threshold, store=store,
                                       allow_unpack=True, agent_samples=samples, allow_archives=False,
                                       budget=budget, deterministic=deterministic,
                                       deep_evidence_threshold=deep_threshold)
                        child_reports.append(cr)
                        archive_info["children"].append({
                            "name": child.name, "risk": cr.verdict.risk.value,
                            "score": cr.prefilter_score, "sha256": cr.sha256,
                        })
                    archive_info["children_scanned"] = len(child_reports)
                    archive_info["children_ai_cap"] = (ai_cap if agent is not None else None)
                    archive_info["children_total"] = len(children)
                    if len(child_reports) < len(children):
                        archive_info["truncated"] = True
                    if len(children) > cap:
                        archive_info["truncated"] = True
        except Exception as exc:  # noqa: BLE001 - 压缩包处理失败不影响主流程
            archive_info = {"error": f"压缩包处理失败: {exc}"}

    budget_blocked = bool(budget is not None and budget.exceeded())
    if budget_blocked:
        budget.note_skipped()
        error = ("Token 预算已用尽（%d/%d），本文件降级为规则判定"
                 % (budget.used, budget.limit))
        verdict = heuristic_verdict(evidence)
        evidence_sources = attribute_evidence(verdict.evidence, agent_trace, agent_used=False)
    elif agent is not None and evidence.prefilter_score >= ai_threshold:
        retry_infos: list[dict] = []
        try:
            # ---- 确定性证据前置（2026-09-27）：本地一次采齐，0 token ----
            # 采集本身是本地跑工具（capa / floss / 字符串 / 验签…），**不是**让 AI 调用：
            # 输出直接渲染进送审提示词，并原样进调用链（source=preload）供证据溯源。
            # 实测动机：旧口径平均 8.0 次工具调用/文件、2.3 万 token/文件，
            # 各工具调用率精确接近 1.00/文件 = 把工具清单从头到尾刷了一遍。
            preload_result = _collect_preload(
                path, sha256, evidence,
                deep=(deep_threshold <= 0 or evidence.prefilter_score >= deep_threshold),
                threshold=deep_threshold,
            )
            preload_calls = preload_tool_calls(preload_result)
            evidence_preload = {k: v for k, v in preload_result.items()
                                if k not in ("entries", "calls")}
            # 预筛信号以前伪装成一次 `prefilter` 工具调用进调用链 —— 那既不是 AI 调的，
            # 也不该算进"用了几次工具调用"。现在它只作为**提示词事实**参与证据溯源。
            prefilter_facts = [f"预筛信号 {r}" for r in (evidence.reasons or [])]

            verdicts: list[Verdict] = []
            agent_trace = [dict(c) for c in preload_calls]
            ai_calls_total = 0
            by_tool: dict[str, int] = {}
            for i in range(samples):
                deps = ScanDeps(file_path=path, sha256=sha256)
                deps.tool_calls.extend(dict(c) for c in preload_calls)
                verdicts.append(analyze_file_with_agent(agent, deps, evidence,
                                                        budget=budget,
                                                        preload=preload_result))
                # 重试留痕：成功也要记（"这次是重试第 2 次才拿到的结论"本身就是信息）
                retry_infos.append(dict(getattr(deps, "agent_retry", None) or {}))
                own = ai_tool_calls(deps.tool_calls)
                ai_calls_total += len(own)
                for call in own:
                    name = str(call.get("tool"))
                    by_tool[name] = by_tool.get(name, 0) + 1
                if samples > 1:
                    # 预采集条目是共享的，不按采样重复记；只按采样记 AI 自己的调用
                    agent_trace.extend({**c, "sample": i + 1} for c in own)
                else:
                    agent_trace = list(deps.tool_calls)
            agent_usage = {
                # 口径：只数 AI 自己发起的调用（预采集/预筛注入的条目不算轮数）
                "tool_calls": ai_calls_total,
                # 有没有走"按需深挖"这条路：0 次 = 纯读预采集证据就下结论
                "deep_dive": ai_calls_total > 0,
                "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -kv[1])),
                "tokens": sum(int(i.get("tokens") or 0) for i in retry_infos),
                "samples": samples,
                "preloaded_tools": list(preload_result.get("tools") or []),
                "preloaded_chars": int(preload_result.get("chars") or 0),
                "preload_ms": preload_result.get("elapsed_ms"),
                "preload_kind": preload_result.get("kind"),
            }
            agent_retry = merge_retry_infos(retry_infos)
            verdict, sampling = merge_sampled_verdicts(verdicts)
            audit = []
            ai_verdict_taken = True       # 从这里开始的 risk 是 AI 自主结论
            if deterministic:
                # 判决权归 AI：策略只记录分歧、不再改判（record_only=True）
                verdict = enforce_policy(verdict, evidence, audit, record_only=True)
            if samples > 1 and sampling.get("agreement", 1.0) < 1.0:
                audit.append({
                    "actor": "agent_sampling", "action": "note",
                    "from": "/".join(sampling["per_sample"]), "to": verdict.risk.value,
                    "basis": f"多次采样多数票（{sampling['votes']}）",
                    "detail": f"{'平票取更严；' if sampling.get('tie_break') else ''}"
                              f"一致性 {sampling['agreement']}",
                })
            agent_used = True
            guarded, _changed = apply_claim_guard(verdict, evidence, audit)
            evidence_sources = attribute_evidence(
                verdict.evidence,
                agent_trace,
                prompt_facts=prompt_fact_texts(deps.yara_details, unavailable_detections(),
                                               extra_facts=prefilter_facts),
            )
            claim_warnings = (find_claim_warnings(verdict.evidence, evidence) + guarded
                              + find_autonomy_warnings(evidence_sources)
                              + find_repetition_warnings(evidence_sources, agent_trace))
            claim_warnings = list(dict.fromkeys(claim_warnings))
        except Exception as exc:
            # 降级必须**看得见**：把"试了几次 / 重试了几次 / 为什么放弃"写进 error，
            # 不允许报告里只留一句"失败了"，让读的人以为这条结论是 AI 下的。
            agent_retry = (getattr(exc, "retry_info", None)
                           or (retry_infos[-1] if retry_infos else {}))
            error = _degrade_note(exc, agent_retry)
            verdict = heuristic_verdict(evidence)
            agent_usage = {
                "tool_calls": ai_calls_total,
                "deep_dive": ai_calls_total > 0,
                "by_tool": by_tool,
                "tokens": sum(int(i.get("tokens") or 0) for i in retry_infos),
                "samples": samples,
                "degraded": True,
                "preloaded_tools": list(evidence_preload.get("tools") or []),
            }
    else:
        verdict = heuristic_verdict(evidence)
        evidence_sources = attribute_evidence(verdict.evidence, agent_trace, agent_used=False)
        if deterministic:
            # 没人能判决时才由规则判决（旧语义；AI 上场时这条路走不到）
            verdict = enforce_policy(verdict, evidence, audit, record_only=False)
            ai_verdict_taken = False      # 规则结论，允许后续子样本抬升

    # ---- 脱壳产物二次判定：壳内载荷才是真相，取更严的结论 ----
    if packing.get("unpack", {}).get("ok"):
        try:
            inner_path = Path(packing["unpack"]["output"])
            inner = scan_file(inner_path, agent=agent, ai_threshold=ai_threshold,
                              deep_evidence_threshold=deep_threshold,
                              store=store, allow_unpack=False, agent_samples=samples,
                              budget=budget, deterministic=deterministic)
            packing["unpack"].update({
                "verdict": inner.verdict.risk.value,
                "sha256": inner.sha256,
                "prefilter_score": inner.prefilter_score,
                "yara_hits": inner.yara_hits,
                "summary": inner.verdict.summary,
            })
            escalate_from = _unpack_escalate_from()
            if (deterministic
                    and _risk_rank(inner.verdict.risk) >= _risk_rank(escalate_from)
                    and _risk_rank(inner.verdict.risk) > _risk_rank(verdict.risk)):
                upgraded_from = verdict.risk.value
                if ai_verdict_taken:
                    # 判决权归 AI：壳内载荷的结论是"另一份 AI 结论"，不是策略改判 AI。
                    # 只记录这条反对意见与载荷证据，父文件 risk 仍由 AI 自主下。
                    audit.append({
                        "actor": "unpack", "action": "proposal", "from": upgraded_from,
                        "to": inner.verdict.risk.value,
                        "proposed": "escalate",
                        "basis": (f"unpacked_payload: {packing.get('packer')} 脱壳后独立判定"
                                  f"（抬升门槛={escalate_from.value}）—— AI 结论未被覆盖"),
                        "detail": f"载荷 {inner_path.name}（sha256={inner.sha256[:16]}…）",
                        "applied": False,
                        "disagreement": _risk_rank(inner.verdict.risk) > _risk_rank(verdict.risk),
                    })
                    verdict.evidence = list(dict.fromkeys(
                        [f"[载荷证据] UPX 脱壳载荷独立判定 {inner.verdict.risk.value}"
                         f"（载荷 sha256={inner.sha256[:16]}…）"] + list(verdict.evidence)))
                else:
                    verdict = inner.verdict
                    verdict.summary = f"[脱壳后] {verdict.summary}"
                    verdict.evidence = list(dict.fromkeys(
                        [f"UPX 脱壳载荷判定 {inner.verdict.risk.value}（载荷 sha256={inner.sha256[:16]}…）"]
                        + list(verdict.evidence)))
                    audit.append({
                        "actor": "unpack", "action": "escalate", "from": upgraded_from,
                        "to": verdict.risk.value,
                        "basis": (f"unpacked_payload: {packing.get('packer')} 脱壳后独立判定"
                                  f"（抬升门槛={escalate_from.value}）"),
                        "detail": f"载荷 {inner_path.name}（sha256={inner.sha256[:16]}…）",
                    })
                evidence_sources = inner.evidence_sources or evidence_sources
                claim_warnings = list(dict.fromkeys(claim_warnings + inner.claim_warnings))
            agent_used = agent_used or inner.agent_used
        except Exception as exc:  # noqa: BLE001
            packing["unpack"]["error"] = f"脱壳产物扫描失败: {exc}"

    # ---- 压缩包内样本：取最严者作为压缩包整体结论 ----
    if child_reports:
        worst = max(child_reports, key=lambda r: _risk_rank(r.verdict.risk))
        agent_used = agent_used or any(r.agent_used for r in child_reports)
        if deterministic and _risk_rank(worst.verdict.risk) > _risk_rank(verdict.risk):
            upgraded_from = verdict.risk.value
            inner_name = Path(worst.path).name
            if ai_verdict_taken:
                # 判决权归 AI：压缩包整体定级 = 父文件自身的 AI 结论，
                # 内嵌样本的 AI 结论只作为反对意见 + 证据记录。
                audit.append({
                    "actor": "archive", "action": "proposal", "from": upgraded_from,
                    "to": worst.verdict.risk.value, "proposed": "escalate",
                    "basis": "archive_child: 内嵌样本独立判定，但父文件 AI 结论未被覆盖",
                    "detail": f"{inner_name}（{worst.verdict.risk.value}，score={worst.prefilter_score}）",
                    "applied": False, "disagreement": True,
                })
                verdict.evidence = list(dict.fromkeys(
                    [f"[压缩包证据] 内嵌样本 {inner_name} 判定 {worst.verdict.risk.value}"
                     f"（sha256={worst.sha256[:16]}…）"] + list(verdict.evidence)))
            else:
                verdict = worst.verdict.model_copy(deep=True)
                verdict.summary = f"[压缩包内 {inner_name}] {verdict.summary}"
                verdict.evidence = list(dict.fromkeys(
                    [f"压缩包内样本 {inner_name} 判定 {worst.verdict.risk.value}"
                     f"（sha256={worst.sha256[:16]}…）"] + list(verdict.evidence)))
                audit.append({
                    "actor": "archive", "action": "escalate", "from": upgraded_from,
                    "to": verdict.risk.value,
                    "basis": "archive_child: 内嵌样本独立判定",
                    "detail": f"{inner_name}（{worst.verdict.risk.value}，score={worst.prefilter_score}）",
                })
            evidence_sources = worst.evidence_sources or evidence_sources
            claim_warnings = list(dict.fromkeys(claim_warnings + worst.claim_warnings))

    # 仅因加壳而可疑 → 确定性纠正（加壳本身不是恶意证据）
    verdict = packer_only_downgrade(verdict, evidence, packing, audit,
                                    record_only=ai_verdict_taken)

    # 脱壳/压缩包那两步会把子样本的句子并进父文件结论，所以落库前再兜一次
    tail_warnings, _ = apply_claim_guard(verdict, evidence, audit)
    if tail_warnings:
        claim_warnings = list(dict.fromkeys(list(claim_warnings) + tail_warnings))
        evidence_sources = attribute_evidence(verdict.evidence, agent_trace) or evidence_sources

    final_report = FileReport(
        path=str(path),
        sha256=sha256,
        size=evidence.size,
        extension=evidence.extension,
        prefilter_score=evidence.prefilter_score,
        prefilter_reasons=evidence.reasons,
        yara_hits=evidence.yara_hits,
        criteria_hits=evidence.criteria_hits,
        unclassified_signals=evidence.unclassified_signals,
        deterministic=evidence.deterministic,
        clamav=evidence.clamav,
        verdict=verdict,
        agent_used=agent_used,
        agent_trace=agent_trace,
        error=error,
        policy_actions=audit,
        # 判决权归 AI：策略想改判但没改成的提议（独立成栏，供报告直接展示分歧）
        policy_proposals=list(verdict.policy_proposals),
        evidence_sources=evidence_sources,
        claim_warnings=claim_warnings,
        packing=packing,
        sampling=sampling,
        archive=archive_info,
        agent_retry=agent_retry,
        evidence_preload=evidence_preload,
        agent_usage=agent_usage,
        disposition=({"status": "previously_quarantined", "id": prev.get("id")}
                     if prev and prev.get("status") == "quarantined" else {}),
    )
    if scan_cache is not None and not error:
        scan_cache.put(sha256, final_report, deterministic=deterministic,
                       ai_enabled=agent is not None,
                       samples=(agent_samples if agent_samples is not None else _agent_samples()),
                       unpack=allow_unpack and _unpack_enabled(),
                       archives=allow_archives and _archives_enabled())
    return final_report


def scan_files_concurrent(
    files: Sequence[Path],
    agent_factory: Callable[[], Agent] | None = None,
    ai_threshold: int = AI_GATE,
    workers: int = 4,
    agent_samples: int | None = None,
    budget: TokenBudget | None = None,
    store: "StateStore | None" = None,
    deterministic: bool = True,
    deep_evidence_threshold: int | None = None,
    clamav_batch: Mapping[str, Any] | None = None,
) -> list[FileReport]:
    """并发扫描多个文件；每个线程使用独立 Agent，避免共享模型客户端。

    `clamav_batch` 见 `scan_file` —— 批次是只读的，多线程共享同一个 dict 没问题。
    """
    if not files:
        return []

    if workers <= 1 or agent_factory is None:
        agent = agent_factory() if agent_factory else None
        return [scan_file(p, agent, ai_threshold, agent_samples=agent_samples, budget=budget,
                          store=store, deterministic=deterministic,
                          deep_evidence_threshold=deep_evidence_threshold,
                          clamav_batch=clamav_batch)
                for p in files]

    local = threading.local()

    def work(path: Path) -> FileReport:
        if not hasattr(local, "agent"):
            try:
                local.agent = agent_factory()
            except Exception:
                local.agent = None
        return scan_file(path, getattr(local, "agent", None), ai_threshold,
                         agent_samples=agent_samples, budget=budget, store=store,
                         deterministic=deterministic,
                         deep_evidence_threshold=deep_evidence_threshold,
                         clamav_batch=clamav_batch)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        return list(executor.map(work, files))
