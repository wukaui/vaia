"""确定性**结构**信号：把"文件长成什么样"计进预筛分数（全部本地可算、0 token）。

════ 为什么要有这个模块（2026-09-27 实测） ════

40 个 Dike pilot 样本（20 恶意 + 20 良性）上量出来的预筛分数分布：

    · 恶意：min 5 / 中位 5 / max 55，**≥12 的只有 2 个**
    · 良性：min 5 / 中位 5 / max 5
    · 分离度 AUC = 0.625（Mann-Whitney U_min = 150/400）

也就是说 35/40 个文件**同分**（都正好 5 分），而 5 分只来自「高风险扩展名」这一条 ——
`.exe` 本来就该是 5 分，恶意与良性在这个维度上没有任何区别。后果有两层：

  1. 分数**不能用来分流**：把阈值提到 12 会漏掉 18/20 个恶意（这正是纯规则档
     召回 0.38 的成因），留在 5 又等于"全送"；
  2. 分数**不能给 AI 提供信号**：送审里那条"预筛信号"对 35 个文件是同一句话。

════ 做法 ════

补的是**结构**事实 —— 不是"文件里有某个字符串"，而是"文件的段表/流表本身长得不对"。
这一类事实有三个好处：本地可算（0 token）、不依赖任何样本名/哈希、且**可解释**
（每条都写成 `结构信号 +N: <事实>（<读数>）` 进 `prefilter_reasons`，
报告里能直接看出这条分是谁给的）。

阈值全部取**整数档**（0.25 / 0.35 / 64KB…），不是从这 40 个样本的分布上拟合出来的；
每个信号的权重也只够"和其它信号合起来过线"，单独一条到不了 `SUSPICIOUS_SCORE_THRESHOLD`。
完整实测（分数分布对照、阈值扫描、holdout、被否掉的候选）见
`~/refs/aiav_prefilter_discrimination_20260927.md`。

════ 三道**反误伤闸**（都是真实良性语料逼出来的，不是拍脑袋加的） ════

  1. **无代码镜像**（入口点 == 0）不参与任何"代码形态"信号。
     真实 Windows 语料里 **41% 的 PE 入口点就是 0**（`.mui`、`api-ms-win-core-*.dll`、
     `KBD*.DLL`、`mfc140*.dll`…）：对它们来说 `.text` 占 0%、导入表 0 条、`.rsrc` 占 99%
     全是**设计如此**。不加这道闸，400 个真实良性文件在阈值 12 上的误报是 **28 个（7.0%）**。
     判据**只认入口点 == 0** —— 不能用"没有可执行段"，那会把"入口点落在未标记可执行的段"
     这个**本身就是异常**的形态一起吞掉（实测 Dike pilot 里 2 个恶意正是这种形态）。
  2. **导入表稀疏必须真的带动态解析 API**。去掉这个前提后，真实 Windows 良性语料里
     **42% 的 PE 都"导入稀疏"**（转发桩 / 键盘布局 DLL / 纯资源 DLL 天然 0 导入），
     而其中带 VirtualAlloc / LoadLibrary / GetProcAddress 的是 **0%**。
  3. **.NET 不算导入稀疏**：.NET 的导入表天然只有 `mscoree.dll!_CorExeMain` 一条。

════ 明确**不**计分的（实测反相关或有误伤） ════

  · **overlay（尾部附加数据）**：本批 20 个恶意全是 0 或 ~1KB，良性反而普遍有
    6~21KB overlay（安装器/自解压壳）。计分会**反向**误伤。
  · **未来时间戳**：本批零区分度（1 恶意 / 1 良性），而真实 Windows 良性语料里
    **22/400 带未来时间戳**（MSVC 的 /Brepro 确定性构建把时间戳换成内容哈希，
    2033/2051/2068/2103 都有）—— 留着它是纯误报源，权重已置 0（`W_FUTURE_TIMESTAMP`）。
  · **"老"时间戳**（1970/1971）：可复现构建的常见形态（本批 4 个良性），反向。
  · **非常规段名**：2 恶意 / 5 良性（Go/Rust/.NET 的段名本来就不标准），反向。
  · **导入表里的可疑 API**（VirtualAlloc / IsDebuggerPresent…）：良性里同样普遍
    （本批良性 8/18 命中），单独用是纯误伤源；只在**导入表整体稀疏**这个前提成立时
    才作为佐证出现（见第 ④ 条信号）。
"""

from __future__ import annotations

import time
from pathlib import Path

# ---------------------------------------------------------------- 阈值常量
# 代码段（.text）原始数据占总段区原始数据的比例低于此值 = "小 stub + 大载荷"。
# 取 0.25：正常编译产物绝大多数在 0.35 以上（本批良性最低 0.353，中位 0.57），
# 而加壳/资源型载荷普遍在 0.25 以下（本批恶意 11/19 命中、良性 0/18）。
TEXT_RATIO_MIN = 0.25
# 资源段（.rsrc）占比高于此值 + 绝对体积够大 = 载荷可能藏在资源里。
RSRC_RATIO_MAX = 0.35
# 上面的占比要配合的绝对体积下限：小文件里占比高是正常的（几个图标就占满）。
RSRC_RAW_MIN = 64 * 1024
# "体积与代码段严重不成比例"的体积门槛：太小的文件占比本来就不稳定。
STRUCTURE_MIN_SIZE = 64 * 1024
# 导入表稀疏：DLL 数与 API 名数同时低于这两条线（且**不是 .NET**，见下）。
SPARSE_DLL_MAX = 3
SPARSE_API_MAX = 15
# 未来时间戳的容忍窗口（秒）：+1 年以外的才算异常。
FUTURE_TIMESTAMP_SLACK = 365 * 24 * 3600
# ⚠ 2026-09-27 实测后**弃用**：MSVC 的确定性构建（/Brepro）把时间戳换成内容哈希，
# 于是**真实 Windows 系统文件大量带"未来时间戳"**（实测 400 个良性里 22 个，
# 2033/2051/2056/2068/2103 都有），而本批 40 样本上它零区分度（1 恶意 / 1 良性）。
# 留着它只会把 22/28 个良性误报喂进阈值。保留常量只为文档可追溯，权重置 0。

# 权重。单独任何一条都 < SUSPICIOUS_SCORE_THRESHOLD(12)，必须两条以上才过线 ——
# 这是刻意的：结构信号是"弱信号"，它的作用是**让分数分得开**，不是单独定性。
W_WX_SECTION = 6            # 可写且可执行段
W_TEXT_RATIO = 6            # 代码段占比失衡（小 stub + 大载荷）
W_RSRC_RATIO = 4            # 资源段占比异常
W_SPARSE_IMPORTS = 6        # 导入表稀疏（非 .NET）
W_EP_NOT_EXECUTABLE = 6     # 入口点不在可执行段
W_FUTURE_TIMESTAMP = 0      # 编译时间戳在未来 —— **已弃用**（见上方 FUTURE_TIMESTAMP_SLACK）

# 容器（OLE / OOXML）结构信号权重
W_OLE_OBJECTPOOL = 4        # ObjectPool：嵌入的 OLE 对象
W_OLE_PACKAGE = 5           # Package 流：嵌入的整份文件
W_OLE_EQUATION = 8          # Equation Native：公式编辑器对象（CVE-2017-11882 载体）
W_OLE_OLE10NATIVE = 5       # \x01Ole10Native：嵌入的原生文件
W_OOXML_EMBEDDING = 5       # OOXML 里的 embeddings/ 或 oleObject
W_OOXML_ACTIVEX = 5         # OOXML 里的 activeX 控件
W_OOXML_EQUATION = 6        # OOXML 里的公式对象

# 动态解析/内存执行类 API：**只在导入表稀疏时**才作为佐证。
# 注意这不是"可疑 API 清单"——良性里同样常见（VirtualProtect 在 JIT/CRT 里到处都是），
# 所以它自己不产生任何分数，只是让"稀疏"这条更站得住。
DYNAMIC_RESOLUTION_APIS = frozenset({
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "NtUnmapViewOfSection", "SetThreadContext", "QueueUserAPC",
    "RtlMoveMemory", "ZwProtectVirtualMemory",
})

# .NET 的导入表天然只有 mscoree.dll!_CorExeMain 一条 —— 真实调用在 CLR 元数据里。
# 不排除它，"导入表稀疏"会把**每一个 .NET 程序**打成可疑（本批良性里 4 个 .NET
# 全是 napi=1，正是这条坑的实证）。
NET_DLLS = frozenset({"mscoree.dll", "mscorlib.dll", "mscorwks.dll"})


def _pe_imports(pe) -> tuple[set[str], set[str]]:
    dlls: set[str] = set()
    apis: set[str] = set()
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return dlls, apis
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        try:
            dlls.add(entry.dll.decode("utf-8", errors="replace").lower())
        except Exception:  # noqa: BLE001
            continue
        for imp in getattr(entry, "imports", []) or []:
            if getattr(imp, "name", None):
                apis.add(imp.name.decode("utf-8", errors="replace"))
    return dlls, apis


def _is_dotnet(pe) -> bool:
    try:
        import pefile  # type: ignore

        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
        ]
        return bool(int(getattr(directory, "VirtualAddress", 0) or 0))
    except Exception:  # noqa: BLE001
        return False


def pe_structure_signals(path: Path) -> tuple[int, list[str]]:
    """PE 段表/导入表层面的结构信号。返回 (分数增量, 理由列表)。

    只解析头部与段表（`fast_load=True` + `parse_data_directories`），不执行任何代码。
    """
    try:
        import pefile  # type: ignore
    except ImportError:
        return 0, []

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:  # noqa: BLE001 - 不是 PE / 解析失败 → 没有结构信号
        return 0, []

    score = 0
    reasons: list[str] = []
    try:
        try:
            pe.parse_data_directories()
        except Exception:  # noqa: BLE001 - 目录解析失败不影响段表信号
            pass

        try:
            size = path.stat().st_size
        except OSError:
            size = 0

        sections = list(getattr(pe, "sections", []) or [])[:32]
        raw_total = sum(int(getattr(s, "SizeOfRawData", 0) or 0) for s in sections)

        try:
            entry_rva = int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0) or 0)
        except Exception:  # noqa: BLE001
            entry_rva = 0
        # ---- **无代码镜像**（resource-only DLL / API set 转发桩 / 键盘布局 DLL）----
        # 2026-09-27 在真实 Windows 语料上量出来的坑：400 个良性系统文件里
        # **41% 的 PE 入口点就是 0**（`.mui`、`msimsg.dll`、`api-ms-win-core-*.dll`、
        # `KBD*.DLL`、`mfc140*.dll`… 全是这一类）。对它们来说：
        #   · `.text` 占 0% 是**设计如此**（本来就没有代码）
        #   · 导入表 0 条是**设计如此**（转发桩 / 纯资源）
        #   · `.rsrc` 占 99% 是**设计如此**（它就是资源包）
        # 拿"代码形态异常"去量"没有代码的文件"，只会造出一整类假信号 ——
        # 实测不加这道闸，真实良性语料在阈值 12 上的误报率是 **7.0%**（0/400 → 28/400）。
        #
        # ⚠ 判据只用 `入口点 == 0`，**不能**用"没有可执行段"：后者会把
        # "入口点落在未标记可执行的段"这个**本身就是异常**的形态一起吞掉
        # （实测 Dike pilot 里 2 个恶意样本正是这种形态，误吞后从 17 分掉回 5 分）。
        code_less = entry_rva == 0

        # ---- ① 可写且可执行段（W+X）：正常编译产物不会这么标，自修改/注入常见 ----
        wx_names = []
        if not code_less:
            for s in sections:
                ch = int(getattr(s, "Characteristics", 0) or 0)
                if (ch & 0x20000000) and (ch & 0x80000000):
                    wx_names.append(s.Name.rstrip(b"\x00").decode("utf-8", errors="replace"))
        if wx_names:
            score += W_WX_SECTION
            reasons.append(
                f"结构信号 +{W_WX_SECTION}: 可写且可执行段 ×{len(wx_names)}"
                f"（{'/'.join(wx_names[:3])}，自修改/注入常见形态）"
            )

        # ---- ② 代码段占比失衡：小 stub + 大载荷 ----
        # 注意：`pe_packing_signals` 已经为"高熵可执行段/加壳节名"给过 +4，
        # 这里量的是**另一个**事实（原始数据分布），不是同一处证据的第二次计分。
        if not code_less and size >= STRUCTURE_MIN_SIZE and raw_total > 0:
            text_raw = sum(
                int(getattr(s, "SizeOfRawData", 0) or 0)
                for s in sections
                if s.Name.rstrip(b"\x00").decode("utf-8", errors="replace").lower().startswith(".text")
            )
            ratio = text_raw / raw_total
            if ratio < TEXT_RATIO_MIN:
                score += W_TEXT_RATIO
                reasons.append(
                    f"结构信号 +{W_TEXT_RATIO}: 代码段占比失衡（.text 只占段区原始数据 "
                    f"{ratio:.1%} < {TEXT_RATIO_MIN:.0%}，小 stub + 大载荷）"
                )

        # ---- ③ 资源段占比异常：载荷藏在资源里 ----
        if not code_less and raw_total > 0:
            rsrc_raw = sum(
                int(getattr(s, "SizeOfRawData", 0) or 0)
                for s in sections
                if "rsrc" in s.Name.rstrip(b"\x00").decode("utf-8", errors="replace").lower()
            )
            rsrc_ratio = rsrc_raw / raw_total
            if rsrc_ratio >= RSRC_RATIO_MAX and rsrc_raw >= RSRC_RAW_MIN:
                score += W_RSRC_RATIO
                reasons.append(
                    f"结构信号 +{W_RSRC_RATIO}: 资源段占比异常（.rsrc 占段区原始数据 "
                    f"{rsrc_ratio:.1%}、{rsrc_raw // 1024}KB，载荷可能藏在资源里）"
                )

        # ---- ④ 导入表稀疏（非 .NET）：少 DLL 却要**动态解析** ----
        dlls, apis = _pe_imports(pe)
        dotnet = _is_dotnet(pe) or bool(dlls & NET_DLLS)
        # 必须**真的带动态解析 API** 才算 —— 这是本信号原本的语义（手工 shellcode loader）。
        # 2026-09-27 实测：去掉这个前提后，真实 Windows 良性语料里 **42%** 的 PE 都"导入稀疏"
        # （转发桩、键盘布局 DLL、纯资源 DLL 天然 0 导入），而其中带动态解析 API 的是 **0%**。
        dyn = sorted(apis & DYNAMIC_RESOLUTION_APIS)
        if (not code_less and not dotnet and dyn
                and len(dlls) <= SPARSE_DLL_MAX and len(apis) <= SPARSE_API_MAX):
            score += W_SPARSE_IMPORTS
            reasons.append(
                f"结构信号 +{W_SPARSE_IMPORTS}: 导入表稀疏（{len(dlls)} 个 DLL / {len(apis)} 个 API，"
                f"却带动态解析 API：{'/'.join(dyn[:4])}）"
            )

        # ---- ⑤ 入口点不在可执行段 ----
        ep = entry_rva
        if ep and not code_less:
            ep_section = None
            ep_executable = False
            for s in sections:
                va = int(getattr(s, "VirtualAddress", 0) or 0)
                span = max(int(getattr(s, "Misc_VirtualSize", 0) or 0),
                           int(getattr(s, "SizeOfRawData", 0) or 0))
                if span and va <= ep < va + span:
                    ep_section = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                    ep_executable = bool(int(getattr(s, "Characteristics", 0) or 0) & 0x20000000)
                    break
            if ep_section is not None and not ep_executable:
                score += W_EP_NOT_EXECUTABLE
                reasons.append(
                    f"结构信号 +{W_EP_NOT_EXECUTABLE}: 入口点落在**未标记可执行**的段"
                    f"（入口在 {ep_section}，但该段缺 EXECUTE 标志）"
                )

        # ---- ⑥ 编译时间戳在未来：**已弃用**（权重 0），只在读数异常时留痕 ----
        # 理由见 FUTURE_TIMESTAMP_SLACK 的注释：MSVC /Brepro 让真实 Windows 系统文件
        # 普遍带未来时间戳，这条信号在真实良性语料上是纯误报源。
        try:
            ts = int(getattr(pe.FILE_HEADER, "TimeDateStamp", 0) or 0)
        except Exception:  # noqa: BLE001
            ts = 0
        if W_FUTURE_TIMESTAMP and ts > int(time.time()) + FUTURE_TIMESTAMP_SLACK:
            score += W_FUTURE_TIMESTAMP
            try:
                stamp = time.strftime("%Y-%m-%d", time.gmtime(ts))
            except (OverflowError, OSError, ValueError):
                stamp = str(ts)
            reasons.append(
                f"结构信号 +{W_FUTURE_TIMESTAMP}: 编译时间戳在未来（{stamp}）"
                "（弱信号，单独不足以定性）"
            )
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001
            pass

    return score, reasons


# ---------------------------------------------------------------- 容器（OLE / OOXML）
def _ole_structure_signals(path: Path) -> tuple[int, list[str]]:
    """CFBF（.doc/.xls/.ppt/.ole/.msi）的**流清单**结构信号。

    只看"容器里存了什么形态的东西"，不看内容 —— 与已有的宏/XLM 分支不重叠：
    那边管的是"宏源码里写了什么"，这边管的是"容器里嵌了对象没有"。
    """
    try:
        import olefile  # type: ignore
    except ImportError:
        return 0, []

    try:
        with olefile.OleFileIO(str(path)) as ole:
            entries = ["/".join(e) for e in ole.listdir(streams=True, storages=True)]
    except Exception:  # noqa: BLE001
        return 0, []

    low = [e.lower() for e in entries]
    score = 0
    reasons: list[str] = []

    if any("objectpool" in e for e in low):
        score += W_OLE_OBJECTPOOL
        reasons.append(
            f"结构信号 +{W_OLE_OBJECTPOOL}: 容器内含 ObjectPool 存储"
            "（嵌入的 OLE 对象，投递型文档常见）"
        )
    if any(e == "package" or e.endswith("/package") for e in low):
        score += W_OLE_PACKAGE
        reasons.append(
            f"结构信号 +{W_OLE_PACKAGE}: 容器内含 Package 流（嵌入的整份文件）"
        )
    if any("equation native" in e or "equation.3" in e for e in low):
        score += W_OLE_EQUATION
        reasons.append(
            f"结构信号 +{W_OLE_EQUATION}: 容器内含公式编辑器对象（Equation Native，"
            "CVE-2017-11882 系漏洞的载体形态）"
        )
    if any("ole10native" in e for e in low):
        score += W_OLE_OLE10NATIVE
        reasons.append(
            f"结构信号 +{W_OLE_OLE10NATIVE}: 容器内含 Ole10Native 流"
            "（以原生文件形态嵌入的对象）"
        )
    return score, reasons


def _ooxml_structure_signals(path: Path) -> tuple[int, list[str]]:
    """OOXML（.docm/.docx/.xlsm/…）zip 目录清单的结构信号。"""
    import zipfile

    try:
        with zipfile.ZipFile(path) as zf:
            names = [n.lower() for n in zf.namelist()]
    except Exception:  # noqa: BLE001
        return 0, []

    score = 0
    reasons: list[str] = []

    if any("/embeddings/" in n or "oleobject" in n for n in names):
        score += W_OOXML_EMBEDDING
        reasons.append(
            f"结构信号 +{W_OOXML_EMBEDDING}: 文档内含嵌入对象"
            "（embeddings/ 或 oleObject，投递型文档常见）"
        )
    if any("activex" in n for n in names):
        score += W_OOXML_ACTIVEX
        reasons.append(f"结构信号 +{W_OOXML_ACTIVEX}: 文档内含 ActiveX 控件部件")
    if any("equation" in n or "/equations/" in n for n in names):
        score += W_OOXML_EQUATION
        reasons.append(
            f"结构信号 +{W_OOXML_EQUATION}: 文档内含公式对象（Equation，"
            "CVE-2017-11882 系漏洞的载体形态）"
        )
    return score, reasons


def container_structure_signals(path: Path) -> tuple[int, list[str]]:
    """容器结构信号：CFBF 与 OOXML 各自走一条，互不干扰。"""
    head = b""
    try:
        with path.open("rb") as f:
            head = f.read(8)
    except OSError:
        return 0, []

    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):     # CFBF 魔数
        return _ole_structure_signals(path)
    if head.startswith(b"PK\x03\x04"):                            # OOXML / zip
        return _ooxml_structure_signals(path)
    return 0, []


def structure_signals(path: Path, extension: str = "") -> tuple[int, list[str]]:
    """总入口：按**魔数优先**判该走 PE 还是容器分支，返回 (分数增量, 理由列表)。

    魔数优先的理由与 `preload.detect_kind` 一致：投递样本的扩展名不可信
    （挂着 `.pdf`/`.doc` 的 PE 很常见），而结构解析必须跟着真实类型走。
    两边都判不出来就返回 0 —— **宁可不加分，也不猜**。
    """
    head = b""
    try:
        with path.open("rb") as f:
            head = f.read(8)
    except OSError:
        return 0, []

    ext = (extension or path.suffix).lower()

    if head.startswith(b"MZ") or ext in {
        ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".pif",
        ".pyd", ".efi", ".ax", ".mui", ".acm", ".drv", ".tsp",
    }:
        return pe_structure_signals(path)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") or head.startswith(b"PK\x03\x04"):
        return container_structure_signals(path)
    return 0, []
