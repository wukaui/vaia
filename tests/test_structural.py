"""确定性**结构**信号（`aiav.structural`）的单元测试。

覆盖四件事：
  1. 信号本身：每个结构读数该不该计分、计多少（用**合成的 PE/OLE 字节**构造，
     不依赖任何真实样本 —— 样本不进 git，测试也不该依赖它们）；
  2. 反误伤纪律：.NET 的稀疏导入表不误伤、良性 overlay 不误伤、非常规段名不误伤；
  3. 解释性：每条理由都写成 `结构信号 +N: <事实>（<读数>）`，能被
     `prefilter_reasons` 直接读出来（报告里看得出这条分是谁给的）；
  4. 与已有信号不重复计分：`pe_packing_signals`（加壳节名 / 高熵可执行段）给的 +4
     不被结构信号再算一遍。

测试用的 PE 是**手工拼出来的最小合法 PE**（DOS 头 + PE 头 + 段表 + 段数据），
不是任何真实恶意样本 —— 样本只做静态解析，这里连样本都不需要。
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aiav import structural


# ---------------------------------------------------------------- 合成 PE 构造

def _section(name: str, vsize: int, rsize: int, va: int, ptr: int,
             characteristics: int, fill: int = 0x90) -> tuple[bytes, bytes]:
    """返回 (段表项 40 字节, 段数据)。"""
    raw_name = name.encode()[:8].ljust(8, b"\x00")
    header = raw_name + struct.pack(
        "<IIIIIIHHI", vsize, va, rsize, ptr, 0, 0, 0, 0, characteristics
    )
    return header, bytes([fill]) * rsize


def build_pe(
    path: Path,
    sections: list[tuple[str, int, int, int, int]],
    *,
    entry_rva: int = 0x1000,
    timestamp: int = 1_600_000_000,
    dotnet: bool = False,
    imports: dict[str, list[str]] | None = None,
    machine: int = 0x14C,
) -> Path:
    """拼一个最小可解析的 PE。

    `sections` 每项是 (名字, 虚拟大小, 原始大小, 虚拟地址, 特征值)。
    `imports` 非空时会**额外追加一个 `.idata` 段**放导入表 —— pefile 只认落在
    段区里的 RVA，把描述符塞在段外它读不出来（第一版就踩了这个，导入表恒为 0 条）。
    """
    file_align, sect_align = 0x200, 0x1000
    image_base = 0x400000
    dirs = [(0, 0)] * 16

    # ---- .idata 段（可选）：描述符 + ILT/IAT + DLL 名 ----
    idata_blob = b""
    idata_va = 0
    if imports:
        idata_va = (max(va + max(vs, rs) for _, vs, rs, va, _ in sections) if sections else 0x1000)
        idata_va = (idata_va + sect_align - 1) // sect_align * sect_align

        n_dll = len(imports)
        desc_size = 20 * (n_dll + 1)
        # 布局：[描述符][ILT 数组][IAT 数组][IMAGE_IMPORT_BY_NAME][DLL 名]
        ilt_off = desc_size
        iat_off = ilt_off + 4 * sum(len(a) + 1 for a in imports.values())
        name_off = iat_off + 4 * sum(len(a) + 1 for a in imports.values())
        str_off = name_off + sum(2 + len(a.encode()) + 1 for apis in imports.values() for a in apis)

        descs, ilts, iats, names, strs = b"", b"", b"", b"", b""
        for i, (dll, apis) in enumerate(imports.items()):
            this_ilt = ilt_off + len(ilts)
            this_iat = iat_off + len(iats)
            for api in apis:
                entry_off = name_off + len(names)
                names += struct.pack("<H", 0) + api.encode() + b"\x00"
                ilts += struct.pack("<I", idata_va + entry_off)
                iats += struct.pack("<I", idata_va + entry_off)
            ilts += struct.pack("<I", 0)
            iats += struct.pack("<I", 0)
            dll_off = str_off + len(strs)
            strs += dll.encode() + b"\x00"
            descs += struct.pack("<IIIII", idata_va + this_ilt, 0, 0,
                                 idata_va + dll_off, idata_va + this_iat)
        descs += b"\x00" * 20
        idata_blob = descs + ilts + iats + names + strs
        dirs[1] = (idata_va, len(idata_blob))

    # ---- 段数据布局（.idata 排在所有给定段之后）----
    n_sections = len(sections) + (1 if imports else 0)
    headers_size = 0x40 + 4 + 20 + 224 + 40 * n_sections    # DOS + 签名 + COFF + 可选头 + 段表
    headers_size = (headers_size + file_align - 1) // file_align * file_align

    ptr = headers_size
    blobs: list[bytes] = []
    entries: list[tuple[str, int, int, int, int, int]] = []
    for name, vsize, rsize, va, ch in sections:
        entries.append((name, vsize, rsize, va, ptr, ch))
        blobs.append(bytes([0x90]) * rsize)
        ptr += (rsize + file_align - 1) // file_align * file_align
    if imports:
        entries.append((".idata", len(idata_blob), len(idata_blob), idata_va, ptr, R))
        blobs.append(idata_blob)

    if dotnet:
        dirs[14] = (0x3000, 0x48)                            # COM_DESCRIPTOR 非零即可

    # ---- 可选头（PE32，固定 224 字节）----
    opt = struct.pack("<HBB", 0x10B, 14, 0)                     # Magic / Linker 版本
    opt += struct.pack("<III", 0x1000, 0x1000, 0)               # 代码/已初始化/未初始化大小
    opt += struct.pack("<III", entry_rva, 0x1000, 0x1000)       # 入口 RVA / 代码基址 / 数据基址
    opt += struct.pack("<III", image_base, sect_align, file_align)
    opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)             # 各版本号
    opt += struct.pack("<III", 0, 0x400000, headers_size)       # Win32Version / SizeOfImage / Headers
    opt += struct.pack("<IHH", 0, 2, 0)                         # CheckSum / Subsystem / DllChar
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)   # 栈/堆保留与提交
    opt += struct.pack("<II", 0, 16)                            # LoaderFlags / NumberOfRvaAndSizes
    for rva, size in dirs:
        opt += struct.pack("<II", rva, size)
    assert len(opt) == 224, len(opt)

    coff = struct.pack("<HHIIIHH", machine, n_sections, timestamp, 0, 0, 224, 0x0102)

    sect_table = b""
    for name, vsize, rsize, va, p, ch in entries:
        sect_table += name.encode()[:8].ljust(8, b"\x00")
        sect_table += struct.pack("<IIIIIIHHI", vsize, va, rsize, p, 0, 0, 0, 0, ch)

    dos = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)
    body = dos + b"PE\x00\x00" + coff + opt + sect_table
    body = body.ljust(headers_size, b"\x00")

    out = bytearray(body)
    for blob, (_, _, rsize, _, p, _) in zip(blobs, entries):
        if len(out) < p:
            out.extend(b"\x00" * (p - len(out)))
        out[p:p + len(blob)] = blob
    path.write_bytes(bytes(out))
    return path


# 特征位
X = 0x60000020        # CODE | EXECUTE | READ
R = 0x40000040        # INITIALIZED_DATA | READ
W = 0xC0000040        # INITIALIZED_DATA | READ | WRITE
WX = 0xE0000020       # CODE | EXECUTE | WRITE | READ


@pytest.fixture
def benign_pe(tmp_path: Path) -> Path:
    """一份"正常"PE：代码段占大头、导入表宽、无可写可执行段。"""
    return build_pe(
        tmp_path / "normal.exe",
        [(".text", 0x8000, 0x8000, 0x1000, X), (".data", 0x1000, 0x400, 0x9000, W)],
        imports={"KERNEL32.dll": ["CreateFileA", "ReadFile", "WriteFile", "CloseHandle",
                                  "GetLastError", "Sleep", "GetTickCount", "HeapAlloc",
                                  "HeapFree", "VirtualProtect", "LoadLibraryA",
                                  "GetProcAddress", "ExitProcess", "GetModuleHandleA",
                                  "SetLastError", "WideCharToMultiByte"]},
    )


# ---------------------------------------------------------------- ① 代码段占比失衡

def test_low_text_ratio_scores(tmp_path: Path):
    """小 stub + 大载荷（.text 只占 1%）→ 计分并写出读数。"""
    p = build_pe(
        tmp_path / "stub.exe",
        [(".text", 0x400, 0x400, 0x1000, X), (".rsrc", 0x40000, 0x40000, 0x2000, R)],
    )
    score, reasons = structural.pe_structure_signals(p)
    assert score >= structural.W_TEXT_RATIO
    assert any("代码段占比失衡" in r for r in reasons)


def test_high_text_ratio_does_not_score(tmp_path: Path, benign_pe: Path):
    score, reasons = structural.pe_structure_signals(benign_pe)
    assert not any("代码段占比失衡" in r for r in reasons)
    assert score == 0


def test_tiny_file_skips_text_ratio(tmp_path: Path):
    """体积门槛之下不做占比判断 —— 小文件占比本来就不稳定。"""
    p = build_pe(
        tmp_path / "tiny.exe",
        [(".text", 0x100, 0x100, 0x1000, X), (".rsrc", 0x2000, 0x2000, 0x2000, R)],
    )
    assert p.stat().st_size < structural.STRUCTURE_MIN_SIZE
    _, reasons = structural.pe_structure_signals(p)
    assert not any("代码段占比失衡" in r for r in reasons)


# ---------------------------------------------------------------- ② 可写可执行段

def test_writable_executable_section_scores(tmp_path: Path):
    p = build_pe(
        tmp_path / "wx.exe",
        [(".text", 0x8000, 0x8000, 0x1000, WX), (".data", 0x1000, 0x400, 0x9000, W)],
        imports={"KERNEL32.dll": [f"Api{i}" for i in range(30)]},
    )
    score, reasons = structural.pe_structure_signals(p)
    assert score >= structural.W_WX_SECTION
    assert any("可写且可执行段" in r for r in reasons)


def test_benign_has_no_wx(tmp_path: Path, benign_pe: Path):
    _, reasons = structural.pe_structure_signals(benign_pe)
    assert not any("可写且可执行段" in r for r in reasons)


# ---------------------------------------------------------------- ③ 资源段占比

def test_high_rsrc_ratio_scores(tmp_path: Path):
    p = build_pe(
        tmp_path / "dropper.exe",
        [(".text", 0x10000, 0x10000, 0x1000, X), (".rsrc", 0x30000, 0x30000, 0x11000, R)],
        imports={"KERNEL32.dll": [f"Api{i}" for i in range(30)]},
    )
    score, reasons = structural.pe_structure_signals(p)
    assert any("资源段占比异常" in r for r in reasons)
    assert score >= structural.W_RSRC_RATIO


def test_small_rsrc_ratio_does_not_score(tmp_path: Path):
    """占比高但绝对体积很小（几个图标就占满）→ 不计分。"""
    p = build_pe(
        tmp_path / "icons.exe",
        [(".text", 0x400, 0x400, 0x1000, X), (".rsrc", 0x8000, 0x8000, 0x2000, R)],
        imports={"KERNEL32.dll": [f"Api{i}" for i in range(30)]},
    )
    _, reasons = structural.pe_structure_signals(p)
    assert not any("资源段占比异常" in r for r in reasons)


# ---------------------------------------------------------------- ④ 导入表稀疏（含 .NET 反误伤）

def test_sparse_imports_score(tmp_path: Path):
    p = build_pe(
        tmp_path / "loader.exe",
        [(".text", 0x8000, 0x8000, 0x1000, X), (".data", 0x1000, 0x400, 0x9000, W)],
        imports={"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualAlloc"]},
    )
    score, reasons = structural.pe_structure_signals(p)
    assert any("导入表稀疏" in r for r in reasons)
    assert score >= structural.W_SPARSE_IMPORTS


def test_dotnet_sparse_imports_not_scored(tmp_path: Path):
    """**.NET 的导入表天然只有 mscoree.dll 一条** —— 不能把每个 .NET 程序打成可疑。

    这是实测踩过的坑：Dike pilot 里 4 个良性样本全是 napi=1 的 .NET 程序。
    """
    p = build_pe(
        tmp_path / "app.exe",
        [(".text", 0x8000, 0x8000, 0x1000, X), (".reloc", 0x200, 0x200, 0x9000, R)],
        dotnet=True,
        imports={"mscoree.dll": ["_CorExeMain"]},
    )
    _, reasons = structural.pe_structure_signals(p)
    assert not any("导入表稀疏" in r for r in reasons)


def test_wide_imports_not_scored(tmp_path: Path, benign_pe: Path):
    _, reasons = structural.pe_structure_signals(benign_pe)
    assert not any("导入表稀疏" in r for r in reasons)


# ---------------------------------------------------------------- ⑤ 入口点不在可执行段

def test_entry_point_outside_executable_section_scores(tmp_path: Path):
    p = build_pe(
        tmp_path / "ep.exe",
        [(".data", 0x1000, 0x400, 0x1000, W), (".text", 0x8000, 0x8000, 0x2000, X)],
        entry_rva=0x1500,                       # 落在 .data（非可执行）里
        imports={"KERNEL32.dll": [f"Api{i}" for i in range(30)]},
    )
    score, reasons = structural.pe_structure_signals(p)
    assert any("入口点落在" in r and "未标记可执行" in r for r in reasons)
    assert score >= structural.W_EP_NOT_EXECUTABLE


def test_normal_entry_point_not_scored(tmp_path: Path, benign_pe: Path):
    _, reasons = structural.pe_structure_signals(benign_pe)
    assert not any("入口点落在" in r for r in reasons)


# ---------------------------------------------------------------- ⑥ 时间戳（极弱信号）

def test_future_timestamp_not_scored(tmp_path: Path):
    """未来时间戳**已弃用**（权重 0）—— 真实良性语料上是纯误报源。

    依据：MSVC 的确定性构建（/Brepro）把时间戳换成内容哈希，于是真实 Windows
    系统文件大量带"未来时间戳"（400 个良性里 22 个，2033/2051/2068/2103 都有），
    而本批 40 样本上零区分度（1 恶意 / 1 良性）。留着它 = 白送 22 个良性过阈值。
    """
    p = build_pe(
        tmp_path / "future.exe",
        [(".text", 0x8000, 0x8000, 0x1000, X), (".data", 0x1000, 0x400, 0x9000, W)],
        timestamp=4_102_444_800,                # 2100 年
        imports={"KERNEL32.dll": [f"Api{i}" for i in range(30)]},
    )
    score, reasons = structural.pe_structure_signals(p)
    assert score == 0, reasons
    assert not any("时间戳" in r for r in reasons)
    assert structural.W_FUTURE_TIMESTAMP == 0


def test_old_timestamp_not_scored(tmp_path: Path):
    """1970/1971 的"可复现构建"时间戳是**良性**常见形态（实测 4 个良性），不计分。"""
    p = build_pe(
        tmp_path / "repro.exe",
        [(".text", 0x8000, 0x8000, 0x1000, X), (".data", 0x1000, 0x400, 0x9000, W)],
        timestamp=86_400,
        imports={"KERNEL32.dll": [f"Api{i}" for i in range(30)]},
    )
    _, reasons = structural.pe_structure_signals(p)
    assert not any("时间戳" in r for r in reasons)


# ---------------------------------------------------------------- 反误伤：明确不采用的信号

def test_odd_section_names_not_scored(tmp_path: Path):
    """非常规段名（Go/Rust/.NET 本来就乱）实测反向相关 → 不计分。"""
    p = build_pe(
        tmp_path / "go.exe",
        [("Go.build", 0x8000, 0x8000, 0x1000, X), ("noptrdata", 0x1000, 0x400, 0x9000, W)],
        imports={"KERNEL32.dll": [f"Api{i}" for i in range(30)]},
    )
    _, reasons = structural.pe_structure_signals(p)
    assert not any("段名" in r for r in reasons)


def test_overlay_not_scored(tmp_path: Path, benign_pe: Path):
    """overlay 在实测里**反相关**（良性安装器普遍有、加壳恶意几乎没有）→ 不计分。"""
    data = benign_pe.read_bytes() + b"\x00" * 300_000
    benign_pe.write_bytes(data)
    _, reasons = structural.pe_structure_signals(benign_pe)
    assert not any("overlay" in r.lower() or "附加数据" in r for r in reasons)


# ---------------------------------------------------------------- 解释性 + 分发

def test_reason_format_is_self_explanatory(tmp_path: Path):
    """每条理由都必须带权重和读数 —— 报告里能看出这条分是谁给的。"""
    p = build_pe(
        tmp_path / "bad.exe",
        [(".text", 0x400, 0x400, 0x1000, WX), (".rsrc", 0x40000, 0x40000, 0x2000, R)],
        imports={"KERNEL32.dll": ["VirtualAlloc"]},
    )
    score, reasons = structural.pe_structure_signals(p)
    assert reasons and score > 0
    for r in reasons:
        assert r.startswith("结构信号 +")
        assert ":" in r
        # 权重之和 == 返回的分数（不多不少，可核对）
    total = sum(int(r.split("+", 1)[1].split(":", 1)[0]) for r in reasons)
    assert total == score


def test_non_pe_returns_zero(tmp_path: Path):
    p = tmp_path / "notes.txt"
    p.write_bytes(b"just text, no magic")
    assert structural.structure_signals(p, ".txt") == (0, [])


def test_unreadable_file_returns_zero(tmp_path: Path):
    missing = tmp_path / "nope.exe"
    assert structural.structure_signals(missing, ".exe") == (0, [])


def test_magic_beats_extension(tmp_path: Path):
    """挂着 .pdf 扩展名的 PE 也要走 PE 分支（投递样本的扩展名不可信）。"""
    p = build_pe(
        tmp_path / "invoice.pdf",
        [(".text", 0x400, 0x400, 0x1000, WX), (".rsrc", 0x40000, 0x40000, 0x2000, R)],
        imports={"KERNEL32.dll": ["VirtualAlloc"]},
    )
    score, reasons = structural.structure_signals(p, ".pdf")
    assert score > 0 and reasons


# ---------------------------------------------------------------- 与已有信号不重复计分

def test_no_double_count_with_packing_signals(tmp_path: Path):
    """`pe_packing_signals` 管"节名/熵"，结构信号管"数据分布/导入表形态" —— 两边不重叠。

    这里造一个**高熵但分布正常**的 PE：packing 会报高熵可执行段（+4，由调用方给），
    结构信号这边不应该再因为"高熵"给一次分。
    """
    import os

    p = build_pe(
        tmp_path / "packed.exe",
        [(".text", 0x8000, 0x8000, 0x1000, X), (".data", 0x1000, 0x400, 0x9000, W)],
        imports={"KERNEL32.dll": [f"Api{i}" for i in range(30)]},
    )
    raw = bytearray(p.read_bytes())
    # 把 .text 段数据换成伪随机字节（提高熵），但段表/导入表形态保持不变
    text_off = None
    import pefile  # type: ignore

    pe = pefile.PE(str(p), fast_load=True)
    text_off = int(pe.sections[0].PointerToRawData)
    text_size = int(pe.sections[0].SizeOfRawData)
    pe.close()
    raw[text_off:text_off + text_size] = os.urandom(text_size)
    p.write_bytes(bytes(raw))

    score, reasons = structural.pe_structure_signals(p)
    assert score == 0, reasons
    assert not any("熵" in r for r in reasons)


# ---------------------------------------------------------------- 反误伤：真实 Windows 良性语料上的坑

def test_code_less_image_not_scored(tmp_path: Path):
    """**无代码镜像**（入口点为 0 / 没有可执行段）不参与任何"代码形态"信号。

    实测：真实 Windows 系统文件里 41% 的 PE 入口点就是 0（`.mui`、`api-ms-win-core-*.dll`、
    `KBD*.DLL`、`mfc140*.dll`…）—— 对它们来说 `.text` 占 0%、导入表 0 条、`.rsrc` 占 99%
    全是**设计如此**。不加这道闸，真实良性语料在阈值 12 上的误报率是 7.0%（0/400 → 28/400）。
    """
    p = build_pe(
        tmp_path / "resources.dll.mui",
        [(".rdata", 0x200, 0x200, 0x1000, R), (".rsrc", 0x40000, 0x40000, 0x2000, R)],
        entry_rva=0,                              # 没有入口点 = 纯资源镜像
    )
    score, reasons = structural.pe_structure_signals(p)
    assert score == 0, reasons


def test_entry_point_in_non_executable_section_is_not_treated_as_code_less(tmp_path: Path):
    """⚠ 反误伤闸**只**认"入口点 == 0"，不能把"没有可执行段"也算进去。

    "入口点落在未标记可执行的段"本身就是**异常形态**（实测 Dike pilot 里 2 个恶意样本
    就是这样：`.text` 被标成可写但没标可执行）。第一版把"没有可执行段"也当成
    "无代码镜像"，于是这 2 个样本从 17 分掉回 5 分 —— 闸门吞掉了它本该报的东西。
    """
    p = build_pe(
        tmp_path / "noexec.exe",
        [(".data", 0x400, 0x400, 0x1000, W), (".text", 0x8000, 0x8000, 0x2000, W)],
        entry_rva=0x2500,                         # 非 0：这就是异常本身
        imports={"KERNEL32.dll": ["LoadLibraryA", "GetProcAddress", "VirtualAlloc"]},
    )
    score, reasons = structural.pe_structure_signals(p)
    assert any("未标记可执行" in r for r in reasons), reasons
    assert score > 0


def test_code_less_with_entry_point_zero_but_exec_section(tmp_path: Path):
    """API set 转发桩：有可执行 `.text` 但入口点为 0 —— 同样按无代码镜像处理。"""
    p = build_pe(
        tmp_path / "api-ms-win-core-x.dll",
        [(".text", 0x600, 0x600, 0x1000, X), (".rsrc", 0x400, 0x400, 0x2000, R)],
        entry_rva=0,
    )
    assert structural.pe_structure_signals(p) == (0, [])


def test_sparse_imports_without_dynamic_resolution_not_scored(tmp_path: Path):
    """"导入稀疏"的本意是**手工 shellcode loader**：少 DLL 却要动态解析。

    去掉这个前提后，真实 Windows 良性语料里 42% 的 PE 都"导入稀疏"，而其中
    带动态解析 API 的是 **0%** —— 所以"没有动态解析"就不该计分。
    """
    p = build_pe(
        tmp_path / "layout.dll",
        [(".text", 0x8000, 0x8000, 0x1000, X), (".data", 0x1000, 0x400, 0x9000, W)],
        entry_rva=0x1000,
        imports={"KERNEL32.dll": ["GetModuleHandleW", "RtlUnwind"]},
    )
    score, reasons = structural.pe_structure_signals(p)
    assert not any("导入表稀疏" in r for r in reasons), reasons
    assert score == 0, reasons
