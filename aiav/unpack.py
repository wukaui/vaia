"""加壳处理：静态壳识别 + UPX 静态脱壳。

铁律：
1. **绝不执行样本**。这里只做两类操作：`pefile` 只读解析、`upx -d`（解压工具，不是运行样本）。
2. **绝不改样本本体**：脱壳产物写到独立目录（`-o`），原件保持原样（单测会校验 sha256 不变）。
3. 脱壳产物**再进一次完整流程**（预筛 + AI），这样"结论不再停在壳里"；
   壳识别不出来（非 UPX）时至少把壳类型、判定信号标进报告，让人知道为什么看不见载荷。

被识别的壳：UPX / ASPack / PECompact / MPRESS / Themida·WinLicense / VMProtect / Enigma /
Petite / FSG / MEW / NsPack / RLPack / kkrunchy / tElock / Yoda / Obsidium / PELock / NeoLite，
以及"高熵 + 导入表极简"这一类通用加壳信号；另外把 .NET（mscoree）、NSIS、PyInstaller 这类
"不是壳但影响分析"的情况单独标注。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SECTION_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("UPX", ("upx0", "upx1", "upx2", "upx!")),
    ("ASPack", (".aspack", ".adata", "aspack")),
    ("PECompact", ("pec2", "pecompact", ".pec1", ".pec2")),
    ("MPRESS", (".mpress1", ".mpress2")),
    ("Themida/WinLicense", (".themida", ".winlice", "themida")),
    ("VMProtect", (".vmp0", ".vmp1", ".vmp2")),
    ("Enigma Protector", (".enigma1", ".enigma2")),
    ("Petite", (".petite", "petite")),
    ("FSG", ("fsg!",)),
    ("MEW", ("mew11", "mew")),
    ("NsPack", (".nsp0", ".nsp1", ".nsp2")),
    ("RLPack", (".rlpack",)),
    ("kkrunchy", (".kkrunchy",)),
    ("tElock", (".telock",)),
    ("Yoda's Protector", (".y0da", "y0da")),
    ("Obsidium", (".obsidium",)),
    ("PELock", (".pelock",)),
    ("NeoLite", ("neolite",)),
    ("PKLITE", ("pklite",)),
    ("WWPACK", ("wwpack",)),
    ("DIET", ("diet",)),
    ("PEBundle", ("pebundle",)),
    ("Shrinker", ("shrnk", "shrink")),
    ("MSVC Rich (非壳)", (".rich",)),
]

NON_PACKER_NOTES = {
    "mscoree.dll": ".NET 托管程序集（不是壳，但静态特征与传统 PE 不同）",
    "nullsoft": "NSIS 安装包",
    "pyi-": "PyInstaller 打包产物",
    "go:buildid": "Go 编译产物",
}


def _tool() -> str | None:
    from aiav.tools import _find_exe  # 复用统一的查找逻辑（PATH → Scripts → 环境变量覆盖）

    return _find_exe("upx", env_var="UPX_EXE")


def _sections(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    import pefile  # type: ignore

    pe = pefile.PE(str(path), fast_load=True)
    try:
        sections = []
        for s in getattr(pe, "sections", [])[:30]:
            name = s.Name.rstrip(b"\x00").decode("latin-1", errors="replace")
            sections.append({
                "name": name,
                "entropy": round(float(s.get_entropy()), 3),
                "raw_size": int(s.SizeOfRawData),
                "executable": bool(s.Characteristics & 0x20000000),
            })
        meta = {
            "timestamp": int(getattr(pe.FILE_HEADER, "TimeDateStamp", 0) or 0),
            "machine": hex(int(getattr(pe.FILE_HEADER, "Machine", 0) or 0)),
        }
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            imports = []
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
                imports.append(entry.dll.decode("latin-1", errors="replace"))
            meta["imports"] = sorted(set(imports))
        except Exception:  # noqa: BLE001
            meta["imports"] = []
        return sections, meta
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001
            pass


def _upx_list(path: Path, timeout: int = 60) -> dict[str, Any]:
    """`upx -l` 确认是不是 UPX 壳（只读列表，不解压）。"""
    exe = _tool()
    if not exe:
        return {"available": False}
    try:
        proc = subprocess.run([exe, "-l", str(path)], capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": True, "error": str(exc)[:200]}
    return {
        "available": True,
        "rc": proc.returncode,
        "is_upx": proc.returncode == 0,
        "stdout": proc.stdout.decode("utf-8", errors="replace")[:600],
        "stderr": proc.stderr.decode("utf-8", errors="replace")[:300],
    }


def detect_packer(path: Path) -> dict[str, Any]:
    """识别壳类型（只读）。返回 packed / packer / evidence / confidence。"""
    info: dict[str, Any] = {"path": str(path), "packed": False, "packer": None,
                            "evidence": [], "confidence": "none", "is_pe": False}
    try:
        with Path(path).open("rb") as f:
            if f.read(2) != b"MZ":
                return info
    except OSError as exc:
        info["error"] = str(exc)
        return info
    info["is_pe"] = True

    try:
        sections, meta = _sections(Path(path))
    except Exception as exc:  # noqa: BLE001
        info["error"] = f"PE 解析失败: {exc}"
        return info

    names = [s["name"].lower() for s in sections]
    for packer, needles in SECTION_SIGNATURES:
        hit = [n for n in names if any(needle in n for needle in needles)]
        if hit:
            info.update({"packed": True, "packer": packer, "confidence": "high",
                         "evidence": [f"节区名命中: {', '.join(sorted(set(hit)))}"]})
            break

    if not info["packed"]:
        # 通用加壳信号：入口节高熵 + 可执行节整体高熵 + 导入表极简
        exec_sections = [s for s in sections if s["executable"] and s["raw_size"] > 0]
        high_entropy = [s["name"] for s in exec_sections if s["entropy"] >= 7.2]
        imports = meta.get("imports") or []
        if high_entropy and len(imports) <= 5:
            info.update({"packed": True, "packer": "unknown-packer", "confidence": "medium",
                         "evidence": [f"高熵可执行节区: {', '.join(high_entropy)}",
                                      f"导入表极简（{len(imports)} 个 DLL）"]})
        elif high_entropy:
            info.update({"packed": True, "packer": "maybe-packed", "confidence": "low",
                         "evidence": [f"高熵可执行节区: {', '.join(high_entropy)}"]})

    # UPX 兜底确认（节区名可能被改）
    upx = _upx_list(Path(path))
    if upx.get("is_upx"):
        info.update({"packed": True, "packer": "UPX", "confidence": "high",
                     "evidence": info["evidence"] + ["upx -l 确认为 UPX 压缩"]})
    info["upx_list"] = upx

    # 非壳但影响分析的产物
    try:
        blob = Path(path).read_bytes()[: 2 * 1024 * 1024].lower()
        for needle, note in NON_PACKER_NOTES.items():
            if needle.encode() in blob:
                info.setdefault("notes", []).append(note)
    except OSError:
        pass

    info["sections"] = sections[:12]
    info["imports_count"] = len(meta.get("imports") or [])
    return info


def upx_unpack(path: Path, work_dir: Path, timeout: int = 120) -> dict[str, Any]:
    """用 `upx -d` 静态脱壳到 work_dir（不动原件）。"""
    result: dict[str, Any] = {"ok": False, "path": str(path), "work_dir": str(work_dir)}
    exe = _tool()
    if not exe:
        result["error"] = "upx 不在 PATH（可设 UPX_EXE）"
        return result

    path = Path(path)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    out = work_dir / f"{path.stem}.unpacked{path.suffix or '.bin'}"
    if out.exists():
        out.unlink()
    cmd = [exe, "-d", "-q", "-f", "-o", str(out), str(path)]
    result["command"] = cmd                       # 留痕：只有 -d，没有执行样本的动作
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        result["error"] = f"upx -d 超时（>{timeout}s）"
        return result
    except OSError as exc:
        result["error"] = f"upx 调用失败: {exc}"
        return result

    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    result.update({"returncode": proc.returncode, "stdout": stdout[-500:], "stderr": stderr[-300:]})
    if proc.returncode != 0 or not out.is_file():
        result["error"] = "upx -d 未能解出文件（可能不是 UPX 壳或已损坏）"
        return result

    # 校验产物确实是 PE，并给出"壳是否真的掉了"的证据
    try:
        after = detect_packer(out)
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"脱壳产物解析失败: {exc}"
        return result
    result.update({
        "ok": True,
        "output": str(out),
        "size": out.stat().st_size,
        "packer_after": after.get("packer"),
        "still_packed": bool(after.get("packed")),
        "sections_after": after.get("sections"),
        "imports_count_after": after.get("imports_count"),
    })
    return result


def prepare_unpacked(path: Path, work_dir: Path, enable: bool = True) -> dict[str, Any]:
    """一步到位：识别壳 → 能解就解。返回给报告用的壳信息（含脱壳产物路径）。"""
    info = detect_packer(path)
    if not enable:
        info["unpack"] = {"ok": False, "skipped": "已关闭（--no-unpack）"}
        return info
    if not info.get("packed"):
        info["unpack"] = {"ok": False, "skipped": "未检出壳"}
        return info
    if (info.get("packer") or "").upper().startswith("UPX"):
        info["unpack"] = upx_unpack(path, work_dir)
    else:
        info["unpack"] = {"ok": False,
                          "skipped": f"暂不支持自动脱壳的壳类型: {info.get('packer')}（已在报告标注）"}
    return info


def default_work_dir() -> Path:
    """脱壳产物目录：放状态目录下，便于报告里给出可复查的路径。"""
    from aiav.disposition import default_store

    return Path(os.getenv("AI_AV_UNPACK_DIR", str(default_store().root / "unpacked")))


def cleanup_work_dir(work_dir: Path, keep: bool = False) -> dict[str, Any]:
    if keep or not Path(work_dir).is_dir():
        return {"removed": 0, "kept": True}
    n = 0
    for f in Path(work_dir).iterdir():
        if f.is_file():
            f.unlink()
            n += 1
    return {"removed": n, "kept": False}


def main() -> None:  # 手工排查用：python unpack.py <file>
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if not target:
        print("用法: python unpack.py <PE 文件>", file=sys.stderr)
        raise SystemExit(2)
    info = prepare_unpacked(target, default_work_dir())
    print(json.dumps(info, ensure_ascii=False, indent=2)[:4000])
    _ = shutil.which("true")  # 保持 shutil 引用（部分环境里用于工具探测）


if __name__ == "__main__":
    main()
