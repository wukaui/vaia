"""压缩包递归：把 zip / 7z / tar 里的内嵌样本解出来进扫描流程（纯静态解包，绝不执行）。

三道安全闸（对着 zip bomb 与 zip slip 来）：

1. **防路径穿越（zip slip）**：自己遍历条目、清洗名字，绝不调用 `ZipFile.extractall()`；
   任何绝对路径、`..`、盘符、符号链接目标都被拒绝，产物只能落在允许的解包目录内。
2. **防解压炸弹**：单文件大小、总解压体积、解压比（解压后/压缩前）、文件数、递归层数五个上限；
   超限即停止并记 `truncated=True` + `skipped` 原因，不硬扛。
3. **绝不执行**：只用 `zipfile`/`tarfile` 读，和 `7z x`（仅解压；`-y` 覆盖、不调用外部程序）。

解包产物落在状态目录下的 `archives/`（`AI_AV_ARCHIVE_DIR` 可覆盖），原件不动。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ZIP_EXTS = {".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".whl", ".nupkg"}
SEVENZIP_EXTS = {".7z", ".rar", ".cab", ".iso", ".gz", ".bz2", ".xz", ".tgz"}
ARCHIVE_EXTS = ZIP_EXTS | SEVENZIP_EXTS


@dataclass
class ArchiveLimits:
    """解压上限（默认值对着"比赛/评测用"的规模设，可调）。"""

    max_depth: int = 2                 # 递归层数（外层算第 1 层）
    max_files: int = 200               # 单个压缩包最多解出多少文件
    max_total_bytes: int = 200 * 1024 * 1024   # 单层解压总字节
    max_file_bytes: int = 50 * 1024 * 1024     # 单个文件上限
    max_ratio: float = 100.0           # 解压比上限（解压后/压缩包本体）
    timeout_seconds: int = 120         # 外部 7z 解压超时


@dataclass
class ExtractResult:
    ok: bool = False
    kind: str | None = None
    work_dir: str = ""
    files: list[str] = field(default_factory=list)
    nested: list[str] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    truncated: bool = False
    errors: list[str] = field(default_factory=list)
    depth: int = 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "kind": self.kind, "work_dir": self.work_dir,
            "files": self.files, "nested": self.nested, "skipped": self.skipped[:20],
            "truncated": self.truncated, "errors": self.errors[:5], "depth": self.depth,
        }


def detect_archive(path: Path) -> dict[str, Any]:
    """按扩展名 + 文件头判断是不是压缩包（避免只看扩展名误判）。"""
    path = Path(path)
    ext = path.suffix.lower()
    info: dict[str, Any] = {"path": str(path), "is_archive": False, "kind": None,
                            "supported": False, "evidence": []}
    try:
        with path.open("rb") as f:
            head = f.read(512)
    except OSError as exc:
        info["error"] = str(exc)
        return info

    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        info.update({"is_archive": True, "kind": "zip", "supported": True,
                     "evidence": ["文件头 PK\\x03\\x04"]})
    elif head[:2] == b"MZ":
        return info
    elif head[:6] == b"7z\xbc\xaf\x27\x1c":
        info.update({"is_archive": True, "kind": "7z", "supported": _has_7z(),
                     "evidence": ["文件头 7z\\xbc\\xaf\\x27\\x1c"]})
    elif head[:4] == b"Rar!":
        info.update({"is_archive": True, "kind": "rar", "supported": _has_7z(),
                     "evidence": ["文件头 Rar!"]})
    elif head[:2] == b"\x1f\x8b":
        info.update({"is_archive": True, "kind": "gzip", "supported": _has_7z() or tarfile.is_tarfile(str(path)),
                     "evidence": ["文件头 \\x1f\\x8b"]})
    elif head[:5] == b"ustar" or (len(head) >= 262 and head[257:262] == b"ustar"):
        info.update({"is_archive": True, "kind": "tar", "supported": True,
                     "evidence": ["tar magic"]})
    if not info["is_archive"] and ext in ARCHIVE_EXTS:
        # 扩展名像压缩包但文件头不对：标注一下，不硬解
        info["evidence"].append(f"扩展名 {ext} 像压缩包但文件头不匹配")
    return info


def _has_7z() -> bool:
    return shutil.which("7z") is not None


def _sevenzip_exe() -> str | None:
    for name in ("7z", "7za", "7zr", "7zz"):
        exe = shutil.which(name)
        if exe:
            return exe
    return None


def _safe_name(name: str) -> str | None:
    """清洗条目名：拒绝绝对路径 / 盘符 / .. / 空名。返回可用的相对名或 None。"""
    if not name:
        return None
    n = name.replace("\\", "/").lstrip("/")
    if len(n) > 1 and n[1] == ":":
        return None
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    parts = [p for p in parts if p != "__MACOSX"]
    if not parts:
        return None
    return "/".join(parts)


def _within(base: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except (ValueError, OSError):
        return False


def _limits_from_env() -> ArchiveLimits:
    def _int(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, str(default)))
        except ValueError:
            return default

    return ArchiveLimits(
        max_depth=_int("AI_AV_ARCHIVE_MAX_DEPTH", 2),
        max_files=_int("AI_AV_ARCHIVE_MAX_FILES", 200),
        max_total_bytes=_int("AI_AV_ARCHIVE_MAX_TOTAL_MB", 200) * 1024 * 1024,
        max_file_bytes=_int("AI_AV_ARCHIVE_MAX_FILE_MB", 50) * 1024 * 1024,
        max_ratio=float(os.getenv("AI_AV_ARCHIVE_MAX_RATIO", "100")),
    )


def extract_zip(path: Path, work_dir: Path, limits: ArchiveLimits) -> ExtractResult:
    res = ExtractResult(kind="zip", work_dir=str(work_dir))
    try:
        archive_size = max(1, Path(path).stat().st_size)
        with zipfile.ZipFile(path) as zf:
            total = 0
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = _safe_name(info.filename)
                if name is None:
                    res.skipped.append({"entry": info.filename, "reason": "路径不安全（zip slip）"})
                    continue
                if len(res.files) >= limits.max_files:
                    res.truncated = True
                    res.skipped.append({"entry": info.filename, "reason": f"超过文件数上限 {limits.max_files}"})
                    continue
                if info.file_size > limits.max_file_bytes:
                    res.skipped.append({"entry": info.filename, "reason": "单文件超过上限"})
                    continue
                if info.file_size / archive_size > limits.max_ratio:
                    res.truncated = True
                    res.skipped.append({"entry": info.filename,
                                        "reason": f"解压比超过 {limits.max_ratio}（疑似解压炸弹）"})
                    continue
                if total + info.file_size > limits.max_total_bytes:
                    res.truncated = True
                    res.skipped.append({"entry": info.filename, "reason": "总解压体积超过上限"})
                    continue
                target = work_dir / name
                if not _within(work_dir, target):
                    res.skipped.append({"entry": info.filename, "reason": "目标路径越界"})
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with zf.open(info) as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
                except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
                    res.errors.append(f"{name}: {type(exc).__name__}: {exc}"[:160])
                    continue
                total += target.stat().st_size
                res.files.append(str(target))
        res.ok = True
    except zipfile.BadZipFile as exc:
        res.errors.append(f"坏 zip: {exc}")
    except OSError as exc:
        res.errors.append(f"读取失败: {exc}")
    return res


def extract_tar(path: Path, work_dir: Path, limits: ArchiveLimits) -> ExtractResult:
    res = ExtractResult(kind="tar", work_dir=str(work_dir))
    try:
        archive_size = max(1, Path(path).stat().st_size)
        total = 0
        with tarfile.open(path) as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue          # 目录/符号链接/设备一律不解
                name = _safe_name(member.name)
                if name is None:
                    res.skipped.append({"entry": member.name, "reason": "路径不安全或非常规文件"})
                    continue
                if len(res.files) >= limits.max_files:
                    res.truncated = True
                    res.skipped.append({"entry": member.name, "reason": "超过文件数上限"})
                    continue
                if member.size > limits.max_file_bytes or member.size / archive_size > limits.max_ratio:
                    res.truncated = True
                    res.skipped.append({"entry": member.name, "reason": "体积/解压比超限"})
                    continue
                if total + member.size > limits.max_total_bytes:
                    res.truncated = True
                    res.skipped.append({"entry": member.name, "reason": "总解压体积超限"})
                    continue
                target = work_dir / name
                if not _within(work_dir, target):
                    res.skipped.append({"entry": member.name, "reason": "目标路径越界"})
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                with fh, target.open("wb") as dst:
                    shutil.copyfileobj(fh, dst, length=1024 * 1024)
                total += target.stat().st_size
                res.files.append(str(target))
        res.ok = True
    except (tarfile.TarError, OSError) as exc:
        res.errors.append(f"tar 解包失败: {exc}")
    return res


def extract_7z(path: Path, work_dir: Path, limits: ArchiveLimits) -> ExtractResult:
    """用 7z CLI 解压（只解压，不执行任何内容）。先列表算体积，超限就不解。"""
    res = ExtractResult(kind="7z", work_dir=str(work_dir))
    exe = _sevenzip_exe()
    if not exe:
        res.errors.append("系统里没有 7z，无法解压该格式")
        return res
    try:
        listing = subprocess.run([exe, "l", "-slt", str(path)], capture_output=True,
                                 timeout=limits.timeout_seconds)
    except (subprocess.TimeoutExpired, OSError) as exc:
        res.errors.append(f"列表失败: {exc}")
        return res
    text = listing.stdout.decode("utf-8", errors="replace")
    sizes = [int(m) for m in __import__("re").findall(r"^Size = (\d+)$", text, flags=__import__("re").M)]
    names = __import__("re").findall(r"^Path = (.+)$", text, flags=__import__("re").M)
    archive_size = max(1, Path(path).stat().st_size)
    total = sum(sizes)
    if len(names) > limits.max_files:
        res.truncated = True
        res.skipped.append({"entry": "*", "reason": f"条目数 {len(names)} 超过上限 {limits.max_files}"})
        return res
    if total > limits.max_total_bytes or total / archive_size > limits.max_ratio:
        res.truncated = True
        res.skipped.append({"entry": "*", "reason": f"解压后总体积 {total} 超出上限/解压比"})
        return res
    if any(s > limits.max_file_bytes for s in sizes):
        res.truncated = True
        res.skipped.append({"entry": "*", "reason": "存在单文件超限"})
        return res

    out_dir = work_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "x", "-y", "-bd", "-bso0", "-bsp0", f"-o{out_dir}", str(path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=limits.timeout_seconds)
    except (subprocess.TimeoutExpired, OSError) as exc:
        res.errors.append(f"解压失败: {exc}")
        return res
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace")[:200]
        res.errors.append(f"7z 返回 {proc.returncode}: {err}")
        return res

    # ---- 事后审计闸（外部审查 P2-2）----
    # 上面那四道闸读的是 `7z l -slt` 的 **声称**体积 —— 那是压缩包头里的数字，
    # 与真实落盘可以不一致（头部被改小、非常规打包器、流式条目…）。所以解压完必须
    # **复核实际落盘体积**，并且把越界/超额产物**删掉**：
    # 旧实现只 `continue` 跳过收集，文件还躺在磁盘上 —— 扫描目录之外的字节照样落地，
    # 而"四道闸"的承诺就此落空。
    res.files = _audit_extracted(res, out_dir, limits, claimed_total=total,
                                 archive_size=archive_size)
    res.ok = True
    return res


def _audit_extracted(res: ExtractResult, out_dir: Path, limits: ArchiveLimits,
                     claimed_total: int, archive_size: int) -> list[str]:
    """事后复核真实落盘体积：越界 / 超单文件 / 超总量的产物**删掉**，并记账。

    单独抽成函数是为了能直接测它（"声称"与"实际"不一致的 7z 不好手工构造，
    但这一层的行为必须被钉住）。返回通过审计的文件列表。
    """
    kept: list[str] = []
    actual_total = 0
    for f in sorted(out_dir.rglob("*")):
        if not f.is_file():
            continue
        size = f.stat().st_size
        if not _within(out_dir, f):
            _remove_artifact(f)
            res.skipped.append({"entry": str(f), "reason": "解压产物越界（已删除）"})
            res.truncated = True
            continue
        if size > limits.max_file_bytes:
            _remove_artifact(f)
            res.skipped.append({"entry": str(f), "reason": "实际体积超过单文件上限（已删除）"})
            res.truncated = True
            continue
        if actual_total + size > limits.max_total_bytes:
            _remove_artifact(f)
            res.skipped.append({"entry": str(f), "reason": "实际解压总量超过上限（已删除）"})
            res.truncated = True
            continue
        actual_total += size
        kept.append(str(f))
    if actual_total / max(1, archive_size) > limits.max_ratio:
        res.truncated = True
        res.skipped.append({
            "entry": "*",
            "reason": f"实际解压比 {actual_total / max(1, archive_size):.1f} 超过上限 {limits.max_ratio}",
        })
    if actual_total != claimed_total:
        # 声称与实际不一致本身就要记账：人工复核时能看出这道闸在看什么
        res.skipped.append({
            "entry": "*",
            "reason": f"7z 声称解压后 {claimed_total} 字节，实际落盘 {actual_total} 字节（以实际为准）",
        })
    if len(kept) > limits.max_files:
        res.truncated = True
        res.skipped.append({"entry": "*", "reason": f"实际文件数 {len(kept)} 超过上限 {limits.max_files}"})
    return kept


def _remove_artifact(path: Path) -> None:
    """删掉一个越界/超额的解压产物（顺带清空目录，别留下空壳）。"""
    try:
        path.unlink()
    except OSError:
        return
    parent = path.parent
    try:
        while parent != parent.parent and not any(parent.iterdir()):
            parent.rmdir()
            parent = parent.parent
    except OSError:
        pass


def extract_archive(path: Path, work_dir: Path, limits: ArchiveLimits | None = None,
                    depth: int = 1) -> ExtractResult:
    """解压一个压缩包（含深度受限的嵌套递归）。"""
    limits = limits or _limits_from_env()
    path = Path(path)
    info = detect_archive(path)
    res = ExtractResult(kind=info.get("kind"), work_dir=str(work_dir), depth=depth)
    if not info.get("is_archive"):
        res.errors.append("不是可识别的压缩包")
        return res
    if not info.get("supported"):
        res.errors.append(f"格式 {info.get('kind')} 在本环境不支持（缺 7z）")
        return res

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    kind = info.get("kind")
    if kind == "zip":
        res = extract_zip(path, work_dir, limits)
    elif kind == "tar":
        res = extract_tar(path, work_dir, limits)
    elif kind in ("7z", "rar", "gzip", "cab", "iso"):
        res = extract_7z(path, work_dir, limits)
    else:
        res.errors.append(f"未处理的类型: {kind}")
        return res
    res.depth = depth

    # 嵌套压缩包：深度受限地继续解
    for f in list(res.files):
        child = Path(f)
        if child.suffix.lower() in ARCHIVE_EXTS and detect_archive(child).get("is_archive"):
            if depth >= limits.max_depth:
                res.truncated = True
                res.skipped.append({"entry": child.name,
                                    "reason": f"嵌套层数达到上限 {limits.max_depth}"})
                continue
            res.nested.append(str(child))
            nested_dir = work_dir / f"{child.stem}_unpacked"
            sub = extract_archive(child, nested_dir, limits, depth=depth + 1)
            res.files.extend(sub.files)
            res.skipped.extend(sub.skipped)
            res.errors.extend(sub.errors)
            res.truncated = res.truncated or sub.truncated
    return res


def default_archive_dir() -> Path:
    from aiav.disposition import default_store

    return Path(os.getenv("AI_AV_ARCHIVE_DIR", str(default_store().root / "archives")))


def work_dir_for(path: Path, sha256: str = "") -> Path:
    """每个压缩包一个独立解包目录（按名字 + sha 前缀，避免互相污染）。"""
    tag = (sha256[:8] + "_") if sha256 else ""
    return default_archive_dir() / f"{tag}{Path(path).stem}"


def cleanup(path: Path, keep: bool = False) -> dict[str, Any]:
    d = Path(path)
    if keep or not d.is_dir():
        return {"removed": 0, "kept": True}
    shutil.rmtree(d, ignore_errors=True)
    return {"removed": 1, "kept": False}
