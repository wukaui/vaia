"""capa 外部语料的获取：规则集 + 签名集。

为什么要有这个模块：capa 是**必装工具**（能力识别 + ATT&CK 映射），但 pip 包
不自带规则和签名 —— `flare-capa` 9.4.0 的 `capa/rules/` 是空目录、`capa/sigs/`
压根不存在。把"自己想办法弄到语料"写进 README 当手工步骤，实测后果就是：
63 文件基准跑完，`capa_scan` 一次都没被调用过，AI 只能在结论里写"capa 不可用"。
必装的工具，获取就必须是一条命令。

版本对齐：规则集和签名集都从 `mandiant/capa*` 的**同一个 tag** 拉，
tag 取自本机 capa 二进制的版本号。版本错配时 capa 会报规则不兼容。
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tarfile
import urllib.request
from pathlib import Path

from aiav.tools import (
    _find_exe,
    capa_data_root,
    capa_ready,
    capa_rules_dir,
    capa_sigs_dir,
)

TIMEOUT = 120
_UA = {"User-Agent": "aiav-capa-setup"}
# 签名集清单：记下"本该有几个 .sig"，用来发现静默残缺
_MANIFEST = "_expected.json"

# GitHub API 未认证限流 60 次/时，被限了就用这份兜底清单（v9.4.0 实测文件名）。
_SIG_FALLBACK = [
    "1_flare_msvc_rtf_32_64.sig",
    "2_flare_msvc_atlmfc_32_64.sig",
    "3_flare_common_libs.sig",
]


def capa_version() -> str | None:
    """本机 capa 的版本号（`9.4.0`），取不到返回 None。

    先问二进制（`capa --version` → `capa 9.4.0`），再退回包元数据。
    必须以二进制为准：`CAPA_EXE` 可以指向一个和 pip 包版本不同的独立可执行文件。
    """
    exe = _find_exe("capa", env_var="CAPA_EXE")
    if exe:
        try:
            out = subprocess.run(
                [exe, "--version"], capture_output=True, timeout=30
            ).stdout.decode("utf-8", errors="replace")
            for token in out.split():
                if token[:1].isdigit() and token.count(".") >= 2:
                    return token.strip()
        except Exception:  # noqa: BLE001 - 取不到就退回元数据
            pass
    try:
        from importlib.metadata import version

        return version("flare-capa")
    except Exception:  # noqa: BLE001
        return None


def _expected_sig_count(sigs: Path) -> int:
    """`capa-setup` 记下的"本该有几个签名"，没记过就返回 0（不判断残缺）。"""
    try:
        data = json.loads((sigs / _MANIFEST).read_text(encoding="utf-8"))
        return len(data.get("sigs") or [])
    except Exception:  # noqa: BLE001 - 老目录没有清单是正常的
        return 0


def _get(url: str, dest: Path | None = None, attempts: int = 5) -> bytes:
    """下载 url。给了 dest 就**流式写盘 + 断点续传 + 重试**。

    为什么这么啰嗦：raw.githubusercontent.com 从国内拉 7.5MB 的 .sig 实测 ~20KB/s，
    120 秒读超时会在下到一半时炸掉。一次性 `resp.read()` 的写法下不了这两个文件
    —— 实测 3 个签名只拿到 1 个，而且是**成功退出**（静默少一批编译器签名，
    正是"必装工具静默降级"的老毛病）。所以：超时了带着 Range 头从断点接着下，最多 5 轮。
    """
    last_exc: Exception | None = None
    for _ in range(attempts):
        done = dest.stat().st_size if (dest and dest.is_file()) else 0
        headers = dict(_UA)
        if done:
            headers["Range"] = f"bytes={done}-"
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=TIMEOUT
            ) as resp:
                total = int(resp.headers.get("Content-Length") or 0)
                if dest is None:
                    return resp.read()
                dest.parent.mkdir(parents=True, exist_ok=True)
                resume = bool(done) and resp.status == 206
                start = done if resume else 0
                if not resume:
                    done = 0
                with dest.open("ab" if resume else "wb") as fh:
                    while True:
                        chunk = resp.read(64 * 1024)
                        if not chunk:
                            break
                        fh.write(chunk)
                        done += len(chunk)
                        if total:
                            print(f"      {dest.name} {done * 100 // (total + start)}%", flush=True)
                return b""
        except Exception as exc:  # noqa: BLE001 - 断了就从断点续
            last_exc = exc
            # 416 = 断点已经到文件末尾了，说明上一轮其实下完了
            if getattr(exc, "code", None) == 416 and dest is not None:
                return b""
            got = dest.stat().st_size if (dest and dest.is_file()) else 0
            print(f"      {dest.name if dest else url} 中断（已收 {got}B），续传 …", flush=True)
    raise last_exc if last_exc else RuntimeError("download failed")


def _extract_rules(blob: bytes, dest: Path) -> int:
    """把 capa-rules 的 tar.gz 解出 `*.yml` 到 dest，返回写入的文件数。

    自己遍历成员而不是 `extractall`：tarball 里顶层是 `capa-rules-<ver>/`，
    直接解会多套一层；顺带挡掉 `..` 之类的路径穿越。
    """
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    written = 0
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith((".yml", ".yaml")):
                continue
            parts = Path(member.name).parts[1:]  # 去掉 capa-rules-<ver>/
            if not parts or ".." in parts:
                continue
            target = dest.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tar.extractfile(member)
            if src is None:
                continue
            target.write_bytes(src.read())
            written += 1
    return written


def _sig_names(version: str) -> list[str]:
    url = f"https://api.github.com/repos/mandiant/capa/contents/sigs?ref=v{version}"
    try:
        data = json.loads(_get(url).decode("utf-8"))
        names = [it["name"] for it in data if it.get("name", "").endswith(".sig")]
        if names:
            return names
    except Exception:  # noqa: BLE001 - 限流/离线都退回清单
        pass
    return list(_SIG_FALLBACK)


def fetch(version: str | None = None, quiet: bool = False, force: bool = False) -> tuple[bool, str]:
    """拉取规则集 + 签名集到 `capa_data_root()`。返回 (成功, 说明)。

    已存在的语料默认跳过（下载慢，重跑不该重下）；`force=True` 强制重来。
    """
    def say(msg: str) -> None:
        if not quiet:
            print(msg, flush=True)

    version = version or capa_version()
    if not version:
        return False, (
            "拿不到 capa 版本号 —— 先装 capa（`pip install flare-capa`），"
            "或设 CAPA_EXE 指向已有的 capa 可执行文件"
        )

    root = capa_data_root()
    root.mkdir(parents=True, exist_ok=True)
    say(f"capa {version} → {root}")

    # 规则集
    rules_dir = root / "capa-rules"
    have_rules = len(list(rules_dir.glob("**/*.yml"))) if rules_dir.is_dir() else 0
    if have_rules and not force:
        say(f"  规则集已就位（{have_rules} 条），跳过；要重下拉加 --force")
        count = have_rules
    else:
        say("  拉规则集 capa-rules …（约 6MB）")
        try:
            blob = _get(
                f"https://codeload.github.com/mandiant/capa-rules/tar.gz/refs/tags/v{version}"
            )
            count = _extract_rules(blob, rules_dir)
        except Exception as exc:  # noqa: BLE001
            return False, f"规则集下载/解包失败: {exc}"
        if count < 100:
            return False, f"规则集只解出 {count} 个 yml，明显不对（正常 1000+），已放弃"
        say(f"  ✓ {count} 条规则")

    # 签名集
    names = _sig_names(version)
    sigs = root / "capa-sigs"
    sigs.mkdir(parents=True, exist_ok=True)
    # 记下"本该有几个"，让 `aiav tools` 能离线看出签名集是否残缺 ——
    # 少一个 .sig 不会报错，只会静默少认一批编译器签名，这种降级必须可见。
    (sigs / _MANIFEST).write_text(
        json.dumps({"version": version, "sigs": names}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    say(f"  拉签名集 {len(names)} 个文件 …（共约 15MB，raw.githubusercontent 慢，耐心等）")
    got = 0
    missing: list[str] = []
    for name in names:
        target = sigs / name
        if target.is_file() and target.stat().st_size > 0 and not force:
            got += 1
            say(f"      {name} 已在，跳过")
            continue
        url = f"https://raw.githubusercontent.com/mandiant/capa/v{version}/sigs/{name}"
        try:
            _get(url, dest=target)
            got += 1
        except Exception as exc:  # noqa: BLE001 - 单个签名失败不该让整步失败
            missing.append(name)
            say(f"  ! {name} 失败: {exc}")
    if got == 0:
        return False, f"签名集一个都没拉到（{len(names)} 个候选全失败）"
    if missing:
        # 部分成功也要说清楚缺了什么，别报一句"成功"了事
        return True, (
            f"规则 {count} 条 / 签名 {got}/{len(names)} 个 —— "
            f"缺 {', '.join(missing)}，capa 能跑但会少认一批编译器签名；"
            f"重跑 `aiav capa-setup` 会断点续传 → {root}"
        )
    return True, f"规则 {count} 条 / 签名 {got} 个 → {root}"


def status() -> tuple[bool, str]:
    """给 CLI 用的一行状态。"""
    exe = _find_exe("capa", env_var="CAPA_EXE")
    rules = capa_rules_dir()
    sigs = capa_sigs_dir()
    n_rules = len(list(rules.glob("**/*.yml"))) if rules.is_dir() else 0
    n_sigs = len(list(sigs.glob("*.sig"))) if sigs.is_dir() else 0
    expect = _expected_sig_count(sigs)
    ok = bool(exe) and n_rules > 0 and n_sigs > 0
    sig_label = f"签名 {n_sigs} 个" if not expect else f"签名 {n_sigs}/{expect} 个"
    complete = not expect or n_sigs >= expect
    parts = [
        f"capa {'✓' if exe else '✗'}",
        f"规则 {n_rules} 条{'✓' if n_rules else '✗'}",
        f"{sig_label}{'✓' if complete and n_sigs else '✗'}",
    ]
    if not ok and exe:
        parts.append("→ 跑 `aiav capa-setup`")
    elif not complete:
        parts.append("→ 签名集残缺，重跑 `aiav capa-setup` 续传")
    return ok, "  ".join(parts)


def capa_ready_or_note() -> str | None:
    """capa 不可用时返回一句人话（给扫描启动时的告警用），可用时返回 None。"""
    ok, why = capa_ready()
    if ok:
        return None
    return f"capa 不可用：{why}。capa 是必装工具，缺失会让能力识别与 ATT&CK 映射整块消失。"


__all__ = ["capa_version", "fetch", "status", "capa_ready_or_note"]
