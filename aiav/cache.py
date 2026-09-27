"""扫描缓存 / 断点续扫：按 sha256 缓存"分析结论"，不缓存"处置状态"。

设计要点（对着踩过的坑）：

1. **键 = 内容 sha256**：同一份内容（哪怕换了文件名/路径）直接命中，天然支持"断点续扫"：
   同一个目录重跑只扫新文件。
2. **不缓存处置状态**：白名单、隔离状态每次扫描都重新判定（缓存里只存分析结论），
   否则"隔离过的文件"会被缓存伪装成没隔离过。
3. **不缓存降级结果**：规则模式下算出来的条目，在有 AI 的run 里**不许命中**
   （否则 AI 被静默跳过 —— 这正是 `docs/DEFENSE...` 那次"看着跑了 AI 其实没跑"的同类风险）。
4. **采样口径一致**：缓存条目记录采样次数，请求次数大于缓存条目时不算命中。
5. **版本/指纹失效**：`CACHE_VERSION`、规则文件指纹（rules/*.yar + known_bad_hashes.txt）、
   系统提示词指纹任一变化即整体失效，避免改了规则还吃旧结论。

缓存目录默认 `<state>/cache/`（`AI_AV_CACHE_DIR` 可覆盖），不进仓库。
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from aiav.models import FileReport

CACHE_VERSION = "6"          # 改报告结构/语义时 +1，让旧条目整体失效


def _file_fingerprint(path: Path) -> str:
    """文件指纹 = **内容哈希**（读不到时退化为"缺失 + 路径"，不静默当成空文件）。

    为什么不用 mtime：这条指纹决定"规则/白名单/提示词变了就整体失效"，而 mtime 两个方向都会错 ——
      · 等长内容替换 + mtime 被复原（git checkout / rsync -t / 手工 utime）→ **漏失效**，
        旧结论继续吃新规则；
      · 内容一模一样、只是被 touch 一下 → **无谓失效**，整个缓存白跑一遍。
    内容哈希没有这两种歧义。规则文件与白名单都很小（几十 KB），哈希成本可以忽略。
    """
    h = hashlib.sha256()
    h.update(f"{path.name}:".encode())
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        # 读不到就按"这份文件此刻不可信"处理：把路径与缺失状态写进去，
        # 不同路径不会撞车，也不会被当成"空文件"（空文件是有意义的合法内容）。
        h.update(f"missing:{path}".encode())
    return h.hexdigest()


def rules_fingerprint() -> str:
    """规则与哈希库的指纹（内容/大小/时间任一变化都会变）。"""
    try:
        from aiav import tools
        rules_dir = Path(tools.RULES_DIR)
        hashes = Path(tools.KNOWN_BAD_HASHES_FILE)
    except Exception:  # noqa: BLE001
        return "unknown"
    h = hashlib.sha256()
    for f in sorted(list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))):
        h.update(_file_fingerprint(f).encode())
    h.update(_file_fingerprint(hashes).encode())
    return h.hexdigest()[:16]


def clamav_fingerprint() -> str:
    """ClamAV **引擎 + 签名库**的指纹（没有它，AV 层的结论会被跨库版本重放）。

    实测踩过（2026-09-27）：一次 ClamAV 批次超时（整批一条结果行都没有）跑出来的报告被写进缓存，
    机器安静下来、ClamAV 跑成之后**重跑还是吃那批"没有 AV 证据"的旧结论** ——
    送审率 0.31% 被缓存重放成 3.45%，而且报告里看不出是缓存干的。
    规则文件变了要整体失效（见 `rules_fingerprint`），**AV 签名库每天更新，同理**。

    "没装 / 没跑成"也是一个指纹值（`unavailable`）：健康的一轮写的条目不会被
    "AV 没跑成"的一轮命中，反之亦然。
    """
    try:
        from aiav import tools

        info = tools.clamav_engine_info()
    except Exception:  # noqa: BLE001
        return "unknown"
    if not info.get("available"):
        return "unavailable"
    return f"{info.get('exe')}:{info.get('db_version') or '?'}"


def whitelist_fingerprint(store_root: Path | None = None) -> str:
    """白名单文件指纹：白名单一变，旧缓存条目整体失效。

    为什么必须加：压缩包/脱壳子样本的判定是**嵌在父报告里**缓存的，
    如果白名单变了（比如把某个子样本加了白），旧父报告会把"clean"重放出来。
    实测踩过：加白过的 LNK 在 zip 里被缓存成 clean，之后换 store 重扫仍然显示 clean。
    """
    if store_root is None:
        base = default_cache_dir().parent
    else:
        base = Path(store_root)
    return _file_fingerprint(Path(base) / "whitelist.json")


def prompt_fingerprint() -> str:
    """系统提示词指纹（改提示词就失效，免得旧结论继续用）。"""
    try:
        from aiav.agent import SYSTEM_PROMPT

        return hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()[:16]
    except Exception:  # noqa: BLE001
        return "unknown"


def default_cache_dir() -> Path:
    from aiav.disposition import default_store

    return Path(os.getenv("AI_AV_CACHE_DIR", str(default_store().root / "cache")))


class ScanCache:
    """极简的文件级缓存：一条记录一个 json，方便人工查看与清理。"""

    def __init__(self, root: Path | None = None, enabled: bool = True,
                 store_root: Path | None = None) -> None:
        self.root = Path(root) if root is not None else default_cache_dir()
        self.store_root = Path(store_root) if store_root is not None else self.root.parent
        self.enabled = enabled
        self._fp: dict[str, str] | None = None

    # ---------------- 内部 ----------------
    @property
    def fingerprints(self) -> dict[str, str]:
        """版本 / 规则 / 提示词 / AV 库指纹（进程内稳定，算一次即可）。"""
        if self._fp is None:
            self._fp = {"version": CACHE_VERSION, "rules": rules_fingerprint(),
                        "prompt": prompt_fingerprint(), "clamav": clamav_fingerprint()}
        return self._fp

    def current_fingerprints(self) -> dict[str, str]:
        """在指纹基础上附加**每次现算**的白名单指纹（白名单随时可能被改）。"""
        return {**self.fingerprints, "whitelist": whitelist_fingerprint(self.store_root)}

    def _path(self, sha256: str) -> Path:
        return self.root / f"{sha256.lower()}.json"

    # ---------------- 读写 ----------------
    @staticmethod
    def mode(agent_available: bool, unpack: bool, archives: bool, deterministic: bool = True) -> str:
        """分析选项指纹：不同选项算出来的结论不能互相顶替。

        踩过的坑：`allow_unpack=False` 的那一臂先把"没脱壳"的结论写进缓存，
        随后 `allow_unpack=True` 的一臂直接命中缓存 —— 脱壳步骤被静默跳过。
        同理，消融档 `deterministic=False`（只取模型原始判定）的结论也绝不能
        被线上档命中，否则"策略兜底"会被静默绕过。
        """
        return (f"ai={int(bool(agent_available))};unpack={int(bool(unpack))}"
                f";archives={int(bool(archives))};det={int(bool(deterministic))}")

    def get(self, sha256: str, *, agent_available: bool, samples: int,
            unpack: bool = True, archives: bool = True,
            deterministic: bool = True) -> dict[str, Any] | None:
        if not self.enabled or not sha256:
            return None
        path = self._path(sha256)
        if not path.is_file():
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        meta = entry.get("meta") or {}
        if meta.get("fingerprints") != self.current_fingerprints():
            return None
        # 规则模式的结果不许在有 AI 的 run 里命中（防静默降级）
        if agent_available and not meta.get("ai_enabled"):
            return None
        # 分析选项必须一致（脱壳/压缩包/AI 开关不同 = 结论不可互换）
        if meta.get("mode") != self.mode(agent_available, unpack, archives, deterministic):
            return None
        if sample_count(meta) < max(1, samples):
            return None
        return entry

    def put(self, sha256: str, report: FileReport, *, ai_enabled: bool, samples: int,
            unpack: bool = True, archives: bool = True,
            deterministic: bool = True) -> bool:
        if not self.enabled or not sha256:
            return False
        payload = report.model_dump(mode="json")
        # 处置状态不进缓存（每次重新判定）
        payload["disposition"] = {}
        payload.pop("error", None)
        entry = {
            "meta": {
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "fingerprints": self.current_fingerprints(),
                "ai_enabled": ai_enabled,
                "mode": self.mode(ai_enabled, unpack, archives, deterministic),
                "samples": max(1, samples),
                "cache_version": CACHE_VERSION,
            },
            "report": payload,
        }
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            # tmp 名必须唯一：`<sha>.tmp` 是**固定名**，两个进程同时写同一个 sha256 时
            # 会互相截断、甚至把对方还没写完的半截内容 replace 到正式条目上。
            # 实测（8 进程 × 40 轮并发写同一 sha256，payload 66 KB）：
            # 固定名下 320 次 put() 有 132~174 次返回 False —— 写者的 tmp 被另一个写者
            # os.replace 走了，自己的 os.replace 撞 FileNotFoundError，条目**静默没落盘**。
            # pid + 随机后缀是这一层唯一能防撞的手段；与 disposition._atomic_write 同款。
            final = self._path(sha256)
            tmp = final.with_suffix(final.suffix + f".{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
            try:
                tmp.write_text(json.dumps(entry, ensure_ascii=False), encoding="utf-8")
                os.replace(tmp, final)
            finally:
                # replace 成功后 tmp 已不存在；失败/异常时别把垃圾留在缓存目录里
                if tmp.exists():
                    try:
                        tmp.unlink()
                    except OSError:
                        pass
            return True
        except OSError:
            return False

    def clear(self) -> int:
        if not self.root.is_dir():
            return 0
        n = 0
        for f in self.root.glob("*.json"):
            try:
                f.unlink()
                n += 1
            except OSError:
                continue
        return n

    def stats(self) -> dict[str, Any]:
        files = list(self.root.glob("*.json")) if self.root.is_dir() else []
        size = sum(f.stat().st_size for f in files if f.is_file())
        return {"dir": str(self.root), "entries": len(files), "bytes": size,
                "enabled": self.enabled, "fingerprints": self.current_fingerprints()}


def sample_count(meta: dict[str, Any]) -> int:
    try:
        return int(meta.get("samples") or 1)
    except (TypeError, ValueError):
        return 1


def cache_enabled() -> bool:
    return os.getenv("AI_AV_CACHE", "1").strip().lower() not in ("0", "false", "no", "off")


def report_from_cache(entry: dict[str, Any], *, path: Path, disposition: dict | None = None,
                      cached_at: str | None = None) -> FileReport:
    """从缓存条目还原 FileReport；处置状态用调用方传进来的最新值。"""
    payload = dict(entry.get("report") or {})
    payload["path"] = str(path)
    payload["disposition"] = disposition or {}
    report = FileReport.model_validate(payload)
    report.cache = {  # type: ignore[attr-defined]
        "from_cache": True,
        "cached_at": cached_at or (entry.get("meta") or {}).get("created_at"),
    }
    return report
