"""处置闭环：隔离区 / 白名单 / 扫描历史。

设计原则（对着风险来）：
1. **默认 dry-run**：没有显式 `apply=True` 就只返回"打算做什么"，不碰任何文件；
2. **只能动扫描目录内的文件**：`quarantine_file()` 必须传 `scan_root`，且做路径包含校验，
   防止把系统文件或样本目录外的东西移走；
3. **动作可回滚**：每次隔离都写 `quarantine.json`（原路径 / 隔离路径 / sha256 / 体积 / 判定 / 依据 / 时间），
   `restore()` 会校验 sha256 再放回原位；
4. **白名单按 sha256 生效**：同一文件（同内容）不再反复进 AI、不再重复报；
5. **历史只追加**：`history.jsonl` 每次扫描一条，方便答辩演示"扫描历史留存"。

状态目录默认 `~/ai-av-bench/ai-av-state`（不进仓库），可用 `AI_AV_STATE_DIR` 覆盖。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_STATE_DIR = Path(os.getenv("AI_AV_STATE_DIR", str(Path.home() / "ai-av-bench" / "ai-av-state")))

QUARANTINE_RISKS = ("malicious", "suspicious")

# 模糊匹配 sha256 前缀的最短长度。低于这个长度就要求**完整** sha256 或记录 id ——
# 4 个十六进制字符（16 bit）在几百条记录里撞车的概率并不低，而还原时撞错记录 =
# 报"sha256 不匹配"，用户会以为隔离区里的文件被篡改了（实际是选错了记录）。
MIN_SHA256_PREFIX = 8


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _atomic_write(path: Path, text: str) -> None:
    # tmp 名必须唯一：`path.tmp` 是**固定名**，并发/多进程同时落盘时两个写者会互相截断，
    # 极端情况下能把半个 json 换到正式文件上（读到 JSONDecodeError → 隔离记录凭空消失）。
    # pid + 随机后缀是这一层唯一能防撞的手段。
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass
class StateStore:
    """一个状态目录：quarantine/ + quarantine.json + whitelist.json + history.jsonl"""

    root: Path

    def __post_init__(self) -> None:
        self.root = Path(self.root).expanduser()
        self.quarantine_dir = self.root / "quarantine"
        self.records_file = self.root / "quarantine.json"
        self.whitelist_file = self.root / "whitelist.json"
        self.history_file = self.root / "history.jsonl"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    # ---------------- 通用读写 ----------------
    def _load_json(self, path: Path, default: Any) -> Any:
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

    def _save_json(self, path: Path, data: Any) -> None:
        self.ensure()
        _atomic_write(path, json.dumps(data, ensure_ascii=False, indent=2))

    # ---------------- 白名单 ----------------
    def whitelist(self) -> list[dict]:
        return self._load_json(self.whitelist_file, [])

    def whitelist_lookup(self, sha256: str) -> dict | None:
        sha256 = (sha256 or "").lower()
        if not sha256:
            return None
        for item in self.whitelist():
            if str(item.get("sha256", "")).lower() == sha256:
                return item
        return None

    def whitelist_add(self, sha256: str, path: str = "", reason: str = "", apply: bool = True) -> dict:
        sha256 = (sha256 or "").lower()
        if len(sha256) != 64:
            raise ValueError("白名单需要完整 sha256")
        existing = self.whitelist_lookup(sha256)
        if existing:
            return {**existing, "already": True}
        entry = {"sha256": sha256, "path": path, "reason": reason,
                 "added_at": _now(), "source": "cli"}
        if not apply:
            return {**entry, "planned": True}
        items = self.whitelist()
        items.append(entry)
        self._save_json(self.whitelist_file, items)
        return entry

    def whitelist_remove(self, sha256: str, apply: bool = True) -> dict:
        sha256 = (sha256 or "").lower()
        items = self.whitelist()
        keep = [i for i in items if str(i.get("sha256", "")).lower() != sha256]
        removed = len(items) - len(keep)
        if apply and removed:
            self._save_json(self.whitelist_file, keep)
        return {"removed": removed, "planned": not apply}

    # ---------------- 隔离区 ----------------
    def records(self) -> list[dict]:
        return self._load_json(self.records_file, [])

    def find(self, key: str) -> dict | None:
        """按记录 id 或 sha256（完整 / ≥8 位前缀）找一条隔离记录。

        三条边界都是实测会踩的：
          · **空 key**：`str.startswith("")` 恒真 → 旧实现返回第一条记录，
            `restore("")` 就会去动一条用户根本没指定的记录；
          · **短前缀**：4 个十六进制字符就能撞上别的记录，还原时报"sha256 不匹配"，
            用户以为隔离区文件被改过（实际只是选错了记录）；
          · **多义前缀**：返回"第一条"是**静默选一个**，两条都合理时必须报错让用户给全。
        """
        key = (key or "").strip().lower()
        if not key:
            return None
        records = self.records()
        for r in records:
            if str(r.get("id", "")).lower() == key:
                return r
        if len(key) < MIN_SHA256_PREFIX:
            return None
        matches = [r for r in records if str(r.get("sha256", "")).lower().startswith(key)]
        if len(matches) > 1:
            raise ValueError(
                f"sha256 前缀 {key!r} 命中 {len(matches)} 条隔离记录，无法确定是哪一条："
                + ", ".join(str(r.get("id")) for r in matches[:6])
                + "；请给出完整 sha256 或记录 id"
            )
        return matches[0] if matches else None

    def _next_seq(self) -> int:
        """下一个隔离序号 = **已有记录里的最大序号 + 1**。

        旧实现用 `len(records) + 1`：只要删过一条记录（或两个进程同时落盘），
        新记录的 id 就会和存量记录**重号** —— 而 `restore(key)` / `find(key)` 按 id 查，
        重号之后还原会打到错误的那条记录上。
        """
        top = 0
        for r in self.records():
            m = re.fullmatch(r"q-(\d+)", str(r.get("id", "")).strip(), flags=re.IGNORECASE)
            if m:
                top = max(top, int(m.group(1)))
        return top + 1

    def _pick_quarantine_target(self, name: str, sha256: str) -> Path:
        """挑一个**不会覆盖已有隔离产物**的目标名。

        旧实现只做两级：`name` 撞了就 `sha256[:8]_name`，再撞就**直接覆盖** ——
        两个同名但内容不同的样本（`invoice.pdf` 这类名字在样本集里很常见）
        第二个会把第一个从隔离区里抹掉，而 quarantine.json 里两条记录都还在，
        还原第一条时才发现文件没了。
        """
        candidate = self.quarantine_dir / name
        if not candidate.exists():
            return candidate
        candidate = self.quarantine_dir / f"{sha256[:8]}_{name}"
        if not candidate.exists():
            return candidate
        for i in range(2, 1000):
            alt = self.quarantine_dir / f"{sha256[:8]}_{i}_{name}"
            if not alt.exists():
                return alt
        raise OSError(f"隔离区同名产物过多，无法为 {name} 找到可用文件名")

    def quarantine_file(
        self,
        path: Path,
        sha256: str,
        scan_root: Path,
        risk: str = "",
        category: str = "",
        summary: str = "",
        basis: list[str] | None = None,
        report_path: str = "",
        apply: bool = False,
    ) -> dict:
        """隔离一个文件（默认只做计划）。返回记录或计划。"""
        path = Path(path)
        scan_root = Path(scan_root)
        plan: dict[str, Any] = {
            "action": "quarantine",
            "path": str(path),
            "sha256": sha256,
            "risk": risk,
            "applied": False,
        }
        if not path.is_file():
            plan["error"] = "文件不存在"
            return plan
        # 只能是扫描目录内的文件（防误伤系统路径 / 状态目录）
        try:
            path.resolve().relative_to(scan_root.resolve())
        except (ValueError, OSError):
            plan["error"] = f"拒绝隔离：不在扫描目录 {scan_root} 内"
            return plan
        if self.root.resolve() in path.resolve().parents:
            plan["error"] = "拒绝隔离：文件在状态目录内"
            return plan

        try:
            existing = self.find(sha256)
        except ValueError:
            existing = None
        if existing and existing.get("status") == "quarantined":
            plan["already_quarantined"] = existing.get("id")
            return plan

        plan["planned_target"] = str(self.quarantine_dir / path.name)
        if not apply:
            plan["note"] = "dry-run（未加 --apply，未移动任何文件）"
            return plan

        self.ensure()
        target = self._pick_quarantine_target(path.name, sha256)
        try:
            shutil.move(str(path), str(target))
        except OSError as exc:
            plan["error"] = f"移动失败: {exc}"
            return plan

        seq = self._next_seq()
        record = {
            "id": f"q-{seq:04d}",
            "status": "quarantined",
            "original_path": str(path),
            "quarantine_path": str(target),
            "sha256": sha256,
            "size": target.stat().st_size,
            "risk": risk,
            "category": category,
            "summary": summary[:300],
            "basis": (basis or [])[:6],
            "report_path": report_path,
            "quarantined_at": _now(),
            "restored_at": None,
        }
        records = self.records()
        records.append(record)
        self._save_json(self.records_file, records)
        plan.update({"applied": True, "id": record["id"], "quarantine_path": str(target)})
        return {**record, **plan}

    def restore(self, key: str, apply: bool = False, verify_hash: bool = True) -> dict:
        try:
            record = self.find(key)
        except ValueError as exc:
            # 前缀多义：宁可拒绝，也不静默挑一条去动文件
            return {"action": "restore", "error": str(exc), "applied": False}
        if not record:
            return {"action": "restore", "error": f"找不到隔离记录: {key}", "applied": False}
        if record.get("status") == "restored":
            return {"action": "restore", "error": "该记录已还原过", "applied": False, "id": record["id"]}

        src = Path(record["quarantine_path"])
        dst = Path(record["original_path"])
        plan: dict[str, Any] = {"action": "restore", "id": record["id"], "from": str(src), "to": str(dst),
                                "applied": False}
        if not src.is_file():
            plan["error"] = "隔离区里找不到文件"
            return plan
        if verify_hash:
            actual = sha256_file(src)
            if actual != record["sha256"]:
                plan["error"] = f"sha256 不匹配（隔离区文件被改动？）：{actual[:16]}…"
                return plan
        if dst.exists():
            plan["error"] = "原路径已存在同名文件，请先手工处理"
            return plan
        if not apply:
            plan["note"] = "dry-run（未加 --apply，未移动任何文件）"
            return plan

        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.move(str(src), str(dst))
        except OSError as exc:
            plan["error"] = f"还原失败: {exc}"
            return plan

        records = self.records()
        for r in records:
            if r.get("id") == record["id"]:
                r["status"] = "restored"
                r["restored_at"] = _now()
        self._save_json(self.records_file, records)
        plan["applied"] = True
        return plan

    # ---------------- 历史 ----------------
    def record_history(self, entry: dict, apply: bool = True) -> dict:
        entry = {"recorded_at": _now(), **entry}
        if not apply:
            return {**entry, "planned": True}
        self.ensure()
        with self.history_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def history(self, limit: int = 20) -> list[dict]:
        if not self.history_file.exists():
            return []
        lines = self.history_file.read_text(encoding="utf-8").splitlines()
        out: list[dict] = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


_default_store: StateStore | None = None


def default_store() -> StateStore:
    """默认状态目录（懒加载，便于测试用 AI_AV_STATE_DIR 覆盖）。"""
    global _default_store
    state_dir = Path(os.getenv("AI_AV_STATE_DIR", str(DEFAULT_STATE_DIR)))
    if _default_store is None or _default_store.root != state_dir:
        _default_store = StateStore(state_dir)
    return _default_store
