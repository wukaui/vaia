"""Web UI 配置（本地单机，默认只绑 127.0.0.1）。

设计原则（对着 `docs/WEB_UI_SPEC.md` 的红线抄）：
  · 上传目录、报告目录、任务索引**全部落在 `<state_dir>` 下**（复用 `disposition.StateStore` 的根），
    不往仓库里写任何产物 —— 样本天条：样本不进 git；
  · 视觉与逻辑全部复用现有模块，这里只放"可调参数"，不放业务逻辑。
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass, fields
from typing import ClassVar
from pathlib import Path

from aiav.criteria import AI_GATE, AI_GATE_LOW, TRIAGE_ENTRY_GATE, TRIAGE_GATE

DEFAULT_STATE_DIR = Path(os.getenv("AI_AV_STATE_DIR", str(Path.home() / "ai-av-bench" / "ai-av-state")))


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_paths(name: str) -> tuple[Path, ...]:
    """冒号分隔的绝对路径列表（`AI_AV_WEB_LOCAL_ROOTS`）。空 = 不限。"""
    raw = os.getenv(name, "").strip()
    if not raw:
        return ()
    return tuple(Path(part).expanduser() for part in raw.split(os.pathsep) if part.strip())


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


@dataclass
class ScanParams:
    """Web 端可调的**扫描参数**（对应 CLI 的开关），一次设置、之后每个任务都按它跑。

    为什么要放进 Web：这一层的默认值（闸门 200/300、低档 225、初筛 60/125）都是
    **算出来的**，换语料就得重算。让人在页面上改，比改环境变量重启服务快，
    也让"这一轮用的什么配置"在页面上看得见（本项目反复踩过"产物看不出配置"的坑）。

    所有值都过 `sanitized()`：非法/越界一律钳到安全区间，绝不让 `--ai-threshold-low > --ai-threshold`
    这种自相矛盾的组合进到扫描器。
    """

    ai: bool = False
    ai_threshold: int = AI_GATE
    ai_threshold_low: int = AI_GATE_LOW
    triage: bool = False
    triage_threshold: int = TRIAGE_GATE
    triage_entry_gate: int = TRIAGE_ENTRY_GATE
    deep_evidence_threshold: int = 0
    token_budget: int = 20000

    #: 前端表单用的上下限（与 `sanitized()` 一致，改一处即可）。ClassVar = 不是字段。
    LIMITS: ClassVar[dict] = {
        "ai_threshold": (1, 100_000),
        "ai_threshold_low": (0, 100_000),
        "triage_threshold": (0, 100),
        "triage_entry_gate": (0, 100_000),
        "deep_evidence_threshold": (0, 100_000),
        "token_budget": (0, 10_000_000),
    }

    def sanitized(self) -> "ScanParams":
        def clamp(raw, lo: int, hi: int, default: int) -> int:
            try:
                val = int(raw)
            except (TypeError, ValueError):
                return default
            return max(lo, min(hi, val))

        gate = clamp(self.ai_threshold, 1, 100_000, AI_GATE)
        return ScanParams(
            ai=bool(self.ai),
            ai_threshold=gate,
            # 低档不许高过闸门；0 = 关掉低档（与 `effective_low_gate` 同义）
            ai_threshold_low=clamp(self.ai_threshold_low, 0, gate, AI_GATE_LOW),
            triage=bool(self.triage),
            triage_threshold=clamp(self.triage_threshold, 0, 100, TRIAGE_GATE),
            # 入口高过闸门 = 初筛永不触发，钳到闸门（`effective_triage_entry_gate` 同义）
            triage_entry_gate=clamp(self.triage_entry_gate, 0, gate, TRIAGE_ENTRY_GATE),
            deep_evidence_threshold=clamp(self.deep_evidence_threshold, 0, 100_000, 0),
            token_budget=clamp(self.token_budget, 0, 10_000_000, 20_000),
        )

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data) -> "ScanParams":
        if not isinstance(data, dict):
            return cls()
        allowed = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in allowed}).sanitized()


@dataclass
class WebConfig:
    """Web 层全部可调项；`from_env()` 是唯一入口，便于测试注入。"""

    state_dir: Path
    host: str = "127.0.0.1"
    port: int = 8080
    # 上传上限（MB）。规格默认 200MB。
    max_upload_mb: int = 200
    # 上传目录保留时长与清理周期（小时）。
    upload_ttl_hours: int = 24
    cleanup_interval_minutes: int = 60
    # 单并发 + 有界队列：排满后新请求直接 429（不无限堆积磁盘占用）。
    max_queued: int = 4
    # 允许扫**服务器本地路径**（文件或目录）。默认关：本地单机工具，页面虽只绑 127.0.0.1，
    # 但"读服务器任意路径"仍是口子，必须显式 opt-in（`AI_AV_WEB_ALLOW_LOCAL_PATH=1`）。
    allow_local_path: bool = False
    # 允许的根目录（空 = 不限，仅靠 localhost 兜底）。给共用机器收口用，冒号分隔。
    local_roots: tuple[Path, ...] = ()
    # 一次本地扫描最多多少个文件（防手滑指到 / 把机器扫爆）；超出部分不扫并记账。
    max_local_files: int = 2000
    # AI 判决档：**默认关闭**；开启需显式开关，且每请求有 token 上限。
    # `ai_enabled` 是**服务端许可**（页面上的 AI/初筛开关只有它开着才放行），
    # 具体的扫描阈值见 `ScanParams`。
    ai_enabled: bool = False
    ai_token_budget: int = 20000

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def uploads_dir(self) -> Path:
        return self.state_dir / "uploads"

    @property
    def reports_dir(self) -> Path:
        return self.state_dir / "web-reports"

    @property
    def jobs_file(self) -> Path:
        return self.state_dir / "web-jobs.json"

    def check_local_path(self, raw: object) -> tuple[Path | None, str]:
        """本地路径能不能扫，返回 `(path | None, 原因)`。所有拒绝理由都要能直接显示给用户。"""
        if not self.allow_local_path:
            return None, "服务端未允许扫描本地路径（启动时加 AI_AV_WEB_ALLOW_LOCAL_PATH=1）"
        text = str(raw or "").strip()
        if not text:
            return None, "路径不能为空"
        try:
            path = Path(text).expanduser()
        except (TypeError, ValueError):
            return None, "路径不合法"
        if not path.exists():
            return None, f"路径不存在：{path}"
        if not (path.is_file() or path.is_dir()):
            return None, "只支持普通文件或目录"
        if self.local_roots:
            try:
                resolved = path.resolve()
            except OSError:
                return None, "路径无法解析"
            roots = [Path(r).expanduser().resolve() for r in self.local_roots]
            ok = any(resolved == r or r in resolved.parents for r in roots)
            if not ok:
                return None, "路径不在允许的根目录内（AI_AV_WEB_LOCAL_ROOTS）"
        return path, ""

    def bind_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @classmethod
    def from_env(cls, **overrides) -> "WebConfig":
        base = dict(
            state_dir=Path(os.getenv("AI_AV_STATE_DIR", str(DEFAULT_STATE_DIR))).expanduser(),
            host=os.getenv("AI_AV_WEB_HOST", "127.0.0.1"),
            port=_env_int("AI_AV_WEB_PORT", 8080),
            max_upload_mb=_env_int("AI_AV_WEB_MAX_UPLOAD_MB", 200),
            upload_ttl_hours=_env_int("AI_AV_WEB_UPLOAD_TTL_HOURS", 24),
            cleanup_interval_minutes=_env_int("AI_AV_WEB_CLEANUP_INTERVAL_MIN", 60),
            max_queued=_env_int("AI_AV_WEB_MAX_QUEUED", 4),
            allow_local_path=_env_flag("AI_AV_WEB_ALLOW_LOCAL_PATH", False),
            local_roots=_env_paths("AI_AV_WEB_LOCAL_ROOTS"),
            max_local_files=_env_int("AI_AV_WEB_MAX_LOCAL_FILES", 2000),
            ai_enabled=_env_flag("AI_AV_WEB_AI", False),
            ai_token_budget=_env_int("AI_AV_WEB_AI_TOKEN_BUDGET", 20000),
        )
        base.update({k: v for k, v in overrides.items() if v is not None})
        base["local_roots"] = tuple(Path(r) for r in (base.get("local_roots") or ()))
        return cls(**base)
