"""Web UI 配置（本地单机，默认只绑 127.0.0.1）。

设计原则（对着 `docs/WEB_UI_SPEC.md` 的红线抄）：
  · 上传目录、报告目录、任务索引**全部落在 `<state_dir>` 下**（复用 `disposition.StateStore` 的根），
    不往仓库里写任何产物 —— 样本天条：样本不进 git；
  · 视觉与逻辑全部复用现有模块，这里只放"可调参数"，不放业务逻辑。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_STATE_DIR = Path(os.getenv("AI_AV_STATE_DIR", str(Path.home() / "ai-av-bench" / "ai-av-state")))


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


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
    # AI 判决档：**默认关闭**；开启需显式开关，且每请求有 token 上限。
    ai_enabled: bool = False
    ai_token_budget: int = 20000
    # 只允许填服务器端路径（默认关闭，规格里的可选能力）。
    allow_local_path: bool = False

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
            ai_enabled=_env_flag("AI_AV_WEB_AI", False),
            ai_token_budget=_env_int("AI_AV_WEB_AI_TOKEN_BUDGET", 20000),
            allow_local_path=_env_flag("AI_AV_WEB_ALLOW_LOCAL_PATH", False),
        )
        base.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**base)

    def safe_upload_child(self, path: Path) -> bool:
        """上传文件必须真的位于 uploads/ 之内（防 `..` / 软链越界）。"""
        try:
            resolved = Path(path).resolve()
            root = self.uploads_dir.resolve()
        except OSError:
            return False
        return resolved == root or root in resolved.parents
