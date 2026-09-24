"""Web 层扫描任务：**单并发**调度 + 复用既有扫描/报告/处置模块。

这一层刻意做得很薄 —— 它只负责"排队、落盘、调既有函数、记历史"，
一行扫描判定逻辑都不新写（规格红线 7）：
  · 扫描   → `scanner.scan_file` / `scanner.scan_files_concurrent`
  · 报告   → `report.write_reports`（HTML/JSON 都走它，页面直接内嵌它的 HTML）
  · 处置   → `disposition.StateStore`（history / quarantine / whitelist）
  · 预算   → `budget.budget_from_env` / `TokenBudget`

并发模型：一个常驻 worker 线程 + 有界队列。同一时刻最多一个任务在跑；
队列排满（默认 4）时 `submit()` 返回 `None`，路由层翻译成 429。
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from queue import Full, Queue
from typing import Any

from aiav.agent import build_agent
from aiav.budget import TokenBudget, budget_from_env
from aiav.disposition import StateStore
from aiav.models import RiskLevel
from aiav.report import write_reports
from aiav.scanner import scan_file, scan_files_concurrent
from aiav.web.config import WebConfig

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_ERROR = "error"

# 终态：前端轮询到这些状态就停
TERMINAL_STATUSES = (STATUS_DONE, STATUS_ERROR)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def safe_display_name(raw: str) -> str:
    """把用户给的文件名收敛成"只当字符串用"的安全名（不参与路径拼接）。

    `UploadFile.filename` 完全由客户端控制，可能带 `../` 或绝对路径；
    真正的落盘名一律用 uuid，这里只留一个给人看的短名。
    """
    name = (raw or "").replace("\\", "/").split("/")[-1].strip()
    name = "".join(ch for ch in name if ch.isprintable() and ch not in "\r\n\t")
    if not name or name in (".", ".."):
        return "upload.bin"
    return name[:120]


def _rename_report(path: Path, target: Path) -> Path:
    """把 `write_reports` 的时间戳产物改成固定文件名（内容一字不改）。"""
    try:
        path.replace(target)
        return target
    except OSError:
        return path


@dataclass
class ScanJob:
    job_id: str
    display_name: str
    stored_path: str
    size: int
    status: str = STATUS_QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    ai: bool = False
    summary: dict[str, Any] | None = None
    html_path: str | None = None
    json_path: str | None = None
    files: int = 0
    error: str | None = None

    def public(self) -> dict[str, Any]:
        """给前端的字段（**不放服务器端绝对路径**，路径只在报告页里以文件名出现）。"""
        return {
            "job_id": self.job_id,
            "file": self.display_name,
            "size": self.size,
            "status": self.status,
            "ai": self.ai,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary,
            "report_url": f"/report/{self.job_id}" if self.html_path else None,
            "error": self.error,
            "files": self.files,
        }


class JobManager:
    """单并发扫描队列。线程安全：状态流转都在 `self._lock` 内。"""

    def __init__(self, config: WebConfig, store: StateStore | None = None) -> None:
        self.config = config
        self.store = store or StateStore(root=config.state_dir)
        # 队列容量 = 上限 - 1（1 个在跑 + 其余排队；总数由 `_pending` 把关）
        self._queue: Queue[str] = Queue(maxsize=max(1, config.max_queued - 1))
        self._jobs: dict[str, ScanJob] = {}
        self._pending = 0
        self._lock = threading.Lock()
        self._worker: threading.Thread | None = None
        self._worker_started = False

    # ---------------- 生命周期 ----------------
    def start(self) -> None:
        """启动常驻 worker（幂等）。"""
        with self._lock:
            if self._worker_started:
                return
            self._worker_started = True
        self._worker = threading.Thread(target=self._run_forever, name="web-scan-worker", daemon=True)
        self._worker.start()

    def stop(self, timeout: float = 5.0) -> None:
        if self._worker is not None:
            try:
                self._queue.put_nowait("__stop__")
            except Full:
                pass
            self._worker.join(timeout=timeout)
            self._worker = None

    def reset_for_tests(self) -> None:
        """测试用：清掉内存态（不动磁盘索引）。"""
        with self._lock:
            self._jobs.clear()
            self._pending = 0

    # ---------------- 提交 ----------------
    def register_upload(self, upload_dir: Path, display_name: str,
                        job_id: str | None = None) -> ScanJob:
        """登记一个已经落盘的上传文件，**不排队**（排队交给 `submit`）。

        `job_id` 可传入，用来和上传目录名保持一致（`uploads/<job_id>/`）。
        """
        job = ScanJob(
            job_id=job_id or uuid.uuid4().hex,
            display_name=safe_display_name(display_name),
            stored_path=str(upload_dir),
            size=upload_dir.stat().st_size if upload_dir.is_file() else 0,
            ai=False,
        )
        with self._lock:
            self._jobs[job.job_id] = job
        return job

    def submit(self, job: ScanJob) -> bool:
        """入队；未完成的任务数已达 `max_queued` 则返回 False（调用方翻译成 429）。

        `max_queued` 的口径是**在跑 + 排队**的总数（默认 4）：同一时刻只有 1 个在跑，
        其余排队，超出就直接拒绝 —— 免得无限堆积占用磁盘与内存。
        """
        self.start()
        with self._lock:
            if self._pending >= self.config.max_queued:
                return False
            self._pending += 1
        try:
            self._queue.put_nowait(job.job_id)
        except Full:
            with self._lock:
                self._pending -= 1
            return False
        return True

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is not None:
            return job
        return self._load_from_index(job_id)

    def discard(self, job_id: str) -> None:
        """丢掉一个**没有入队成功**的任务（429 那条路）。

        必须真的丢掉：否则 `jobs()` 里会留着一个永远 queued 的幽灵任务，
        网页上会显示成"在排队"，实际永远不会被扫。
        """
        with self._lock:
            self._jobs.pop(job_id, None)

    def jobs(self) -> list[ScanJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    # ---------------- worker ----------------
    def _run_forever(self) -> None:
        while True:
            job_id = self._queue.get()
            if job_id == "__stop__":
                self._queue.task_done()
                return
            try:
                self._run_job(job_id)
            except Exception as exc:  # noqa: BLE001 - worker 绝不能因单任务异常而死
                self._fail(job_id, f"{type(exc).__name__}: {exc}")
            finally:
                self._queue.task_done()

    def _run_job(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                self._pending = max(0, self._pending - 1)
                return
            job.status = STATUS_RUNNING
            job.started_at = time.time()
        try:
            self._pre_scan_hook()
            self._scan(job)
        finally:
            with self._lock:
                self._pending = max(0, self._pending - 1)

    def _pre_scan_hook(self) -> None:
        """测试钩子：在真正开扫之前插一段可控等待。

        存在的理由：`max_queued` / 单并发是硬约束，必须能被**确定性**验证 ——
        靠"塞一堆小文件看谁先被 worker 拿走"是竞态，会 flaky。测试里把它换成
        `threading.Event.wait`，就能稳定地构造出"队列已满 → 429"。
        """
        return None

    def _scan(self, job: ScanJob) -> None:
        target = Path(job.stored_path)
        cfg = self.config
        budget = self._budget()
        agent = self._agent()
        report_dir = cfg.reports_dir / job.job_id

        if target.is_dir():
            files = [p for p in sorted(target.rglob("*")) if p.is_file()]
        else:
            files = [target]

        ai_used = False
        if agent is not None and len(files) > 1:
            # 复用并发入口（单 worker 内串行等待；AI 档才多线程）
            reports = scan_files_concurrent(
                files, agent_factory=self._agent, workers=min(2, len(files)),
                budget=budget, store=self.store,
            )
        else:
            reports = [scan_file(p, agent=agent, budget=budget, store=self.store) for p in files]

        for r in reports:
            # 报告里显示用户给的文件名（落盘名固定 upload.bin，服务器绝对路径不外泄）
            r.path = job.display_name
            r.disposition = self._disposition_of(r.sha256)
            ai_used = ai_used or r.agent_used

        extra = {"token_budget": budget.as_dict()} if budget is not None else None
        extra = {**(extra or {}), "web_job_id": job.job_id, "ai_enabled": job.ai}
        json_path, html_path, audit_path = write_reports(reports, report_dir, extra=extra)
        # 固定文件名，便于 `GET /report/<job_id>/raw` 在进程重启后仍按 job_id 找到报告
        html_path = _rename_report(html_path, report_dir / "scan.html")
        json_path = _rename_report(json_path, report_dir / "scan.json")
        _rename_report(audit_path, report_dir / "scan.audit.json")

        summary = {
            "total": len(reports),
            "clean": sum(1 for r in reports if r.verdict.risk == RiskLevel.clean),
            "suspicious": sum(1 for r in reports if r.verdict.risk == RiskLevel.suspicious),
            "malicious": sum(1 for r in reports if r.verdict.risk == RiskLevel.malicious),
            "agent_used": sum(1 for r in reports if r.agent_used),
            "ai_enabled": job.ai,
            "per_file": [
                {
                    "name": Path(r.path).name,
                    "risk": r.verdict.risk.value,
                    "category": r.verdict.category,
                    "summary": r.verdict.summary,
                    "evidence_basis": r.verdict.evidence[-1] if r.verdict.evidence else "",
                    "agent_used": r.agent_used,
                    "report_label": (
                        "AI 档结论" if r.agent_used
                        else "确定性判定（规则档，未调用模型）"
                    ),
                }
                for r in reports
            ],
        }

        self.store.record_history({
            "scan_dir": f"web:{job.display_name}",
            "job_id": job.job_id,
            "source": "web",
            "total": summary["total"],
            "clean": summary["clean"],
            "suspicious": summary["suspicious"],
            "malicious": summary["malicious"],
            "agent_used": summary["agent_used"],
            "report_json": str(json_path),
            "quarantine_mode": "off",
            "quarantine_applied": False,
        })

        with self._lock:
            job.status = STATUS_DONE
            job.finished_at = time.time()
            job.summary = summary
            job.html_path = str(html_path)
            job.json_path = str(json_path)
            job.files = len(reports)
            job.ai = ai_used or job.ai
        self._persist_index()

    # ---------------- 依赖构造 ----------------
    def _budget(self) -> TokenBudget | None:
        try:
            if self.config.ai_token_budget > 0:
                return TokenBudget(limit=self.config.ai_token_budget)
            return budget_from_env()
        except Exception:  # noqa: BLE001 - 预算不可用不该阻断扫描
            return None

    def _agent(self):
        """AI 档默认关闭：只有显式打开且真的配了 key 才返回 Agent。"""
        if not self.config.ai_enabled:
            return None
        try:
            return build_agent()
        except Exception:  # noqa: BLE001 - 缺 key 时退回确定性判定，绝不把异常抛给用户
            return None

    def _disposition_of(self, sha256: str) -> dict[str, Any]:
        try:
            for record in self.store.records():
                if str(record.get("sha256", "")).lower() == (sha256 or "").lower():
                    return {"status": record.get("status", "quarantined"),
                            "id": record.get("id"), "at": record.get("quarantined_at")}
            if self.store.whitelist_lookup(sha256):
                return {"status": "whitelisted"}
        except Exception:  # noqa: BLE001
            pass
        return {}

    def _fail(self, job_id: str, message: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            job.status = STATUS_ERROR
            job.error = message[:400]
            job.finished_at = time.time()
        self._persist_index()

    # ---------------- 任务索引（重启后 /report/<id> 仍可用） ----------------
    def _persist_index(self) -> None:
        try:
            data = {j.job_id: asdict(j) for j in self.jobs()}
            _atomic_write(self.config.jobs_file, json.dumps(data, ensure_ascii=False, indent=2))
        except OSError:
            pass

    def _load_from_index(self, job_id: str) -> ScanJob | None:
        try:
            raw = json.loads(self.config.jobs_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        item = raw.get(job_id)
        if not isinstance(item, dict):
            return None
        try:
            return ScanJob(**item)
        except TypeError:
            return None


def cleanup_uploads(config: WebConfig, now: float | None = None) -> dict[str, Any]:
    """清理 `<state_dir>/uploads/` 下超期目录（默认 24h）。只删上传区，不碰别处。"""
    now = now or time.time()
    ttl = max(1, config.upload_ttl_hours) * 3600
    removed, kept, freed = 0, 0, 0
    root = config.uploads_dir
    if not root.is_dir():
        return {"removed": 0, "kept": 0, "freed_bytes": 0, "root": str(root)}
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        try:
            age = now - child.stat().st_mtime
        except OSError:
            continue
        if age < ttl:
            kept += 1
            continue
        size = sum(p.stat().st_size for p in child.rglob("*") if p.is_file())
        for p in sorted(child.rglob("*"), reverse=True):
            try:
                p.unlink() if p.is_file() else p.rmdir()
            except OSError:
                pass
        try:
            child.rmdir()
        except OSError:
            continue
        removed += 1
        freed += size
    return {"removed": removed, "kept": kept, "freed_bytes": freed, "root": str(root)}
