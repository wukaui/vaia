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

import itertools
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
from aiav.scanner import iter_files, scan_file, scan_files_concurrent
from aiav.web.config import ScanParams, WebConfig

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_ERROR = "error"

# 终态：前端轮询到这些状态就停
TERMINAL_STATUSES = (STATUS_DONE, STATUS_ERROR)


#: 任务索引最多留多少条（`web-jobs.json` 只增不减会越来越大）
INDEX_KEEP = 200


def _api_key_present() -> bool:
    """`build_agent` / `TriageClient` 都只在这几个环境变量里取 key（见 agent.py / triage.py）。"""
    import os

    return bool(os.getenv("AGENT_API_KEY") or os.getenv("OPENAI_API_KEY")
                or os.getenv("DEEPSEEK_API_KEY"))


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


def safe_upload_suffix(raw: str) -> str:
    """从用户文件名里抽出**安全的扩展名**，让扫描器看到真实的文件类型。

    为什么必须保留（2026-10-08 修）：上传文件以前一律落成 `upload.bin`，扫描器按
    `.bin` 分析 —— `.exe` / `.doc` / `.pdf` 这些**扩展名判据**（HIGH_RISK_EXTENSION）
    与按类型选工具的路径全部失效，且报告里"显示名 sample.exe / extension .bin"
    自相矛盾。只取值、不取路径：落盘名仍是服务器生成的 `upload<ext>`，
    目录是 uuid，`..` / 绝对路径进不来。
    """
    name = safe_display_name(raw)
    suffix = Path(name).suffix
    # 只收「. + 字母数字」这种正常后缀；怪字符一律退回 .bin（宁可少判，不许注入）
    if not suffix or len(suffix) > 12 or not all(ch.isalnum() or ch == "." for ch in suffix):
        return ".bin"
    return suffix


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
    #: `upload` = 上传到 uploads/；`local` = 直接扫服务器本地路径（目录或文件）
    source: str = "upload"
    status: str = STATUS_QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    ai: bool = False
    #: AI 是否真的可用（缺 key / 服务端不允许时为 False，且 `ai_reason` 有原因）
    ai_ready: bool = False
    ai_reason: str = ""
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
            "source": self.source,
            "size": self.size,
            "status": self.status,
            "ai": self.ai,
            "ai_ready": self.ai_ready,
            "ai_reason": self.ai_reason,
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
        self._stopping = threading.Event()
        # Web 端可调的扫描参数（持久化在 state_dir，重启后还在）
        self.params_path = config.state_dir / "web-settings.json"
        self._params = self._load_params()

    # ---------------- 生命周期 ----------------
    def start(self) -> None:
        """启动常驻 worker（幂等）。"""
        with self._lock:
            if self._worker_started:
                return
            self._worker_started = True
            self._stopping.clear()
        self._worker = threading.Thread(target=self._run_forever, name="web-scan-worker", daemon=True)
        self._worker.start()

    def stop(self, timeout: float = 5.0) -> None:
        """停 worker：置停止旗标 + 丢一个哨兵唤醒阻塞的 `get()`。

        队列满时哨兵可能塞不进去 —— 那时靠旗标兜底：worker 跑完当前任务就返回，
        不会像以前那样"塞不进哨兵就永远停不掉"。
        """
        self._stopping.set()
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

    def register_local(self, path: Path) -> ScanJob:
        """登记一个**本地路径**任务（不复制文件）：文件或目录，只读扫。"""
        job = ScanJob(
            job_id=uuid.uuid4().hex,
            display_name=str(path),
            stored_path=str(path),
            size=path.stat().st_size if path.is_file() else 0,
            ai=False,
            source="local",
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

    # ---------------- 扫描参数（Web 页面上改） ----------------
    def params(self) -> ScanParams:
        with self._lock:
            return self._params

    def set_params(self, data: Any) -> ScanParams:
        """保存页面改的扫描参数。AI / 初筛要服务端先允许（`AI_AV_WEB_AI`），不允许就不放行 ——
        免得从页面绕过成本闸。"""
        p = ScanParams.from_dict(data)
        if not self.config.ai_enabled:
            p.ai = False
            p.triage = False
        with self._lock:
            self._params = p
        self._save_params()
        return p

    def _load_params(self) -> ScanParams:
        default = ScanParams(ai=self.config.ai_enabled, token_budget=self.config.ai_token_budget)
        try:
            raw = json.loads(self.params_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default.sanitized()
        p = ScanParams.from_dict(raw)
        if not self.config.ai_enabled:
            p.ai = False
            p.triage = False
        return p.sanitized()

    def _save_params(self) -> None:
        try:
            _atomic_write(self.params_path,
                          json.dumps(self.params().to_dict(), ensure_ascii=False, indent=2))
        except OSError:
            pass

    def ai_status(self) -> dict[str, Any]:
        """AI 档**到底能不能用** —— 前端据此禁用开关 / 显示原因。

        反面教材：以前首页无条件写"AI 判决档：已开启"，而缺 key 时 `_agent()` 返回 None、
        全程规则档、一个字都不提示（本项目最忌的静默降级）。现在状态由这里统一给。
        """
        if not self.config.ai_enabled:
            return {"allowed": False, "ready": False,
                    "reason": "服务端未允许 AI 档（AI_AV_WEB_AI=0）"}
        if not _api_key_present():
            return {"allowed": True, "ready": False,
                    "reason": "缺 API Key（AGENT_API_KEY / OPENAI_API_KEY / DEEPSEEK_API_KEY）"}
        return {"allowed": True, "ready": True, "reason": ""}

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
            if self._stopping.is_set():
                return

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
        p = self.params()
        budget = self._budget(p)
        agent, agent_reason = self._agent(p)
        triage_client, triage_reason = self._triage_client(p)
        report_dir = cfg.reports_dir / job.job_id

        # 目录走 `iter_files`（与 CLI 同一套：跳过系统/隐藏目录、>50MB 不计），
        # 并受 `max_local_files` 硬上限保护 —— 手滑指到 / 也不会把机器扫爆。
        skip_stats: dict[str, int] = {}
        truncated = False
        if target.is_dir():
            it = iter_files(target, skip_stats=skip_stats)
            files = list(itertools.islice(it, max(1, cfg.max_local_files)))
            if next(it, None) is not None:
                truncated = True
        else:
            files = [target]
        if not files:
            raise RuntimeError(f"路径下没有可扫的文件：{target}")

        # ①层 ClamAV 批量预扫：一次进程扫一批。**别省略** —— 一个文件起一次 clamscan
        # 要重新加载几百万条签名（秒级/次），扫目录会慢到不可用。
        clamav_batch = None
        try:
            from aiav.tools import clamav_scan_batch

            batch = clamav_scan_batch(files)
            if batch.get("available"):
                clamav_batch = batch
        except Exception:  # noqa: BLE001 - AV 预扫失败不该阻断扫描
            clamav_batch = None

        # 页面上的参数原样喂给扫描器（阈值/初筛/取证分流/预算），一行判定逻辑都不新写
        scan_kw: dict[str, Any] = dict(
            ai_threshold=p.ai_threshold,
            ai_threshold_low=p.ai_threshold_low,
            triage_enabled=triage_client is not None,
            triage_threshold=p.triage_threshold,
            triage_entry_gate=p.triage_entry_gate,
            triage_client=triage_client,
            triage_cache=self._triage_cache(),
            deep_evidence_threshold=p.deep_evidence_threshold,
            clamav_batch=clamav_batch,
            budget=budget,
            store=self.store,
        )
        if agent is not None and len(files) > 1:
            # 复用并发入口（单 worker 内串行等待；AI 档才多线程）
            reports = scan_files_concurrent(
                files, agent_factory=lambda: self._agent(p)[0],
                workers=min(2, len(files)), **scan_kw)
        else:
            reports = [scan_file(x, agent=agent, **scan_kw) for x in files]

        for r in reports:
            # 上传：报告里显示用户给的文件名（落盘名是 upload<ext>，服务器绝对路径不外泄）。
            # 本地路径：用户自己给的路，保留原名 —— 目录里要能分清是哪个文件。
            if job.source == "upload":
                r.path = job.display_name
            r.disposition = self._disposition_of(r.sha256)

        ai_used = sum(1 for r in reports if r.agent_used)
        extra = {"token_budget": budget.as_dict()} if budget is not None else None
        extra = {**(extra or {}), "web_job_id": job.job_id, "ai_enabled": agent is not None}
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
            "agent_used": ai_used,
            "ai_enabled": agent is not None,
            # 请求了却没用上 AI 的话，把原因写进产物 —— 不许静默
            "ai_requested": bool(p.ai),
            "ai_fallback": "" if agent is not None or not p.ai else agent_reason,
            "triage_requested": bool(p.triage),
            "triage_enabled": triage_client is not None,
            "triage_fallback": "" if triage_client is not None or not p.triage else triage_reason,
            "params": p.to_dict(),
            "source": job.source,
            # 目录扫描要看得出"跳过了什么、有没有被单次上限截断"
            "skipped": dict(sorted(skip_stats.items())),
            "truncated": truncated,
            "max_local_files": cfg.max_local_files,
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
            job.ai = bool(p.ai)
            job.ai_ready = agent is not None
            job.ai_reason = "" if agent is not None else agent_reason
        self._persist_index()

    # ---------------- 依赖构造 ----------------
    def _budget(self, p: ScanParams) -> TokenBudget | None:
        try:
            if p.token_budget and p.token_budget > 0:
                return TokenBudget(limit=p.token_budget)
            return budget_from_env()
        except Exception:  # noqa: BLE001 - 预算不可用不该阻断扫描
            return None

    def _agent(self, p: ScanParams):
        """返回 `(agent | None, 原因)`：AI 档要 服务端允许 + 本次勾选 + 真能建起来。"""
        if not self.config.ai_enabled:
            return None, "服务端未允许 AI 档"
        if not p.ai:
            return None, "本次未启用 AI 档"
        try:
            return build_agent(), ""
        except Exception as exc:  # noqa: BLE001 - 缺 key 时退回确定性判定，绝不把异常抛给用户
            return None, f"AI 档不可用（{type(exc).__name__}: {exc}）"[:200]

    def _triage_client(self, p: ScanParams):
        """②层初筛客户端（缺 key / 未勾选 / 服务端不允许 → None + 原因）。"""
        if not self.config.ai_enabled:
            return None, "服务端未允许 ②层初筛"
        if not p.triage:
            return None, "本次未启用 ②层初筛"
        try:
            from aiav.triage import TriageClient

            return TriageClient(), ""
        except Exception as exc:  # noqa: BLE001
            return None, f"②层初筛不可用（{type(exc).__name__}: {exc}）"[:200]

    def _triage_cache(self):
        """初筛缓存（与 CLI 同一套 `TriageCache`，同一 sha256 不重复计费）。"""
        try:
            from aiav.cache import TriageCache, cache_enabled

            if not cache_enabled():
                return None
            return TriageCache(root=self.config.state_dir / "triage-cache",
                               store_root=self.config.state_dir)
        except Exception:  # noqa: BLE001
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
            # 只留最新 N 条：`web-jobs.json` 只增不减会越来越大（旧任务的报告仍在磁盘上，
            # 只是不再从索引里可达 —— 这是本地工具可接受的取舍）
            data = {j.job_id: asdict(j) for j in self.jobs()[:INDEX_KEEP]}
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
