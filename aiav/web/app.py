"""本地 Web UI（阶段一）：给既有 CLI 套一层**纯 Python** 的壳。

跑起来：
    python -m uvicorn web.app:app --host 127.0.0.1 --port 8080
    # 或者：scripts/run_web.sh

红线（`docs/WEB_UI_SPEC.md`）：
  · 没有前端构建链 —— 模板 + 原生 JS + 复用 `report.py` 的 CSS 变量/class；
  · 不另写扫描逻辑 —— 判定/报告/处置全部调现有模块（见 `web/jobs.py`）；
  · 上传落 `<state_dir>/uploads/<uuid>/`，**绝不执行上传文件**（全链路只读字节）；
  · AI 档默认关闭、单并发、页面不出现密钥/真名/校名/导师名/学号。
"""
from __future__ import annotations

import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aiav.web.config import WebConfig
from aiav.web.jobs import JobManager, TERMINAL_STATUSES, cleanup_uploads, safe_display_name

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

DISPOSITION_RISKS = ("malicious", "suspicious")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _bootstrap(config: WebConfig) -> JobManager:
    config.uploads_dir.mkdir(parents=True, exist_ok=True)
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    manager = JobManager(config)
    manager.start()
    cleanup_uploads(config)
    return manager


@asynccontextmanager
async def _lifespan(app: FastAPI):
    import asyncio

    manager: JobManager = app.state.manager
    stop = asyncio.Event()

    async def _periodic() -> None:
        interval = max(1, app.state.config.cleanup_interval_minutes) * 60
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                await asyncio.to_thread(cleanup_uploads, app.state.config)

    task = asyncio.create_task(_periodic())
    try:
        yield
    finally:
        stop.set()
        task.cancel()
        manager.stop()


def create_app(config: WebConfig | None = None) -> FastAPI:
    config = config or WebConfig.from_env()
    app = FastAPI(title="AI AV Web UI", docs_url=None, redoc_url=None, lifespan=_lifespan)
    app.state.config = config
    app.state.manager = _bootstrap(config)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ---------------- 页面 ----------------
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "index.html", {
            "config": request.app.state.config,
            "max_upload_mb": config.max_upload_mb,
            "ai_enabled": config.ai_enabled,
            "allow_local_path": config.allow_local_path,
        })

    @app.get("/report/{job_id}", response_class=HTMLResponse)
    async def report_page(request: Request, job_id: str) -> HTMLResponse:
        """报告页：内嵌现有 HTML 报告（iframe 指向 `/report/<id>/raw`）。"""
        job = request.app.state.manager.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="没有这个任务")
        return templates.TemplateResponse(request, "report.html", {"job": job.public()})

    @app.get("/report/{job_id}/raw", response_class=HTMLResponse)
    async def report_raw(request: Request, job_id: str) -> HTMLResponse:
        """原样返回 `report.write_reports` 产出的 HTML（同一套 CSS，不做二次加工）。"""
        job = request.app.state.manager.get(job_id)
        if job is None or not job.html_path:
            raise HTTPException(status_code=404, detail="报告还没生成")
        path = Path(job.html_path)
        if not path.is_file():
            raise HTTPException(status_code=404, detail="报告文件不在磁盘上了")
        return HTMLResponse(path.read_text(encoding="utf-8"))

    # ---------------- 扫描接口 ----------------
    @app.post("/api/scan")
    async def api_scan(request: Request, file: UploadFile | None = None):
        manager: JobManager = request.app.state.manager
        if file is None or not file.filename:
            raise HTTPException(status_code=400, detail="需要一个名为 file 的上传字段")

        job_id = uuid.uuid4().hex
        dest_dir = config.uploads_dir / job_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        # 落盘名固定为 upload.bin：客户端给的文件名只当展示字符串用（不参与路径）
        dest = dest_dir / "upload.bin"

        total = 0
        try:
            with dest.open("wb") as fh:
                while True:
                    chunk = await file.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > config.max_upload_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail=f"文件超过上限 {config.max_upload_mb}MB",
                        )
                    fh.write(chunk)
        except HTTPException:
            shutil.rmtree(dest_dir, ignore_errors=True)
            raise
        except OSError as exc:
            shutil.rmtree(dest_dir, ignore_errors=True)
            raise HTTPException(status_code=500, detail=f"写入上传区失败: {type(exc).__name__}") from exc

        if total == 0:
            shutil.rmtree(dest_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail="空文件没有扫描价值")

        job = manager.register_upload(dest, safe_display_name(file.filename), job_id=job_id)
        if not manager.submit(job):
            manager.discard(job_id)
            shutil.rmtree(dest_dir, ignore_errors=True)
            return JSONResponse(
                status_code=429,
                content={"detail": "扫描队列已满（单并发），稍后再试", "max_queued": config.max_queued},
            )
        return {"job_id": job.job_id, "status": job.status, "file": job.display_name}

    @app.get("/api/scan/{job_id}")
    async def api_scan_status(request: Request, job_id: str):
        job = request.app.state.manager.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="没有这个任务")
        payload = job.public()
        payload["terminal"] = job.status in TERMINAL_STATUSES
        return payload

    # ---------------- 处置页面（读现有 StateStore） ----------------
    @app.get("/history", response_class=HTMLResponse)
    async def history_page(request: Request, limit: int = 50) -> HTMLResponse:
        store = request.app.state.manager.store
        rows = list(reversed(store.history(limit=max(1, min(limit, 500)))))
        return templates.TemplateResponse(request, "history.html", {"rows": rows, "limit": limit})

    @app.get("/quarantine", response_class=HTMLResponse)
    async def quarantine_page(request: Request, flash: str = "") -> HTMLResponse:
        store = request.app.state.manager.store
        records = sorted(store.records(), key=lambda r: str(r.get("quarantined_at", "")), reverse=True)
        rows = [{**r, "name": Path(str(r.get("original_path", ""))).name} for r in records]
        return templates.TemplateResponse(request, "quarantine.html", {"rows": rows, "flash": flash})

    @app.post("/api/quarantine/{record_id}/restore")
    async def api_restore(request: Request, record_id: str):
        store = request.app.state.manager.store
        plan = store.restore(record_id, apply=True, verify_hash=True)
        if plan.get("error"):
            return JSONResponse(status_code=400, content=plan)
        return plan

    @app.post("/quarantine/{record_id}/restore")
    async def restore_form(request: Request, record_id: str):
        """表单式还原（无 JS 也能用）：复用同一个 `StateStore.restore`，出错把原因显示在页面上。"""
        store = request.app.state.manager.store
        plan = store.restore(record_id, apply=True, verify_hash=True)
        name = Path(str(plan.get("to", ""))).name or record_id
        if plan.get("error"):
            msg = f"还原失败（{name}）：{plan['error']}"
        else:
            msg = f"已还原：{name} → 原路径（sha256 校验通过）"
        return RedirectResponse(url=f"/quarantine?flash={quote(msg)}", status_code=303)

    @app.get("/whitelist", response_class=HTMLResponse)
    async def whitelist_page(request: Request) -> HTMLResponse:
        store = request.app.state.manager.store
        rows = sorted(store.whitelist(), key=lambda r: str(r.get("added_at", "")), reverse=True)
        return templates.TemplateResponse(request, "whitelist.html", {"rows": rows})

    # ---------------- 探活 ----------------
    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/debug/layout", response_class=HTMLResponse)
    async def debug_layout(request: Request) -> HTMLResponse:
        """自检页：数出"横向溢出"实测值，供 `scripts/web_screenshots.py` 做手机宽度验收。

        为什么要有它：headless chrome 的截图窗口最小 500px（硬限制），
        所以"≤420px 不崩"这条不能靠肉眼看截图，得靠**可复现的实测数字**：
        `scrollWidth / clientWidth`（文档是否溢出）+ 每张表的
        `scrollWidth > clientWidth`（表格是否落在可横向滚动的容器里）。
        页面上只有数字，没有任何敏感信息。
        """
        return templates.TemplateResponse(request, "debug_layout.html", {})

    return app


def _env_app() -> FastAPI:
    """uvicorn 的入口应用（`python -m uvicorn web.app:app`）。"""
    return create_app(WebConfig.from_env())


app = _env_app()
