"""Web UI 的冒烟与关键不变量（2026-10-08 新建）。

背景：`aiav/web/` 之前**零测试**。这里守住几条最容易静默坏掉的：
  1. 上传保留原始扩展名 —— 丢了 = 扩展名判据（HIGH_RISK_EXTENSION）与
     按文件类型选工具的路径全部失效（本项目最忌的"静默降级"）；
  2. 文件名里的路径穿越 / HTML 不注入；
  3. 上传超限 413 且不留残目录；队列满 429。

Web 是可选依赖，没装 fastapi 就整体跳过。
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

# `aiav.web.app` 在 import 时就会建目录 + 起 worker 线程：先指向临时状态目录，别污染真实 state。
os.environ.setdefault("AI_AV_STATE_DIR", tempfile.mkdtemp(prefix="aiav-web-test-"))

from fastapi.testclient import TestClient  # noqa: E402

from aiav.web.app import create_app  # noqa: E402
from aiav.web.config import WebConfig  # noqa: E402


def _wait_done(client: TestClient, job_id: str, timeout: float = 60.0) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        s = client.get(f"/api/scan/{job_id}").json()
        if s.get("terminal"):
            return s
        time.sleep(0.2)
    raise AssertionError("任务超时未完成")


@pytest.fixture()
def client(tmp_path):
    cfg = WebConfig.from_env(state_dir=tmp_path / "state")
    app = create_app(cfg)
    with TestClient(app) as c:
        yield c, cfg


def test_smoke_pages(client) -> None:
    c, _cfg = client
    for path in ("/", "/history", "/quarantine", "/whitelist", "/healthz", "/debug/layout"):
        assert c.get(path).status_code == 200, path


def test_upload_keeps_original_extension(client) -> None:
    """上传 `sample.exe` 必须按 `.exe` 分析，不能退化成落盘名 `.bin`。

    回归：2026-10-08 前落盘一律 `upload.bin`，扫描器按 `.bin` 走 →
    `HIGH_RISK_EXTENSION` 不命中、`prefilter_score` 从 125 掉到 0。
    """
    c, cfg = client
    exe = b"MZ" + b"\x00" * 200 + b"kernel32.dll\x00CreateFileW\x00"
    r = c.post("/api/scan", files={"file": ("sample.exe", exe)})
    assert r.status_code == 200, r.text
    s = _wait_done(c, r.json()["job_id"])
    assert s["status"] == "done"
    assert s["file"] == "sample.exe"

    reports = sorted(cfg.reports_dir.glob("*/scan.json"))
    assert reports, "报告没落盘"
    rep = json.loads(reports[0].read_text(encoding="utf-8"))["reports"][0]
    assert rep["extension"] == ".exe"
    assert rep["prefilter_score"] == 125
    assert "HIGH_RISK_EXTENSION" in [h.get("heur_id") for h in rep.get("criteria_hits") or []]


def test_upload_filename_cannot_traverse_or_inject(client) -> None:
    """客户端文件名只当展示字符串：不进路径、落盘目录永远是 uuid。"""
    c, cfg = client
    r = c.post("/api/scan", files={"file": ("../../../../etc/passwd", b"x" * 8)})
    assert r.status_code == 200
    name = r.json()["file"]
    assert "/" not in name and "\\" not in name and ".." not in name
    dirs = [p.name for p in cfg.uploads_dir.iterdir()]
    assert dirs and all(len(d) == 32 for d in dirs), dirs


def test_oversize_is_413_and_leaves_nothing(tmp_path) -> None:
    cfg = WebConfig.from_env(state_dir=tmp_path / "state", max_upload_mb=1)
    app = create_app(cfg)
    with TestClient(app) as c:
        big = b"A" * (1024 * 1024 + 1)
        r = c.post("/api/scan", files={"file": ("big.bin", big)})
        assert r.status_code == 413
        assert list(cfg.uploads_dir.iterdir()) == []


def test_display_name_is_escaped_in_report(client) -> None:
    """恶意文件名不许注入到内嵌报告（HTML 转义）。"""
    c, _cfg = client
    evil = "<img src=x onerror=alert(1)>.txt"
    r = c.post("/api/scan", files={"file": (evil, b"hello world\n")})
    s = _wait_done(c, r.json()["job_id"])
    raw = c.get(f"/report/{s['job_id']}/raw").text
    assert "<img src=x onerror" not in raw
    assert "&lt;img" in raw


def test_queue_full_returns_429(client, monkeypatch) -> None:
    """单并发 + 有界队列：排满就 429，不无限堆积。"""
    c, _cfg = client
    mgr = c.app.state.manager
    release = threading.Event()
    monkeypatch.setattr(mgr, "_pre_scan_hook", lambda: release.wait(10))
    try:
        codes = [c.post("/api/scan", files={"file": (f"f{i}.txt", b"x" * 8)}).status_code
                 for i in range(6)]
    finally:
        release.set()
    assert codes[0] == 200
    assert 429 in codes, codes


# ------------------------------------------------------------------ 扫描参数（页面可改）

def _report_json(cfg) -> dict:
    """读最近一份 web 报告 JSON（等终态后再读，加一次重试防 rename 竞态）。"""
    import glob as _glob_mod
    for _ in range(20):
        hits = sorted(_glob_mod.glob(str(cfg.reports_dir / "*" / "scan.json")))
        if hits:
            try:
                return json.loads(Path(hits[-1]).read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                time.sleep(0.1)
        time.sleep(0.1)
    raise AssertionError("没找到可读的报告 JSON")


def test_settings_defaults_and_clamping(client) -> None:
    """非法/越界/自相矛盾的参数一律钳到安全区间，未知键丢弃。"""
    c, _cfg = client
    before = c.get("/api/settings").json()
    assert before["params"]["ai_threshold"] == 300
    assert set(before["limits"]) >= {"ai_threshold", "triage_threshold", "token_budget"}

    r = c.put("/api/settings", json={
        "ai_threshold": 200, "ai_threshold_low": 999,      # 低档不许高过闸门
        "triage_threshold": 9999,                          # >100 → 钳到 100
        "triage_entry_gate": -5,                           # <0 → 0
        "deep_evidence_threshold": "abc",                  # 非法 → 默认 0
        "bogus": 1,                                        # 未知键丢弃
    })
    assert r.status_code == 200
    got = r.json()["params"]
    assert got["ai_threshold"] == 200
    assert got["ai_threshold_low"] == 200          # 钳到闸门
    assert got["triage_threshold"] == 100
    assert got["triage_entry_gate"] == 0
    assert got["deep_evidence_threshold"] == 0
    assert "bogus" not in got
    # 落盘之后再读，值一致
    assert c.get("/api/settings").json()["params"] == got


def test_settings_persist_across_restart(tmp_path) -> None:
    cfg = WebConfig.from_env(state_dir=tmp_path / "state")
    app = create_app(cfg)
    with TestClient(app) as c:
        c.put("/api/settings", json={"ai_threshold": 250, "deep_evidence_threshold": 300})
    app2 = create_app(cfg)
    with TestClient(app2) as c:
        got = c.get("/api/settings").json()["params"]
    assert got["ai_threshold"] == 250
    assert got["deep_evidence_threshold"] == 300


def test_settings_ai_guard_when_server_disallows(client) -> None:
    """服务端没允许（AI_AV_WEB_AI=0）时，页面勾了 AI/初筛也不放行 —— 不让人从页面绕过成本闸。"""
    c, _cfg = client
    got = c.put("/api/settings", json={"ai": True, "triage": True}).json()["params"]
    assert got["ai"] is False and got["triage"] is False
    assert c.get("/api/settings").json()["ai"]["allowed"] is False


def test_scan_uses_saved_thresholds(client) -> None:
    """页面上改的闸门必须真进扫描（报告 deterministic.gate 能看出用的哪一档）。"""
    c, cfg = client
    c.put("/api/settings", json={"ai_threshold": 200, "ai_threshold_low": 0})
    r = c.post("/api/scan", files={"file": ("x.exe", b"MZ" + b"\x00" * 200 + b"k.dll\x00")})
    _wait_done(c, r.json()["job_id"])
    rep = _report_json(cfg)["reports"][0]
    det = rep["deterministic"]
    assert det.get("gate") == 200          # 默认 300 → 页面改成 200
    # 低档 0 = 关闭，`quick_prefilter` 会把有效下界归一成闸门本身（200）
    assert det.get("gate_low") == 200


def test_ai_requested_but_unavailable_is_reported(tmp_path, monkeypatch) -> None:
    """服务端允许 AI、但没有 key：勾了 AI 也不能静默降级 —— 产物里必须写明。"""
    for var in ("AGENT_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    cfg = WebConfig.from_env(state_dir=tmp_path / "state", ai_enabled=True)
    app = create_app(cfg)
    with TestClient(app) as c:
        st = c.get("/api/settings").json()["ai"]
        assert st["allowed"] is True and st["ready"] is False
        assert "Key" in st["reason"]
        assert c.put("/api/settings", json={"ai": True}).json()["params"]["ai"] is True

        r = c.post("/api/scan", files={"file": ("y.txt", b"hello world\n")})
        s = _wait_done(c, r.json()["job_id"])
        assert s["summary"]["ai_requested"] is True
        assert s["summary"]["ai_enabled"] is False
        assert s["summary"]["ai_fallback"]          # 有原因，不是空
        assert s["ai_ready"] is False
        assert s["ai_reason"]


# ------------------------------------------------------------------ 本地路径扫描（文件夹）

def test_local_scan_disallowed_by_default(client) -> None:
    """默认不许扫本地路径（任意路径读取是个口子，必须显式 opt-in）。"""
    c, _cfg = client
    r = c.post("/api/scan-local", json={"path": "/tmp"})
    assert r.status_code == 400
    assert "AI_AV_WEB_ALLOW_LOCAL_PATH" in r.json()["detail"]


def test_local_scan_scans_a_directory(tmp_path) -> None:
    """允许后，给一个文件夹要把它下面的文件都扫到（含子目录），来源记 local。"""
    corpus = tmp_path / "corpus"
    (corpus / "sub").mkdir(parents=True)
    for i in range(3):
        (corpus / f"f{i}.exe").write_bytes(b"MZ" + b"\x00" * 64)
    (corpus / "a.txt").write_bytes(b"hello\n")
    (corpus / "sub" / "nested.bin").write_bytes(b"x")

    cfg = WebConfig.from_env(state_dir=tmp_path / "state", allow_local_path=True)
    app = create_app(cfg)
    with TestClient(app) as c:
        r = c.post("/api/scan-local", json={"path": str(corpus)})
        assert r.status_code == 200, r.text
        assert r.json()["source"] == "local"
        s = _wait_done(c, r.json()["job_id"])
        assert s["status"] == "done"
        assert s["files"] == 5
        su = s["summary"]
        assert su["source"] == "local"
        assert su["total"] == 5
        assert {f["name"] for f in su["per_file"]} == {
            "f0.exe", "f1.exe", "f2.exe", "a.txt", "nested.bin"}
        # 本地扫描保留原始路径（目录里要分清是哪个文件）
        rep = _report_json(cfg)["reports"][0]
        assert str(corpus) in rep["path"] or rep["path"].endswith(rep["name"])


def test_local_path_rejects_bad_paths(tmp_path) -> None:
    cfg = WebConfig.from_env(state_dir=tmp_path / "state", allow_local_path=True)
    app = create_app(cfg)
    with TestClient(app) as c:
        assert c.post("/api/scan-local", json={"path": "/definitely/not/here"}).status_code == 400
        assert c.post("/api/scan-local", json={}).status_code == 400


def test_local_roots_confines_the_scope(tmp_path) -> None:
    """配了 AI_AV_WEB_LOCAL_ROOTS 就只能扫根目录内的东西。"""
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "a.txt").write_bytes(b"hello")
    (outside / "b.txt").write_bytes(b"hello")

    cfg = WebConfig.from_env(state_dir=tmp_path / "state", allow_local_path=True,
                             local_roots=(str(allowed),))
    app = create_app(cfg)
    with TestClient(app) as c:
        assert c.post("/api/scan-local", json={"path": str(allowed)}).status_code == 200
        bad = c.post("/api/scan-local", json={"path": str(outside)})
        assert bad.status_code == 400
        assert "根目录" in bad.json()["detail"]
