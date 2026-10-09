"""②层 LLM 初筛**接进流水线**（2026-09-27）—— 回归测试。

守四件事（每一条都是"读产物的人会看错"的地方）：

  1. **入口**：只有"未结案 + 预筛分 ∈ [入口, 深度 AI 闸门)"的文件才进初筛；
     ≥ 闸门的由规则直送（不过初筛）、< 入口的不烧 token、①层结案的永不进。
  2. **路由**：初筛分 ≥ 门槛 → 文件**即使预筛分没到闸门**也进 ③；
     < 门槛 → 静默放行；**拿不到分数（调用失败）不许当成"没过门槛"**。
  3. **报告字段**：`deterministic.triage` 与抬头账本（候选/选中/放行/没拿到分数）
     能分开数，且初筛选中的文件在送审三档里记 `triage`（不是"未结案"）。
  4. **钱**：一个真实模型调用都不发 —— 假 HTTP 客户端顶掉 `httpx.post`。

假客户端返回的是**真 JSON 形状**（走 `TriageClient.classify` 的真解析路径），
不是直接塞一个分数进去 —— 否则"解析口径"这一段就没被测到。
"""

from __future__ import annotations

from pathlib import Path

from aiav import criteria as C
from aiav import scanner
from aiav.models import PreliminaryEvidence, RiskLevel, Verdict


# ------------------------------------------------------------------ 纯函数：入口 / 档位

def test_effective_triage_entry_gate_normalises_both_ends() -> None:
    """`0` = 入口不设下界；入口 ≥ 闸门 = 初筛永不触发。"""
    assert C.effective_triage_entry_gate(125, 300) == 125
    assert C.effective_triage_entry_gate(0, 300) == 0
    assert C.effective_triage_entry_gate(-5, 300) == 0
    assert C.effective_triage_entry_gate(500, 300) == 300   # 入口比闸门还高 = 不放人进初筛


def test_is_triage_candidate_covers_the_gray_band_only() -> None:
    """灰区 [125, 300) 进初筛；≥300 规则直送；<125 判据没信号、不烧。"""
    assert C.is_triage_candidate(125) is True
    assert C.is_triage_candidate(199) is True
    assert C.is_triage_candidate(299) is True
    assert C.is_triage_candidate(300) is False
    assert C.is_triage_candidate(1125) is False
    assert C.is_triage_candidate(124) is False
    assert C.is_triage_candidate(0) is False
    # 入口 0 = 不设下界（任何未结案文件都能进初筛）
    assert C.is_triage_candidate(0, entry_gate=0) is True


def test_triage_tier_never_turns_missing_score_into_a_verdict() -> None:
    """没拿到分数 → `none`，**不是** `drop`。故障不许伪装成判定。"""
    assert C.triage_tier(60) == "select"
    assert C.triage_tier(59) == "drop"
    assert C.triage_tier(0) == "drop"
    assert C.triage_tier(None) == "none"


# ------------------------------------------------------------------ 假模型客户端

class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = payload
        self.status_code = 200
        self.text = str(payload)
        self.headers: dict[str, str] = {}

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        return None


class _FakeHttp:
    """顶掉 `httpx.Client`：只实现 `post` / `close`，返回真 JSON 形状。"""

    def __init__(self, score: int | None, *, reason: str = "（测试桩）"):
        self.score = score
        self.reason = reason
        self.calls: list[str] = []

    def post(self, url: str, json: dict | None = None) -> _FakeResponse:
        self.calls.append(url)
        if self.score is None:
            # 空输出（被 max_tokens 截断的那种）：`classify` 会重试再作废
            return _FakeResponse({"choices": [{"message": {"content": ""},
                                               "finish_reason": "length"}],
                                  "usage": {"prompt_tokens": 10, "completion_tokens": 0,
                                            "total_tokens": 10}})
        content = f'{{"score": {self.score}, "reason": "{self.reason}"}}'
        return _FakeResponse({
            "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 700, "completion_tokens": 120, "total_tokens": 820},
        })

    def close(self) -> None:
        return None

    def __enter__(self) -> "_FakeHttp":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class _FakeTriageClient:
    """真的 `TriageClient` + 假 HTTP —— **不重写 `classify`**。

    为什么不用手写的替身：`classify` 里的重试 / 空输出 / usage 口径正是这一层
    最该被测到的部分，手写替身会把它整段跳过。这里只做两件事：
    给一个假 key 让它构造得起来，再把 `_client()` 指到假 HTTP。
    """

    def __init__(self, score: int | None, *, reason: str = "（测试桩）"):
        from aiav.triage import TriageClient

        self._real = TriageClient(model="fake-flash", base_url="https://example.invalid/v1",
                                  api_key="sk-test", timeout=5.0, retries=0)
        self.http = _FakeHttp(score, reason=reason)
        self._real._client = lambda: self.http          # 单文件路径：直接用假 HTTP

    def __getattr__(self, item):
        return getattr(self._real, item)


def _install_fake_http(monkeypatch, http: _FakeHttp) -> None:
    """批量路径（`run_batch`）自己 `with httpx.Client(...)` —— 从 triage 模块里换掉它。"""
    from aiav import triage as T

    monkeypatch.setattr(T.httpx, "Client", lambda **kw: http)


def _stub_evidence(path: str, score: int, kwargs: dict) -> PreliminaryEvidence:
    """替掉 `quick_prefilter` 的最小证据块（只带路由要看的字段）。"""
    gate = int(kwargs.get("ai_threshold") or 300)
    gate_low = kwargs.get("ai_threshold_low")
    gate_low = C.AI_GATE_LOW if gate_low is None else int(gate_low)
    low = C.effective_low_gate(gate, gate_low)
    return PreliminaryEvidence(
        path=path, sha256="a" * 64, size=66, extension=".exe", prefilter_score=score,
        deterministic={
            "disposition": "send_ai" if score >= low else "pass",
            "tier": "weak", "band": "suspicious", "band_label": "可疑", "score": score,
            "sends_to_ai": score >= low, "reasons": ["（测试桩）"],
            "gate": gate, "gate_low": low,
            "ai_tier": C.ai_tier(score, gate=gate, gate_low=gate_low) if score >= low else "none",
        },
    )


def _patch(monkeypatch, tmp_path: Path, score: int, prefilter: int):
    """统一的测试台：假预筛 + 假模型 + 假深度 AI，返回"深度 AI 被调了几次"的列表。"""
    p = tmp_path / "t.exe"
    # 桩内容**按用例加盐**：扫描缓存的键是**内容 sha256**，内容一样 = 上一条用例写下的
    # 结论会被这一条原样读走（2026-09-29 那 5 条恒红就是踩了这个：`agent_used` 变 True、
    # 初筛分变成别人的 80、深度 AI 一次没被调）。目录名带用例名，天然唯一。
    p.write_bytes(b"MZ" + b"\x01" * 64 + tmp_path.name.encode())
    monkeypatch.setenv("AI_AV_SIGNATURE_CHECK", "0")
    monkeypatch.setattr(scanner, "quick_prefilter",
                        lambda *a, **k: _stub_evidence(str(p), prefilter, k))
    client = _FakeTriageClient(score)
    _install_fake_http(monkeypatch, client.http)
    called: list[int] = []

    def fake_analyze(agent, deps, evidence, budget=None, preload=None):
        called.append(evidence.prefilter_score)
        return Verdict(risk=RiskLevel.clean, confidence=0.9, category="clean", summary="ok")

    monkeypatch.setattr(scanner, "analyze_file_with_agent", fake_analyze)
    return p, client, called


def _scan(p: Path, client, **kw):
    return scanner.scan_file(p, agent=object(), ai_threshold=300, ai_threshold_low=0,
                             store=None, allow_unpack=False, allow_archives=False,
                             cache=None, deep_evidence_threshold=0,
                             triage_enabled=True, triage_client=client, **kw)


# ------------------------------------------------------------------ 路由

def test_triage_selected_file_reaches_deep_ai_despite_low_rule_score(tmp_path, monkeypatch):
    """灰区文件（125 分）初筛 80 ≥ 60 → **真的进 ③**，档位记 `triage`。"""
    p, client, called = _patch(monkeypatch, tmp_path, 80, 125)
    report = _scan(p, client)

    assert called == [125]                          # 深度 AI 真被调了
    assert report.agent_used is True
    assert report.deterministic["ai_tier"] == "triage"
    assert report.deterministic["disposition"] == "send_ai"
    tri = report.deterministic["triage"]
    assert tri["candidate"] is True and tri["score"] == 80 and tri["tier"] == "select"
    assert tri["entry_gate"] == 125 and tri["threshold"] == 60
    assert tri["source"] == "run" and tri["error"] == ""
    assert client.http.calls == ["https://example.invalid/v1/chat/completions"]


def test_triage_below_threshold_passes_silently(tmp_path, monkeypatch):
    """初筛 40 < 60 → 不送 ③、不下结论，但分数与门槛**留在产物里**。"""
    p, client, called = _patch(monkeypatch, tmp_path, 40, 125)
    report = _scan(p, client)

    assert called == []
    assert report.agent_used is False
    assert report.deterministic["disposition"] == "pass"
    assert report.deterministic["ai_tier"] == "none"
    tri = report.deterministic["triage"]
    assert tri["candidate"] is True and tri["score"] == 40 and tri["tier"] == "drop"


def test_triage_failure_is_not_a_drop(tmp_path, monkeypatch):
    """调用失败（空输出）→ `tier=none` + 错误留痕；**不许**记成"没过门槛"。"""
    p, client, called = _patch(monkeypatch, tmp_path, None, 125)
    report = _scan(p, client)

    assert called == []                             # 没拿到分数就不送（这一档本来没结案）
    tri = report.deterministic["triage"]
    assert tri["candidate"] is True
    assert tri["score"] is None
    assert tri["tier"] == "none"                    # 不是 drop
    assert "empty_output" in tri["error"]


def test_files_above_the_gate_skip_triage_entirely(tmp_path, monkeypatch):
    """≥ 闸门的分由规则直送 ③：初筛**一次都不许调**（规则已经说值得看）。"""
    p, client, called = _patch(monkeypatch, tmp_path, 80, 425)
    report = _scan(p, client)

    assert called == [425]                          # 直送 ③
    assert report.deterministic["ai_tier"] == "high"
    assert report.deterministic["triage"]["candidate"] is False
    assert client.http.calls == []                  # 0 次初筛调用


def test_files_below_the_entry_gate_do_not_burn_tokens(tmp_path, monkeypatch):
    """<125 判据没信号：不进初筛（这一层要真花钱）。"""
    p, client, called = _patch(monkeypatch, tmp_path, 99, 0)
    report = _scan(p, client)

    assert called == []
    assert report.deterministic["triage"]["candidate"] is False
    assert client.http.calls == []


def test_triage_off_by_default_never_calls_the_model(tmp_path, monkeypatch):
    """默认关：不传 `triage_enabled` 时一个初筛调用都不发（成本不许静默变样）。"""
    p, client, called = _patch(monkeypatch, tmp_path, 80, 125)
    report = scanner.scan_file(p, agent=object(), ai_threshold=300, ai_threshold_low=0,
                               store=None, allow_unpack=False, allow_archives=False,
                               cache=None, deep_evidence_threshold=0)
    assert called == []
    assert client.http.calls == []
    assert report.deterministic["triage"]["enabled"] is False


# ------------------------------------------------------------------ 批量：候选挑选

def test_collect_triage_scores_only_pays_for_the_gray_band(tmp_path, monkeypatch):
    """批量挑候选：只有灰区未结案的文件被送去花钱，其余三类各有计数。"""
    p125, client, _ = _patch(monkeypatch, tmp_path, 70, 125)
    # 四个文件都得真存在（sha 要算得出来）；内容各不相同 + 按用例加盐，
    # 免得 sha 撞在一起（撞了就是缓存串味，见 `_patch` 里的说明）。
    for i, name in enumerate(("t.exe", "high.exe", "zero.exe", "closed.exe")):
        (tmp_path / name).write_bytes(b"MZ" + bytes([i + 1]) * 64 + tmp_path.name.encode())

    # 四个文件各代表一类：灰区候选 / ≥闸门 / <入口 / ①层结案
    scores = {"t.exe": 125, "high.exe": 425, "zero.exe": 0, "closed.exe": 1125}

    def prefilter_with_conclusive(path, sha256, **k):
        if Path(path).name == "closed.exe":
            ev = _stub_evidence(str(path), 1125, k)
            ev.deterministic["disposition"] = "closed_malicious"
            ev.deterministic["sends_to_ai"] = False
            ev.deterministic["ai_tier"] = "none"
            return ev
        return _stub_evidence(str(path), scores[Path(path).name], k)

    monkeypatch.setattr(scanner, "quick_prefilter", prefilter_with_conclusive)
    files = [tmp_path / n for n in ("t.exe", "high.exe", "zero.exe", "closed.exe")]
    records, stats = scanner.collect_triage_scores(
        files, client=client, threshold=60, entry_gate=125, gate=300)

    assert stats["candidates"] == 1                 # 只有 t.exe（125 分未结案）
    assert stats["ran"] == 1 and stats["ok"] == 1
    assert stats["selected"] == 1
    assert stats["skipped"]["规则直送（≥闸门）"] == 1
    assert stats["skipped"]["①层已结案"] == 1
    assert stats["skipped"]["不在初筛入口档"] == 1
    assert list(records) == [scanner.compute_sha256(tmp_path / "t.exe")]
    assert records[list(records)[0]]["score"] == 70
    assert len(client.http.calls) == 1              # 只花了 1 次模型调用


# ------------------------------------------------------------------ 批次口径一致性

def test_collect_uses_the_same_signature_evidence_as_scan_file(tmp_path, monkeypatch):
    """挑候选的预筛**必须跟 `scan_file` 用同一档签名证据**。

    2026-09-27 第一遍 r1 踩的坑：批次挑候选时没采签名证据 → `DET_TRUSTED_SIGNATURE`
    不命中 → 51 个"签名可信 → 判干净结案"的良性文件在批次眼里是 125 分未结案，
    于是被当成灰区候选**送去花钱初筛**（批次报 191 个候选），
    而 `scan_file` 那边它们早就结案了（产物里只有 143 个真跑过）。
    两个数并排放在同一份报告里，**一点异常都看不出来**。
    """
    p = tmp_path / "signed.exe"
    p.write_bytes(b"MZ" + b"\x03" * 64)
    seen: list[bool] = []

    def fake_prefilter(path, sha256, **kw):
        seen.append(bool(kw.get("with_signature")))
        ev = _stub_evidence(str(path), 125, kw)
        if kw.get("with_signature"):
            ev.deterministic["disposition"] = "closed_clean"
            ev.deterministic["sends_to_ai"] = False
            ev.deterministic["ai_tier"] = "none"
            ev.prefilter_score = 0
        return ev

    monkeypatch.setattr(scanner, "quick_prefilter", fake_prefilter)
    client = _FakeTriageClient(70)
    _install_fake_http(monkeypatch, client.http)

    records, stats = scanner.collect_triage_scores(
        [p], client=client, threshold=60, entry_gate=125, gate=200)
    assert seen == [True]                      # 采了签名证据
    assert stats["candidates"] == 0            # 已结案的良性不进初筛
    assert stats["skipped"]["①层已结案"] == 1
    assert records == {}
    assert client.http.calls == []


# ------------------------------------------------------------------ 报告

def test_report_counts_the_triage_tier(tmp_path) -> None:
    """报告抬头能把"初筛选中送 ③"单独数出来，逐文件行有它自己的档位标签。"""
    from aiav.models import FileReport
    from aiav.report import build_summary, write_reports

    def rep(score: int, tier: str, tri: dict, used: bool) -> FileReport:
        return FileReport(
            path=f"/x/{score}-{tier}.exe", sha256=f"{score:064d}"[:64],
            size=1, extension=".exe", prefilter_score=score,
            deterministic={"disposition": "send_ai" if tier != "none" else "pass",
                           "tier": "weak", "band": "suspicious", "band_label": "可疑",
                           "score": score, "sends_to_ai": tier != "none", "reasons": [],
                           "gate": 200, "gate_low": 200, "ai_tier": tier, "triage": tri},
            verdict=Verdict(risk=RiskLevel.clean, confidence=0.9, category="test", summary="x"),
            agent_used=used,
        )

    tri_select = {"enabled": True, "entry_gate": 125, "threshold": 60, "candidate": True,
                  "score": 80, "tier": "select", "model": "fake-flash", "reason": "r",
                  "source": "run", "error": ""}
    tri_drop = dict(tri_select, score=30, tier="drop")
    tri_fail = dict(tri_select, score=None, tier="none", error="empty_output")
    tri_none = {"enabled": True, "entry_gate": 125, "threshold": 60, "candidate": False,
                "score": None, "tier": "none", "model": "", "reason": "", "source": "none",
                "error": ""}
    reports = [
        rep(425, "high", tri_none, True),
        rep(125, "triage", tri_select, True),
        rep(125, "none", tri_drop, False),
        rep(125, "none", tri_fail, False),
    ]
    det = build_summary(reports)["deterministic"]
    assert det["sent_triage"] == 1
    assert det["ai_tiers"] == {"high": 1, "low": 0, "triage": 1, "none": 2}
    tri = det["triage"]
    assert tri["enabled"] is True
    assert tri["candidates"] == 3 and tri["selected"] == 1
    assert tri["dropped"] == 1 and tri["no_score"] == 1
    assert tri["ai_files"] == 1 and tri["flagged"] == 0

    _json, html, _audit = write_reports(reports, tmp_path / "out")
    text = html.read_text(encoding="utf-8")
    assert "②层 LLM 初筛" in text
    assert "初筛选中送 ③" in text
    assert "只看初筛送审" in text
    assert 'data-tier="triage"' in text
    assert "没拿到分数" in text                     # 抬头把"故障 ≠ 判定"写出来了
    # 逐文件行也要能看出"初筛失败"（2026-10-08 修：以前失败只显示"未送（静默）"）
    assert "初筛失败" in text
    assert "empty_output" in text


# ------------------------------------------------------------------ 2026-10-08 修复：失败文案 / 缓存键

def test_triage_failure_reason_never_says_below_threshold(tmp_path, monkeypatch):
    """自由文本里也不许把"调用失败"写成"未达门槛"。

    结构化 `tier=none` 早已正确，但 `prefilter_reasons` 的自由文本曾拼成
    「LLM 初筛 失败（…）：未达门槛 60」—— 一次故障被读成一个判定，
    正是项目书 6.2.3 说的"最隐蔽的一类错误"。
    """
    p, client, called = _patch(monkeypatch, tmp_path, None, 125)
    report = _scan(p, client)

    reasons = [r for r in report.prefilter_reasons if "初筛" in r]
    assert reasons, "应当留下一条初筛理由"
    joined = " ".join(reasons)
    assert "失败" in joined
    assert "未达门槛" not in joined          # 失败 ≠ 未达门槛
    assert "调用故障" in joined


def test_triage_drop_reason_still_says_below_threshold(tmp_path, monkeypatch):
    """真正"未达门槛"（拿到分但 < 门槛）的文案不许被误伤。"""
    p, client, called = _patch(monkeypatch, tmp_path, 40, 125)
    report = _scan(p, client)

    joined = " ".join(r for r in report.prefilter_reasons if "初筛" in r)
    assert "未达门槛" in joined
    assert "失败" not in joined


def test_scan_cache_mode_carries_triage_settings():
    """②层初筛设置必须进 `ScanCache.mode` 键（否则初筛会被缓存静默跳过）。"""
    from aiav.cache import ScanCache

    off = ScanCache.mode(True, True, True, True, 300, 0, False, 60, 125, None)
    on = ScanCache.mode(True, True, True, True, 300, 0, True, 60, 125, "fake-flash")
    assert off != on
    # 门槛 / 入口 / 模型 任一不同 → 键不同
    assert on != ScanCache.mode(True, True, True, True, 300, 0, True, 70, 125, "fake-flash")
    assert on != ScanCache.mode(True, True, True, True, 300, 0, True, 60, 100, "fake-flash")
    assert on != ScanCache.mode(True, True, True, True, 300, 0, True, 60, 125, "other-flash")
    # 关掉初筛时，门槛/模型不该把同一份"没开初筛"拆成多个键
    assert off == ScanCache.mode(True, True, True, True, 300, 0, False, 99, 1, "x")


def test_scan_cache_does_not_reuse_triage_off_report_for_triage_on(tmp_path, monkeypatch):
    """先跑无初筛、再跑有初筛：第二轮不许命中第一轮的缓存。

    这是"缓存吃掉第二层"的最小复现：旧 `mode` 不含初筛设置，第二轮 `--triage`
    直接吃第一轮的条目，报告回到 `triage.enabled=False`、初筛被静默跳过。
    """
    from aiav.cache import ScanCache

    p, client, called = _patch(monkeypatch, tmp_path, 80, 125)
    cache = ScanCache(root=tmp_path / "cache")

    common = dict(agent=object(), ai_threshold=300, ai_threshold_low=0, store=None,
                  allow_unpack=False, allow_archives=False, cache=cache,
                  deep_evidence_threshold=0)

    # 第一轮：无初筛 → 写进 triage=0 的条目
    r1 = scanner.scan_file(p, triage_enabled=False, triage_client=None, **common)
    assert r1.deterministic["triage"]["enabled"] is False
    assert (r1.cache or {}).get("from_cache") is not True

    # 第二轮：开初筛 → 必须不命中第一轮，真跑初筛
    r2 = scanner.scan_file(p, triage_enabled=True, triage_client=client, **common)
    assert (r2.cache or {}).get("from_cache") is not True, "开了初筛却吃了无初筛的缓存"
    assert r2.deterministic["triage"]["enabled"] is True
    assert r2.deterministic["triage"]["score"] == 80
    assert r2.deterministic["ai_tier"] == "triage"


def test_cli_scan_injects_triage_cache(tmp_path, monkeypatch):
    """主扫描必须把 `TriageCache` 传进 `scan_file`（2026-10-08 修）。

    以前 CLI 只传 `triage_client`、不传 `triage_cache`，生产扫描 ②层每轮重新计费，
    与 `triage_cached` 的 docstring（"流水线与脚本都走这个函数"）矛盾。
    这里用假 agent / 假客户端 / 假 scan_file 把 CLI 表面跑通，断言它真被传下去。
    """
    from typer.testing import CliRunner

    from aiav import cli
    from aiav import triage as T
    from aiav.models import FileReport

    seen: dict = {}

    class _FakeTriageClient:
        def __init__(self, model=None, base_url=None):
            self.model = model or "fake-flash"

    def fake_scan_file(path, **kw):
        seen.clear()
        seen.update(kw)
        return FileReport(path=str(path), sha256="a" * 64, size=1, extension=".exe",
                          prefilter_score=0, deterministic={"triage": {"enabled": True}},
                          verdict=Verdict(risk=RiskLevel.clean, confidence=0.9,
                                          category="clean", summary="x"))

    monkeypatch.setattr(cli, "build_agent", lambda **kw: object())
    monkeypatch.setattr(T, "TriageClient", _FakeTriageClient)
    monkeypatch.setattr(cli, "scan_file", fake_scan_file)
    monkeypatch.setattr(cli, "clamav_scan_batch",
                        lambda *a, **k: {"available": False, "error": "测试桩"})
    monkeypatch.setenv("AI_AV_CACHE", "1")
    monkeypatch.setenv("AI_AV_STATE_DIR", str(tmp_path / "state"))

    sample = tmp_path / "x.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 32)

    result = CliRunner().invoke(cli.app, ["scan", str(sample), "--triage",
                                          "--no-history", "-o", str(tmp_path / "reports")])
    assert result.exit_code == 0, result.output
    assert seen.get("triage_enabled") is True
    assert seen.get("triage_client") is not None
    assert seen.get("triage_cache") is not None, "主扫描没把 TriageCache 传下去"

    # AI_AV_CACHE=0 时不许建缓存（与 ScanCache 同一个开关）
    seen.clear()
    monkeypatch.setenv("AI_AV_CACHE", "0")
    result = CliRunner().invoke(cli.app, ["scan", str(sample), "--triage",
                                          "--no-history", "-o", str(tmp_path / "reports2")])
    assert result.exit_code == 0, result.output
    assert seen.get("triage_cache") is None
