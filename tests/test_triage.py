"""LLM 初筛层（`aiav.triage`）的单元测试。

覆盖四件事（都是本轮真踩过或真需要守住的）：
  1. **摘要**：熵、字符串抽取、预算收敛（超 1000 token 要砍字符串，不是砍骨架）；
     摘要里**不许出现规则分/判据名**（泄题会把这一层变成规则分的复读机）；
  2. **解析**：严格 JSON / 反斜杠修复档 / 正则兜底档 / 干脆失败；
     `parse_mode` 必须逐条留痕（修好的坏输出不能被当成正常输出）；
  3. **成本口径**：provider usage 优先、缺了退估并标注、缓存命中不计费；
  4. **缓存**：同 sha256 + 同模型命中；**换模型不许命中**（不同模型的分数不可互换）。

一个模型调用都不发**：测试只碰纯函数、缓存与假响应，跑测试不花钱。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiav import triage
from aiav.cache import TriageCache


# ---------------------------------------------------------------- 摘要
def test_entropy_known_values() -> None:
    assert triage.shannon_entropy(b"") == 0.0
    assert triage.shannon_entropy(b"\x00" * 100) == 0.0
    assert triage.shannon_entropy(bytes(range(256))) == 8.0
    # 两符号均匀分布 = 1 bit
    assert triage.shannon_entropy(b"AB" * 50) == 1.0


def test_extract_strings_takes_first_by_offset_and_skips_boilerplate() -> None:
    blob = (
        b"!This program cannot be run in DOS mode.\r\r\n"   # 装订板，必须跳过
        b"\x00\x00MZ\x00\x00"
        b"kernel32.dll\x00"
        b"VirtualAlloc\x00"
        b"AAAAAAAAAAAA\x00"                                  # 单字符填充，必须跳过
        b"http://evil.example/payload.bin\x00"
    )
    out = triage.extract_strings(blob, limit=10)
    assert "kernel32.dll" in out
    assert "VirtualAlloc" in out
    assert "http://evil.example/payload.bin" in out
    assert not any("cannot be run in DOS mode" in s for s in out)
    assert "AAAAAAAAAAAA" not in out
    # 偏移顺序：kernel32.dll 在 VirtualAlloc 之前
    assert out.index("kernel32.dll") < out.index("VirtualAlloc")


def test_extract_strings_handles_utf16() -> None:
    blob = "PowerShell -EncodedCommand".encode("utf-16-le") + b"\x00" * 4
    out = triage.extract_strings(blob, limit=5)
    assert any("PowerShell" in s for s in out)


def test_extract_strings_respects_limit_and_truncates_long_ones() -> None:
    blob = b"\x00".join(f"string{i:02d}abcdef".encode() for i in range(50))
    out = triage.extract_strings(blob, limit=20)
    assert len(out) == 20
    blob2 = b"prefix_" + b"A1b2C3d4" * 700 + b"\x00"
    out2 = triage.extract_strings(blob2, limit=1)
    assert len(out2[0]) == triage.MAX_STRING_CHARS


def test_summary_never_leaks_rule_score_or_criteria(tmp_path: Path) -> None:
    """摘要里不许有规则分/判据名 —— 给了就是泄题（模型会去复述它）。"""
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 200 + b"kernel32.dll\x00CreateFileW\x00")
    summary = triage.build_summary(sample, "a" * 64)
    dumped = json.dumps(summary, ensure_ascii=False)
    for forbidden in ("prefilter", "HIGH_RISK", "score", "判据", "DET_"):
        assert forbidden not in dumped, f"摘要泄露了 {forbidden}"
    rendered = triage.render_prompt(summary)
    for forbidden in ("prefilter", "HIGH_RISK", "DET_"):
        assert forbidden not in rendered.user


def test_render_prompt_stays_within_token_budget() -> None:
    """超预算时砍的是**字符串**（从尾部），骨架字段一个都不能少。"""
    summary = {
        "name": "x.exe", "size": 1234, "extension": ".exe", "kind": "pe",
        "entropy": 7.5,
        "layout": [f".sec{i} raw={i}KB ent=7.0 XWR" for i in range(12)],
        "imports": {"dll_count": 3, "api_count": 12,
                    "dlls": ["kernel32.dll"], "key_apis": ["VirtualAlloc"]},
        "pe_flags": {"entry_rva": 4096, "dotnet": False, "machine": "0x14c"},
        "strings": [f"longstring{i:03d}" + "y" * 100 for i in range(20)],
    }
    prompt = triage.render_prompt(summary, max_tokens=800)
    assert prompt.est_tokens <= 800
    assert prompt.truncated is True
    assert prompt.strings_used < 20
    assert prompt.over_budget is False
    # 骨架还在
    assert "布局:" in prompt.user
    assert "导入表:" in prompt.user
    assert "整体熵" in prompt.user


def test_render_prompt_flags_over_budget_instead_of_silently_exceeding() -> None:
    """砍无可砍时必须**留痕**，不能静默交一份超预算的提示词。

    系统提示词自己就 ~500 token，所以 max_tokens 低于它时必然装不下 ——
    这个合同漏洞是测试逼出来的（原来 `or not strings` 直接 break，超了也不说）。
    """
    summary = {
        "name": "x.exe", "size": 1, "extension": ".exe", "kind": "pe", "entropy": 1.0,
        "layout": [f".sec{i} raw={i}KB ent=7.0 XWR" for i in range(12)],
        "imports": {"dll_count": 3, "api_count": 12,
                    "dlls": ["a.dll", "b.dll", "c.dll", "d.dll", "e.dll"],
                    "key_apis": ["VirtualAlloc"]},
        "pe_flags": {"entry_rva": 4096, "dotnet": False, "machine": "0x14c"},
        "strings": [f"s{i}" for i in range(20)],
    }
    prompt = triage.render_prompt(summary, max_tokens=100)
    assert prompt.over_budget is True
    assert prompt.strings_used == 0
    assert prompt.est_tokens > 100
    # 骨架瘦身也执行了：布局砍到 8 条、DLL 砍到 4 个
    assert len(prompt.summary["layout"]) == 8
    assert prompt.summary["layout_more"] == 4
    assert len(prompt.summary["imports"]["dlls"]) == 4


def test_cost_reports_over_budget_entries() -> None:
    rows = [dict(_record(10, 1), summary_over_budget=True),
            dict(_record(10, 1), summary_over_budget=False)]
    cost = triage.summarize_cost(rows)
    assert cost["summary_over_budget"] == 1


def test_render_prompt_marks_no_truncation_when_it_fits() -> None:
    summary = {"name": "a.exe", "size": 10, "extension": ".exe", "kind": "pe",
               "entropy": 1.0, "strings": ["hello"]}
    prompt = triage.render_prompt(summary, max_tokens=triage.TARGET_PROMPT_TOKENS)
    assert prompt.truncated is False
    assert prompt.dropped == 0
    assert prompt.strings_used == 1


# ---------------------------------------------------------------- 解析
def test_parse_strict_json() -> None:
    score, reason, err, mode = triage._parse_score('{"score": 71, "reason": "高熵载荷"}')
    assert (score, reason, err, mode) == (71, "高熵载荷", "", "strict_json")


def test_parse_accepts_code_fence_and_surrounding_prose() -> None:
    text = '好的，我的判断是：\n```json\n{"score": 12, "reason": "正常程序"}\n```\n以上。'
    score, _reason, err, mode = triage._parse_score(text)
    assert score == 12 and err == "" and mode == "strict_json"


def test_parse_repairs_single_backslash_escape() -> None:
    """实测失败类：模型把摘要里的乱码串原样引进 reason，写出非法 JSON 转义。

    这类失败**重试没用**（temperature=0 得到同一个坏字节），只能在解析侧修回来。
    """
    broken = r'{"score": 76, "reason": "乱码 `vqtMFpulT\anMxeW1` 符合加壳特征"}'
    with pytest.raises(json.JSONDecodeError):
        json.loads(broken)
    score, reason, err, mode = triage._parse_score(broken)
    assert err == "" and score == 76
    assert mode == "repaired_escape"
    assert "加壳" in reason


def test_parse_regex_fallback_when_repair_fails() -> None:
    text = r'{"score": 88, "reason": "未闭合的引号 和 \x 坏转义'
    score, _reason, err, mode = triage._parse_score(text)
    assert score == 88 and err == "" and mode == "regex_fallback"


def test_parse_refuses_to_invent_a_score() -> None:
    """抓不到分数就**报失败**，绝不用默认值/猜测顶上。"""
    score, _reason, err, mode = triage._parse_score("这个文件看起来很可疑，我给 70 分")
    assert score is None and err and mode == "none"
    assert triage._parse_score("")[0] is None
    assert triage._parse_score('{"reason": "没有分数字段"}')[0] is None


def test_parse_rejects_out_of_range() -> None:
    score, _reason, err, _mode = triage._parse_score('{"score": 150, "reason": "x"}')
    assert score is None and "out_of_range" in err
    score, _reason, err, _mode = triage._parse_score('{"score": -3, "reason": "x"}')
    assert score is None and "out_of_range" in err


def test_parse_accepts_numeric_string_score() -> None:
    score, _reason, err, _mode = triage._parse_score('{"score": "55", "reason": "x"}')
    assert score == 55 and err == ""


# ---------------------------------------------------------------- 成本口径
def _record(score: int | None, tokens: int, *, ok: bool = True, cached: bool = False,
            source: str = "provider", mode: str = "strict_json") -> dict:
    return {"ok": ok, "score": score, "total_tokens": tokens,
            "prompt_tokens": tokens - 10, "completion_tokens": 10,
            "usage_source": source, "from_cache": cached, "parse_mode": mode}


def test_cost_counts_provider_tokens_and_flags_estimates() -> None:
    rows = [_record(10, 1000), _record(20, 1200, source="estimate")]
    cost = triage.summarize_cost(rows)
    assert cost["total_tokens"] == 2200
    assert cost["avg_tokens_per_file"] == 1100.0
    assert cost["estimated_entries"] == 1
    assert cost["usage_source"] == "mixed"
    assert cost["ok"] == 2 and cost["failed"] == 0


def test_cost_excludes_cache_hits_from_the_bill() -> None:
    """缓存命中不该再计一次钱（否则"复用缓存"这个优化在报告里看不出效果）。"""
    rows = [_record(10, 1000), _record(10, 9999, cached=True)]
    cost = triage.summarize_cost(rows)
    assert cost["total_tokens"] == 1000
    assert cost["from_cache"] == 1
    assert cost["charged_files"] == 1
    assert cost["files"] == 2


def test_cost_reports_parse_modes_for_verification() -> None:
    rows = [_record(10, 1, mode="strict_json"), _record(10, 1, mode="repaired_escape")]
    cost = triage.summarize_cost(rows)
    assert cost["parse_modes"] == {"strict_json": 1, "repaired_escape": 1}
    assert cost["repaired_or_fallback"] == 1


def test_cost_price_comes_from_the_single_project_constant() -> None:
    from aiav.budget import CNY_PER_MILLION_TOKENS

    cost = triage.summarize_cost([_record(10, 1_000_000)])
    assert cost["cny_per_million_tokens"] == CNY_PER_MILLION_TOKENS
    assert cost["cost_cny"] == pytest.approx(CNY_PER_MILLION_TOKENS, rel=1e-6)


def test_cost_handles_empty_batch() -> None:
    cost = triage.summarize_cost([])
    assert cost["files"] == 0 and cost["total_tokens"] == 0
    assert cost["avg_tokens_per_file"] == 0.0


# ---------------------------------------------------------------- 缓存
def test_triage_cache_roundtrip_and_model_isolation(tmp_path: Path) -> None:
    cache = TriageCache(root=tmp_path / "tc")
    record = {"ok": True, "score": 42, "reason": "x"}
    assert cache.put_triage("a" * 64, record, model="flash-a") is True
    hit = cache.get_triage("a" * 64, model="flash-a")
    assert hit and hit["result"]["score"] == 42
    # 换模型不许命中：不同模型的分数不可互换
    assert cache.get_triage("a" * 64, model="flash-b") is None
    # 没写过的 sha256 不命中
    assert cache.get_triage("b" * 64, model="flash-a") is None


def test_triage_cache_survives_on_disk_and_reloads(tmp_path: Path) -> None:
    root = tmp_path / "tc"
    TriageCache(root=root).put_triage("c" * 64, {"ok": True, "score": 7}, model="m")
    reopened = TriageCache(root=root)
    hit = reopened.get_triage("c" * 64, model="m")
    assert hit and hit["result"]["score"] == 7


def test_triage_cache_fingerprint_changes_with_prompt(tmp_path: Path, monkeypatch) -> None:
    """提示词一改，旧条目整体失效（否则改了评分口径还在吃旧分）。"""
    cache = TriageCache(root=tmp_path / "tc")
    cache.put_triage("d" * 64, {"ok": True, "score": 1}, model="m")
    assert cache.get_triage("d" * 64, model="m") is not None
    monkeypatch.setattr(triage, "SYSTEM_PROMPT", triage.SYSTEM_PROMPT + "\n新增一行")
    fresh = TriageCache(root=tmp_path / "tc")
    assert fresh.get_triage("d" * 64, model="m") is None


def test_triage_cache_disabled_is_a_noop(tmp_path: Path) -> None:
    cache = TriageCache(root=tmp_path / "tc", enabled=False)
    assert cache.put_triage("e" * 64, {"ok": True, "score": 1}, model="m") is False
    assert cache.get_triage("e" * 64, model="m") is None


def test_triage_cache_does_not_collide_with_scan_cache(tmp_path: Path) -> None:
    """两个缓存目录分开，且 `TriageCache` 不写 `FileReport` 形状的条目。"""
    from aiav.cache import ScanCache

    triage_cache = TriageCache(root=tmp_path / "triage")
    scan_cache = ScanCache(root=tmp_path / "scan")
    triage_cache.put_triage("f" * 64, {"ok": True, "score": 9}, model="m")
    entry = json.loads((tmp_path / "triage" / f"{'f' * 64}.m.json").read_text())
    assert "report" not in entry          # 不是 FileReport 条目
    assert entry["result"]["score"] == 9
    assert scan_cache.get("f" * 64, agent_available=False, samples=1) is None


# ---------------------------------------------------------------- 重试 / 空输出
class _FakeResponse:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status
        self.request = None

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            import httpx

            raise httpx.HTTPStatusError("bad", request=None, response=self)  # type: ignore[arg-type]

    def json(self) -> dict:
        return self._payload


class _FakeHTTP:
    """假 HTTP 客户端：按脚本逐次返回。**一个真请求都不发。**"""

    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.calls = 0

    def post(self, *_a, **_kw):
        self.calls += 1
        item = self.responses[min(self.calls - 1, len(self.responses) - 1)]
        if isinstance(item, Exception):
            raise item
        return item

    def close(self) -> None:
        pass


def _prompt() -> triage.RenderedPrompt:
    return triage.render_prompt({"name": "a.exe", "size": 1, "extension": ".exe",
                                 "kind": "pe", "entropy": 1.0, "strings": []})


def test_empty_output_is_retried_then_succeeds(monkeypatch) -> None:
    """实测失败类：推理模型把 max_tokens 烧在 reasoning 上 → content 为空。

    与网络抖动一样**可重试**（重发一次往往就正常），不该直接作废这条。
    """
    monkeypatch.setattr(triage.time, "sleep", lambda _s: None)
    empty = _FakeResponse({"choices": [{"message": {"content": ""}, "finish_reason": "length"}],
                           "usage": {"prompt_tokens": 900, "completion_tokens": 2000,
                                     "total_tokens": 2900}})
    good = _FakeResponse({"choices": [{"message": {"content": '{"score": 33, "reason": "x"}'},
                                       "finish_reason": "stop"}],
                          "usage": {"prompt_tokens": 900, "completion_tokens": 120,
                                    "total_tokens": 1020}})
    http = _FakeHTTP([empty, good])
    client = triage.TriageClient(model="m", base_url="http://x", api_key="k")
    call = client.classify(_prompt(), client=http)  # type: ignore[arg-type]
    assert http.calls == 2
    assert call.ok and call.score == 33 and call.attempts == 2
    # 白烧的那一次也要算进成本，否则成本被系统性低估
    assert call.total_tokens == 2900 + 1020


def test_persistent_empty_output_fails_loudly(monkeypatch) -> None:
    monkeypatch.setattr(triage.time, "sleep", lambda _s: None)
    empty = _FakeResponse({"choices": [{"message": {"content": ""}, "finish_reason": "length"}],
                           "usage": {"total_tokens": 3000}})
    client = triage.TriageClient(model="m", base_url="http://x", api_key="k")
    call = client.classify(_prompt(), client=_FakeHTTP([empty]))  # type: ignore[arg-type]
    assert call.ok is False and call.score is None
    assert "empty_output" in call.error


def test_retryable_and_non_retryable_http_errors() -> None:
    import httpx

    def err(status: int) -> httpx.HTTPStatusError:
        resp = httpx.Response(status, request=httpx.Request("POST", "http://x"))
        return httpx.HTTPStatusError("e", request=resp.request, response=resp)

    assert triage.TriageClient._retryable(err(429)) is True
    assert triage.TriageClient._retryable(err(503)) is True
    assert triage.TriageClient._retryable(err(401)) is False
    assert triage.TriageClient._retryable(err(400)) is False
    assert triage.TriageClient._retryable(httpx.ConnectError("x")) is True


def test_workspace_headers_are_sent(monkeypatch) -> None:
    """网关缺 `x-opencode-session` 会直接 4xx（实测）—— 头必须与深度 AI 那一层一致。"""
    client = triage.TriageClient(model="m", base_url="https://opencode.ai/zen/go/v1",
                                 api_key="k")
    assert client.headers.get("x-opencode-session")
    other = triage.TriageClient(model="m", base_url="https://api.deepseek.com/v1",
                                api_key="k")
    assert "x-opencode-session" not in other.headers
