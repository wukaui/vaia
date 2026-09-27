"""「全送 AI 对照」抽样口径的测试（2026-09-27 变更："抽样吧"）。

盯住四件事：
  1. **分层按比例**：样本里"干净 : 恶意"必须与语料**完全一致**（不是近似）
  2. **固定种子可复现**：同 seed 抽两遍清单逐字节一样；换 seed 换一批
  3. **名额分配**：最大余数法，总数不多不少
  4. **实测 ≠ 外推**：`summarize()` 出来的两块必须分开标 `kind`，外推的基数是抽样均值 × 规模
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sample_ai_arm import allocate, draw_sample, summarize  # noqa: E402


def _corpus(n_benign: int = 300, n_malicious: int = 20) -> list[dict]:
    """造一份假语料：良性按 2:1 分两个池，恶意一个池（跟真实语料同构）。"""
    out = []
    for i in range(n_benign):
        pool = "benign-0" if i < n_benign * 2 // 3 else "benign-1"
        out.append({"path": f"/x/benign/b{i:04d}.bin", "name": f"b{i:04d}.bin",
                    "label": "benign", "pool": pool, "sha256": f"b{i}", "bytes": 1})
    for i in range(n_malicious):
        out.append({"path": f"/x/malware/m{i:04d}.exe", "name": f"m{i:04d}.exe",
                    "label": "malicious", "pool": "dike", "sha256": f"m{i}", "bytes": 1})
    out.sort(key=lambda r: (r["label"], r["name"]))
    return out


def test_allocate_sums_to_n_and_keeps_ratio():
    quota = allocate({"a": 300, "b": 20}, 48)
    assert sum(quota.values()) == 48
    # 20/320 = 3/48 → 恶意那一层正好 3 个
    assert quota == {"a": 45, "b": 3}


def test_sample_ratio_matches_corpus_exactly():
    corpus = _corpus()
    picked = draw_sample(corpus, 48, seed=20260927)
    assert len(picked) == 48
    mal = sum(1 for r in picked if r["label"] == "malicious")
    assert mal / len(picked) == 20 / len(corpus) == 0.0625
    # 良性两个池也按 2:1 分
    pools = {r["pool"] for r in picked if r["label"] == "benign"}
    assert pools == {"benign-0", "benign-1"}
    assert sum(1 for r in picked if r["pool"] == "benign-0") == 30


def test_same_seed_reproducible_and_other_seed_differs():
    corpus = _corpus()
    a = [r["path"] for r in draw_sample(corpus, 48, seed=20260927)]
    b = [r["path"] for r in draw_sample(corpus, 48, seed=20260927)]
    c = [r["path"] for r in draw_sample(corpus, 48, seed=1)]
    assert a == b
    assert a != c


def test_too_many_asked_for_raises():
    with pytest.raises(SystemExit):
        draw_sample(_corpus(n_benign=10, n_malicious=2), 20, seed=1)


def test_summarize_separates_measured_from_extrapolated():
    per_file = [
        {"name": "b0", "label": "benign", "pool": "benign-0", "sha256": "x", "bytes": 1,
         "path": "/x/b0", "in_ai_report": True, "reached_ai": True, "outcome": "ai_verdict",
         "tokens": 8000, "preload_ms": 1000.0, "tool_calls": 0, "risk": "clean"},
        {"name": "b1", "label": "benign", "pool": "benign-0", "sha256": "y", "bytes": 1,
         "path": "/x/b1", "in_ai_report": True, "reached_ai": True, "outcome": "ai_verdict",
         "tokens": 10000, "preload_ms": 3000.0, "tool_calls": 0, "risk": "clean"},
        {"name": "m0", "label": "malicious", "pool": "dike", "sha256": "z", "bytes": 1,
         "path": "/x/m0", "in_ai_report": True, "reached_ai": False,
         "outcome": "closed_deterministic", "tokens": None, "preload_ms": None,
         "tool_calls": None, "risk": None},
    ]
    full = {"files_reaching_ai": 273, "tokens": 2_190_000, "mean_tokens_per_ai_file": 8021.9,
            "files_sent_to_ai": 274, "files_degraded_to_rules": 1}
    blocks = summarize([], per_file, n_corpus=320, unit_price=8.0, wall_clock_s=2460.0,
                       n_full_ai=273, full_run=full)

    m, e = blocks["sample_measured"], blocks["extrapolated"]
    assert m["kind"] == "measured" and e["kind"] == "extrapolated"
    assert m["mean_tokens_per_ai_file"] == 9000.0        # (8000+10000)/2
    assert m["files_drawn"] == 3 and m["files_reaching_ai"] == 2
    assert m["files_short_circuited"] == 1
    assert m["mean_cny_per_ai_file"] == pytest.approx(0.072)
    assert e["tokens"] == 9000 * 320                     # 外推 = 抽样均值 × 语料规模
    assert e["same_scope"]["tokens"] == 9000 * 273        # 同口径 = 抽样均值 × 出结论的文件数
    # 参照块必须标出它是全量实测，不是抽样产物的一部分
    ref = blocks["sampling_check_vs_full_run"]
    assert ref["kind"] == "measured" and ref["scope"] == "full-run reference"
