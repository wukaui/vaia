#!/usr/bin/env python3
"""扫完一轮之后看结果：工具调用分布 / 判定 / 证据溯源 / 告警 / 缓存命中。

用法：
  .venv/bin/python scripts/analyze_scan.py <报告目录或 .audit.json 路径>

为什么单独抽出来：改一次提示词或工具表就要跑一轮验证，每次手写解析脚本
既慢又容易写错口径（比如把 build/lib 的重复拷贝当成两个文件）。
"""
from __future__ import annotations

import collections
import glob
import json
import sys
from pathlib import Path

# 这些工具已经从 ALL_TOOLS 摘掉了。新扫描里再出现就说明改动没生效。
RETIRED_TOOLS = {"yara_scan", "hash_lookup", "vt_lookup", "clamav_scan"}
# 本机没装、由 available_tools() 过滤掉的（装了的话不算异常）
ENV_GATED_TOOLS = {"capa_scan", "floss_scan"}


def load_reports(target: str) -> list[dict]:
    p = Path(target).expanduser()
    if p.is_dir():
        cands = sorted(glob.glob(str(p / "*.audit.json"))) or sorted(glob.glob(str(p / "*.json")))
        if not cands:
            raise SystemExit(f"{p} 里没有 JSON 报告")
        p = Path(cands[-1])
    data = json.loads(p.read_text(encoding="utf-8"))

    found: list[dict] = []

    def walk(o):
        if isinstance(o, dict):
            if "verdict" in o and "path" in o and "agent_trace" in o:
                found.append(o)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(data)
    # 同一份报告里可能有重复（例如 build/lib 的拷贝），按 path 去重
    seen, uniq = set(), []
    for r in found:
        if r["path"] in seen:
            continue
        seen.add(r["path"])
        uniq.append(r)
    print(f"[报告] {p.name}   文件 {len(uniq)}")
    return uniq


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    reps = load_reports(sys.argv[1])

    cached = [r for r in reps if r.get("cache")]
    print(f"[缓存] 命中 {len(cached)}/{len(reps)}"
          + ("   ← 命中过多说明这轮没真跑，换 AI_AV_STATE_DIR 重跑" if len(cached) > len(reps) * 0.3 else ""))

    cnt = collections.Counter()
    per_file = []
    for r in reps:
        ai = [c.get("tool") for c in r["agent_trace"] if c.get("tool") != "prefilter"]
        per_file.append(len(ai))
        cnt.update(ai)

    print("\n=== AI 工具调用 ===")
    for k, v in cnt.most_common():
        flag = "  ← 已摘除，不该出现" if k in RETIRED_TOOLS else ""
        flag = flag or ("  ← 本机没装，不该出现" if k in ENV_GATED_TOOLS else "")
        print(f"  {k:<24}{v:>5} 次{flag}")
    total = sum(cnt.values())
    print(f"  合计 {total} 次 / {len(reps)} 文件 = 每文件 {total / max(1, len(reps)):.1f} 次")

    print("\n=== 判定分布 ===")
    groups = sorted({p.split("/")[-2] for p in (r["path"] for r in reps) if "/" in p})
    for g in groups:
        sub = [r for r in reps if f"/{g}/" in r["path"]]
        c = collections.Counter(r["verdict"]["risk"] for r in sub)
        ai = sum(1 for r in sub if r.get("agent_used"))
        print(f"  {g:<8}{len(sub):>4} 个  {dict(c)}   走 AI {ai}")
    print(f"  {'全部':<8}{len(reps):>4} 个  "
          f"{dict(collections.Counter(r['verdict']['risk'] for r in reps))}")

    print("\n=== 证据溯源 ===")
    sup = collections.Counter()
    for r in reps:
        for s in (r.get("evidence_sources") or []):
            sup[s.get("support")] += 1
    for k, v in sup.most_common():
        print(f"  {str(k):<16}{v:>5}")

    warns = [(r["path"].split("/")[-1], w) for r in reps for w in (r.get("claim_warnings") or [])]
    print(f"\n=== 告警 {len(warns)} 条 ===")
    wc = collections.Counter(w.split("：")[0] for _, w in warns)
    for k, v in wc.most_common():
        print(f"  {k:<24}{v:>4}")
    for name, w in warns[:8]:
        print(f"    · [{name}] {w[:110]}")

    print("\n=== 没走 AI 的文件 ===")
    noai = [r for r in reps if not r.get("agent_used")]
    for r in noai:
        print(f"  {r['path'].split('/')[-1]:<30} 预筛{r['prefilter_score']:>4}  "
              f"{r['verdict']['risk']:<10} {(r.get('prefilter_reasons') or ['(无信号)'])[0][:44]}")
    print(f"  共 {len(noai)}/{len(reps)} 个没进 AI")


if __name__ == "__main__":
    main()
