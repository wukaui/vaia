#!/usr/bin/env python3
"""①层实测：送审率 / 召回 / 纯①层结案率。

用法：

    .venv/bin/python scripts/measure_deterministic.py \
        --corpus "pilot40=/tmp/dike-pilot" \
        --corpus "dike20=$HOME/ai-av-bench/dike-sample20" \
        --corpus "nonupx104=$HOME/ai-av-bench/nonupx-bench" \
        --corpus "benign-win800=$HOME/ai-av-bench/benign-win:800" \
        --out ~/ai-av-bench/al-core-measure --gate 300 --runs 2

口径（写死在代码里，免得每次换说法）：

  · **送审率** = 走 AI 的文件数 / 总文件数。
  · **纯①层结案率** = 不送 AI 就把结论定下来的比例 =（确定性判恶意 + 确定性判干净）/ 总数。
  · **未结案率** = `pass`（没线索、不送 AI、也没结论）。⚠️ **未结案 ≠ 判白**。
  · **召回**（①层口径）= 恶意文件里被"确定性判恶意"或"送审 AI"覆盖的比例。
    这是"送审前会不会漏"的那条线 —— 没送审又没结案的恶意文件就是漏了。
  · **核验**：`unclassified_signals` 计数必须为 0；工具未安装/报错单独计数。
    任一项不为 0，这一批数字按核验铁律作废（报告里会标红）。

不带 AI（`agent=None`）—— 测的就是纯①层，AI 送不送由 disposition 决定。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))


def parse_corpus(spec: str) -> tuple[str, Path, int | None, str | None]:
    """`名字=路径[:上限][@标签规则]`，标签规则 ∈ {dike（M_ 恶意 / B_ 良性）, nupx, benign, subdir}。"""
    name, _, rest = spec.partition("=")
    label = None
    if "@" in rest:
        rest, _, label = rest.partition("@")
    limit = None
    if ":" in rest:
        rest, _, lim = rest.rpartition(":")
        if lim.isdigit():
            limit = int(lim)
        else:
            rest = f"{rest}:{lim}"
    return name, Path(os.path.expanduser(rest)), limit, label


def collect_files(root: Path, limit: int | None) -> list[Path]:
    if root.is_file():
        return [root]
    files = sorted(p for p in root.rglob("*") if p.is_file())
    return files[:limit] if limit else files


def load_label_map(rule: str) -> dict[str, str]:
    """`@json:<路径>` —— 外部标签表（{文件名: malicious|benign}）。"""
    path = Path(os.path.expanduser(rule.split(":", 1)[1]))
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(k): (v if isinstance(v, str) else v.get("label", "unknown"))
            for k, v in data.items()}


def label_of(path: Path, rule: str | None, labels: dict[str, str] | None = None) -> str:
    if rule and rule.startswith("json:"):
        return (labels or {}).get(path.name, "unknown")
    if rule == "dike":
        return "malicious" if path.name.startswith("M_") else "benign"
    if rule == "nupx":
        return "malicious" if "mal" in str(path).lower() else "benign"
    if rule == "subdir":
        low = str(path).lower()
        return "malicious" if "/malware" in low else ("benign" if "/benign" in low else "unknown")
    if rule == "benign":
        return "benign"
    return "unknown"


def run_corpus(name: str, files: list[Path], rule: str | None, gate: int,
               labels: dict[str, str] | None = None) -> dict:
    from aiav import scanner, tools
    from aiav.models import RiskLevel

    # ---- ①层 ClamAV 批量预扫（2026-09-27）----
    # **一次进程扫整批**：单文件一次要重新加载 362 万条签名（6.3 s），批量摊到 0.1~0.4 s/文件。
    # 单独计时 —— 报告里"①层多花了多少时间"就是这一块。
    clamav_batch = tools.clamav_scan_batch(files)

    rows = []
    t0 = time.time()
    for path in files:
        try:
            report = scanner.scan_file(
                path, agent=None, ai_threshold=gate, store=None,
                allow_unpack=False, allow_archives=False, cache=None,
                clamav_batch=clamav_batch,
                # 这个脚本量的是**单档闸门曲线**（`--ai-threshold` 逐档），
                # 两档送审（2026-09-27）是另一件事 —— 低档显式关掉，
                # 否则"闸门 300"这一档会把 225~299 的文件也算成送审，曲线含义就变了。
                ai_threshold_low=0,
            )
        except Exception as exc:  # noqa: BLE001
            rows.append({"path": str(path), "label": label_of(path, rule, labels),
                         "error": f"{type(exc).__name__}: {exc}"})
            continue
        det = report.deterministic or {}
        rows.append({
            "path": str(path),
            "name": path.name,
            "label": label_of(path, rule, labels),
            "score": report.prefilter_score,
            "disposition": det.get("disposition", "unknown"),
            "tier": det.get("tier"),
            "band": det.get("band"),
            "agent_used": report.agent_used,
            "risk": report.verdict.risk.value,
            "is_malicious_risk": report.verdict.risk is RiskLevel.malicious,
            "criteria": [h["heur_id"] for h in (report.criteria_hits or []) if h.get("score")],
            # ClamAV 命中逐条留档：判据 ID + **签名名原样**（证据链）。零分的 PUA 也留，
            # 否则"PUA 命中了几条"会凭空消失（`criteria` 那一列只收有分的）。
            "clamav": [{"heur_id": h["heur_id"], "score": h.get("score"),
                        "signatures": [s["name"] for s in (h.get("signature") or [])]}
                       for h in (report.criteria_hits or [])
                       if str(h.get("heur_id", "")).startswith("DET_CLAMAV_")],
            "unclassified": report.unclassified_signals or [],
            "error": report.error,
            })
    elapsed = time.time() - t0
    result = {"corpus": name, "gate": gate, "count": len(files), "elapsed_s": round(elapsed, 1),
              "rows": rows, "summary": summarize(rows)}
    result["clamav_batch"] = {
        k: v for k, v in clamav_batch.items() if k != "results"
    }
    result["clamav_batch"]["per_file_s"] = (
        round(clamav_batch["elapsed_s"] / len(files), 3) if files else None)
    result["elapsed_s_with_clamav"] = round(elapsed + clamav_batch["elapsed_s"], 1)
    return result


def summarize(rows: list[dict]) -> dict:
    n = len(rows) or 1
    disp = Counter(r.get("disposition", "unknown") for r in rows)
    # ⚠️ 送审率看的是**①层的处置**（send_ai），不是 `agent_used`。
    # 不带 AI 跑的时候 `agent_used` 永远是 False —— 拿它当送审率会得到"0%"这种假数
    # （踩过一次：40 个恶意样本的送审率被报成 0.000）。
    sent = sum(1 for r in rows if r.get("disposition") == "send_ai" or r.get("agent_used"))
    closed_mal = disp.get("closed_malicious", 0)
    closed_clean = disp.get("closed_clean", 0)
    passed = disp.get("pass", 0)

    mal = [r for r in rows if r.get("label") == "malicious"]
    ben = [r for r in rows if r.get("label") == "benign"]

    def _caught(r: dict) -> bool:
        """①层口径的"抓住了"：确定性判恶意，或者送审 AI。"""
        return r.get("disposition") in ("closed_malicious", "send_ai") or r.get("agent_used")

    mal_caught = sum(1 for r in mal if _caught(r))
    ben_sent = sum(1 for r in ben if r.get("disposition") == "send_ai" or r.get("agent_used"))

    unclassified = sum(len(r.get("unclassified") or []) for r in rows)
    errors = sum(1 for r in rows if r.get("error"))

    # ClamAV 命中：逐条按判据 ID 分类 —— 真病毒 / 启发式 / PUA 各多少。
    av_hits = [c for r in rows for c in (r.get("clamav") or [])]
    av_kinds = Counter(c["heur_id"] for c in av_hits)
    av_sigs = Counter(s for c in av_hits for s in (c.get("signatures") or []))

    return {
        "total": len(rows),
        "send_rate": round(sent / n, 4),
        "sent": sent,
        "closed_malicious": closed_mal,
        "closed_clean": closed_clean,
        "closed_rate": round((closed_mal + closed_clean) / n, 4),
        "unresolved": passed,
        "unresolved_rate": round(passed / n, 4),
        "dispositions": dict(disp),
        # 召回（只在有标签的语料上有意义）
        "labeled_malicious": len(mal),
        "labeled_benign": len(ben),
        "recall_layer1": round(mal_caught / len(mal), 4) if mal else None,
        "recall_deterministic_only": round(closed_mal / len(mal), 4) if mal else None,
        "benign_send_rate": round(ben_sent / len(ben), 4) if ben else None,
        # ①层确定性判恶意里的 ClamAV 贡献（这是本轮的关键数：之前是 0）
        "clamav": {
            "hit_files": sum(1 for r in rows if r.get("clamav")),
            "hits": len(av_hits),
            "malware_signature": av_kinds.get("DET_CLAMAV_SIGNATURE", 0),
            "heuristic": av_kinds.get("DET_CLAMAV_HEUR", 0),
            "pua": av_kinds.get("DET_CLAMAV_PUA", 0),
            "signatures_top": dict(av_sigs.most_common(20)),
        },
        # 核验铁律
        "unclassified_signals": unclassified,
        "errors": errors,
        "criteria_fired": dict(Counter(
            c for r in rows for c in (r.get("criteria") or [])).most_common(25)),
        "score_histogram": dict(sorted(Counter(_bucket(r.get("score", 0)) for r in rows).items())),
    }


def _bucket(score: int) -> str:
    if score == 0:
        return "0"
    if score < 300:
        return "1-299"
    if score < 500:
        return "300-499"
    if score < 1000:
        return "500-999"
    return ">=1000"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", action="append", required=True,
                    help="名字=路径[:上限][@标签规则]，可重复")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--gate", type=int, default=300)
    ap.add_argument("--runs", type=int, default=1, help="跑几遍（一致性核验）")
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    corpora = [parse_corpus(s) for s in args.corpus]

    # ---- 核验铁律第一步：先验"工具真跑了吗" ----
    # ClamAV 是这一批的**唯一新增产出方**，所以它单独验三样：
    #   · `which clamscan` 找到了（装了）
    #   · `clamscan --version` 报出了非零的**库版本**（库真加载了）
    #   · EICAR 自检拿到 FOUND（引擎端到端真在工作 —— 装了但库空，长得跟"扫过且干净"一模一样）
    from aiav import tools as _tools

    engine = _tools.clamav_engine_info()
    selftest = _tools.clamav_selftest()
    print("ClamAV 核验：", json.dumps({"engine": {k: engine.get(k) for k in
                                              ("available", "version", "db_version", "db_date")},
                                       "db_files": engine.get("db_files"),
                                       "selftest": selftest}, ensure_ascii=False), flush=True)

    all_runs = []
    for run_index in range(args.runs):
        run = {}
        for name, root, limit, rule in corpora:
            files = collect_files(root, limit)
            if not files:
                print(f"!! {name}: {root} 里没有文件", file=sys.stderr)
                continue
            print(f"[run {run_index + 1}] {name}: {len(files)} 个文件 …", flush=True)
            labels = load_label_map(rule) if rule and rule.startswith("json:") else None
            result = run_corpus(name, files, rule, args.gate, labels)
            run[name] = result
            s = result["summary"]
            cb = result["clamav_batch"]
            print(f"    送审率 {s['send_rate']:.3f} · 结案率 {s['closed_rate']:.3f} · "
                  f"未结案 {s['unresolved_rate']:.3f} · 召回 {s['recall_layer1']} · "
                  f"判恶意 {s['closed_malicious']} · "
                  f"耗时 {result['elapsed_s']}s · 未分类信号 {s['unclassified_signals']} · 错误 {s['errors']}",
                  flush=True)
            print(f"    ClamAV：{cb['scanned']}/{result['count']} 个文件有结果行 · "
                  f"命中 {cb['found']}（真病毒 {cb['kinds']['malware']} / "
                  f"启发式 {cb['kinds']['heuristic']} / PUA {cb['kinds']['pua']}）· "
                  f"{cb['invocations']} 次进程调用 · {cb['elapsed_s']}s"
                  f"（{cb['per_file_s']}s/文件）· 静默跳过 {len(cb['unreported'])} · "
                  f"错误 {cb['error'] or '无'}", flush=True)
        all_runs.append(run)

    # 一致率：同一批跑两次，逐文件比对 disposition
    consistency = None
    if len(all_runs) > 1:
        same = total = 0
        for name in all_runs[0]:
            a = {r["path"]: r.get("disposition") for r in all_runs[0][name]["rows"]}
            b = {r["path"]: r.get("disposition") for r in all_runs[1][name]["rows"]}
            for path, disp in a.items():
                total += 1
                same += int(b.get(path) == disp)
        consistency = {"files": total, "same": same,
                       "rate": round(same / total, 4) if total else None}

    # 核验铁律第二步：整批的静默降级计数。任一项不为 0，这一批数字作废。
    verification = {
        "clamav_engine": engine,
        "clamav_selftest": selftest,
        "clamav_unreported_total": sum(
            len(run[name]["clamav_batch"]["unreported"]) for run in all_runs for name in run),
        "clamav_errors_total": sum(
            1 for run in all_runs for name in run if run[name]["clamav_batch"]["error"]),
        "unclassified_signals_total": sum(
            run[name]["summary"]["unclassified_signals"] for run in all_runs for name in run),
        "file_errors_total": sum(run[name]["summary"]["errors"] for run in all_runs for name in run),
    }
    verification["ok"] = bool(
        selftest.get("ok")
        and not verification["clamav_unreported_total"]
        and not verification["clamav_errors_total"]
        and not verification["unclassified_signals_total"]
    )

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "gate": args.gate,
        "runs": len(all_runs),
        "consistency": consistency,
        "verification": verification,
        "corpora": {name: all_runs[0][name] for name in all_runs[0]},
        "all_runs": all_runs,
    }
    out_path = args.out / f"measure_gate{args.gate}_{time.strftime('%Y%m%d_%H%M%S')}.json"
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n写入 {out_path}")
    if consistency:
        print(f"两次一致率：{consistency['rate']}（{consistency['same']}/{consistency['files']}）")
    print(f"核验：{json.dumps(verification, ensure_ascii=False)[:600]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
