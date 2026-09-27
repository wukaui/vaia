#!/usr/bin/env python3
"""真实分布小测试集 —— 干净为主（~300）+ 少量恶意（~20，≈5%）。

**为什么要有这个脚本。** 之前那 40 个样本是"一半恶意"的人为构造，送审率 32.5% 看着吓人，
但不代表真实机器：用户电脑上 99% 是干净文件，恶意只占极少数。衡量"送审率"这个指标，
语料的类别比例必须是真实比例，否则测的是评测集、不是产品。

抽样是**确定性**的（同一批源文件永远抽出同一批，谁都能重跑出一样的集合）：

  · 良性：两池各自按文件名排序后**等距抽样**，不用 RNG；
  · 恶意：固定 seed 的 RNG 从 DikeDataset 恶意池里抽，**排除调优集**
    （`pilot40` 的 20 个 + `dike-sample20` 的 10 个）—— 排除掉的那批是判据表调参时看过的，
    留下没看过的就是 holdout。

产出：`<out>/files/benign/`、`<out>/files/malware/`（**硬链接**，同设备才成；跨设备退回复制）
     + `<out>/manifest.json`（来源池、池大小、抽样方法、排除项、每个文件的出处与大小/哈希）。

⚠️ 样本放在 `<out>/files/` 下面，`manifest.json` 放在外面 —— 扫描器是 `rglob` 递归收文件的，
manifest 落在语料目录里会被当成第 321 个文件收进去（踩过一次：320 的语料报成 321）。

纪律：样本**只静态分析、不执行、不上传**；脚本本身不执行任何样本。

用法：

    .venv/bin/python scripts/build_real_dist.py --out /tmp/real-dist-320
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import sys
from pathlib import Path

BENCH = Path(os.path.expanduser("~/ai-av-bench"))

#: 恶意池：DikeDataset（200 恶意 / 200 良性，每文件一个 sha256 文件名 + 真实扩展名）。
MAL_POOL = BENCH / "dike-bench" / "files" / "malware"

#: 判据表调参时看过的两批（**必须排除**，否则 holdout 不成立）：
#:   · `/tmp/dike-pilot` 的 20 个 `M_<sha256>.<ext>`（上一轮的调优集）
#:   · `~/ai-av-bench/dike-sample20/malware/` 的 10 个 `<sha256>.<ext>`
TUNING_DIRS = (Path("/tmp/dike-pilot"), BENCH / "dike-sample20" / "malware")


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def evenly_spaced(items: list[Path], k: int) -> list[Path]:
    """按排序后的位置等距取 k 个（无 RNG → 可复现、不偏）。"""
    if k >= len(items):
        return list(items)
    if k <= 1:
        return items[:1]
    step = (len(items) - 1) / (k - 1)
    picked = {items[round(i * step)] for i in range(k)}
    return sorted(picked)


def tuning_hashes() -> set[str]:
    """调优集里的样本 sha256（文件名去掉 `M_` 前缀、去掉扩展名）。"""
    out: set[str] = set()
    for d in TUNING_DIRS:
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if not p.is_file():
                continue
            stem = p.stem
            if stem.startswith("M_"):
                stem = stem[2:]
            out.add(stem.lower())
    return out


def link_or_copy(src: Path, dst: Path) -> str:
    """硬链接（省空间、不复制样本本体）；跨设备退回复制。返回用了哪种。"""
    if dst.exists():
        dst.unlink()
    try:
        os.link(src, dst)
        return "hardlink"
    except OSError:
        shutil.copy2(src, dst)
        return "copy"


def unique_dst(dst_dir: Path, name: str, pool: str) -> Path:
    """同名文件（两个良性池可能撞名）加池名前缀 —— 撞名会让一个样本把另一个覆盖掉。"""
    dst = dst_dir / name
    return dst if not dst.exists() else dst_dir / f"{pool}__{name}"


def take(pool: Path, k: int, dst_dir: Path, pool_name: str = "") -> tuple[list[dict], list[Path]]:
    """从 pool 等距抽 k 个，链接进 dst_dir。返回 (manifest 条目, 抽中的源路径)。"""
    files = sorted(p for p in pool.iterdir() if p.is_file())
    picked = evenly_spaced(files, k)
    entries = []
    for src in picked:
        dst = unique_dst(dst_dir, src.name, pool_name or pool.name)
        mode = link_or_copy(src, dst)
        entries.append({"name": dst.name, "source": str(src), "bytes": src.stat().st_size,
                        "sha256": sha256_of(src), "link": mode})
    return entries, picked


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True, help="测试集落地目录")
    ap.add_argument("--benign-win", type=int, default=200, help="从 benign-win 抽多少（真实 Windows 系统文件）")
    ap.add_argument("--benign-wheel", type=int, default=100, help="从 benign-wheel 抽多少（wheel 里的二进制）")
    ap.add_argument("--malicious", type=int, default=20, help="从 DikeDataset 恶意池抽多少（holdout）")
    ap.add_argument("--seed", type=int, default=20260927, help="恶意抽样的 RNG seed")
    ap.add_argument("--keep-tuning", action="store_true",
                    help="不排除调优集（**只用于对照，默认关**：开了就不是 holdout）")
    args = ap.parse_args()

    benign_pools = [("benign-win", BENCH / "benign-win", args.benign_win),
                    ("benign-wheel", BENCH / "benign-wheel", args.benign_wheel)]
    for name, pool, _ in benign_pools:
        if not pool.is_dir():
            print(f"!! 良性池不存在：{pool}", file=sys.stderr)
            return 2
    if not MAL_POOL.is_dir():
        print(f"!! 恶意池不存在：{MAL_POOL}", file=sys.stderr)
        return 2

    benign_dir = args.out / "files" / "benign"
    mal_dir = args.out / "files" / "malware"
    for d in (benign_dir, mal_dir):
        d.mkdir(parents=True, exist_ok=True)

    manifest: dict = {
        "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
        "purpose": "真实分布（干净为主）小规模实测：衡量送审率 / 结案率 / 召回 / 成本",
        "discipline": "只静态分析、不执行、不上传",
        "sampling": {
            "benign": "文件名排序后等距抽样（无 RNG，可复现）",
            "malicious": f"DikeDataset 恶意池固定 seed RNG（seed={args.seed}）",
            "seed": args.seed,
        },
        "pools": {},
        "classes": {},
    }

    benign_entries: list[dict] = []
    for name, pool, k in benign_pools:
        files = sorted(p for p in pool.iterdir() if p.is_file())
        entries, _ = take(pool, k, benign_dir, pool_name=name)
        for e in entries:
            e["pool"] = name
        benign_entries += entries
        manifest["pools"][name] = {"path": str(pool), "files": len(files), "taken": len(entries)}
        print(f"良性 {name}: 池 {len(files)} → 抽 {len(entries)}")

    # ---- 恶意：排除调优集后随机抽 ----
    mal_files = sorted(p for p in MAL_POOL.iterdir() if p.is_file())
    excluded = tuning_hashes() if not args.keep_tuning else set()
    candidates = [p for p in mal_files if p.stem.lower() not in excluded]
    rng = random.Random(args.seed)
    picked = sorted(rng.sample(candidates, min(args.malicious, len(candidates))))
    mal_entries = []
    for src in picked:
        dst = mal_dir / src.name
        mode = link_or_copy(src, dst)
        mal_entries.append({"name": dst.name, "source": str(src), "bytes": src.stat().st_size,
                            "sha256": sha256_of(src), "link": mode, "pool": "dike-bench-malware"})
    manifest["pools"]["dike-bench-malware"] = {
        "path": str(MAL_POOL), "files": len(mal_files),
        "excluded_tuning": sorted(excluded) if excluded else [],
        "excluded_count": len(mal_files) - len(candidates),
        "candidates": len(candidates), "taken": len(mal_entries),
        "holdout": not args.keep_tuning,
    }
    print(f"恶意 dike-bench: 池 {len(mal_files)} − 调优集 {len(mal_files) - len(candidates)} "
          f"= 候选 {len(candidates)} → 抽 {len(mal_entries)}")

    total = len(benign_entries) + len(mal_entries)
    manifest["classes"] = {
        "benign": {"count": len(benign_entries), "files": benign_entries},
        "malicious": {"count": len(mal_entries), "files": mal_entries},
        "total": total,
        "malicious_share": round(len(mal_entries) / total, 4) if total else None,
    }
    (args.out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"落地：{args.out} · 共 {total} 个（良性 {len(benign_entries)} / "
          f"恶意 {len(mal_entries)} = {manifest['classes']['malicious_share']:.2%}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
