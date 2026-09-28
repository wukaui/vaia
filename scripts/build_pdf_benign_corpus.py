#!/usr/bin/env python3
"""PDF 重测的**良性语料**构建（2026-09-27）。

为什么要单独一个脚本：`mb-pdf` 那 60 个**全是恶意**，而它又参与过批次 A 的测量
（过拟合风险）。没有一批**没看过的良性 PDF**，"误报/送审率"那一半账就是空的。
这里把良性 PDF 固定成一份**可复现的清单**，并把来源、sha256、大小逐条记账。

两段来源（都写进 manifest，报告里必须写清）：

  A. `~/ai-av-bench/alt-forms-benign/*.pdf`（60 个）
     —— 项目自己造的良性文档语料（表单域 / 批注 / 书签 / AcroForm 计算），
        标签文件 `alt-forms-benign-labels.json` 里 60 个全是 `clean`。
  B. 系统与开源文档（20 个，按 sha256 去重后的**唯一**文件）
     —— `/usr/share/doc`、matplotlib 内置图标、公开 LaTeX 论文模板、
        pwndbg 速查表、项目自造的 `benign_report.pdf`。

**刻意排除的东西**（不是漏了，是不该进来）：

  · `~/ai-av-bench/mb-*`（MalwareBazaar 恶意语料）、`ab-verify/mal/`（里面有
    `pdf_01/02.pdf` 两个恶意样本）、`mb-lnk` 里那个 pdf；
  · 任何"证明漏洞"的 PoC PDF（`PayloadsAllTheThings` 下那份 ghostscript 命令执行）；
  · **他本人的私人文档**（项目书 / 习题 / 读书笔记）：②层会把摘要**发到模型 API**，
    私人文档不进这个语料。

只读静态：复制字节，不执行、不打开、不渲染任何 PDF。

用法：
    .venv/bin/python scripts/build_pdf_benign_corpus.py --out /tmp/pdf-fix/corpus/benign
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aiav.preload import detect_kind  # noqa: E402

HOME = Path.home()

#: A 段：项目自造的良性文档语料（60 个，标签文件里全是 `clean`）。
FORM_CORPUS = HOME / "ai-av-bench" / "alt-forms-benign"
FORM_LABELS = HOME / "ai-av-bench" / "alt-forms-benign-labels.json"

#: B 段：系统与开源文档（按 glob 展开后**按 sha256 去重**）。
SYSTEM_GLOBS = [
    "/usr/share/doc/**/*.pdf",
    "/usr/share/matplotlib/**/*.pdf",
    str(HOME / ".hermes/hermes-agent/optional-skills/research/research-paper-writing/templates/**/*.pdf"),
    str(HOME / ".hermes/skills/research/research-paper-writing/templates/**/*.pdf"),
]
SYSTEM_FILES = [
    HOME / ".hermes/hermes-agent/docs/hermes-kanban-v1-spec.pdf",
    HOME / "ctf/tools/pwndbg/docs/CHEATSHEET.pdf",
    HOME / "ai-av-bench/pdf-demo/benign_report.pdf",
]


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description="构建良性 PDF 语料（可复现清单）")
    ap.add_argument("--out", type=Path, required=True, help="语料目录")
    args = ap.parse_args()

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)

    labels = json.loads(FORM_LABELS.read_text(encoding="utf-8")) if FORM_LABELS.is_file() else {}
    items: list[dict[str, object]] = []
    seen_sha: dict[str, str] = {}

    def _add(source: Path, group: str, index: int, label: str) -> None:
        digest = sha256_of(source)
        if digest in seen_sha:
            items.append({"name": "", "source": str(source), "sha256": digest,
                          "size": source.stat().st_size, "group": group,
                          "label": label, "duplicate_of": seen_sha[digest]})
            return
        name = f"{index:02d}_{group}_{source.name}"
        shutil.copyfile(source, out / name)
        seen_sha[digest] = name
        items.append({"name": name, "source": str(source), "sha256": digest,
                      "size": source.stat().st_size, "group": group, "label": label})

    # A 段
    for index, path in enumerate(sorted(FORM_CORPUS.glob("*.pdf")), start=1):
        _add(path, "altforms", index, str(labels.get(path.name, "clean")))
    # B 段
    candidates: list[Path] = []
    for pattern in SYSTEM_GLOBS:
        candidates.extend(Path(p) for p in sorted(glob.glob(pattern, recursive=True)))
    candidates.extend(SYSTEM_FILES)
    for index, path in enumerate([c for c in candidates if c.is_file()], start=1):
        _add(path, "system", index, "clean")

    copied = [item for item in items if item.get("name")]
    manifest = {
        "generated_at": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        "out_dir": str(out),
        "note": "良性 PDF 语料：全部 label=clean。②层摘要会发到模型 API —— "
                "私人文档与 PoC 已被刻意排除（见脚本 docstring）。",
        "counts": {
            "files": len(copied),
            "altforms": sum(1 for i in copied if i["group"] == "altforms"),
            "system": sum(1 for i in copied if i["group"] == "system"),
            "duplicates_skipped": len(items) - len(copied),
        },
        "items": items,
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")

    kinds: dict[str, int] = {}
    for item in copied:
        kind = detect_kind(out / str(item["name"]))
        kinds[kind] = kinds.get(kind, 0) + 1
    print(f"良性 PDF 语料: {out}")
    print(f"  文件 {manifest['counts']['files']} 个"
          f"（altforms {manifest['counts']['altforms']} + system {manifest['counts']['system']}，"
          f"按 sha256 去重跳过 {manifest['counts']['duplicates_skipped']} 个）")
    print(f"  detect_kind 分布: {kinds}")
    print(f"  清单: {out / 'manifest.json'}")


if __name__ == "__main__":
    main()
