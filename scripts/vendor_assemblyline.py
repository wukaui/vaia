#!/usr/bin/env python3
"""把 Assemblyline 的 ODM 核心抄进 `aiav/assemblyline_core/`（MIT，保留声明）。

为什么是"抄"而不是"装"：见 `~/refs/aiav_assemblyline_adopt_20260927.md` 第一节。
一句话 —— 装包会拖 75 个依赖（Azure / AWS / ES / Redis / ONNX），交付 exe 装不动；
我们只要它的**模型定义与计分语义**，不要它的架子。

用法：

    # 从已安装的 assemblyline 包里抄（推荐，先 pip download / pip install 一份）
    python3 scripts/vendor_assemblyline.py --source <site-packages>/assemblyline

    # 只校验副本与上游一致（CI / 复核用）
    python3 scripts/vendor_assemblyline.py --check

    # 顺手导出我们用到的 ATT&CK ID 的名字与分类（attack_map.py 有 3MB，不全抄）
    python3 scripts/vendor_assemblyline.py --source ... --attack-ids T1055,T1027

产出：
    aiav/assemblyline_core/LICENCE.md     上游 MIT 原文
    aiav/assemblyline_core/VENDOR.json    上游版本 + 每个文件的 sha256 + 改写记录
    aiav/assemblyline_core/odm/           抄来的 ODM 基类与模型（仅改写 import）
    aiav/assemblyline_core/_compat/       抄来的纯函数助手 + 手写 forge 垫片
    aiav/assemblyline_core/attack_ids.py  ATT&CK ID -> 名字/分类（派生的，只含用到的 ID）

**不抄**（有意为之，写进 VENDOR.json 的 "dropped"）：
    datastore / filestore / cachestore / remote / run   —— ES / Redis / S3 / K8s 那一套
    odm/models/config.py（117KB，整个平台的配置树）      —— 我们不需要平台
    common/forge.py（真身）                              —— 它 import elasticapm / hauntedhouse
    common/attack_map.py（3MB）                          —— 只派生用到的 ID
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEST_ROOT = REPO / "aiav" / "assemblyline_core"

# 上游相对路径 -> 我们仓库里的相对路径（相对 aiav/assemblyline_core/）
COPY_MAP = {
    # --- ODM 基类 ---
    "odm/__init__.py": "odm/__init__.py",
    "odm/base.py": "odm/base.py",
    # --- 模型（任务点名的 8 个 + submission：提交级"取最高文件分"的聚合语义在这） ---
    "odm/models/__init__.py": "odm/models/__init__.py",
    "odm/models/heuristic.py": "odm/models/heuristic.py",
    "odm/models/statistics.py": "odm/models/statistics.py",
    "odm/models/filescore.py": "odm/models/filescore.py",
    "odm/models/file.py": "odm/models/file.py",
    "odm/models/result.py": "odm/models/result.py",
    "odm/models/tagging.py": "odm/models/tagging.py",
    "odm/models/badlist.py": "odm/models/badlist.py",
    "odm/models/safelist.py": "odm/models/safelist.py",
    "odm/models/submission.py": "odm/models/submission.py",
    # --- 纯函数助手（被上面的模型 import，缺一个都 import 不起来） ---
    "common/dict_utils.py": "_compat/dict_utils.py",
    "common/isotime.py": "_compat/isotime.py",
    "common/net.py": "_compat/net.py",
    "common/net_static.py": "_compat/net_static.py",
    "common/uid.py": "_compat/uid.py",
    "common/caching.py": "_compat/caching.py",
    "common/tagging.py": "_compat/tagging.py",
    "common/constants.py": "_compat/constants.py",
    "common/path.py": "_compat/path.py",
    # classification 是访问控制，跟研判无关，但 Classification 字段要它 —— 整份抄，纯 Python
    "common/classification.py": "_compat/classification.py",
    "common/classification.yml": "_compat/classification.yml",
    "common/heuristics.py": "_compat/heuristics.py",
}

# 抄来的代码里，这些 import 要改写成我们包内的相对路径
_REWRITES = [
    (re.compile(r"^from assemblyline\.common import (.+)$", re.M), "common_import"),
    (re.compile(r"^from assemblyline\.common\.([\w.]+) import (.+)$", re.M), "common_sub"),
    (re.compile(r"^from assemblyline\.odm\.models\.([\w.]+) import (.+)$", re.M), "models_sub"),
    (re.compile(r"^from assemblyline\.odm\.base import (.+)$", re.M), "base_import"),
    (re.compile(r"^from assemblyline import odm$", re.M), "odm_import"),
    (re.compile(r"^from assemblyline import (.+)$", re.M), "root_import"),
]

_MAIN_BLOCK = re.compile(r"\nif __name__ == [\"']__main__[\"']:.*\Z", re.S)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _join(ref: str, name: str) -> str:
    """把包引用和名字拼起来：`.` + `base` -> `.base`，`.._compat` + `forge` -> `.._compat.forge`。"""
    return ref + name if ref.endswith(".") else f"{ref}.{name}"


def rel_prefixes(dest_rel: str) -> tuple[str, str, str, str]:
    """算出从该文件所在模块出发的四个包引用。

    `odm/models/result.py` -> root=`...`      odm=`..`   models=`.`           compat=`..._compat`
    `odm/base.py`          -> root=`..`       odm=`.`    models=`.models`     compat=`.._compat`
    `_compat/net.py`       -> root=`..`       odm=`..odm` models=`..odm.models` compat=`.`

    `root` 指向 `aiav.assemblyline_core`（上游的顶层 `assemblyline`），
    所以 `from assemblyline import odm` 要改写成 `from {root} import odm` —— 是**子模块导入**，
    不是从 odm 包里再取个叫 odm 的名字。
    """
    parts = dest_rel.split("/")[:-1]
    root_ref = "." * (len(parts) + 1)
    if parts and parts[0] == "odm":
        odm_ref = "." * len(parts)
    else:
        odm_ref = root_ref + "odm"
    models_ref = "." if parts == ["odm", "models"] else _join(odm_ref, "models")
    compat_ref = "." if (parts and parts[0] == "_compat") else root_ref + "_compat"
    return odm_ref, models_ref, compat_ref, root_ref


def rewrite_imports(text: str, dest_rel: str) -> tuple[str, list[str]]:
    odm_ref, models_ref, compat_ref, root_ref = rel_prefixes(dest_rel)
    notes: list[str] = []

    def sub(pattern: re.Pattern, kind: str, text: str) -> str:
        def repl(m: re.Match) -> str:
            if kind == "common_import":
                out = f"from {compat_ref} import {m.group(1)}"
            elif kind == "common_sub":
                out = f"from {_join(compat_ref, m.group(1))} import {m.group(2)}"
            elif kind == "models_sub":
                out = f"from {_join(models_ref, m.group(1))} import {m.group(2)}"
            elif kind == "base_import":
                out = f"from {_join(odm_ref, 'base')} import {m.group(1)}"
            elif kind == "odm_import":
                out = f"from {root_ref} import odm"
            elif kind == "root_import":
                out = f"from {root_ref} import {m.group(1)}"
            else:  # pragma: no cover
                raise AssertionError(kind)
            notes.append(f"{m.group(0)}  ->  {out}")
            return out

        return pattern.sub(repl, text)

    for pattern, kind in _REWRITES:
        text = sub(pattern, kind, text)
    return text, notes


def strip_main_block(text: str) -> tuple[str, bool]:
    """模型文件尾部的 `if __name__ == "__main__":` 会 import 没抄的 randomizer，砍掉。"""
    new, n = _MAIN_BLOCK.subn("\n", text)
    return new, n > 0


def header(source_version: str, src_rel: str) -> str:
    lines = [
        "# ---------------------------------------------------------------------------",
        "# 抄自 Assemblyline（CybercentreCanada/assemblyline），MIT License。",
        f"# 上游版本：{source_version}",
        f"# 上游路径：assemblyline/{src_rel}",
        "# 本文件除 import 路径改写外与上游一致；改写记录见 ../VENDOR.json。",
        "# 完整许可证原文见 ../LICENCE.md。请勿手工编辑本文件 —— 用 scripts/vendor_assemblyline.py 重新生成。",
        "# ---------------------------------------------------------------------------",
    ]
    return "\n".join(lines) + "\n"


def vendor(source: Path, attack_ids: list[str]) -> int:
    version_file = source / "VERSION"
    source_version = version_file.read_text().strip() if version_file.exists() else "unknown"

    # 只清掉"抄来的"那些文件；`__init__.py` / `forge.py` / `scoring.py` / `README.md`
    # 是手写的，留着（它们不在 COPY_MAP 里）。
    (DEST_ROOT / "odm" / "models").mkdir(parents=True, exist_ok=True)
    (DEST_ROOT / "_compat").mkdir(parents=True, exist_ok=True)
    for stale in list(DEST_ROOT.rglob("*.py")) + list(DEST_ROOT.rglob("*.yml")):
        rel = stale.relative_to(DEST_ROOT).as_posix()
        if rel in COPY_MAP.values() or rel == "attack_ids.py":
            stale.unlink()

    manifest = {
        "upstream": "CybercentreCanada/assemblyline",
        "upstream_version": source_version,
        "licence": "MIT",
        "generated_by": "scripts/vendor_assemblyline.py",
        "files": {},
        "dropped": [
            "assemblyline/datastore, filestore, cachestore, remote, run (ES/Redis/S3/K8s)",
            "assemblyline/odm/models/config.py (117KB 平台配置树)",
            "assemblyline/common/forge.py (真身 import elasticapm/hauntedhouse) —— 换成手写垫片",
            "assemblyline/common/attack_map.py (3MB) —— 只派生用到的 ATT&CK ID",
            "assemblyline/odm/randomizer.py, random_data/",
        ],
    }

    for src_rel, dest_rel in COPY_MAP.items():
        src = source / src_rel
        if not src.exists():
            print(f"!! 上游缺文件：{src_rel}", file=sys.stderr)
            return 2
        raw = src.read_text(encoding="utf-8")
        src_hash = hashlib.sha256(raw.encode()).hexdigest()

        if src.suffix == ".yml":
            (DEST_ROOT / dest_rel).write_text(raw, encoding="utf-8")
            manifest["files"][dest_rel] = {
                "upstream_path": f"assemblyline/{src_rel}",
                "upstream_sha256": src_hash,
                "rewritten": False,
            }
            continue

        text, notes = rewrite_imports(raw, dest_rel)
        text, stripped = strip_main_block(text)
        text = header(source_version, src_rel) + text
        (DEST_ROOT / dest_rel).write_text(text, encoding="utf-8")
        manifest["files"][dest_rel] = {
            "upstream_path": f"assemblyline/{src_rel}",
            "upstream_sha256": src_hash,
            "vendored_sha256": sha256_of(DEST_ROOT / dest_rel),
            "rewritten": bool(notes),
            "import_rewrites": notes,
            "stripped_main_block": stripped,
        }

    licence_candidates = [
        source / "LICENCE.md",
        source.parent / "LICENCE.md",
        source.parent.parent / "LICENCE.md",
    ]
    # wheel 装的包：许可证在 <dist-info>/licenses/LICENCE.md
    for dist_info in sorted(source.parent.glob("assemblyline-*.dist-info")):
        licence_candidates += list(dist_info.glob("licenses/*"))
    for cand in licence_candidates:
        if cand.exists():
            shutil.copyfile(cand, DEST_ROOT / "LICENCE.md")
            manifest["licence_file"] = "LICENCE.md"
            break
    else:
        print("!! 找不到上游 LICENCE.md，副本许可证不完整", file=sys.stderr)
        return 2

    if attack_ids:
        manifest["attack_ids"] = export_attack_ids(source, attack_ids)

    (DEST_ROOT / "VENDOR.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    n_rewrites = sum(len(v.get("import_rewrites", [])) for v in manifest["files"].values())
    print(f"抄了 {len(manifest['files'])} 个文件（上游 {source_version}），改写 import {n_rewrites} 处。")
    return 0


def export_attack_ids(source: Path, ids: list[str]) -> dict:
    """从 3MB 的 attack_map.py 里只捞我们用到的 ID 的名字与分类（派生的，可复核）。"""
    ns: dict = {}
    exec(compile((source / "common" / "attack_map.py").read_text(), "attack_map.py", "exec"), ns)  # noqa: S102
    out: dict[str, dict] = {}
    for i in ids:
        i = i.strip()
        if not i:
            continue
        for table, kind in (("attack_map", "technique"), ("software_map", "software"), ("group_map", "group")):
            entry = ns.get(table, {}).get(i)
            if entry:
                out[i] = {
                    "kind": kind,
                    "name": entry.get("name", i),
                    "categories": entry.get("categories", []),
                    "attack_ids": entry.get("attack_ids", []),
                }
                break
        else:
            print(f"!! ATT&CK ID 在 attack_map 里查不到：{i}", file=sys.stderr)

    body = [
        '"""ATT&CK ID -> 名字 / 分类。**派生数据**，由 scripts/vendor_assemblyline.py 从上游',
        "`assemblyline/common/attack_map.py`（MIT, 3MB）里只捞出我们用到的 ID 生成，不整份抄。",
        "",
        "重新生成：`python3 scripts/vendor_assemblyline.py --source <pkg> --attack-ids T1055,...`",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "ATTACK_IDS: dict[str, dict] = " + json.dumps(out, indent=4, ensure_ascii=False, sort_keys=True),
        "",
        "",
        "def describe(attack_id: str) -> dict | None:",
        '    """给一个 ATT&CK ID，返回 {kind, name, categories}；查不到返回 None。"""',
        "    return ATTACK_IDS.get(attack_id)",
        "",
    ]
    (DEST_ROOT / "attack_ids.py").write_text("\n".join(body), encoding="utf-8")
    return out


def check() -> int:
    manifest_path = DEST_ROOT / "VENDOR.json"
    if not manifest_path.exists():
        print("没有 VENDOR.json —— 先跑一次 vendor。", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bad = 0
    for dest_rel, meta in manifest["files"].items():
        path = DEST_ROOT / dest_rel
        if not path.exists():
            print(f"缺文件 {dest_rel}")
            bad += 1
            continue
        want = meta.get("vendored_sha256")
        if want and sha256_of(path) != want:
            print(f"被改过（sha256 不符）{dest_rel}")
            bad += 1
    print(f"校验 {len(manifest['files'])} 个文件，异常 {bad} 个。")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", type=Path, help="已安装的 assemblyline 包目录（含 VERSION / odm / common）")
    ap.add_argument("--check", action="store_true", help="只校验副本 sha256")
    ap.add_argument("--attack-ids", default="", help="逗号分隔的 ATT&CK ID，导出名字与分类")
    args = ap.parse_args()

    if args.check:
        return check()
    if not args.source:
        try:
            import assemblyline  # noqa: PLC0415

            args.source = Path(assemblyline.__file__).resolve().parent
            print(f"用当前环境里的 assemblyline：{args.source}")
        except ImportError:
            print("没给 --source，当前环境也没装 assemblyline。", file=sys.stderr)
            return 2
    ids = [x for x in args.attack_ids.split(",") if x.strip()]
    return vendor(args.source, ids)


if __name__ == "__main__":
    raise SystemExit(main())
