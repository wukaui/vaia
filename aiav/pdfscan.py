"""PDF 静态分析：脚本 / JavaScript / URI / 内嵌文件 / 可执行动作（只读解析，绝不打开执行）。

为什么单独做：PDF 是"文档外壳 + 脚本引擎"，真正的恶意往往在
`/OpenAction → /JavaScript`、`/Names → /JavaScript`、`/AA`（附加动作）、
`/AcroForm → /XFA`（可脚本化表单）、`/Launch`（拉起外部程序）与 `/EmbeddedFiles`（内嵌载荷）里。
只读元数据（作者/标题）对研判几乎没有价值，所以这里**只抓可执行面**。

实现要点：
- 用 `pypdf` 解引用对象树（会用 /Filter 解压流，压缩的 JS 也能看到）；
- 目录树覆盖不到的地方（孤立对象、XObject 内嵌对象）再用**原始字节 + 对象正则**兜底扫一遍；
- 抓到的文本喂给既有的 `find_script_patterns()`（复用脚本层规则），再叠加 PDF 专属模式；
- 内嵌文件按扩展名给风险权重（.exe/.dll/.js/.ps1/.vbs 等可直接执行/脚本化的类型）。
"""
from __future__ import annotations

import io
import re
from pathlib import Path
from typing import Any

PDF_EXTS = {".pdf", ".pdf.xml"}

# PDF 里"能干事"的键
ACTION_KEYS = ("/JS", "/JavaScript", "/Launch", "/URI", "/GoToR", "/SubmitForm", "/ImportData",
               "/Rendition", "/RichMedia", "/Sound", "/Movie", "/ResetForm", "/Hide")
# 动作"类型"写在 /S 里（/S /Launch 这种），必须按值判断
ACTION_TYPE_VALUES = ("/Launch", "/JavaScript", "/URI", "/GoToR", "/SubmitForm", "/ImportData",
                      "/Rendition", "/RichMedia", "/Sound", "/Movie", "/ResetForm", "/Hide",
                      "/Named", "/Thread", "/Trans")

RISKY_EMBEDDED_EXTS = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
                       ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk", ".msi", ".py",
                       ".sh", ".psm1", ".cpl", ".reg"}

PDF_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)app\.launchURL", "PDF JS: app.launchURL"),
    (r"(?i)this\.exportDataObject", "PDF JS: exportDataObject（导出内嵌文件）"),
    (r"(?i)this\.submitForm|submitForm\(", "PDF JS: submitForm"),
    (r"(?i)util\.printf|%u9090|\\x90\\x90", "PDF JS: 疑似堆喷射/编码载荷"),
    (r"(?i)\beval\s*\(", "PDF JS: eval"),
    (r"(?i)unescape\s*\(|String\.fromCharCode", "PDF JS: 字符串解码"),
    (r"(?i)getURL\s*\(|Collab\.getIcon", "PDF JS: getURL/数据外带"),
    (r"(?i)/Launch\b", "PDF 动作: /Launch（拉起外部程序）"),
    (r"(?i)/RichMedia|/XFA\b", "PDF 动作: RichMedia/XFA（可脚本化）"),
    (r"(?i)com\.adobe\.acrobat", "PDF JS: Acrobat 特权对象"),
]

_JS_OBJ_RE = re.compile(rb"/JS\b|/JavaScript\b", re.I)
_STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)


def _looks_like_pdf(path: Path) -> bool:
    try:
        with Path(path).open("rb") as f:
            return f.read(5) == b"%PDF-"
    except OSError:
        return False


def _texts_from_pypdf(path: Path, limit_bytes: int) -> dict[str, Any]:
    """用 pypdf 走对象树，抓 JS / 动作 / 内嵌文件 / XFA。"""
    out: dict[str, Any] = {"javascript": [], "actions": [], "embedded_files": [], "uris": [],
                           "xfa": False, "errors": []}
    try:
        from pypdf import PdfReader
    except ImportError:
        out["errors"].append("pypdf 未安装")
        return out

    try:
        reader = PdfReader(str(path), strict=False)
    except Exception as exc:  # noqa: BLE001
        out["errors"].append(f"pypdf 打开失败: {type(exc).__name__}: {exc}"[:200])
        return out

    budget = [limit_bytes]

    def _take(value: Any) -> None:
        if budget[0] <= 0:
            return
        text = ""
        try:
            if hasattr(value, "get_data"):          # 流对象：真正的内容在 get_data() 里
                data = value.get_data()
                text = data.decode("latin-1", errors="replace") if isinstance(data, bytes) else str(data)
            else:
                resolved = _resolve(value)
                text = str(resolved)
        except Exception:  # noqa: BLE001
            return
        if text and len(text) > 3:
            out["javascript"].append(text[:2000])
            budget[0] -= len(text)

    # 1) 文档级目录
    try:
        root = reader.trailer.get("/Root") or {}
        for key in ("/OpenAction", "/AA"):
            if key in root:
                out["actions"].append(key)
                _walk_action(root[key], out, _take)
        names = root.get("/Names")
        if names:
            try:
                js_tree = names.get("/JavaScript")
                if js_tree:
                    for entry in _iter_name_tree(js_tree):
                        out["actions"].append("/Names/JavaScript")
                        _take(entry)
            except Exception as exc:  # noqa: BLE001
                out["errors"].append(f"Names/JavaScript 解析失败: {exc}"[:120])
        acro = root.get("/AcroForm")
        if acro is not None:
            try:
                if "/XFA" in acro:
                    out["xfa"] = True
                    out["actions"].append("/AcroForm/XFA")
                    _take(acro["/XFA"])
            except Exception:  # noqa: BLE001
                pass
    except Exception as exc:  # noqa: BLE001
        out["errors"].append(f"Root 解析失败: {exc}"[:120])

    # 2) 页面级注释与附加动作
    try:
        for page in reader.pages[:200]:
            try:
                if "/AA" in page:
                    out["actions"].append("page/AA")
                    _walk_action(page["/AA"], out, _take)
                for annot in (page.get("/Annots") or []):
                    try:
                        obj = annot.get_object()
                    except Exception:  # noqa: BLE001
                        continue
                    _walk_action(obj, out, _take)
            except Exception:  # noqa: BLE001
                continue
    except Exception as exc:  # noqa: BLE001
        out["errors"].append(f"页面遍历失败: {exc}"[:120])

    # 3) 内嵌文件
    try:
        for name, payload in (reader.attachments or {}).items():
            for item in payload:
                try:
                    data = item if isinstance(item, bytes) else bytes(item)
                except Exception:  # noqa: BLE001
                    data = b""
                out["embedded_files"].append({"name": name, "size": len(data)})
    except Exception as exc:  # noqa: BLE001
        out["errors"].append(f"内嵌文件解析失败: {exc}"[:120])

    out["javascript"] = out["javascript"][:40]
    out["actions"] = sorted(set(str(a) for a in out["actions"]))
    return out


def _resolve(node: Any) -> Any:
    """解间接引用（PDF 里动作/脚本几乎都挂在 IndirectObject 后面）。"""
    for _ in range(4):
        if not hasattr(node, "get_object"):
            return node
        try:
            node = node.get_object()
        except Exception:  # noqa: BLE001
            return node
    return node


def _walk_action(node: Any, out: dict[str, Any], take, depth: int = 0) -> None:
    """递归找动作字典里的 /JS /URI /Launch 等键（跟进间接引用与嵌套字典/数组）。"""
    if depth > 6:
        return
    node = _resolve(node)
    try:
        if isinstance(node, dict):
            for key, value in node.items():
                k = str(key)
                resolved = _resolve(value)
                if k in ACTION_KEYS:
                    out["actions"].append(k)
                    if k in ("/JS", "/JavaScript"):
                        take(resolved)
                    elif k == "/URI":
                        out["uris"].append(str(resolved)[:300])
                if k == "/S" and str(resolved) in ACTION_TYPE_VALUES:
                    # 动作类型：/S /Launch、/S /JavaScript …
                    out["actions"].append(str(resolved))
                    if str(resolved) == "/JavaScript":
                        take(node)
                if isinstance(resolved, (dict, list)):
                    _walk_action(resolved, out, take, depth + 1)
        elif isinstance(node, list):
            for item in node[:50]:
                _walk_action(item, out, take, depth + 1)
    except Exception:  # noqa: BLE001
        pass


def _iter_name_tree(node: Any, depth: int = 0) -> list[str]:
    """遍历 /Names 名称树，返回条目值（JS 名树里是脚本字典）。"""
    out: list[str] = []
    if depth > 6:
        return out
    try:
        obj = node.get_object() if hasattr(node, "get_object") else node
        if not isinstance(obj, dict):
            return out
        if "/Names" in obj:
            pairs = obj["/Names"]
            for i in range(0, len(pairs) - 1, 2):
                try:
                    out.append(str(pairs[i + 1].get_object()))
                except Exception:  # noqa: BLE001
                    out.append(str(pairs[i + 1]))
        for kid in (obj.get("/Kids") or []):
            out.extend(_iter_name_tree(kid, depth + 1))
    except Exception:  # noqa: BLE001
        pass
    return out


def _raw_object_scan(path: Path, limit_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    """兜底：原始字节扫描（含未压缩流的孤立对象）。"""
    out = {"js_objects": 0, "streams_excerpt": [], "uri_raw": []}
    try:
        data = Path(path).read_bytes()[:limit_bytes]
    except OSError:
        return out
    out["js_objects"] = len(_JS_OBJ_RE.findall(data))
    for m in list(_STREAM_RE.finditer(data))[:20]:
        blob = m.group(1)
        if any(tok in blob for tok in (b"app.", b"eval", b"util.", b"unescape", b"getURL")):
            out["streams_excerpt"].append(blob[:1500].decode("latin-1", errors="replace"))
    out["uri_raw"] = [u.decode("latin-1", errors="replace")[:200]
                      for u in re.findall(rb"/URI\s*\(([^)]{4,200})\)", data)][:20]
    return out


def analyze_pdf(path: Path, max_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    """PDF 可执行面静态分析（返回结构化证据，供预筛与 Agent 共用）。"""
    path = Path(path)
    result: dict[str, Any] = {
        "available": True, "is_pdf": False, "pages": 0,
        "javascript": [], "actions": [], "uris": [], "embedded_files": [],
        "xfa": False, "patterns": [], "scores": 0, "reasons": [],
        "raw": {}, "errors": [], "engine": "pypdf",
    }
    if not _looks_like_pdf(path):
        result["is_pdf"] = False
        return result
    result["is_pdf"] = True

    info = _texts_from_pypdf(path, max_bytes)
    result["errors"].extend(info["errors"])
    result["javascript"] = info["javascript"]
    result["actions"] = info["actions"]
    result["uris"] = info["uris"][:30]
    result["embedded_files"] = info["embedded_files"]
    result["xfa"] = info["xfa"]

    try:
        from pypdf import PdfReader

        if not result["errors"] or not result["errors"][0].startswith("pypdf 打开失败"):
            result["pages"] = len(PdfReader(str(path), strict=False).pages)
    except Exception:  # noqa: BLE001
        pass

    raw = _raw_object_scan(path)
    result["raw"] = raw
    if raw.get("uri_raw"):
        result["uris"] = sorted(set(result["uris"] + raw["uri_raw"]))[:30]

    # ---- 模式匹配：既有脚本规则 + PDF 专属模式 ----
    blob = "\n".join([
        "\n".join(result["javascript"]),
        "\n".join(raw.get("streams_excerpt") or []),
        " ".join(result["actions"]),
        " ".join(result["uris"]),
    ])
    try:
        from aiav.tools import find_script_patterns

        result["patterns"].extend(find_script_patterns(blob))
    except Exception:  # noqa: BLE001
        pass
    for pattern, label in PDF_PATTERNS:
        if re.search(pattern, blob):
            result["patterns"].append(label)
    result["patterns"] = sorted(set(result["patterns"]))

    # ---- 打分（与项目其它预筛信号同量级；不单独定性，只决定是否送 AI）----
    score = 0
    if result["javascript"] or raw.get("js_objects"):
        score += 5
        result["reasons"].append(f"PDF 含 JavaScript（{len(result['javascript'])} 段/ {raw.get('js_objects')} 个 /JS 对象）")
    risky_patterns = [p for p in result["patterns"]]
    if risky_patterns:
        score += 5 * min(len(risky_patterns), 4)
        result["reasons"].append("PDF 可疑模式: " + ", ".join(risky_patterns[:8]))
    if result["xfa"]:
        score += 5
        result["reasons"].append("PDF 含 XFA 表单（可脚本化）")
    if "/Launch" in " ".join(result["actions"]):
        score += 5
        result["reasons"].append("PDF 含 /Launch 动作（拉起外部程序）")
    risky_files = [f for f in result["embedded_files"]
                   if Path(f["name"]).suffix.lower() in RISKY_EMBEDDED_EXTS]
    if risky_files:
        score += 8
        result["reasons"].append("PDF 内嵌可执行/脚本文件: "
                                + ", ".join(f["name"] for f in risky_files[:5]))
    elif result["embedded_files"]:
        score += 3
        result["reasons"].append(f"PDF 含内嵌文件 {len(result['embedded_files'])} 个")
    if result["uris"]:
        score += 3
        result["reasons"].append(f"PDF 含 URI 动作 {len(result['uris'])} 个")
    result["scores"] = score
    return result


# ---------------------------------------------------------------- 结构面 / 原始 JS
# 下面这几件是**给②层最小摘要用的**（`aiav/triage.py` 的 PDF 分支），
# 与上面 `analyze_pdf()`（①层判据用）**完全解耦**：`analyze_pdf` 不调用它们，
# 所以加这些东西不会动到任何判据分数。
#: 结构面与原始 JS 的扫描上限（与 `_raw_object_scan` 同档）。
STRUCTURE_READ_BYTES = 4 * 1024 * 1024

_PDF_HEADER_RE = re.compile(rb"%PDF-(\d\.\d)")
_OBJ_DEF_RE = re.compile(rb"(?m)(?:^|[\s>])\d+\s+\d+\s+obj\b")
_STREAM_KW_RE = re.compile(rb"(?<!end)stream\b")
_ENCRYPT_RE = re.compile(rb"/Encrypt\b")
_OBJSTM_RE = re.compile(rb"/ObjStm\b")
_JS_KEY_RE = re.compile(rb"/(?:JS|JavaScript)(?![A-Za-z0-9])")
_HEX_RE = re.compile(rb"\A[0-9A-Fa-f\s]+\Z")


def _pdf_literal_string(data: bytes, start: int, limit: int = 8000) -> tuple[str, int]:
    """从 `start`（指向 `(`）读一个 PDF 字面量字符串，处理 `\\` 转义与嵌套括号。

    只做这一件事：**不解压、不渲染、不执行**。为什么非走一遍括号不可：
    `mb-pdf` 的投递样本大量是"xref 坏了 / ObjStm 解不开"的 PDF，pypdf 走对象树
    会直接失败（实测 60 个里只有 12 个能拿到 JS），而 `/JS (…)` 字面量就摆在明面上。
    按第一个 `)` 截断会把 `app.alert("x")` 切成 `app.alert("x"` —— 括号必须配对。
    """
    out = bytearray()
    depth = 0
    i = start
    end = min(len(data), start + limit)
    while i < end:
        ch = data[i]
        if ch == 0x5C and i + 1 < end:          # `\` 转义：下一个字节原样收下
            out.append(data[i + 1])
            i += 2
            continue
        if ch == 0x28:                          # `(`
            depth += 1
            if depth > 1:
                out.append(ch)
            i += 1
            continue
        if ch == 0x29:                          # `)`
            depth -= 1
            i += 1
            if depth == 0:
                break
            out.append(ch)
            continue
        out.append(ch)
        i += 1
    return out.decode("latin-1", errors="replace"), i


def raw_js_literals(data: bytes, limit: int = 8) -> list[str]:
    """原始字节里的 `/JS (…)` / `/JS <hex>` 字面量（**对象树坏了也能拿到**）。

    只读：不执行、不渲染、不打开 PDF。
    """
    out: list[str] = []
    for match in _JS_KEY_RE.finditer(data):
        if len(out) >= limit:
            break
        i = match.end()
        while i < len(data) and data[i] in b" \t\r\n":
            i += 1
        if i >= len(data):
            continue
        if data[i] == 0x28:                     # `(` 字面量
            text, _ = _pdf_literal_string(data, i)
        elif data[i] == 0x3C:                   # `<hex>`
            close = data.find(b">", i + 1)
            if close < 0:
                continue
            blob = data[i + 1:close]
            if not _HEX_RE.match(blob):
                continue
            try:
                text = bytes.fromhex(re.sub(rb"\s+", b"", blob).decode("ascii")
                                     ).decode("latin-1", errors="replace")
            except ValueError:
                continue
        else:
            continue
        text = text.strip()
        if len(text) >= 8:
            out.append(text)
    return out


def _structure_pdfid(path: Path) -> dict[str, Any] | None:
    """用 pdfid（Didier Stevens 的现成工具）数结构面。没装就返回 None。"""
    try:
        from pdfid.pdfid import PDFiD, cPDFiD  # type: ignore
    except Exception:  # noqa: BLE001 - 没装：退到原始字节正则，不是错误
        return None
    try:
        parsed = cPDFiD(PDFiD(str(path), force=True), True)
        if parsed.errorOccured:
            return None
        keywords = getattr(parsed, "keywords", None)
        if not keywords:
            return None
        counts = {name: int(count.count) for name, count in keywords.items()}
        return {
            "header": getattr(parsed, "header", "") or "",
            "objects": counts.get("obj", 0),
            "streams": counts.get("stream", 0),
            "encrypted": counts.get("/Encrypt", 0) > 0,
            "objstm": counts.get("/ObjStm", 0),
            "pages": counts.get("/Page", 0),
            "counts": {
                "js": counts.get("/JS", 0),
                "javascript": counts.get("/JavaScript", 0),
                "openaction": counts.get("/OpenAction", 0),
                "aa": counts.get("/AA", 0),
                "launch": counts.get("/Launch", 0),
                "embeddedfile": counts.get("/EmbeddedFile", 0),
                "richmedia": counts.get("/RichMedia", 0),
                "xfa": counts.get("/XFA", 0),
                "acroform": counts.get("/AcroForm", 0),
                "jbig2": counts.get("/JBIG2Decode", 0),
            },
        }
    except Exception:  # noqa: BLE001 - 工具本身炸了：退到正则，不猜
        return None


def _structure_raw(data: bytes) -> dict[str, Any]:
    """原始字节兜底（pdfid 没装 / 报错时用）。`engine` 字段会写明是谁算的。"""
    match = _PDF_HEADER_RE.search(data[:1024])
    return {
        "header": match.group(0).decode("latin-1") if match else "",
        "objects": len(_OBJ_DEF_RE.findall(data)),
        "streams": len(_STREAM_KW_RE.findall(data)),
        "encrypted": bool(_ENCRYPT_RE.search(data)),
        "objstm": len(_OBJSTM_RE.findall(data)),
        "pages": 0,
        "counts": {},
    }


def structure_info(path: Path, limit_bytes: int = STRUCTURE_READ_BYTES) -> dict[str, Any]:
    """PDF **结构面**：版本 / 对象数 / 流数 / 是否加密 / ObjStm / 页数。

    为什么单列一条：②层的最小摘要以前在 PDF 上只给"文件名 + 大小 + 熵 +
    前 20 条字符串"，而 PDF 正文是压缩流 —— 字符串全是乱码，摘要等于没给信息。
    这几项是**不解压就能拿到的确定性事实**，成本几乎为零。

    引擎：优先 `pdfid`（现成工具，装了就一定用），没有就退到原始字节正则。
    `engine` 必须写进摘要 —— **不同引擎算出来的数不许混着读**。
    """
    path = Path(path)
    result: dict[str, Any] = {
        "available": True, "engine": "raw", "version": "", "header": "",
        "objects": 0, "streams": 0, "encrypted": False, "objstm": 0, "pages": 0,
        "counts": {}, "errors": [],
    }
    try:
        data = path.read_bytes()[:limit_bytes]
    except OSError as exc:
        result["errors"].append(f"读取失败: {type(exc).__name__}: {exc}"[:120])
        return result

    header_match = _PDF_HEADER_RE.search(data[:1024])
    result["version"] = header_match.group(1).decode("latin-1") if header_match else ""

    parsed = _structure_pdfid(path)
    if parsed is None:
        parsed = _structure_raw(data)
    else:
        result["engine"] = "pdfid"
    result.update(parsed)
    if not result["version"]:
        found = _PDF_HEADER_RE.search(result.get("header", "").encode("latin-1", "replace"))
        if found:
            result["version"] = found.group(1).decode("latin-1")
    return result


def summary_text(info: dict[str, Any]) -> str:
    bits = [
        f"pages={info.get('pages')}",
        f"js={len(info.get('javascript') or [])}",
        f"actions={info.get('actions')}",
        f"uris={len(info.get('uris') or [])}",
        f"embedded={[f.get('name') for f in (info.get('embedded_files') or [])][:5]}",
        f"xfa={info.get('xfa')}",
        f"patterns={info.get('patterns')}",
    ]
    return "; ".join(str(b) for b in bits)


def main() -> None:  # 手工排查：python pdfscan.py <file.pdf>
    import json
    import sys

    if len(sys.argv) < 2:
        print("用法: python pdfscan.py <file.pdf>", file=sys.stderr)
        raise SystemExit(2)
    info = analyze_pdf(Path(sys.argv[1]))
    print(json.dumps({k: v for k, v in info.items() if k != "javascript"}, ensure_ascii=False, indent=2)[:3000])
    _ = io  # 保持 io 引用（部分环境用于内存流测试）


if __name__ == "__main__":
    main()
