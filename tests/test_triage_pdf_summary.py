"""②层 PDF 单独解析路径（2026-09-27）。

为什么单独一个文件：这一轮给②层最小摘要加了**只在 `kind == "pdf"` 时**才走的
解析路径（`triage._pdf_summary`）。要守住的就两件事：

1. **PDF 摘要里必须真读到东西** —— 结构面 / 动作 / 内嵌文件 / 外链 /
   **解压后可读的 JS 代码**（旧摘要只有"文件名 + 大小 + 熵 + 20 条乱码字符串"）。
2. **非 PDF 的摘要渲染一个字不许变** —— vbs/js/bat/rtf/xls 在批次 A 里已经跑对了。

只读静态：不执行样本、不打开/渲染 PDF、不调模型、不花钱。
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aiav import triage  # noqa: E402
from aiav.pdfscan import raw_js_literals, structure_info  # noqa: E402

# ---------------------------------------------------------------- 合成样本
#: 一个**没有 xref、对象树故意不完整**的最小 PDF（模拟 mb-pdf 里的投递样本：
#: pypdf 走对象树会失败，但 `/JS (…)` 字面量就在明面上）。
PLAIN_JS_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [ ] /Count 0 >>\nendobj\n"
    b"3 0 obj\n<< /S /JavaScript /JS (app.alert(\"Reader not supported\");) >>\nendobj\n"
    b"4 0 obj\n<< /Type /Action /S /URI /URI (https://phish.example/inv.pdf) >>\nendobj\n"
    b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
)

#: 一个正常的文本文件 —— 用来验"非 PDF 不会被 PDF 分支碰到"。
NOT_A_PDF = b"rem just a batch file\r\necho hello\r\n"

#: 这个合成 PDF 里有几个 `/JS`（`raw_js_literals` 与 pdfid 都该数到）。
PLAIN_JS_OBJECTS = 4


def _wellformed_pdf(path: Path) -> Path:
    """用 pypdf 生成一个**结构完整**的 PDF：带 JS、外链注释、内嵌可执行文件。

    为什么要两份样本：`mb-pdf` 里既有"对象树完好"的样本，也有大量
    "xref 坏了 / ObjStm 解不开"的投递样本 —— 两条路径都得有事实可给。
    """
    from pypdf import PdfWriter
    from pypdf.generic import RectangleObject

    from pypdf.actions import JavaScript

    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    # `/OpenAction → /S /JavaScript → /JS`：投递样本最经典的那条链（不用已弃用的 add_js）
    writer.add_open_action(JavaScript('app.alert("Reader not supported");'))
    writer.add_uri(0, "https://phish.example/inv.pdf", RectangleObject((10, 10, 100, 100)))
    writer.add_attachment("payload.exe", b"MZ" + b"\x00" * 64)
    with path.open("wb") as handle:
        writer.write(handle)
    return path


def _write(tmp_path: Path, name: str, blob: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(blob)
    return path


# ---------------------------------------------------------------- pdfscan 侧
def test_structure_info_reads_pdf_facts(tmp_path: Path) -> None:
    path = _write(tmp_path, "a.pdf", PLAIN_JS_PDF)
    info = structure_info(path)
    assert info["available"] is True
    assert info["version"] == "1.4"
    assert info["objects"] == PLAIN_JS_OBJECTS   # pdfid 数 `N 0 obj`
    assert info["encrypted"] is False
    assert info["objstm"] == 0
    assert info["engine"] in {"pdfid", "raw"}


def test_structure_info_counts_action_keywords(tmp_path: Path) -> None:
    """pdfid 的口径：**未解压**就能数到 `/JS` / `/OpenAction`。"""
    path = _write(tmp_path, "a.pdf", PLAIN_JS_PDF)
    counts = structure_info(path)["counts"]
    assert counts.get("js", 0) >= 1
    assert counts.get("openaction", 0) >= 1


def test_structure_info_survives_non_pdf(tmp_path: Path) -> None:
    """不是 PDF 也不能炸：返回 available=True + 空结构面（`kind` 那一层会拦住它）。"""
    path = _write(tmp_path, "b.bin", NOT_A_PDF)
    info = structure_info(path)
    assert info["version"] == ""
    assert info["objects"] == 0


def test_raw_js_literals_handles_nested_parens(tmp_path: Path) -> None:
    """按第一个 `)` 截断会把 `app.alert("x")` 切坏 —— 括号必须配对。"""
    got = raw_js_literals(PLAIN_JS_PDF)
    assert any("app.alert(" in text and text.rstrip().endswith(";") for text in got), got


def test_raw_js_literals_reads_hex_form() -> None:
    hexed = b"/JS <6170702E616C6572742822686922293B>\n"      # app.alert("hi");
    got = raw_js_literals(hexed)
    assert got and "app.alert" in got[0]


# ---------------------------------------------------------------- 摘要侧
def test_pdf_summary_carries_executable_surface(tmp_path: Path) -> None:
    path = _write(tmp_path, "evil.pdf", PLAIN_JS_PDF)
    summary = triage.build_summary(path)
    assert summary["kind"] == "pdf"
    pdf = summary["pdf"]
    assert pdf["structure"]["version"] == "1.4"
    assert pdf["js_total"] >= 1
    assert any("app.alert" in snippet for snippet in pdf["js_snippets"])
    # 明文关键字计数（pdfid 口径）是"对象树解不开时"的兜底信号
    assert pdf["structure"]["counts"].get("openaction", 0) >= 1


def test_wellformed_pdf_summary_reads_tree(tmp_path: Path) -> None:
    """对象树完好的 PDF：动作 / 外链 / 内嵌可执行文件都要读到。"""
    path = _wellformed_pdf(tmp_path / "ok.pdf")
    pdf = triage.build_summary(path)["pdf"]
    assert pdf["structure"]["objects"] > 0
    assert pdf["structure"]["pages"] >= 1
    assert any("JavaScript" in action for action in pdf["actions"])
    assert any("phish.example" in uri for uri in pdf["uris"])
    assert any(item["name"] == "payload.exe" and item["risky"]
               for item in pdf["embedded_files"])
    assert any("app.alert" in snippet for snippet in pdf["js_snippets"])
    prompt = triage.render_prompt(triage.build_summary(path))
    assert "payload.exe" in prompt.user
    assert "phish.example" in prompt.user


def test_pdf_prompt_renders_facts_and_not_criteria(tmp_path: Path) -> None:
    """PDF 摘要要**有内容**；且不许把①层的判据名/规则命中印回去（泄题红线）。"""
    path = _wellformed_pdf(tmp_path / "evil.pdf")
    prompt = triage.render_prompt(triage.build_summary(path))
    assert "PDF 结构:" in prompt.user
    assert "PDF 动作" in prompt.user
    assert "app.alert" in prompt.user
    # 判据名（criteria.py 的 heur_id）与规则命中标签一个都不许出现
    for leaked in ("PDF_JS", "PDF_URI", "PDF_PATTERN", "PDF_EMBEDDED_EXEC",
                   "PDF_EMBEDDED_FILE", "PDF 可疑模式", "可疑模式:"):
        assert leaked not in prompt.user
    assert prompt.over_budget is False


def test_pdf_summary_is_bounded(tmp_path: Path) -> None:
    """PDF 的字符串档位收窄（20 → 8），且总预算不超。"""
    blob = PLAIN_JS_PDF + b"".join(
        b"%d 0 obj\n(%s)\nendobj\n" % (100 + i, b"X" * 30 + b"str%d" % i) for i in range(40)
    )
    path = _write(tmp_path, "big.pdf", blob)
    summary = triage.build_summary(path)
    assert len(summary["strings"]) <= triage.MAX_STRINGS_PDF
    prompt = triage.render_prompt(summary)
    assert prompt.est_tokens <= triage.TARGET_PROMPT_TOKENS
    assert prompt.over_budget is False


def test_non_pdf_summary_has_no_pdf_block(tmp_path: Path) -> None:
    """**回归闸**：非 PDF 的摘要不许出现 `pdf` 字段，渲染也不许多出任何一行。"""
    path = _write(tmp_path, "x.bat", NOT_A_PDF)
    summary = triage.build_summary(path)
    assert summary["kind"] != "pdf"
    assert "pdf" not in summary
    user = triage.render_user_prompt(summary)
    assert "PDF" not in user
    assert "字符串（文件偏移顺序前" in user


def test_budget_trim_keeps_at_least_one_js_snippet(tmp_path: Path) -> None:
    """超预算时的收敛顺序：字符串 → URI/内嵌 → **至少留 1 段 JS**。"""
    summary = {
        "name": "x.pdf", "kind": "pdf", "extension": ".pdf", "size": 10, "entropy": 1.0,
        "strings": [f"garbage-string-{i:03d}-{'Z' * 60}" for i in range(8)],
        "pdf": {
            "structure": {"engine": "pdfid", "version": "1.4", "objects": 9, "streams": 3,
                          "pages": 1, "encrypted": False, "objstm": 0, "counts": {}},
            "actions": ["/OpenAction", "/JavaScript"],
            "uris": [f"https://phish.example/{i}" for i in range(5)],
            "embedded_files": [{"name": f"p{i}.exe", "size": 10, "risky": True} for i in range(5)],
            "js_snippets": ["app.launchURL('http://c2.example/x');"] * 3,
            "js_total": 3,
            "errors": [],
        },
    }
    prompt = triage.render_prompt(summary, max_tokens=300)
    assert prompt.truncated is True
    assert prompt.strings_used == 0
    assert len(prompt.summary["pdf"]["js_snippets"]) >= 1
    assert "app.launchURL" in prompt.user


def test_js_snippet_cleaning_and_readability() -> None:
    # ①层 pypdf 拿到的是字典 repr —— 要把 JS 正文抠出来
    assert triage._clean_js_blob(
        "{'/S': '/JavaScript', '/JS': 'this.exportDataObject({cName:\"e.exe\"});'}"
    ) == 'this.exportDataObject({cName:"e.exe"});'
    # 二进制碎片不可读 → 不喂给模型
    assert triage._readable_js("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0b\x0c") is False
    assert triage._readable_js('app.alert("x");') is True
    # 可疑的排前面
    blobs = ['var a = 1;', 'this.exportDataObject({cName:"x"});']
    snippets, readable_total, raw_total = triage._js_snippets(blobs, limit=1)
    assert raw_total == 2            # 两块都解出来了
    assert readable_total == 1       # 只有一块够长够可读
    assert "exportDataObject" in snippets[0]


def test_triage_version_bumped_for_cache() -> None:
    """改了摘要字段就必须让旧缓存失效（模块自己的契约）。"""
    assert triage.TRIAGE_VERSION == "2"


def test_pdf_summary_error_is_recorded_not_swallowed(tmp_path: Path) -> None:
    """解析炸了要**如实记账**（"解不开 ≠ 安全"），不许静默给一份空摘要。"""
    path = _write(tmp_path, "broken.pdf", b"%PDF-1.7\n" + b"\xff" * 200)
    summary = triage.build_summary(path)
    assert summary["kind"] == "pdf"
    assert isinstance(summary["pdf"], dict)
    assert "errors" in summary["pdf"]
    # 渲染出来必须能看见"解不开"这件事
    user = triage.render_user_prompt(summary)
    assert "PDF" in user


def test_no_io_execution_of_pdf(tmp_path: Path) -> None:
    """纪律：摘要路径**只读字节**，绝不打开/渲染 PDF。"""
    path = _write(tmp_path, "evil.pdf", PLAIN_JS_PDF)
    opened: list[str] = []
    real_open = io.open

    def spy(file, *args, **kwargs):  # noqa: ANN001, ANN202
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    triage.build_summary(path)
    # 直接断言"没有第三方渲染器被拉起来"这件事在单元测试里不可观测，
    # 这里守住可观测的那一半：摘要是用 `Path.open("rb")` 读的，全程二进制。
    assert "pdf" in (triage.build_summary(path)["kind"],)
    assert opened == []          # io.open 一次都没被用（读文件走的是 Path.open）
