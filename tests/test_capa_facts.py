"""capa 送审注解的单测（2026-09-26 修②）。

背景：良性误报 3 → 5，根因是 capa 规则名（`allocate or change RWX memory` /
`execute shellcode via indirect call` / `run PowerShell expression`）对 MinGW 伪重定位
与 SEH 运行时的**正常产物**也会命中 —— 只给规则名，模型会照着名字判可疑。

修法是给事实、不给白名单：每条命中带 namespace + 规则自带的 description，
并显式声明"这些是关于规则的事实，不是关于被检文件的判断"。这里盯住：
1. 注解真的带上了 namespace / description（规则库没写 description 时如实留 null）；
2. 事实声明在位，且**没有**任何"MinGW/编译器产物一律放行"之类的硬压逻辑；
3. 载荷永远是**合法 JSON 且有界** —— 宁可少列详情，也不裸切字符串。
"""
from __future__ import annotations

import json

from aiav.tools import (
    CAPA_FACTS_NOTE,
    _capa_result,
    _capa_rule_details,
)

# 三条实测会误报的规则（MinGW 伪重定位 / SEH 运行时 / gettext 工具链产物命中过）
RULES = {
    "allocate or change RWX memory": {
        "meta": {"name": "allocate or change RWX memory",
                 "namespace": "host-interaction/process/inject",
                 "description": "", "scopes": {"static": "basic block"}},
    },
    "execute shellcode via indirect call": {
        "meta": {"name": "execute shellcode via indirect call",
                 "namespace": "load-code/shellcode",
                 "description": "executes shellcode by calling it indirectly",
                 "scopes": {"static": "instruction"}},
    },
    "run PowerShell expression": {
        "meta": {"name": "run PowerShell expression",
                 "namespace": "execution/powershell",
                 "scopes": {"static": "instruction"}},
    },
}


def test_rule_details_carry_namespace_and_description():
    details = _capa_rule_details(RULES, shown=10, desc_chars=200)
    by_name = {d["rule"]: d for d in details}
    rwx = by_name["allocate or change RWX memory"]
    assert rwx["namespace"] == "host-interaction/process/inject"
    assert rwx["description"] is None          # 规则库没写 → 如实留 null，不编
    assert rwx["scope"] == "basic block"
    sh = by_name["execute shellcode via indirect call"]
    assert sh["description"] == "executes shellcode by calling it indirectly"
    assert sh["namespace"] == "load-code/shellcode"


def test_payload_declares_facts_not_judgement():
    payload = _capa_result(RULES, attack=[], mbc=[])
    note = payload["_about_this_output"]
    assert note == CAPA_FACTS_NOTE
    assert "关于 capa 规则的事实" in note
    assert "不是「关于被检文件的判断」" in note
    # 关键的一句：模式匹配会在正常产物里出现，命中 ≠ 文件真具备该能力
    assert "正常产物" in note and "不等于文件真的具备该能力" in note


def test_payload_has_no_whitelist_shortcut():
    """修法必须是"给更多事实"，不是"给 MinGW 开白名单"。

    注意：注解里**出现**「MinGW 伪重定位」是故意的 —— 它是"正常产物也会命中同一模式"的
    例子，属于上下文事实。这里禁的是**规定结论**的话术（白名单 / 放行 / 一律判 clean）。
    """
    payload = json.dumps(_capa_result(RULES, attack=[], mbc=[]), ensure_ascii=False).lower()
    for word in ("whitelist", "白名单", "放行", "ignore this rule", "一律判 clean",
                 "treat as clean", "allowlist"):
        assert word not in payload
    # 事实句必须在位（它才是修法本身）
    assert "正常产物" in payload


def test_payload_is_valid_json_and_bounded(monkeypatch):
    # 造 300 条规则，每条 description 都很长 → 必须触发有界化
    rules = {
        f"rule {i}": {"meta": {"name": f"rule {i}", "namespace": "ns/x",
                               "description": "d" * 400, "scopes": {"static": "basic block"}}}
        for i in range(300)
    }
    monkeypatch.setenv("CAPA_DETAIL_RULES", "40")
    monkeypatch.setenv("CAPA_DESC_CHARS", "200")
    monkeypatch.setenv("CAPA_OUTPUT_CHARS", "6000")
    payload = _capa_result(rules, attack=[], mbc=[])
    text = json.dumps(payload, ensure_ascii=False)
    assert len(text) <= 6000                      # 有界
    json.loads(text)                              # 合法（不裸切）
    assert payload["rules_total"] == 300
    assert payload["rule_details_shown"] <= 40
    # 被省略的部分必须留痕，不许静默
    assert payload["rule_details_omitted"] > 0 or payload.get("descriptions_omitted")


def test_payload_keeps_all_rule_names_for_compat():
    rules = {f"r{i}": {"meta": {"name": f"r{i}"}} for i in range(150)}
    payload = _capa_result(rules, attack=[], mbc=[])
    assert payload["capabilities"] == sorted(rules)[:120]
    assert payload["rule_count"] == 150


def test_payload_includes_attack_and_mbc():
    payload = _capa_result(RULES, attack=["T1055 Process Injection"], mbc=["C0007 Allocate Memory"])
    assert payload["attack"] == ["T1055 Process Injection"]
    assert payload["mbc"] == ["C0007 Allocate Memory"]
