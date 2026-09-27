from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    clean = "clean"
    suspicious = "suspicious"
    malicious = "malicious"


class Verdict(BaseModel):
    """Agent 最终输出的结构化结论。"""

    risk: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0, description="0-1 之间的置信度")
    category: str = Field(default="unknown", description="如 trojan / downloader / macro / clean")
    summary: str = Field(default="", description="一句话中文结论")
    evidence: list[str] = Field(default_factory=list, description="来自工具调用的证据")
    mitre: list[str] = Field(default_factory=list, description="可选的 ATT&CK 技术编号")
    recommended_action: str = Field(default="review", description="isolate / review / ignore")
    # 「AI 判决权」审计：策略/规则层想改判但**没有**改判时，把提议原样记在这里。
    # 每条形如 {actor, proposed, from, to, basis, detail, applied: False, disagreement: True}。
    # 判定由 AI 自主完成，这一栏只用于回答"规则到底同不同意 AI"。
    policy_proposals: list[dict[str, Any]] = Field(default_factory=list)


class PreliminaryEvidence(BaseModel):
    """规则预筛阶段的证据，会一起发给 Agent。"""

    path: str
    sha256: str
    size: int
    extension: str
    prefilter_score: int
    reasons: list[str] = Field(default_factory=list)
    yara_hits: list[str] = Field(default_factory=list)
    eicar: bool = False
    known_bad_hash: bool = False
    # 预筛层读不到内容时的**显式记账**（见 scanner.quick_prefilter）：
    # 旧实现把 OSError 吞成 `head=b""`，各项都不加分 → 判 clean ——
    # 「读不了 ≠ 安全」这条声明在预筛层被绕过（入口那层是判 suspicious+review 的）。
    read_error: str = ""
    # 确定性签名证据块（tools.signature_evidence），只从工具/Windows 验签来，不靠模型推断
    signature: dict[str, Any] = Field(default_factory=dict)
    # ①层判据命中（2026-09-27）：每条都对齐 Assemblyline `result.py::Heuristic` 的形状
    # （heur_id / name / description / score / max_score / attack / signature）。
    # 用途：报告里能说清"这 375 分是哪几条判据给的、每条上限多少、哪个工具产出的"。
    criteria_hits: list[dict[str, Any]] = Field(default_factory=list)
    # 产出方给了理由文本、但判据表里分不出是哪条判据的信号。**必须为空**：
    # 不为空就说明有信号加了分却没进判据表（幽灵分）。报告与测试都会盯这个字段。
    unclassified_signals: list[str] = Field(default_factory=list)
    # 确定性层的结论（三档语义）：disposition / tier / band / score / gate / reasons。
    # disposition ∈ {closed_malicious, closed_clean, send_ai, pass}。
    # ⚠️ `pass` **不是判白**，只是"没线索，不值得花 token"。
    deterministic: dict[str, Any] = Field(default_factory=dict)


class FileReport(BaseModel):
    path: str
    sha256: str
    size: int
    extension: str
    prefilter_score: int
    prefilter_reasons: list[str] = Field(default_factory=list)
    yara_hits: list[str] = Field(default_factory=list)
    # ①层判据命中 + 确定性结论（2026-09-27）。报告结构照 Assemblyline 摆的证据链
    # 就是从这里长出来的，见 `aiav/assemblyline_view.py`。
    criteria_hits: list[dict[str, Any]] = Field(default_factory=list)
    unclassified_signals: list[str] = Field(default_factory=list)
    deterministic: dict[str, Any] = Field(default_factory=dict)
    verdict: Verdict
    agent_used: bool = False
    agent_trace: list[dict[str, Any]] = Field(default_factory=list)
    error: str | None = None
    # 策略兜底审计：谁把谁抬到哪、依据是什么（每一条都可追溯）
    policy_actions: list[dict[str, Any]] = Field(default_factory=list)
    # 规则/策略与 AI 结论不一致、但未被采纳的提议（判决权归 AI 的审计面）
    policy_proposals: list[dict[str, Any]] = Field(default_factory=list)
    # 结论级证据来源：每条 evidence 对应哪个工具 + 原始输出片段
    evidence_sources: list[dict[str, Any]] = Field(default_factory=list)
    # 与确定性证据冲突 / 无工具支撑的断言（例如工具没报『无签名』却写『无签名』）
    claim_warnings: list[str] = Field(default_factory=list)
    # 处置状态：whitelisted / quarantined / quarantine_planned / previously_quarantined
    disposition: dict[str, Any] = Field(default_factory=dict)
    # 加壳信息：壳类型 / 判定证据 / 脱壳产物与其独立判定
    packing: dict[str, Any] = Field(default_factory=dict)
    # 多次采样：样本数 / 票型 / 一致性（用于量化判定稳定性）
    sampling: dict[str, Any] = Field(default_factory=dict)
    # 压缩包递归：类型 / 解包产物 / 内嵌样本判定 / 是否因限额截断
    archive: dict[str, Any] = Field(default_factory=dict)
    # 缓存命中信息（from_cache / cached_at）
    cache: dict[str, Any] = Field(default_factory=dict)
    # 模型调用的重试留痕（2026-09-26 修①）：这次判定是**一次过**、**重试过**，
    # 还是最终**降级到规则判定**。旧实现失败即静默降级，报告里只留一句 error，
    # 看不出"重试过没有"、也看不出"这条结论其实不是 AI 下的"。
    # 结构：{attempts, max_attempts, retried, retry_count, outcome, failures[], final_error, policy}
    agent_retry: dict[str, Any] = Field(default_factory=dict)
    # 确定性证据前置（2026-09-27）：这次送审前**本地预采集**了哪些工具输出、多大、多久。
    # 结构：{kind, tools[], skipped[], chars, elapsed_ms, truncated, budget_note, policy}
    # 用途：回答"这次判定到底是不是靠 AI 一轮轮调工具调出来的"。
    evidence_preload: dict[str, Any] = Field(default_factory=dict)
    # 工具调用 / token 留痕（2026-09-27）：这次判定**用了几次工具调用**、**有没有走深挖路径**、
    # 花了多少 token。口径：`tool_calls` 只数 AI 自己发起的（预采集是本地 0 token 的活，
    # 单独记在 evidence_preload 里），`deep_dive` = 有没有走过工具调用这条路。
    # 结构：{tool_calls, deep_dive, tokens, by_tool{}, preloaded_tools[]}
    agent_usage: dict[str, Any] = Field(default_factory=dict)


@dataclass
class ScanDeps:
    """Agent 运行期间的依赖对象，工具通过它访问当前文件。"""

    file_path: Path
    sha256: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    shell_history: list[str] = field(default_factory=list)
    # 送审提示词里给出的 YARA 命中详情（偏移 / 命中字节 / 上下文 / 规则 meta）。
    # 用途：证据溯源时把"AI 引用送审事实"和"AI 凭空推断"区分开 ——
    # 送审事实是文件里的真实字节，引用它算有依据；两者都对不上的才算无依据。
    yara_details: list[dict[str, Any]] = field(default_factory=list)
    # 模型调用的重试留痕（agent.run_agent_with_retry 原地写入）：
    # 成功与失败两条路都写，`scanner` 据此把"用过重试/降级到规则"记进报告。
    agent_retry: dict[str, Any] = field(default_factory=dict)
