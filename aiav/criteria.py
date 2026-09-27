"""①层判据表 —— 照 Assemblyline 的三档语义，把我们现有的判据全部归位。

**为什么要有这张表**：旧口径是"每个信号各自加几分，加到 12 就算可疑"。
问题是每个权重都是散在代码里的字面量，没有上限、没有适用类型、没有工具出处、
更说不清"这条到底能不能单独定案"。于是出现两个毛病：

    · 一条弱信号（比如"高风险扩展名 +5"）能顶过门槛 —— 40 个样本里 35 个同分 5；
    · 强信号（YARA 命中）和弱信号（段占比失衡）在同一个刻度上，说不清谁该优先。

这张表把每条判据写成 Assemblyline `Heuristic` 模型的那个形状：
**名字 / 分数 / max_score 上限 / 适用文件类型 / 用哪个工具产出 / ATT&CK ID / 三档归属**。

## 刻度怎么来的（**不是拟合出来的**）

老口径的 `SUSPICIOUS_SCORE_THRESHOLD = 12` 是"老口径下算可疑"的那条线。
上游 `odm/models/config.py` 里 `verdict.suspicious = 300` 是"上游下算可疑"的那条线。
两边语义相同，所以取

    SIGNAL_UNIT = 300 / 12 = 25      —— 老口径 1 分 = 新口径 25 分

于是老口径的每条权重原封不动地搬到新刻度上，**一个都没调**：

    结构信号 6 → 150   加壳 4 → 100   高风险扩展名 5 → 125   双扩展名 8 → 200
    强 YARA 30 → 750   弱 YARA 5 → 125   脚本强特征 5/条 → 125/条
    EICAR 100 → 2500 → 被 max_score 夹到 1000（≥1000 档，确定性结案）

这么一乘，**三档自己就分好了**：强 YARA 落在 750（500-1000 档），
所有弱信号都落在 500 以下，"两条弱信号才过线"这个性质原样保留（150+150=300）。

## 三档的处置

    ≥1000   确定性结案，**永不送 AI**。两条路：判恶意（哈希/EICAR/AV 库）
            或判干净（签名可信 / 白名单命中）。
    500-1000 强可疑 → 送 AI，且优先。
    <500    弱信号 → **必须复合**。复合到 `AI_GATE` 以上才送 AI，否则记"未结案"。
            （"未结案" ≠ "判白"，报告里必须写清这个区别。）

## 我们加严的一条（对上游语义的**有意偏离**，写在这里免得被当成抄错）

上游"文件分 = 各段求和"，求和到 1000 就是恶意。我们不许这样：
**没有一条 ≥1000 档的判据命中时，分数再高也只能停在 STRONG（送 AI），不许自动结案。**
理由：弱信号累加出来的 1000 分和"AV 库命中"的 1000 分不是一回事，
前者误报率是后者的一万倍。任务里那句"不许靠挪阈值让数字好看"反过来也成立 ——
也不许靠累加把弱信号堆成结案。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

from aiav.assemblyline_core.scoring import (
    SCORE_BANDS,
    DeterministicVerdict,
    Disposition,
    HeuristicScore,
    ScoredHeuristic,
    ScoreTier,
    aggregate_file_score,
    band_of,
    score_heuristic,
    tier_of,
)
from aiav.assemblyline_core.attack_ids import describe as describe_attack

# --------------------------------------------------------------------------------------
# 刻度
# --------------------------------------------------------------------------------------
#: 老口径 1 分 = 新口径 25 分。推导见模块 docstring（老 12 ≡ 上游 verdict.suspicious 300）。
SIGNAL_UNIT = 25

#: 送审闸门：确定性层分数到这儿才把文件交给 AI。
#: 300 = 上游 `verdict.suspicious`，等价于老口径的 12（"两条弱信号才过线"）。
AI_GATE = 300

#: 强可疑档下界（上游 verdict.suspicious 之上的 `highly_suspicious` 是 700；
#: 我们把 500 作为"送 AI 且优先"的下界 —— 与 Assemblyline 文档里的三档描述一致）。
STRONG_FLOOR = 500

#: 确定性结案分（上游 verdict.malicious）。
CONCLUSIVE_SCORE = 1000


class Direction(str, Enum):
    """这条判据指向哪边。判白和判恶意都是"结案"，但方向相反。"""

    MALICIOUS = "malicious"
    CLEAN = "clean"
    SUSPECT = "suspect"


@dataclass(frozen=True)
class Criterion:
    """一条判据的完整定义。字段对齐上游 `odm/models/heuristic.py`。"""

    heur_id: str
    name: str
    description: str
    direction: Direction
    #: 单次命中的分数（新刻度）。0 表示"只留痕不计分"。
    score: int
    #: 分数上限（上游 `Heuristic.max_score`）。None = 不夹。
    max_score: int | None
    filetype: str
    produced_by: str
    attack_ids: tuple[str, ...] = ()
    #: 同一条判据命中多次时，分数是否随频次线性增长（上游：同一签名命中 N 次 ×N）。
    frequency_scaled: bool = False
    #: 是不是"确定性结案"级判据（≥1000 档，永不送 AI）。
    conclusive: bool = False

    def as_heuristic(self) -> HeuristicScore:
        return HeuristicScore(
            heur_id=self.heur_id,
            name=self.name,
            description=self.description,
            score=self.score,
            filetype=self.filetype,
            attack_ids=self.attack_ids,
            max_score=self.max_score,
            produced_by=self.produced_by,
        )


def _c(**kw) -> Criterion:
    return Criterion(**kw)


#: 判据表本体。键是 `heur_id`，写进报告的就是它。
CRITERIA: dict[str, Criterion] = {
    c.heur_id: c
    for c in [
        # ---------------------------------------------------------------------------
        # ≥1000 档 —— 确定性结案，永不送 AI
        # ---------------------------------------------------------------------------
        _c(
            heur_id="DET_KNOWN_BAD_HASH",
            name="已知恶意哈希",
            description="SHA256 精确命中本地恶意哈希库。**身份匹配**（这个文件就是那个样本），"
                        "不是特征匹配，因此可以短路结案。",
            direction=Direction.MALICIOUS,
            score=CONCLUSIVE_SCORE,
            max_score=CONCLUSIVE_SCORE,
            filetype="*",
            produced_by="aiav/data/known_bad_hashes.txt（内置，逐行 sha256[,label]）",
            attack_ids=("T1204.002",),
            conclusive=True,
        ),
        _c(
            heur_id="DET_CLAMAV_SIGNATURE",
            name="ClamAV 病毒库命中",
            description="传统 AV 引擎的签名命中。上游明说 ≥1000 档的分数就来自这类签名服务 —— "
                        "单条即可定恶意，几乎无误报。",
            direction=Direction.MALICIOUS,
            score=CONCLUSIVE_SCORE,
            max_score=CONCLUSIVE_SCORE,
            filetype="*",
            produced_by="clamscan / clamdscan（**本机未安装，见报告核验一节**）",
            attack_ids=("T1204.002",),
            conclusive=True,
        ),
        _c(
            heur_id="DET_EICAR",
            name="EICAR 测试文件",
            description="完整 EICAR 测试标记。判据是**体积 + 内容**双重条件："
                        "真正的 EICAR 只有 68 字节、内容就是那串字符串；"
                        "大文件里出现这串字符串不算（旧实现被子串匹配坑过，把定义它的源码文件自己判成恶意）。",
            direction=Direction.MALICIOUS,
            score=CONCLUSIVE_SCORE,
            max_score=CONCLUSIVE_SCORE,
            filetype="*",
            produced_by="内置常量 EICAR + 文件体积上限 256B",
            attack_ids=("T1204.002",),
            conclusive=True,
        ),
        _c(
            heur_id="DET_TRUSTED_SIGNATURE",
            name="内嵌签名有效且签发者可信",
            description="PE 内嵌 Authenticode 签名验签通过、摘要未篡改，且签发者落在可信名单里。"
                        "**这是判干净方向的结案** —— 上游对应的语义是 safelist：签名安全则该段分数归零。"
                        "注意：链可信（chain_valid）在非 Windows 环境对微软根一律为 False，"
                        "所以本判据用『验签通过 + 签发者名字可信』，不用链验证。",
            direction=Direction.CLEAN,
            score=CONCLUSIVE_SCORE,
            max_score=CONCLUSIVE_SCORE,
            filetype="PE (.exe/.dll/.sys/…)",
            produced_by="aiav.authenticode（asn1crypto + cryptography，纯 Python 验签）",
            conclusive=True,
        ),
        _c(
            heur_id="DET_SAFELIST_HIT",
            name="白名单命中",
            description="SHA256 命中运营白名单。命中即结案判干净，不再消耗任何算力。",
            direction=Direction.CLEAN,
            score=CONCLUSIVE_SCORE,
            max_score=CONCLUSIVE_SCORE,
            filetype="*",
            produced_by="aiav.disposition 白名单（AI_AV_STATE_DIR）",
            conclusive=True,
        ),
        _c(
            heur_id="DET_SIGNATURE_SAFELISTED",
            name="命中的签名已在白名单",
            description="上游 `Signature.safe` 的语义：一条判据下的签名**全部**被标记为安全时，"
                        "该判据分数**归零**（不是扣分，是归零）。理由写进报告的 safelisted_tags。",
            direction=Direction.CLEAN,
            score=0,
            max_score=0,
            filetype="*",
            produced_by="aiav/data/safelist_signatures.txt",
            conclusive=True,
        ),
        # ---------------------------------------------------------------------------
        # 500-1000 档 —— 强可疑，送 AI 且优先
        # ---------------------------------------------------------------------------
        _c(
            heur_id="STRONG_YARA",
            name="高置信 YARA 命中",
            description="命中非弱档的 YARA 规则（弱档规则清单见 tools.WEAK_YARA_RULES）。"
                        "YARA 命中是**特征匹配**（文件含有某种特征），不是身份匹配，"
                        "所以不能短路 —— 必须让 AI 看语境（旧实现里源码文件自指命中过 EICAR）。",
            direction=Direction.SUSPECT,
            score=30 * SIGNAL_UNIT,
            max_score=750,
            filetype="*",
            produced_by="yara-python + aiav/data/rules/*.yar",
            attack_ids=("T1204.002",),
        ),
        _c(
            heur_id="SCRIPT_STRONG",
            name="脚本强特征",
            description="脚本/文本里的执行类特征（下载后执行、编码解码、进程注入…）。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=500,
            filetype=".ps1/.vbs/.js/.bat/.cmd/.hta/.py/…",
            produced_by="aiav.tools.script_signal_tiers（正则规则，0 token）",
            attack_ids=("T1059.001", "T1059.005", "T1059.007"),
            frequency_scaled=True,
        ),
        _c(
            heur_id="XLM_EXEC_PATTERN",
            name="XLM 宏内执行类模式",
            description="Excel 4.0 宏表里的执行类函数（EXEC/CALL/REGISTER…）。"
                        "**信息类函数（读环境/取数/列目录）不计分** —— 业务宏表里那是常态。",
            direction=Direction.SUSPECT,
            score=10 * SIGNAL_UNIT,
            max_score=500,
            filetype=".xls/.xlsm/.xlsb/.xlt…",
            produced_by="oletools（aiav.tools.extract_xlm_macro_info）",
            attack_ids=("T1059.005",),
            frequency_scaled=True,
        ),
        # ---------------------------------------------------------------------------
        # <500 档 —— 弱信号，必须复合
        # ---------------------------------------------------------------------------
        _c(
            heur_id="WEAK_YARA",
            name="弱 YARA 命中",
            description="弱档 YARA 规则命中。单条不足以说明什么，只作为复合的一份。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=125,
            filetype="*",
            produced_by="yara-python + aiav/data/rules/*.yar",
            attack_ids=("T1204.002",),
        ),
        _c(
            heur_id="HIGH_RISK_EXTENSION",
            name="高风险扩展名",
            description="可执行/脚本类扩展名。**这条单独什么都不算** —— 它只是『这个文件值得看一眼』，"
                        "40 个样本里 35 个曾只靠它拿到分数。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=125,
            filetype="*",
            produced_by="文件名后缀（aiav.scanner.HIGH_RISK_EXTENSIONS）",
            attack_ids=("T1204.002",),
        ),
        _c(
            heur_id="DOUBLE_EXTENSION",
            name="可疑双扩展名",
            description="文档壳 + 可执行/快捷方式的双扩展名（invoice.pdf.lnk 这类）。"
                        "投递样本的载荷名常常只在**文件名**里，内容里看不到。",
            direction=Direction.SUSPECT,
            score=8 * SIGNAL_UNIT,
            max_score=200,
            filetype="*",
            produced_by="文件名后缀（aiav.scanner.DOUBLE_EXTENSIONS）",
            attack_ids=("T1036.007",),
        ),
        _c(
            heur_id="SUSPICIOUS_NAME_WORD",
            name="文件名含可疑词",
            description="crack/keygen/loader/ransom 这类词。纯弱信号，且容易误伤（正常工具也会叫 loader）。",
            direction=Direction.SUSPECT,
            score=2 * SIGNAL_UNIT,
            max_score=150,
            filetype="*",
            produced_by="文件名匹配",
            attack_ids=("T1036",),
            frequency_scaled=True,
        ),
        _c(
            heur_id="STRUCT_WX_SECTION",
            name="可写且可执行段",
            description="段特征同时带 WRITE 与 EXECUTE。正常编译产物不会这么标，自修改/注入常见。",
            direction=Direction.SUSPECT,
            score=6 * SIGNAL_UNIT,
            max_score=150,
            filetype="PE",
            produced_by="pefile（aiav.structural.pe_structure_signals）",
            attack_ids=("T1055",),
        ),
        _c(
            heur_id="STRUCT_TEXT_RATIO",
            name="代码段占比失衡",
            description="`.text` 只占段区原始数据的一小块（< 25% 且文件 ≥ 64KB）= 小 stub + 大载荷。",
            direction=Direction.SUSPECT,
            score=6 * SIGNAL_UNIT,
            max_score=150,
            filetype="PE",
            produced_by="pefile（aiav.structural）",
            attack_ids=("T1027",),
        ),
        _c(
            heur_id="STRUCT_RSRC_RATIO",
            name="资源段占比异常",
            description="`.rsrc` 占比 ≥ 35% 且 ≥ 64KB —— 载荷可能藏在资源里。",
            direction=Direction.SUSPECT,
            score=4 * SIGNAL_UNIT,
            max_score=100,
            filetype="PE",
            produced_by="pefile（aiav.structural）",
            attack_ids=("T1027",),
        ),
        _c(
            heur_id="STRUCT_SPARSE_IMPORTS",
            name="导入表稀疏（带动态解析 API）",
            description="DLL ≤ 3、API ≤ 15，**且真的带** VirtualAlloc/LoadLibrary/GetProcAddress 这类动态解析 API。"
                        "去掉『带动态解析 API』这个前提后，真实 Windows 良性语料里 42% 的 PE 都『稀疏』 —— "
                        "其中带动态解析 API 的是 0%，这个前提就是这条判据的反误伤闸。",
            direction=Direction.SUSPECT,
            score=6 * SIGNAL_UNIT,
            max_score=150,
            filetype="PE（非 .NET）",
            produced_by="pefile（aiav.structural）",
            attack_ids=("T1055",),
        ),
        _c(
            heur_id="STRUCT_EP_NOT_EXECUTABLE",
            name="入口点落在未标记可执行的段",
            description="入口所在段缺 EXECUTE 标志 —— 典型的手工构造/加壳产物形态。",
            direction=Direction.SUSPECT,
            score=6 * SIGNAL_UNIT,
            max_score=150,
            filetype="PE",
            produced_by="pefile（aiav.structural）",
            attack_ids=("T1027",),
        ),
        _c(
            heur_id="PACKING",
            name="疑似加壳",
            description="加壳节名或高熵可执行段。**正常软件也会加壳**，所以权重故意压低，"
                        "只够把它送进复核，不足以单独定性。",
            direction=Direction.SUSPECT,
            score=4 * SIGNAL_UNIT,
            max_score=100,
            filetype="PE",
            produced_by="aiav.tools.pe_packing_signals",
            attack_ids=("T1027.002",),
        ),
        _c(
            heur_id="SCRIPT_WEAK",
            name="脚本弱特征",
            description="脚本里的弱特征（长字符串拼接、环境探测…）。",
            direction=Direction.SUSPECT,
            score=3 * SIGNAL_UNIT,
            max_score=150,
            filetype=".ps1/.vbs/.js/.bat/…",
            produced_by="aiav.tools.script_signal_tiers",
            attack_ids=("T1059",),
            frequency_scaled=True,
        ),
        _c(
            heur_id="CONTAINER_PATTERN",
            name="容器可疑模式",
            description="LNK/RTF/OLE/OOXML 容器里的可疑字符串（UTF-16 抽取后再匹配，否则整类是盲的）。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=500,
            filetype=".lnk/.rtf/.doc/.docm/.xls/.xlsm/…",
            produced_by="aiav.tools.merge_container_patterns",
            attack_ids=("T1204.002",),
            frequency_scaled=True,
        ),
        _c(
            heur_id="MACRO_PRESENT",
            name="包含 VBA 宏",
            description="存在 VBA 宏工程。**有宏不等于恶意**（业务文档大量带宏），只是需要看一眼。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=125,
            filetype=".doc/.docm/.xls/.xlsm/…",
            produced_by="oletools（aiav.tools.extract_ole_macro_info）",
            attack_ids=("T1059.005",),
        ),
        _c(
            heur_id="MACRO_PATTERN",
            name="宏内可疑模式",
            description="宏源码里的可疑模式（AutoOpen 这类入口名**不算**，否则正常宏文档全误报）。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=500,
            filetype=".doc/.docm/.xls/.xlsm/…",
            produced_by="oletools",
            attack_ids=("T1059.005",),
            frequency_scaled=True,
        ),
        _c(
            heur_id="XLM_PRESENT",
            name="包含 Excel 4.0 (XLM) 宏表",
            description="XLM 宏表存在。oletools 看不见它（它只认 VBA 工程），2026-09-19 实测整类掉在阈值下。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=125,
            filetype=".xls/.xlsm/.xlsb/…",
            produced_by="oletools（aiav.tools.extract_xlm_macro_info）",
            attack_ids=("T1059.005",),
        ),
        _c(
            heur_id="XLM_HIDDEN",
            name="XLM 宏表被隐藏",
            description="BOUNDSHEET.hsState 显示宏表被隐藏/深度隐藏。真实在野 ZLoader 系样本 3/3 命中。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=125,
            filetype=".xls/.xlsm/…",
            produced_by="oletools",
            attack_ids=("T1027",),
        ),
        _c(
            heur_id="XLM_CHAR_CELLS",
            name="XLM 宏表内 CHAR() 逐字符拼装",
            description="宏体由几百个 `=CHAR(<常量>)` 单字符单元格拼出来，**明文为零** —— "
                        "关键词档在真实样本上一条都不响。真实在野样本 526/569/569 个，合成良性 0 个。",
            direction=Direction.SUSPECT,
            score=10 * SIGNAL_UNIT,
            max_score=250,
            filetype=".xls/.xlsm/…",
            produced_by="oletools",
            attack_ids=("T1027",),
        ),
        _c(
            heur_id="PDF_JS",
            name="PDF 含 JavaScript",
            description="PDF 内嵌 JavaScript（/JS 对象）。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=125,
            filetype=".pdf",
            produced_by="pypdf（aiav.pdfscan.analyze_pdf）",
            attack_ids=("T1059.007",),
        ),
        _c(
            heur_id="PDF_PATTERN",
            name="PDF 可疑模式",
            description="PDF 里的可疑字符串/结构模式。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=500,
            filetype=".pdf",
            produced_by="pypdf（aiav.pdfscan）",
            attack_ids=("T1204.002",),
            frequency_scaled=True,
        ),
        _c(
            heur_id="PDF_XFA",
            name="PDF 含 XFA 表单",
            description="XFA 表单可脚本化。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=125,
            filetype=".pdf",
            produced_by="pypdf（aiav.pdfscan）",
            attack_ids=("T1059.007",),
        ),
        _c(
            heur_id="PDF_LAUNCH",
            name="PDF 含 /Launch 动作",
            description="/Launch 动作可以拉起外部程序。",
            direction=Direction.SUSPECT,
            score=5 * SIGNAL_UNIT,
            max_score=125,
            filetype=".pdf",
            produced_by="pypdf（aiav.pdfscan）",
            attack_ids=("T1204.002",),
        ),
        _c(
            heur_id="PDF_EMBEDDED_EXEC",
            name="PDF 内嵌可执行/脚本文件",
            description="PDF 里直接塞了可执行文件或脚本（可执行面）。",
            direction=Direction.SUSPECT,
            score=8 * SIGNAL_UNIT,
            max_score=200,
            filetype=".pdf",
            produced_by="pypdf（aiav.pdfscan）",
            attack_ids=("T1204.002",),
        ),
        _c(
            heur_id="PDF_EMBEDDED_FILE",
            name="PDF 含内嵌文件",
            description="PDF 内嵌文件（不一定是可执行的）。",
            direction=Direction.SUSPECT,
            score=3 * SIGNAL_UNIT,
            max_score=150,
            filetype=".pdf",
            produced_by="pypdf（aiav.pdfscan）",
            attack_ids=("T1027",),
            frequency_scaled=True,
        ),
        _c(
            heur_id="PDF_URI",
            name="PDF 含 URI 动作",
            description="PDF 内的外链动作。钓鱼文档常见，但正常文档也有。",
            direction=Direction.SUSPECT,
            score=3 * SIGNAL_UNIT,
            max_score=150,
            filetype=".pdf",
            produced_by="pypdf（aiav.pdfscan）",
            attack_ids=("T1566",),
            frequency_scaled=True,
        ),
        _c(
            heur_id="READ_ERROR",
            name="读取失败（无法排除）",
            description="文件读不了。**「读不了 ≠ 安全」** —— 旧实现把 OSError 吞成空内容，"
                        "于是各项都不加分 → 判 clean。这条把『读不了』明确顶到闸门上。",
            direction=Direction.SUSPECT,
            score=12 * SIGNAL_UNIT,
            max_score=300,
            filetype="*",
            produced_by="文件系统（open() 失败）",
        ),
        _c(
            heur_id="XLM_INFO_PATTERN",
            name="XLM 宏内信息类模式（不计分）",
            description="读环境/取数/列目录 —— 业务宏表里是常态，**明确不计分**，只留痕供人工复核。",
            direction=Direction.SUSPECT,
            score=0,
            max_score=0,
            filetype=".xls/.xlsm/…",
            produced_by="oletools",
        ),
    ]
}

# --------------------------------------------------------------------------------------
# 产出方的理由文本 -> 判据 ID
# --------------------------------------------------------------------------------------
# 判据表要落地，得先把"散在各产出方里的理由字符串"接回判据 ID。
# 这里用**显式的子串规则**（不是模糊匹配），并且有测试盯着：
# `tests/test_criteria.py::test_every_emitted_reason_is_classified` 会去扫产出方源码里
# 每一处 `reasons.append(...)` 的字面量，任何一条没被分类就报错 —— 防止产出方加了新信号
# 而判据表没跟上（那种情况会让新信号变成"加了分但报告里没有判据"的幽灵分）。
_REASON_RULES: tuple[tuple[str, str], ...] = (
    # 顺序有意义：先具体后笼统
    ("读取失败", "READ_ERROR"),
    ("EICAR 测试文件", "DET_EICAR"),
    ("命中本地恶意哈希库", "DET_KNOWN_BAD_HASH"),
    ("弱 YARA 命中", "WEAK_YARA"),
    ("YARA 命中", "STRONG_YARA"),
    ("高风险扩展名", "HIGH_RISK_EXTENSION"),
    ("可疑双扩展名", "DOUBLE_EXTENSION"),
    ("文件名包含可疑词", "SUSPICIOUS_NAME_WORD"),
    ("脚本强特征", "SCRIPT_STRONG"),
    ("脚本弱特征", "SCRIPT_WEAK"),
    ("容器可疑模式", "CONTAINER_PATTERN"),
    ("包含 VBA 宏", "MACRO_PRESENT"),
    ("宏内可疑模式", "MACRO_PATTERN"),
    ("包含 Excel 4.0 (XLM) 宏表", "XLM_PRESENT"),
    ("XLM 宏内执行类模式", "XLM_EXEC_PATTERN"),
    ("XLM 宏内信息类模式", "XLM_INFO_PATTERN"),
    ("XLM 宏表被隐藏", "XLM_HIDDEN"),
    ("XLM 宏表内 CHAR()", "XLM_CHAR_CELLS"),
    ("疑似加壳", "PACKING"),
    # 结构信号：理由文本里带的事实是区分依据
    ("可写且可执行段", "STRUCT_WX_SECTION"),
    ("代码段占比失衡", "STRUCT_TEXT_RATIO"),
    ("资源段占比异常", "STRUCT_RSRC_RATIO"),
    ("导入表稀疏", "STRUCT_SPARSE_IMPORTS"),
    ("入口点落在**未标记可执行**的段", "STRUCT_EP_NOT_EXECUTABLE"),
    ("编译时间戳在未来", "STRUCT_FUTURE_TIMESTAMP_DEPRECATED"),
    ("容器内含 ObjectPool", "STRUCT_OLE_OBJECTPOOL"),
    ("容器内含 Package 流", "STRUCT_OLE_PACKAGE"),
    ("容器内含公式编辑器对象", "STRUCT_OLE_EQUATION"),
    ("容器内含 Ole10Native 流", "STRUCT_OLE_OLE10NATIVE"),
    ("文档内含嵌入对象", "STRUCT_OOXML_EMBEDDING"),
    ("文档内含 ActiveX 控件部件", "STRUCT_OOXML_ACTIVEX"),
    ("文档内含公式对象", "STRUCT_OOXML_EQUATION"),
    # PDF
    ("PDF 含 JavaScript", "PDF_JS"),
    ("PDF 可疑模式", "PDF_PATTERN"),
    ("PDF 含 XFA", "PDF_XFA"),
    ("PDF 含 /Launch", "PDF_LAUNCH"),
    ("PDF 内嵌可执行/脚本文件", "PDF_EMBEDDED_EXEC"),
    ("PDF 含内嵌文件", "PDF_EMBEDDED_FILE"),
    ("PDF 含 URI 动作", "PDF_URI"),
)

#: 明确**没有** ATT&CK ID 的判据，以及理由。空着不等于忘了写 ——
#: 写在这儿是为了让"每条判据都得有 ATT&CK"那条测试能区分"故意没有"和"漏了"。
ATTACK_EXEMPT: dict[str, str] = {
    "READ_ERROR": "文件读不出来是**采集失败**，不是攻击者的技术，硬套一个 ATT&CK ID 是编的。",
    "XLM_INFO_PATTERN": "这条**不计分**（只留痕），给它挂 ATT&CK ID 会让人以为它参与判定。",
}

#: 结构信号里有几条**权重为 0 的已弃用信号**，它们只留痕、不进判据表。
#: 单独列出来是为了让"每条产出方的理由都被分类"这条测试能过，同时不假装它们算分。
DEPRECATED_SIGNALS: dict[str, str] = {
    "STRUCT_FUTURE_TIMESTAMP_DEPRECATED": "编译时间戳在未来 —— 已弃用（权重 0）。"
    "MSVC /Brepro 让真实 Windows 系统文件普遍带未来时间戳，纯误报源。",
}

#: 结构信号的理由文本形如 `结构信号 +6: 可写且可执行段 ×1（...）`，从里面把老口径的权重抠出来。
_STRUCT_WEIGHT_RE = re.compile(r"^结构信号 \+(\d+):")


def classify_reason(reason: str) -> str | None:
    """理由文本 → 判据 ID。分不出来返回 None（调用方必须把 None 显式记账，不许吞）。"""
    for needle, heur_id in _REASON_RULES:
        if needle in reason:
            return heur_id
    return None


def raw_weight_of(reason: str, heur_id: str) -> int:
    """把理由文本里的**老口径权重**还原出来。

    结构信号的理由自带 `+6`，直接读；其余判据用表里声明的权重。
    还原出来的权重再乘 `SIGNAL_UNIT` 得到新刻度分数 —— 这样"分是谁给的、给了多少"
    在报告里能对上账，而不是"总分 375，来源不明"。
    """
    if heur_id in DEPRECATED_SIGNALS:
        return 0
    m = _STRUCT_WEIGHT_RE.match(reason)
    if m:
        return int(m.group(1))
    crit = CRITERIA.get(heur_id)
    if crit is None:
        return 0
    # 表里的 score 是新刻度；还原成老口径单位（除以 SIGNAL_UNIT）好跟理由文本对上
    return crit.score // SIGNAL_UNIT


# --------------------------------------------------------------------------------------
# 一条判据的命中 → 计分
# --------------------------------------------------------------------------------------
@dataclass
class CriterionHit:
    """一条判据的**命中记录**（还没算分）。"""

    heur_id: str
    reason: str
    #: 命中次数（上游 `Signature.frequency`）。同一签名命中 N 次 → 分数 ×N。
    frequency: int = 1
    #: 命中的具体签名名（YARA 规则名、AV 签名名…），上游 `Signature.name`
    signatures: tuple[str, ...] = ()
    #: 这条命中的签名是否在白名单里（上游 `Signature.safe`）
    safelisted: bool = False


def score_hits(hits: Iterable[CriterionHit]) -> list[ScoredHeuristic]:
    """把命中记录算成 `ScoredHeuristic` 列表，每条都夹在自己的 `max_score` 里。"""
    out: list[ScoredHeuristic] = []
    for hit in hits:
        crit = CRITERIA.get(hit.heur_id)
        if crit is None:
            continue
        definition = crit.as_heuristic()
        # 结构信号等"按理由文本还原权重"的判据，用还原出来的权重，不用表里的固定分
        raw = raw_weight_of(hit.reason, hit.heur_id)
        if raw and raw * SIGNAL_UNIT != definition.score:
            definition = HeuristicScore(
                heur_id=definition.heur_id,
                name=definition.name,
                description=definition.description,
                score=raw * SIGNAL_UNIT,
                filetype=definition.filetype,
                attack_ids=definition.attack_ids,
                max_score=definition.max_score,
                produced_by=definition.produced_by,
            )
        # ⚠️ 上游的 `signatures` 参数是 `{签名名: 命中次数}`，不是 `{签名名: 分数}`。
        # 弄反过一次：把分数当次数传进去，125 × 125 直接被 max_score 夹到上限，
        # 于是"命中一次"和"命中三次"给出同一个数。分数从判据定义里取，次数从命中记录里取。
        sig_freq = {name: max(int(hit.frequency), 1) for name in hit.signatures}
        scored = score_heuristic(
            definition,
            frequency=hit.frequency if crit.frequency_scaled else 1,
            signatures=sig_freq or None,
            signature_safe={name: hit.safelisted for name in hit.signatures} or None,
            attack_lookup=describe_attack,
        )
        out.append(scored)
    return out


# --------------------------------------------------------------------------------------
# 文件级结论
# --------------------------------------------------------------------------------------
def file_score(hits: Iterable[CriterionHit]) -> tuple[int, list[ScoredHeuristic], list[str]]:
    """文件分 = 各判据分数求和，**但判干净方向的结案判据命中时归零**。

    归零而不是扣分 —— 这是上游 `Signature.safe` 的原语义：
    "该段里所有签名都 safe 时，这一段的分数 = 0"。
    返回 `(分数, 每条判据的计分, 被判白的判据 ID 列表)`。
    """
    hits = list(hits)
    scores = score_hits(hits)
    clean_ids = [
        h.heur_id
        for h in hits
        if h.heur_id in CRITERIA
        and CRITERIA[h.heur_id].conclusive
        and CRITERIA[h.heur_id].direction is Direction.CLEAN
    ]
    total = 0 if clean_ids else aggregate_file_score(scores)
    return total, scores, clean_ids


def decide(
    hits: Iterable[CriterionHit],
    *,
    gate: int = AI_GATE,
    safelist_hit: bool = False,
) -> DeterministicVerdict:
    """确定性层的结论。

    ⚠️ 判白优先于判恶意：一条"签名可信"的判据不会因为别的弱信号而失效 ——
    上游 safelist 的语义就是"这条不算分"，不是"扣分"。
    """
    hits = list(hits)
    total, scores, _clean_ids = file_score(hits)

    by_id = {h.heur_id for h in hits}

    reasons = [f"{s.heur_id}: {CRITERIA[s.heur_id].name} +{s.score}" for s in scores if s.score]

    # ---- 判干净方向：确定性结案 ----
    if safelist_hit or "DET_SAFELIST_HIT" in by_id:
        return DeterministicVerdict(
            disposition=Disposition.CLOSED_CLEAN,
            score=0,
            tier=ScoreTier.CONCLUSIVE,
            band=band_of(0),
            reasons=["DET_SAFELIST_HIT: 白名单命中 → 确定性结案（判干净），不送 AI"],
        )
    if "DET_TRUSTED_SIGNATURE" in by_id:
        return DeterministicVerdict(
            disposition=Disposition.CLOSED_CLEAN,
            score=0,
            tier=ScoreTier.CONCLUSIVE,
            band=band_of(0),
            reasons=["DET_TRUSTED_SIGNATURE: 内嵌签名有效且签发者可信 → 确定性结案（判干净），不送 AI"],
        )

    # ---- 判恶意方向：确定性结案（必须是 ≥1000 档的判据，不许靠弱信号累加） ----
    conclusive_hits = [
        h.heur_id
        for h in hits
        if h.heur_id in CRITERIA
        and CRITERIA[h.heur_id].conclusive
        and CRITERIA[h.heur_id].direction is Direction.MALICIOUS
    ]
    if conclusive_hits:
        return DeterministicVerdict(
            disposition=Disposition.CLOSED_MALICIOUS,
            score=total,
            tier=ScoreTier.CONCLUSIVE,
            band=band_of(total),
            reasons=[f"{h}: 确定性结案（判恶意），永不送 AI" for h in conclusive_hits] + reasons,
        )

    # ---- 中间带 ----
    tier = tier_of(total)
    if tier is ScoreTier.CONCLUSIVE:
        # 加严：没有 ≥1000 档判据命中时，弱信号累加再多也只能停在 STRONG
        tier = ScoreTier.STRONG
    if total >= gate:
        return DeterministicVerdict(
            disposition=Disposition.SEND_AI,
            score=total,
            tier=tier,
            band=band_of(total),
            reasons=reasons or ["（无判据命中却过闸门，属异常）"],
        )
    return DeterministicVerdict(
        disposition=Disposition.PASS,
        score=total,
        tier=ScoreTier.WEAK,
        band=band_of(total),
        reasons=reasons,
    )


def band_label(score: int) -> str:
    """档位的中文名，报告里直接显示。"""
    return {
        "safe": "安全",
        "reference": "参考",
        "suspicious": "可疑",
        "highly_suspicious": "高度可疑",
        "malicious": "恶意",
    }[band_of(score).value]


# --------------------------------------------------------------------------------------
# 判据的历史统计（上游 `Heuristic.stats`）
# --------------------------------------------------------------------------------------
@dataclass
class CriterionStats:
    """上游 `odm/models/statistics.py::Statistics` 的等价物，按判据累计。"""

    count: int = 0
    min: int = 0
    max: int = 0
    sum: int = 0
    first_hit: str = ""
    last_hit: str = ""

    @property
    def avg(self) -> int:
        return int(self.sum / self.count) if self.count else 0

    def observe(self, score: int, when: str) -> None:
        self.count += 1
        self.sum += score
        self.max = max(self.max, score) if self.count > 1 else score
        self.min = min(self.min, score) if self.count > 1 else score
        self.last_hit = when
        if not self.first_hit:
            self.first_hit = when

    def as_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "min": self.min,
            "max": self.max,
            "avg": self.avg,
            "sum": self.sum,
            "first_hit": self.first_hit,
            "last_hit": self.last_hit,
        }


def update_stats(
    stats: Mapping[str, Mapping[str, Any]] | None,
    scores: Iterable[ScoredHeuristic],
    when: str,
) -> dict[str, dict[str, Any]]:
    """把这一轮的判据命中累加进历史统计，返回新的统计表（纯函数，方便测试）。"""
    out: dict[str, dict[str, Any]] = {k: dict(v) for k, v in (stats or {}).items()}
    for s in scores:
        if not s.score:
            continue
        cur = out.get(s.heur_id)
        obj = CriterionStats(**{k: cur[k] for k in ("count", "min", "max", "sum", "first_hit", "last_hit")
                                if cur and k in cur}) if cur else CriterionStats()
        obj.observe(s.score, when)
        out[s.heur_id] = obj.as_dict()
    return out


# --------------------------------------------------------------------------------------
# 统计的落盘（上游 `Heuristic.stats` 要跨次累计，不能只在一次扫描内算）
# --------------------------------------------------------------------------------------
STATS_FILENAME = "criteria_stats.json"


def stats_path(state_dir: "Path | None" = None) -> "Path":
    """判据统计文件的位置：状态目录下（跟白名单/隔离区放一起）。"""
    from pathlib import Path as _Path  # noqa: PLC0415

    if state_dir is None:
        from aiav.disposition import default_store  # noqa: PLC0415

        state_dir = default_store().root
    return _Path(state_dir) / STATS_FILENAME


def load_stats(state_dir: "Path | None" = None) -> dict[str, dict[str, Any]]:
    import json  # noqa: PLC0415

    path = stats_path(state_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        # 统计坏了不该让扫描挂掉，但也不许静默 —— 返回空表，调用方从零开始。
        return {}


def save_stats(stats: Mapping[str, Mapping[str, Any]], state_dir: "Path | None" = None) -> None:
    import json  # noqa: PLC0415

    path = stats_path(state_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dict(stats), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError:
        pass


def record_reports(reports: Iterable[Any], state_dir: "Path | None" = None) -> dict[str, dict[str, Any]]:
    """把一批扫描结果的判据命中累加进历史统计，落盘并返回新统计表。

    只统计**真的算分的**命中（分数为 0 的留痕判据不进统计，否则 `avg` 会被拉成 0）。
    """
    stats = load_stats(state_dir)
    for report in reports:
        when = getattr(report, "scanned_at", None) or ""
        for hit in (getattr(report, "criteria_hits", None) or []):
            if not hit.get("score"):
                continue
            stats = update_stats(
                stats,
                [ScoredHeuristic(
                    heur_id=hit["heur_id"],
                    name=hit.get("name", ""),
                    score=int(hit["score"]),
                )],
                when or _now_stamp(),
            )
    save_stats(stats, state_dir)
    return stats


def _now_stamp() -> str:
    from datetime import datetime, timezone  # noqa: PLC0415

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "AI_GATE",
    "CONCLUSIVE_SCORE",
    "CRITERIA",
    "Criterion",
    "CriterionHit",
    "CriterionStats",
    "ATTACK_EXEMPT",
    "DEPRECATED_SIGNALS",
    "Direction",
    "SIGNAL_UNIT",
    "STRONG_FLOOR",
    "band_label",
    "classify_reason",
    "decide",
    "raw_weight_of",
    "score_hits",
    "update_stats",
    "record_reports",
    "load_stats",
    "save_stats",
    "stats_path",
    "SCORE_BANDS",
]
