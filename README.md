# 「第二意见」AI 恶意文件研判台（`aiav`）

> **杀软告诉你"是不是恶意"，我们负责告诉你"为什么"** —— 一条只读、可解释、可回滚的
> 恶意文件研判流水线：确定性证据先看清，**判定由 AI 自主完成**（规则只做预筛与证据），
> 策略层只记分歧、不改判，处置随时可回滚。

## 快速开始

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"     # CLI（含 capa / floss）
.venv/bin/python -m pip install -e ".[web]"     # 需要本地 Web UI 时再加

.venv/bin/aiav capa-setup                       # 必做：拉 capa 规则集 + 签名集（约 20MB）
.venv/bin/aiav tools                            # 核对：8 个工具是否都到位

cp .env.example .env                            # 填 AGENT_API_KEY 后 AI 档才可用
.venv/bin/aiav scan <文件或目录> --no-ai         # 零 token 先跑通（只用规则与确定性证据）
.venv/bin/aiav scan <文件或目录>                 # 带 AI 判决（花 token，受 --token-budget 硬闸约束）
```

报告落在 `-o` 指定的目录（默认 `./reports/`），同时产出 JSON 与 HTML。

```bash
.venv/bin/aiav --help
.venv/bin/aiav quarantine list                  # 隔离区（默认 dry-run，还原时校验 sha256）
.venv/bin/aiav whitelist add <sha256>
.venv/bin/aiav history
```

Web UI：

```bash
.venv/bin/python -m uvicorn aiav.web.app:app --host 127.0.0.1 --port 8080
```

## 它做什么

```text
目录遍历 → 白名单/缓存 → ①层判据（YARA / 容器 / 宏 / LNK / RTF / 壳 / 结构信号 / 压缩包 / PDF / 签名）
        → ①层处置（三档，见下）：确定性结案（判恶意/判干净，**永不送 AI**）
                               强可疑（≥500）→ 送 AI 且优先
                               弱信号（<500）→ 必须复合，复合到闸门 300 才送 AI
        → 送 AI 的那部分：确定性证据前置（本地采齐 PE / 字符串 / 签名 / capa / floss / 脚本 / 宏 / PDF，0 token）
          · 可选分流·取证层：分数 < `--deep-evidence-threshold` 的文件跳过 capa/floss，只给轻量证据
        → 脱壳与解包后的二次判定 → AI 判决（证据已给全，默认不必再调工具，按需深挖）
        → 策略层：记录分歧与提示（不改判）→ 处置（隔离 / 白名单 / 历史，默认 dry-run）
        → JSON + HTML 报告（每条结论挂判据 ID + 证据来源 + 用了几次工具调用）
          · 报告结构照 Assemblyline `Result` 摆证据链，产物**过它模型的 schema 校验**
            （模型来自装进 venv 的 `assemblyline` 包，不是我们抄的一份副本）
```

### ①层三档（判据表在 `aiav/criteria.py`）

刻度是 **Assemblyline 刻度**：老口径的 12 分 ≡ 上游 `verdict.suspicious` 300 分
（`SIGNAL_UNIT = 25`，老口径每条权重一个都没调）。

| 档 | 分数 | 处置 | 例 |
|---|---|---|---|
| 确定性结案 | ≥1000 | **永不送 AI**。判恶意：已知哈希 / ClamAV 命中 / EICAR；判干净：签名有效且签发者可信 / 白名单命中 | `DET_KNOWN_BAD_HASH` |
| 强可疑 | 500-1000 | 送 AI，且优先 | `STRONG_YARA`(750) |
| 弱信号 | <500 | **必须复合**，复合到闸门 `--ai-threshold`（默认 300）才送 AI | 结构信号(100~200) |

**未结案 ≠ 判白**：分数不到闸门又没结案的文件记 `pass`，报告里与"判干净"分开算。

**红线**：样本全程只读、不执行；不自动删除；隔离默认 dry-run；页面与报告不出现密钥。

## 包内布局

| 路径 | 职责 |
|---|---|
| `aiav/cli.py` | CLI 入口（`aiav` 命令） |
| `aiav/criteria.py` | **①层判据表**：每条判据的名字 / 分数 / max_score 上限 / 适用类型 / 产出工具 / ATT&CK + 三档处置 |
| `aiav/assemblyline_core/` | **Assemblyline 适配层**（装包路线，MIT）：模型直接用上游包，算分委托上游 `common/heuristics.py`，档位边界从上游 `DEFAULT_VERDICTS` 读。**不依赖它的平台**（MongoDB / ES / Redis / K8s），见该目录 README |
| `aiav/assemblyline_view.py` | 报告结构照 Assemblyline `Result` 摆证据链（判据 / 依据 / 证据段 / 服务 / 血缘），产物过**上游包那个** `Result` 的 schema |
| `aiav/scanner.py` | 扫描编排：预筛 → 证据 → AI 判决 → 策略 → 处置 |
| `aiav/tools.py` | AI 可调用的工具集 + YARA / 哈希等确定性证据 |
| `aiav/preload.py` | 确定性证据前置：送审前本地按文件类型采齐工具输出（0 token），渲染进送审上下文；含分流·取证层（capa/floss 按分数跳过） |
| `aiav/structural.py` | 确定性**结构**信号：段表/导入表/资源占比/容器流清单等读数计进预筛分数（0 token，可解释） |
| `aiav/capa_data.py` | capa 语料获取与状态（`aiav capa-setup` / `aiav tools`） |
| `aiav/agent.py` | LLM Agent 装配（判决者） |
| `aiav/authenticode.py` | 纯 Python PE Authenticode 验签（不依赖 Windows） |
| `aiav/models.py` | 数据模型（`FileReport` / `Verdict` / `RiskLevel` …） |
| `aiav/report.py` | JSON + HTML 报告渲染 |
| `aiav/cache.py` | 扫描缓存（按规则指纹失效） |
| `aiav/disposition.py` | 隔离区 / 白名单 / 历史 |
| `aiav/archive.py` `unpack.py` `pdfscan.py` | 压缩包解包 / 脱壳 / PDF 可执行面分析 |
| `aiav/web/` | 本地 Web UI（FastAPI，`[web]` extra） |
| `aiav/data/` | YARA 规则（`rules/*.yar`）+ 已知恶意 hash 表 |

## 环境变量

| 变量 | 用途 |
|---|---|
| `AGENT_API_KEY` / `AGENT_BASE_URL` / `AGENT_MODEL` | LLM 接入（不配则只能 `--no-ai`） |
| `AGENT_MAX_TOKENS` | **必须 ≥ 16000**。推理模型的思考 token 也算在里面，默认 3000 会被挤爆 → 模型零输出 → 静默降级到规则判定 |
| `AI_AV_STATE_DIR` | 隔离区 / 白名单 / 历史 / Web 上传目录 |
| `VT_API_KEY` | VirusTotal 按 hash 查询（可选，不上传样本） |
| `CAPA_TIMEOUT` | capa 单文件超时秒数，默认 180 |
| `CAPA_DATA` / `CAPA_RULES` / `CAPA_SIGS` / `CAPA_EXE` | 覆盖 capa 语料与可执行文件位置 |
| `AI_AV_ENABLE_SHELL` | 设为 `1` 才把 shell 放进工具表（默认关，防 Agent 反复调命令烧 token） |
| `AI_AV_TOKEN_BUDGET` | token 预算硬闸，超出后自动降级为规则判定 |
| `AI_AV_AGENT_SAMPLES` | AI 多次采样取多数票，默认 1 |
| `AI_AV_PRELOAD` | 确定性证据前置开关，默认 `1`（开）。设 `0` 退回旧行为：证据全靠 AI 自己一轮轮调工具（实测 8.0 次调用 / 2.3 万 token 每文件）。开着时按文件类型挑工具、每个文件只采一次，采集 0 token；报告留痕 `evidence_preload` + `agent_usage`（用了几次工具调用 / 有没有走深挖） |
| `AI_AV_PRELOAD_MAX_CHARS` | 证据块整体字符预算，默认 14000。超出按优先级降级（结构化裁剪 → 整条不纳入），并显式标注 |
| `AI_AV_PRELOAD_PER_TOOL_CHARS` | 覆盖单个工具的载荷字符上限（默认按工具给 3000~6000） |
| `AI_AV_DEEP_EVIDENCE_THRESHOLD` | 分流·取证层阈值，默认 `0`（不分流，全部文件都跑 capa/floss）。设成 `300` 时，①层分数 < 300 的文件只采轻量证据（PE 头/导入表/明文字符串/签名），并在送审里**显式声明"深度取证已跳过"**。单位是 Assemblyline 刻度（300 = 老口径 12） |
| `AI_AV_SIGNATURE_CHECK` | 签名证据采集档：`auto`（默认）= 会进 AI **或**开了①层结案就采；`1` = 纯规则扫描也采（全量机器扫描会明显变慢，约 0.5s/文件）；`0` = 一律不采（这一档下 `DET_TRUSTED_SIGNATURE` 永远不命中，送审率会明显变高） |
| `AI_AV_DETERMINISTIC_CLOSE` | ①层结案开关，默认 `1`。设 `0` 时 `auto` 档不再因为"要出①层结论"而采集签名 |
| `AGENT_RETRIES` | 模型调用重试次数，默认 `2`（指数退避 1s/2s + ±30% 抖动）。只重试**可重试类**错误：provider 上游 400 / 5xx / 429 / 网络抖动 / 空响应 / 输出截断；401/403/404 与非上游 400 这类确定性错误一次就放弃。每次判定在报告里留痕（`agent_retry`：用过重试还是最终降级到规则） |
| `AGENT_RETRY_BASE_DELAY` / `AGENT_RETRY_MAX_DELAY` / `AGENT_RETRY_JITTER` | 退避基数（默认 1s）/ 单次等待上限（默认 20s）/ 抖动比例（默认 0.3） |
| `CAPA_DETAIL_RULES` / `CAPA_DESC_CHARS` / `CAPA_OUTPUT_CHARS` | capa 送审注解预算：最多列几条详情（默认 40）/ 每条 description 截断长度（默认 200）/ 整段上限字符（默认 12000）。超出时按「砍 description → 砍条数」降级，并显式标注省略 |
