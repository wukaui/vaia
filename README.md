# 「第二意见」AI 恶意文件研判台（`aiav`）

> **杀软告诉你"是不是恶意"，我们负责告诉你"为什么"** —— 一条只读、可解释、可回滚的
> 恶意文件研判流水线：确定性证据先看清，**判定由 AI 自主完成**（规则只做预筛与证据），
> 策略层只记分歧、不改判，处置随时可回滚。

## 快速开始

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"        # CLI + 测试
.venv/bin/python -m pip install -e ".[web]"        # 需要本地 Web UI 时再加

cp .env.example .env                               # 填 AGENT_API_KEY 后 AI 档才可用
.venv/bin/aiav scan <文件或目录> --no-ai            # 零 token 先跑通（只用规则与确定性证据）
.venv/bin/aiav scan <文件或目录>                    # 带 AI 判决（花 token，受 --token-budget 硬闸约束）
```

报告落在 `-o` 指定的目录（默认 `./reports/`），同时产出 JSON 与 HTML。

```bash
.venv/bin/aiav --help
.venv/bin/aiav quarantine list                     # 隔离区（默认 dry-run，还原时校验 sha256）
.venv/bin/aiav whitelist add <sha256>
.venv/bin/aiav history
```

Web UI（可选依赖）：

```bash
.venv/bin/python -m uvicorn aiav.web.app:app --host 127.0.0.1 --port 8080
```

## 它做什么

```text
目录遍历 → 白名单/缓存 → 预筛（YARA / 容器 / 宏 / LNK / RTF / 壳 / 压缩包 / PDF / 签名证据）
        → 脱壳与解包后的二次判定 → AI 多步工具调用（判决者）
        → 策略层：记录分歧与提示（不改判）→ 处置（隔离 / 白名单 / 历史，默认 dry-run）
        → JSON + HTML 报告（每条结论挂证据来源）
```

**红线**：样本全程只读、不执行；不自动删除；隔离默认 dry-run；页面与报告不出现密钥。

## 包内布局

| 路径 | 职责 |
|---|---|
| `aiav/cli.py` | CLI 入口（`aiav` 命令） |
| `aiav/scanner.py` | 扫描编排：预筛 → 证据 → AI 判决 → 策略 → 处置 |
| `aiav/tools.py` | AI 可调用的工具集 + YARA / 哈希等确定性证据 |
| `aiav/agent.py` | LLM Agent 装配（判决者） |
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
| `AGENT_MAX_TOKENS` | **必须 ≥ 16000**。推理模型的思考 token 也算在里面，默认 3000 会被挤爆 → 模型零输出 → 静默降级到规则判定（实测 4/63 个文件失败，其中 2 个降级成 clean） |
| `AI_AV_STATE_DIR` | 隔离区/白名单/历史/上传目录，默认 `~/ai-av-bench/ai-av-state` |
| `VT_API_KEY` | VirusTotal 按 hash 查询（可选，不上传样本） |
| `CAPA_RULES` / `CAPA_SIGS` / `CAPA_EXE` | capa 数据与可执行文件位置（可选） |

## 可选：capa 数据（规则 + 签名，**两样都要**）

`pip install -e ".[static]"` 装出来的 capa **不自带规则、也不带签名集**，直接跑会报错退出：

```
ERROR capa: default embedded rules not found! (maybe you installed capa as a library?)
ERROR capa: Using default signature path, but it doesn't exist. Please install the signatures first
```

所以需要另外拉一次（体积大、1000+ 文件，**不进仓库**）：

```bash
git clone --depth 1 https://github.com/mandiant/capa-rules third_party/capa-rules
# 签名集在 capa 主仓库的 sigs/ 里，**没有独立的 capa-sigs 仓库**：
git clone --depth 1 --filter=blob:none --sparse https://github.com/mandiant/capa third_party/capa-src
git -C third_party/capa-src sparse-checkout set sigs
mv third_party/capa-src/sigs third_party/capa-sigs && rm -rf third_party/capa-src
```

**三样（二进制 + 规则集 + 签名集）齐了 `capa_scan` 才会出现在工具表里。**
缺任何一样它都不会暴露给 AI，而是由送审提示词的「本次未执行的检测」段声明原因 ——
这样 AI 知道"这个维度没查"，而不是"查了没问题"。不装完全不影响主流程。


## 测试

```bash
.venv/bin/python -m pytest              # 默认跳过 integration（需要真实 API Key）
.venv/bin/python -m pytest -m integration
```
