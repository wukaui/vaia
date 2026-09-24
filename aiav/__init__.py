"""「第二意见」AI 恶意文件研判台 —— 只读、可解释、可回滚的恶意文件研判流水线。

包内布局：
  cli.py         CLI 入口（`aiav scan ...`）
  scanner.py     扫描编排：预筛 → 证据 → AI 判决 → 策略 → 处置
  tools.py       AI 可调用的工具集 + YARA/哈希等确定性证据
  agent.py       LLM Agent 装配（判决者）
  models.py      数据模型（FileReport / Verdict / RiskLevel …）
  report.py      JSON + HTML 报告渲染
  cache.py       扫描缓存（按规则指纹失效）
  disposition.py 隔离区 / 白名单 / 历史
  archive.py     压缩包解包（含嵌套与体积闸）
  unpack.py      壳检测与脱壳
  pdfscan.py     PDF 可执行面静态分析
  web/           本地 Web UI（可选依赖，见 pyproject 的 [web] extra）
  data/          YARA 规则 + 已知恶意 hash 表
"""

__version__ = "0.1.0"
