# Web UI 规格（红线）

本地单机 Web 壳，给既有 CLI 套一层页面。**默认只绑 `127.0.0.1`**。

## 红线

1. **没有前端构建链** —— Jinja2 模板 + 原生 JS，复用 `report.py` 的 CSS 变量/class。
2. **不另写扫描逻辑** —— 判定/报告/处置全部调现有模块（`scanner` / `report` / `disposition`）。
3. **上传只读字节**，**绝不执行上传文件**；样本落在 `<state_dir>/uploads/<uuid>/`，
   按 TTL（默认 24h）定时清理，不进 git。
4. **单并发 + 有界队列** —— 同一时刻只跑一个任务，队列满返回 429。
5. **不静默降级** —— AI 档不能用（缺 key / 服务端不允许）时必须在页面上说明，
   报告里也要留原因（`summary.ai_fallback`）。不许页面声称"已开启"而实际走规则档。
6. **页面不出现密钥 / 真名 / 校名 / 导师名 / 学号**；服务端绝对路径不外泄
   （报告里的文件路径换成用户给的展示名）。

## 可调参数

扫描参数在首页「扫描参数」面板里改，持久化到 `<state_dir>/web-settings.json`，
对新任务生效（`aiav/web/config.py::ScanParams`）：

| 字段 | 含义 | 默认 |
|---|---|---|
| `ai` | ③层深度 AI 开关（需服务端 `AI_AV_WEB_AI=1` + 有 API Key） | 关 |
| `triage` | ②层 LLM 初筛开关 | 关 |
| `ai_threshold` | 送审闸门 | 300 |
| `ai_threshold_low` | 低档送审线（0 = 关闭） | 225 |
| `triage_threshold` | 初筛门槛 | 60 |
| `triage_entry_gate` | 初筛入口 | 125 |
| `deep_evidence_threshold` | 分流·取证层阈值（0 = 不分流） | 0 |
| `token_budget` | 单次 token 预算（0 = 不限） | 20000 |

所有值都过 `ScanParams.sanitized()` 钳位，非法/自相矛盾的组合进不到扫描器。

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` | 首页（上传 + 参数面板） |
| GET/PUT | `/api/settings` | 读/写扫描参数 |
| POST | `/api/scan` | 上传并排队（`multipart/form-data`，字段名 `file`） |
| GET | `/api/scan/{id}` | 任务状态（终态带 `terminal: true`） |
| GET | `/report/{id}` / `/report/{id}/raw` | 报告页 / 原样 HTML |
| GET | `/history` `/quarantine` `/whitelist` | 读现有 `StateStore` |
| POST | `/quarantine/{id}/restore` | 表单式还原（校验 sha256） |
| GET | `/healthz` | 探活 |
| GET | `/debug/layout` | 布局自检（输出 `LAYOUT_JSON`，供手机宽度验收） |
