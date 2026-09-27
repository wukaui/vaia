# `aiav.assemblyline_core` —— Assemblyline 适配层（装包路线）

上游：[CybercentreCanada/assemblyline](https://github.com/CybercentreCanada/assemblyline)
（加拿大政府 CSE 开源，MIT，工业级文件分诊系统）。

**它是 `pyproject.toml` 里的一个依赖，不是这个仓库里的一份副本。**
`pip install assemblyline` 装进 venv，我们 import 它的模型与计分语义。
这个目录里没有它的任何一行代码，只有两层薄适配。

> 2026-09-27 更正：此前走的是"抄模型"（把 ODM 核心抄进仓库、只装 3 个依赖）。
> 判据换成"哪种方式能最快把它的语义接进扫描流水线"之后改回装包 ——
> 装包实测跑得通（模型 + 计分都不需要平台），那就用装包。
> 体积不再是判据：依赖多几个、包大几百 MB 都无所谓。

## 目录

| 路径 | 来源 | 说明 |
|---|---|---|
| `scoring.py` | **手写适配** | 判据定义 ↔ 上游 `odm/models/heuristic.py`；**算分交给上游** `common/heuristics.py::HeuristicHandler`；档位边界从上游 `odm/models/config.py::DEFAULT_VERDICTS` 读 |
| `attack_ids.py` | **手写适配** | ATT&CK ID → 名字/分类，直接查上游 `common/attack_map.py`（846 条 technique + software/group 两张表） |
| `__init__.py` | **手写适配** | 出口 + `upstream_version()`（读 `importlib.metadata`，没装就明说） |

模型不经过我们这层，直接用上游的：

```python
from assemblyline.odm.models.result import Result          # 报告结构校验
from assemblyline.odm.models.submission import Submission  # 提交级（max_score）
from assemblyline.odm.models.tagging import Tagging        # tags 字段白名单
```

## 红线：不依赖它的平台

**不碰 MongoDB / Elasticsearch / Redis / K8s。** 不跑它的
`datastore` / `filestore` / `cachestore` / `remote` / `run`，不调 `forge.get_datastore()`。

理由**不是体积，是运维负担**：我们要的是它的模型与评分语义能跑起来并接进我们的流水线，
不是把它的服务器也搬过来。

硬证据（`tests/test_assemblyline_core.py`）：

| 测试 | 盯什么 |
|---|---|
| `test_semantics_run_with_sockets_blocked` | 子进程里把 `socket.connect` 拦掉，导入 + 算分 + 构造 `Result` 全程零连接 |
| `test_we_never_call_forge_datastore` | `forge.get_datastore()` 在拦网环境下**当场炸** —— 说明我们一次都没调过它（调了就活不到今天） |
| `test_no_vendored_copy_in_repo` | 仓库里不许再出现上游源码副本（`odm/` / `_compat/` / `VENDOR.json` 都不在） |
| `test_upstream_version_is_pinned` | 装进来的版本 = `pyproject.toml` 里钉的版本 |

`elasticapm` / `elasticsearch` 这些**客户端库**会随依赖树进来、会进 `sys.modules` ——
那是依赖树的事，不是"要平台"：它们没被调用，也没有服务需要跑。

## 依赖

上游包自己带依赖（31 个直接依赖 / 75 个包 / site-packages 约 324MB）。
我们不为了瘦身去砍它 —— 那是"抄模型"路线的判据，已经不适用了。
