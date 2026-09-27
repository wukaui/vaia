# `aiav.assemblyline_core` —— 抄来的 Assemblyline 核心

上游：[CybercentreCanada/assemblyline](https://github.com/CybercentreCanada/assemblyline)
（加拿大政府 CSE 开源，MIT，工业级文件分诊系统）。
本目录抄的是它的**模型定义与计分语义**，**不是它的架子**。

## 为什么抄而不是装

装包路线（`pip install assemblyline`）实测：**31 个直接依赖 / 75 个包 / 324MB**，
拉进来 Azure Blob、AWS S3、Elasticsearch、Redis、elastic-apm、hauntedhouse、magika+ONNX。
我们只要它两个东西：模型形状 + 计分语义。交付要打 exe，装不动。

对比表与实测数字见 `~/refs/aiav_assemblyline_adopt_20260927.md` 第一节。

## 目录

| 路径 | 来源 | 说明 |
|---|---|---|
| `odm/base.py` | 抄 | ODM 基类（1619 行）。**只改写 import 路径** |
| `odm/models/*.py` | 抄 | 9 个模型：heuristic / statistics / filescore / file / result / tagging / badlist / safelist / submission |
| `_compat/*.py` | 抄 | 被模型 import 的纯函数助手（dict_utils / isotime / net / net_static / uid / caching / tagging / constants / path / classification / heuristics） |
| `_compat/classification.yml` | 抄 | 上游默认分类定义（5.4KB） |
| `_compat/forge.py` | **手写** | 上游那份 import elasticapm / hauntedhouse，换成垫片。碰到"要连平台"的调用**明确抛错** |
| `scoring.py` | **手写** | 三档计分语义（累加 / 频次乘 / max_score 上限 / 白名单归零），逐条对齐上游 `common/heuristics.py` |
| `attack_ids.py` | **派生** | ATT&CK ID → 名字/分类。从上游 3MB 的 `attack_map.py` 里只捞用到的 ID |
| `VENDOR.json` | 生成 | 每个文件的上游 sha256 + import 改写记录 |
| `LICENCE.md` | 抄 | 上游 MIT 原文（Crown Copyright, Government of Canada） |

## 重新生成 / 校验

```bash
# 重新抄一遍（--source 指向已安装的 assemblyline 包）
python3 scripts/vendor_assemblyline.py --source <site-packages>/assemblyline \
    --attack-ids T1204.002,T1035,T1027,...

# 只校验副本有没有被手改（CI / 复核）
python3 scripts/vendor_assemblyline.py --check
```

`tests/test_assemblyline_core.py` 里那条 `test_vendor_manifest_exists_and_matches`
会在每次跑测试时校验一遍 sha256 —— 手改副本会当场失败。

## 一致性核验（"抄对了"的硬证据）

`scripts/parity_check_assemblyline.py` 拿同一份内容，分别用上游包和我们的副本构造，
比对三样东西：

| 比对项 | 结果 |
|---|---|
| `Result` 模型字段表 | 266 个字段，sha256 一致 |
| 构造出的 JSON（抹掉取当前时间的字段） | 逐字节一致 |
| 计分语义（6 个用例：频次 / 累加 / 上限 / 夹逼） | 全部一致 |

```bash
UP=<装了 assemblyline 的 python>  OURS=<项目 venv 的 python>
$UP   scripts/parity_check_assemblyline.py --emit /tmp/up.json
$OURS scripts/parity_check_assemblyline.py --emit /tmp/ours.json
python3 scripts/parity_check_assemblyline.py --compare /tmp/up.json /tmp/ours.json
```

## 依赖

抄模型路线**不依赖 pydantic**（上游 ODM 是自研的，不是 pydantic 模型）。
实际需要的是：

| 包 | 为什么 | 体积 |
|---|---|---|
| `arrow` + `python-dateutil` | `odm/base.py` 的 Date 字段解析（用了一次：`arrow.get(value).datetime`） | 1.5MB |
| `python-baseconv` | `_compat/uid.py` / `_compat/caching.py` 的 base62 编码 | 30KB |
| `PyYAML` | 加载 `classification.yml`（aiav 本来就有，capa 传递依赖） | 3.1MB |

`tests/test_assemblyline_core.py::test_importing_models_pulls_no_platform`
用子进程验证：导入这些模型**不会**把 elasticsearch / redis / boto3 / azure /
paramiko / hauntedhouse / elasticapm / onnxruntime / magika / numpy 拉进来。

## 没抄什么（有意为之）

- `datastore` / `filestore` / `cachestore` / `remote` / `run` —— ES / Redis / S3 / K8s 那一套
- `odm/models/config.py`（117KB 的平台配置树）
- `common/forge.py` 真身（它 import elasticapm / hauntedhouse）
- `common/attack_map.py`（3MB）—— 只派生用到的 ID
- `odm/randomizer.py` / `random_data/`

上游 17 条未关 issue 里全是 K8s / Scaler / EKS 的坑，那不是我们该踩的。
