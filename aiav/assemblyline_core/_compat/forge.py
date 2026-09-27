"""上游 `assemblyline.common.forge` 的**手写垫片**（不是抄的，这是唯一一处替代实现）。

上游那份 forge.py 是"平台工厂"：它 import `elasticapm`、`hauntedhouse`，`get_datastore()`
会去连 Elasticsearch，`get_config()` 要加载 117KB 的平台配置树。我们一个都不要。

抄来的代码只用它三个东西，这里如实实现：

    get_classification()  从 `classification.yml` 造出真正的 Classification 引擎（照抄上游逻辑，
                          只是 yml 路径指向本目录；`_compat/classification.py` 是上游原文）
    get_constants()       返回 `_compat/constants.py` 模块本身（上游是 importlib 按配置名导入）
    CachedObject          定时刷新代理（上游那份包了 APM span，这里去掉 APM）
    get_datastore()       **故意抛错** —— 碰到它就说明有代码想连 ES，那是我们明确不走的路线

`get_config()` / `get_apm_client()` 同样故意抛错。
"""

from __future__ import annotations

import os
import time
from typing import Optional

import yaml

from .classification import Classification, InvalidDefinition
from .dict_utils import recursive_update

config_cache: dict = {}
classification_engines: dict = {}

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CLASSIFICATION_YML = os.path.join(_HERE, "classification.yml")


class PlatformNotVendoredError(RuntimeError):
    """碰到需要 Assemblyline 平台（ES / Redis / S3 / 配置服务）的调用。"""


def _not_vendored(what: str):
    raise PlatformNotVendoredError(
        f"{what} 需要 Assemblyline 平台（Elasticsearch / Redis / 配置服务），"
        "aiav 只抄了它的 ODM 与计分语义，没抄架子。"
    )


def get_classification(yml_config: Optional[str] = None):
    """照上游 forge.get_classification 的逻辑，yml 默认指向本目录那一份。"""
    if yml_config is None:
        yml_config = "/etc/assemblyline/classification.yml"

    if yml_config in classification_engines:
        return classification_engines[yml_config]

    classification_definition = {}
    if os.path.exists(DEFAULT_CLASSIFICATION_YML):
        with open(DEFAULT_CLASSIFICATION_YML, encoding="utf-8") as default_fh:
            default_yml_data = yaml.safe_load(default_fh.read())
            if default_yml_data:
                classification_definition.update(default_yml_data)

    if os.path.exists(yml_config):
        with open(yml_config, encoding="utf-8") as yml_fh:
            yml_data = yaml.safe_load(yml_fh.read())
            if yml_data:
                classification_definition = recursive_update(classification_definition, yml_data)

    if not classification_definition:
        raise InvalidDefinition("Could not find any classification definition to load.")

    engine = Classification(classification_definition)
    classification_engines[yml_config] = engine
    return engine


def get_constants(config=None):
    from . import constants  # noqa: PLC0415

    return constants


def get_config(yml_config: Optional[str] = None):
    _not_vendored("get_config()")


def get_apm_client(service_name):
    _not_vendored("get_apm_client()")


def get_datastore(config=None, archive_access: bool = False):
    _not_vendored("get_datastore()")


def get_archivestore(config=None, connection_attempts=None):
    _not_vendored("get_archivestore()")


class CachedObject:
    """上游 CachedObject 的等价物，去掉 elasticapm 的 span 包装。"""

    def __init__(self, factory, refresh=None, args=None, kwargs=None):
        self.__factory = factory
        self.__refresh = float(refresh or 60)
        self.__cached = None
        self.__update_time = 0
        self.__args = args or []
        self.__kwargs = kwargs or {}

    def __reload(self):
        if time.time() - self.__update_time > self.__refresh:
            self.__cached = self.__factory(*self.__args, **self.__kwargs)
            self.__update_time = time.time()

    def __getattr__(self, key):
        self.__reload()
        return getattr(self.__cached, key)
