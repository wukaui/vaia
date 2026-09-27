"""上游 `assemblyline.common.*` 里被 ODM 模型 import 的纯函数助手（抄来的，MIT）。

只改写 import 路径，函数体与上游一致。被抄的模块：

    dict_utils   recursive_update / flatten —— result.py 用 flatten 摊平 tags
    isotime      now_as_iso 等 —— odm/base.py 的 Date 默认值
    net          is_valid_domain / is_valid_ip —— odm/base.py 的域名、IP 字段校验
    net_static   IANA TLD 表（20KB 纯数据）
    uid          get_random_id —— odm/base.py 的 UUID 字段默认值
    caching      generate_conf_key —— result.py / error.py 的缓存键
    tagging      tag_dict_to_list —— result.py 把 tags 摊成列表
    constants    队列名 / 优先级常量 —— submission.py 的 MAX_PRIORITY
    path         modulepath —— constants.py 定位规则文件
    classification  访问控制引擎（纯 Python，976 行）—— Classification 字段要它
    heuristics   Heuristic 计分类 —— 见 `../scoring.py`（我们在它上面包了一层）
"""

from __future__ import annotations
