"""ATT&CK ID → 名字 / 分类 —— **直接查上游包，不再派生一份副本**。

以前这里是从上游 3MB 的 `common/attack_map.py` 里"只捞我们用到的 ID"生成的一份表
（为了瘦身）。现在走装包路线，整份 map 就在 site-packages 里躺着，查它就行：
一份 846 条 technique 的表，加上 software / group 的映射，全都能用上。

`ATTACK_IDS` 保留"我们判据表里引用到的那些 ID"这个语义 —— 报告里要能一眼看出
我们挂了哪些技术，而不是把 846 条全列出来。
"""

from __future__ import annotations

from assemblyline.common.attack_map import attack_map, group_map, software_map

#: 判据表里引用到的 ATT&CK ID（`criteria.py` 的 `attack_ids` 字段）。
#: 上游 map 里有 846 条 technique，我们只用得着这些 —— 报告列全表没有意义。
USED_ATTACK_IDS: tuple[str, ...] = (
    "T1027",
    "T1027.002",
    "T1036",
    "T1036.007",
    "T1055",
    "T1059",
    "T1059.001",
    "T1059.005",
    "T1059.007",
    "T1204.002",
    "T1566",
)


def describe(attack_id: str) -> dict | None:
    """给一个 ATT&CK ID，返回 `{kind, name, categories}`；查不到返回 None。

    technique / software / group 三张上游表都查 —— 上游 `common/heuristics.py` 展开
    ATT&CK 时用的就是这三张（software 还会再展开成它关联的 technique）。
    """
    if not attack_id:
        return None
    if attack_id in attack_map:
        entry = attack_map[attack_id]
        return {
            "kind": "technique",
            "name": entry.get("name", attack_id),
            "categories": list(entry.get("categories") or []),
        }
    if attack_id in software_map:
        entry = software_map[attack_id]
        return {
            "kind": "software",
            "name": entry.get("name", attack_id),
            "categories": ["software"],
        }
    if attack_id in group_map:
        entry = group_map[attack_id]
        return {
            "kind": "group",
            "name": entry.get("name", attack_id),
            "categories": ["group"],
        }
    return None


#: 我们用到的 ID → 上游查出来的名字/分类。查不到的会在测试里当场炸（不许静默丢）。
ATTACK_IDS: dict[str, dict] = {
    aid: info for aid in USED_ATTACK_IDS if (info := describe(aid)) is not None
}
