"""ATT&CK ID -> 名字 / 分类。**派生数据**，由 scripts/vendor_assemblyline.py 从上游
`assemblyline/common/attack_map.py`（MIT, 3MB）里只捞出我们用到的 ID 生成，不整份抄。

重新生成：`python3 scripts/vendor_assemblyline.py --source <pkg> --attack-ids T1055,...`
"""

from __future__ import annotations

ATTACK_IDS: dict[str, dict] = {
    "T1027": {
        "attack_ids": [],
        "categories": [
            "stealth"
        ],
        "kind": "technique",
        "name": "Obfuscated Files or Information"
    },
    "T1027.002": {
        "attack_ids": [],
        "categories": [
            "stealth"
        ],
        "kind": "technique",
        "name": "Software Packing"
    },
    "T1036": {
        "attack_ids": [],
        "categories": [
            "stealth"
        ],
        "kind": "technique",
        "name": "Masquerading"
    },
    "T1036.007": {
        "attack_ids": [],
        "categories": [
            "stealth"
        ],
        "kind": "technique",
        "name": "Double File Extension"
    },
    "T1055": {
        "attack_ids": [],
        "categories": [
            "stealth",
            "privilege-escalation"
        ],
        "kind": "technique",
        "name": "Process Injection"
    },
    "T1059": {
        "attack_ids": [],
        "categories": [
            "execution"
        ],
        "kind": "technique",
        "name": "Command and Scripting Interpreter"
    },
    "T1059.001": {
        "attack_ids": [],
        "categories": [
            "execution"
        ],
        "kind": "technique",
        "name": "PowerShell"
    },
    "T1059.005": {
        "attack_ids": [],
        "categories": [
            "execution"
        ],
        "kind": "technique",
        "name": "Visual Basic"
    },
    "T1059.007": {
        "attack_ids": [],
        "categories": [
            "execution"
        ],
        "kind": "technique",
        "name": "JavaScript"
    },
    "T1204.002": {
        "attack_ids": [],
        "categories": [
            "execution"
        ],
        "kind": "technique",
        "name": "Malicious File"
    },
    "T1566": {
        "attack_ids": [],
        "categories": [
            "initial-access"
        ],
        "kind": "technique",
        "name": "Phishing"
    }
}


def describe(attack_id: str) -> dict | None:
    """给一个 ATT&CK ID，返回 {kind, name, categories}；查不到返回 None。"""
    return ATTACK_IDS.get(attack_id)
