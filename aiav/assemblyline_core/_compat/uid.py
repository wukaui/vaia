# ---------------------------------------------------------------------------
# 抄自 Assemblyline（CybercentreCanada/assemblyline），MIT License。
# 上游版本：4.7.4.20
# 上游路径：assemblyline/common/uid.py
# 本文件除 import 路径改写外与上游一致；改写记录见 ../VENDOR.json。
# 完整许可证原文见 ../LICENCE.md。请勿手工编辑本文件 —— 用 scripts/vendor_assemblyline.py 重新生成。
# ---------------------------------------------------------------------------
import hashlib
import uuid

import baseconv

TINY = 8
SHORT = 16
MEDIUM = NORMAL = 32
LONG = 64


def get_random_id() -> str:
    return baseconv.base62.encode(uuid.uuid4().int)


def get_id_from_data(data, prefix=None, length=MEDIUM):
    possible_len = [TINY, SHORT, MEDIUM, LONG]
    if length not in possible_len:
        raise ValueError(f"Invalid hash length of {length}. Possible values are: {str(possible_len)}.")
    sha256_hash = hashlib.sha256(str(data).encode()).hexdigest()[:length]
    _hash = baseconv.base62.encode(int(sha256_hash, 16))

    if isinstance(prefix, str):
        _hash = f"{prefix}_{_hash}"

    return _hash
