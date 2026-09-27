# ---------------------------------------------------------------------------
# 抄自 Assemblyline（CybercentreCanada/assemblyline），MIT License。
# 上游版本：4.7.4.20
# 上游路径：assemblyline/odm/models/filescore.py
# 本文件除 import 路径改写外与上游一致；改写记录见 ../VENDOR.json。
# 完整许可证原文见 ../LICENCE.md。请勿手工编辑本文件 —— 用 scripts/vendor_assemblyline.py 重新生成。
# ---------------------------------------------------------------------------
from ... import odm


@odm.model(index=False, store=False, description="Model of Scoring related to a File")
class FileScore(odm.Model):
    psid = odm.Optional(odm.UUID(), description=" Parent submission ID of the associated submission")
    expiry_ts = odm.Date(index=True, description="Expiry timestamp, used for garbage collection")
    score = odm.Integer(description="Maximum score for the associated submission")
    errors = odm.Integer(description="Number of errors that occurred during the previous analysis")
    sid = odm.UUID(description="ID of the associated submission")
    time = odm.Float(description="Epoch time at which the FileScore entry was created")
