# ---------------------------------------------------------------------------
# 抄自 Assemblyline（CybercentreCanada/assemblyline），MIT License。
# 上游版本：4.7.4.20
# 上游路径：assemblyline/odm/models/statistics.py
# 本文件除 import 路径改写外与上游一致；改写记录见 ../VENDOR.json。
# 完整许可证原文见 ../LICENCE.md。请勿手工编辑本文件 —— 用 scripts/vendor_assemblyline.py 重新生成。
# ---------------------------------------------------------------------------
from ... import odm


@odm.model(index=True, store=True, description="Statistics Model")
class Statistics(odm.Model):
    count = odm.Integer(default=0, description="Count of statistical hits")
    min = odm.Integer(default=0, description="Minimum value of all stastical hits")
    max = odm.Integer(default=0, description="Maximum value of all stastical hits")
    avg = odm.Integer(default=0, description="Average of all stastical hits")
    sum = odm.Integer(default=0, description="Sum of all stastical hits")
    first_hit = odm.Optional(odm.Date(), description="Date of first hit of statistic")
    last_hit = odm.Optional(odm.Date(), description="Date of last hit of statistic")
