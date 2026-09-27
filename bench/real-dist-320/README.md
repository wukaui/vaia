# 真实分布小规模实测的产物（2026-09-27）

这里只放**这一轮四个数的汇总产物**（`summary.json`），不放样本、不放逐文件原始行。

| 文件 | 是什么 |
|---|---|
| `summary.json` | `scripts/real_dist_summary.py` 的输出：①层那一臂（送审率 / 结案率 / 召回 / 耗时 / 核验）+ "全部送 AI"对照臂（token / 金额 / 均值）+ 外推口径 + 生产档实际 token + **摘掉 ClamAV 那 1000 分的消融** |

语料（`/tmp/real-dist-320/`，300 良性 + 20 恶意）与逐文件原始行（`/tmp/real-dist-out/`、
`/tmp/final-out/`）在 `/tmp` 下，**重启会没**。要重造：

```bash
.venv/bin/python scripts/build_real_dist.py --out /tmp/real-dist-320   # 确定性，跑两遍一样
```

完整结论与口径在 `~/refs/aiav_assemblyline_adopt_20260927.md` 的
"九、真实分布小规模实测"一节。
