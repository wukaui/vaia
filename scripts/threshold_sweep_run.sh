#!/usr/bin/env bash
# 阈值扫描驱动（2026-09-27）
#
# 目的：在**同一批** 320 个样本（300 良 + 20 恶）的真实分布测试集上，
#       对 --ai-threshold 逐档**真跑 AI**，量出「AI 到底值多少」。
#
# 纪律：
#   * 顺序执行，绝不并发 —— 上一轮实测过：并发 clamscan + AI worker 会把
#     批量 ClamAV 顶到超时（整批没有结果行），那一批按铁律作废。
#   * `AI_AV_CACHE=0` + 每档独立 `--state-dir` —— 缓存指纹里**没有闸门**，
#     共用 state 会让低档的结论被高档的旧结论顶替（那就不是"真跑"了）。
#   * 样本只静态分析，不执行、不上传。
set -u

cd "$(dirname "$0")/.." || exit 1
REPO="$(pwd)"
CORPUS=/tmp/real-dist-320/files
OUT=/tmp/thr-sweep
PY="$REPO/.venv/bin/python"
AIAV="$REPO/.venv/bin/aiav"

export AI_AV_CACHE=0

mkdir -p "$OUT"

run_one() {
  local label="$1"; shift
  local gate="$1"; shift
  local outdir="$OUT/$label"
  local statedir="$OUT/state-$label"
  rm -rf "$outdir" "$statedir"
  mkdir -p "$outdir" "$statedir"

  local t0 t1 rc
  t0=$(date +%s.%N)
  "$AIAV" scan "$CORPUS" \
      --ai-threshold "$gate" \
      -o "$outdir" \
      --no-history \
      --state-dir "$statedir" \
      --workers 6 \
      "$@" > "$OUT/$label.log" 2>&1
  rc=$?
  t1=$(date +%s.%N)

  local wall
  wall=$("$PY" -c "print(round($t1-$t0,1))")
  printf '%s\tgate=%s\trc=%s\twall_s=%s\textra=%s\n' \
      "$label" "$gate" "$rc" "$wall" "$*" >> "$OUT/runlog.tsv"
  echo "[done] $label gate=$gate rc=$rc wall=${wall}s"
}

# ---- 便宜的先跑，早拿数早发现坑 ----
# g300 已单独跑过一遍（冒烟测试 + 工具核验），产物在 /tmp/thr-sweep/g300，
# 记录手工写进 runlog.tsv，这里不重复跑（省一次全量①层）。
run_one g200 200
run_one g150 150
run_one g200b 200                       # 一致性：同一档第二遍
run_one g200-deep300 200 --deep-evidence-threshold 300   # 取证成本隔离探针
run_one g100 100
run_one g50 50

echo "[all done]"
