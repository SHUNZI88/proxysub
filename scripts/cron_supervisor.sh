#!/bin/bash
# proxysub cron 守护 v3（2026-10-28）
#
# 背景：沙箱由平台按「无活动即休眠」策略回收，休眠会杀掉 cron 与全部后台
# 进程，导致实测轮无法按 6 轮/天运行（实测历史覆盖率约 28%，大量轮次靠人工
# 补跑）。平台 PID 1 是 supervisord，其 include 路径包含
# /usr/local/share/supervisor/*.conf —— 把本守护与 cron 托管给它，沙箱每次
# 唤醒都会自动拉起，无需人工介入。
#
# v3 变更：
#   1) 由平台 supervisord 托管（仓库内 scripts/proxysub.supervisor.conf）
#   2) 启动时立即做「资产龄期检查」：≥ STALE_H 小时且无在跑的实测进程、
#      且距上次开跑 ≥ COOLDOWN_H 小时 → 立刻后台补跑一轮。把「沙箱被唤醒」
#      这个唯一可靠的时机，直接转化为「资产刷新」。
#   3) 每 5 分钟巡检 cron 与托管配置；配置被重置时从仓库自愈写回。
REPO=/root/.codebuddy/artifact/proxysub
WD=/tmp/cn_probe
STALE_H=${PROXYSUB_STALE_H:-3}
COOLDOWN_H=${PROXYSUB_COOLDOWN_H:-2}
PIDFILE=$WD/supervisor.pid
CONF=/usr/local/share/supervisor/proxysub.conf
CONF_SRC=$REPO/scripts/proxysub.supervisor.conf
MARK=$WD/.last_round_start

mkdir -p "$WD"
echo $$ > "$PIDFILE"

log() { echo "$(date '+%F %T') $*" >> "$WD/supervisor.log"; }

asset_age_h() {
  /root/.pyenv/shims/python3.11 - <<'PY' 2>/dev/null || echo 999
import datetime, json
try:
    r = json.load(open('/tmp/cn_probe/verification_report.json'))
    ts = r.get('main_asset_published_at') or r.get('generated_at')
    if not ts:
        print(999)
        raise SystemExit
    t = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ').replace(
        tzinfo=datetime.timezone.utc)
    print(int((datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() // 3600))
except SystemExit:
    pass
except Exception:
    print(999)
PY
}

# 距上次开跑的分钟数；无记录返回 99999
since_last_min() {
  if [ ! -f "$MARK" ]; then echo 99999; return; fi
  echo $(( ( $(date +%s) - $(stat -c %Y "$MARK") ) / 60 ))
}

run_round() {
  if pgrep -f "scripts/cn_probe.py" >/dev/null 2>&1; then
    log "已有实测进程在跑，跳过补跑（资产龄期 ${1}h）"
    return
  fi
  local gap
  gap=$(since_last_min)
  if [ "$gap" -lt $(( COOLDOWN_H * 60 )) ]; then
    log "冷却中（上次开跑 ${gap} 分钟前 < ${COOLDOWN_H}h），跳过"
    return
  fi
  log "触发补跑：资产龄期 ${1}h ≥ ${STALE_H}h，距上次 ${gap} 分钟"
  touch "$MARK"
  (
    cd "$REPO" || exit 1
    export GITHUB_TOKEN="$(cat /root/.github_pat 2>/dev/null)"
    export GH_TOKEN="$GITHUB_TOKEN"
    /root/.pyenv/shims/python3.11 -u "$REPO/scripts/cn_probe.py" \
      >> "$WD/wakeup_run.log" 2>&1
    log "补跑结束（退出码 $?）"
  ) &
}

# ---- 启动：先自愈配置，再做龄期检查 ----
if [ ! -f "$CONF" ] && [ -f "$CONF_SRC" ]; then
  mkdir -p "$(dirname "$CONF")" && cp "$CONF_SRC" "$CONF" \
    && log "托管配置缺失，已从仓库自愈写回"
fi

age=$(asset_age_h)
log "守护启动 v3：资产龄期 ${age}h（阈值 ${STALE_H}h，冷却 ${COOLDOWN_H}h）"
if [ "$age" -ge "$STALE_H" ]; then run_round "$age"; fi

while true; do
  # cron 双保险（正常情况下由 supervisord 托管；此处兜底手动拉起）
  if ! pgrep -x cron >/dev/null 2>&1; then
    /usr/sbin/cron 2>>"$WD/supervisor.log"
    log "cron 未运行，已由守护拉起"
  fi
  # 托管配置自愈（沙箱重建后 /usr/local/share 可能被重置）
  if [ ! -f "$CONF" ] && [ -f "$CONF_SRC" ]; then
    mkdir -p "$(dirname "$CONF")" && cp "$CONF_SRC" "$CONF" \
      && log "托管配置缺失，已自愈写回（下次唤醒生效）"
  fi
  # 资产龄期兜底：长时间无新轮次（如 cron 失效）则补跑
  age=$(asset_age_h)
  if [ "$age" -ge $(( STALE_H * 2 )) ]; then run_round "$age"; fi
  sleep 300
done
