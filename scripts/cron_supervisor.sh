#!/bin/bash
# proxysub cron 守护 v4（2026-11-05）
#
# 背景：沙箱由平台按「无活动即休眠」策略回收，休眠会杀掉 cron 与全部后台
# 进程，导致实测轮无法按 6 轮/天运行（实测历史覆盖率约 28%，大量轮次靠人工
# 补跑）。平台 PID 1 是 supervisord，其 include 路径包含
# /usr/local/share/supervisor/*.conf —— 把本守护与 cron 托管给它，沙箱每次
# 唤醒都会自动拉起，无需人工介入。
#
# v4 变更（任务#120，2026-11-05；对应事故：主资产 13h 未刷新）
#   决策逻辑整体移入 `scripts/round_guard.py`，本脚本只负责「托管 + 调用」。
#   原因：v3 在这里手写了一套冷却/存活判定，与 cron_watchdog.py、
#   wake_trigger.py 各写一套且语义冲突，三处同时出错时无人能一眼看清。
#   两处致命缺陷（v3 实测导致死循环）：
#     1) 冷却以 `.last_round_start` 的 mtime 为准，而该标记在**开跑前**就被
#        touch。一轮被杀 → 标记刷新 → 空等 COOLDOWN_H(2h) → 再被断，形成
#        死循环，资产龄期（真正该看的信号）反被忽略。
#     2) `pgrep -f "scripts/cn_probe.py"` 既会自匹配调用方命令行，也会把
#        沙箱冻结（SIGSTOP）的进程算作「在跑」——两种误判都真实发生过。
#   v4 改为：锁探测判存活、资产龄期判新鲜、连续失败指数退避、成功即清零。
REPO=/root/.codebuddy/artifact/proxysub
WD=/tmp/cn_probe
STALE_H=${PROXYSUB_STALE_H:-3}
PIDFILE=$WD/supervisor.pid
CONF=/usr/local/share/supervisor/proxysub.conf
CONF_SRC=$REPO/scripts/proxysub.supervisor.conf
PY=/root/.pyenv/shims/python3.11
GUARD="$PY -u $REPO/scripts/round_guard.py --workdir $WD"

mkdir -p "$WD"
echo $$ > "$PIDFILE"

log() { echo "$(date '+%F %T') $*" >> "$WD/supervisor.log"; }

run_round() {
  local why
  # decide 以退出码表达决策：0=该跑，1=不跑（原因见 stdout）。策略只有一份，
  # 就在 round_guard.py 里，本脚本不重复实现。
  if ! why=$($GUARD decide --stale-h "$STALE_H" 2>&1); then
    log "跳过补跑：$why"
    return
  fi
  log "触发补跑：$why"
  $GUARD note-attempt >> "$WD/supervisor.log" 2>&1
  (
    cd "$REPO" || exit 1
    export GITHUB_TOKEN="$(cat /root/.github_pat 2>/dev/null)"
    export GH_TOKEN="$GITHUB_TOKEN"
    "$PY" -u "$REPO/scripts/cn_probe.py" >> "$WD/wakeup_run.log" 2>&1
    rc=$?
    # 成败不按退出码判：cn_probe 在「另一实例持锁」「轮次已测」等路径上都
    # 以 0 退出，把 rc==0 当成功会让失败静默累积、退避永不生效。
    $GUARD note-result --rc "$rc" >> "$WD/supervisor.log" 2>&1
    log "补跑结束（退出码 $rc）"
  ) &
}

# ---- 启动：先自愈配置，再做龄期检查 ----
if [ ! -f "$CONF" ] && [ -f "$CONF_SRC" ]; then
  mkdir -p "$(dirname "$CONF")" && cp "$CONF_SRC" "$CONF" \
    && log "托管配置缺失，已从仓库自愈写回"
fi

log "守护启动 v4：决策交由 round_guard.py（阈值 ${STALE_H}h）"
run_round

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
  # 资产龄期兜底巡检：是否该跑由 round_guard 判定（含退避与锁探测）
  run_round
  sleep 300
done
