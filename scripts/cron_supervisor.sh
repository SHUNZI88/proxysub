#!/bin/bash
# cron 守护监督 v2：沙箱休眠可能杀死 cron，每 5 分钟检查并拉起。
# v2（2026-10-27）：写 PID 文件 + 日志，供外部可靠核活（pgrep -f 会误报）。
PIDFILE=/tmp/cn_probe/supervisor.pid
mkdir -p /tmp/cn_probe
echo $$ > "$PIDFILE"
while true; do
  if ! pgrep -x cron >/dev/null 2>&1; then
    service cron start >>/tmp/cn_probe/supervisor.log 2>&1
    echo "$(date '+%F %T') cron 已拉起" >>/tmp/cn_probe/supervisor.log
  fi
  sleep 300
done
