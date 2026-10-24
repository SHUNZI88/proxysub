#!/bin/bash
# cron 守护监督：沙箱休眠可能杀死 cron，每 5 分钟检查并拉起
while true; do
  if ! pgrep -x cron >/dev/null 2>&1; then
    service cron start >>/tmp/cn_probe/supervisor.log 2>&1
    echo "$(date '+%F %T') cron 已拉起" >>/tmp/cn_probe/supervisor.log
  fi
  sleep 300
done
