#!/usr/bin/env bash
# 安装/修复沙箱侧 cron 槽位（幂等）。沙箱重建、cron 配置丢失或看门狗告警
# 「拉起失败」后，用本脚本一条命令恢复 L1（cn_probe 定时轮）+ L2（看门狗）。
#
# 设计：标记块 + 先删后写，重复执行结果恒等；不动 crontab 里其他条目。
# 时刻表与 docs/cn_probe.md §2 保持一致，改时刻必须两处同步。
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARK_CN="# proxysub:cn-probe"
MARK_WD="# proxysub:cron-watchdog"

# python 解释器：优先 pyenv shim（与既有 crontab 条目一致），回退 python3
if [ -x /root/.pyenv/shims/python3.11 ]; then
    PY=/root/.pyenv/shims/python3.11
else
    PY="$(command -v python3)"
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# 1) 剥掉旧条目：凡调用本仓库 cn_probe.py / cron_watchdog.py 的行（无论有无
#    标记——历史上存在无标记的遗留行）连同标记注释一并删除，保留其他条目。
#    这两个脚本由本仓库独占，按调用路径剥离是安全的。
crontab -l 2>/dev/null \
    | grep -v -e "scripts/cn_probe\.py" -e "scripts/cron_watchdog\.py" \
             -e "^${MARK_CN}" -e "^${MARK_WD}" \
    > "$TMP" || true

# 2) 追加新标记块
{
    echo "$MARK_CN"
    # L1: 每日 4 轮中国出口实测（CST 01:18/07:18/13:18/19:18，
    # 分别接住 CI 00:17/06:17/12:17/18:17 产出的待测文档）
    echo "18 1,7,13,19 * * * cd $REPO_ROOT && export GITHUB_TOKEN=\"\$(cat /root/.github_pat)\" && export GH_TOKEN=\"\$GITHUB_TOKEN\" && $PY -u $REPO_ROOT/scripts/cn_probe.py >> /tmp/cn_probe/cron.log 2>&1"
    echo "$MARK_WD"
    # L2: 看门狗每 2h 一拍——cron 保活 + 漏跑补测
    echo "17 */2 * * * $PY -u $REPO_ROOT/scripts/cron_watchdog.py >> /tmp/cn_probe/watchdog.log 2>&1"
} >> "$TMP"

# 3) 安装并确保守护进程在跑
crontab "$TMP"
service cron start 2>/dev/null || service cron restart 2>/dev/null || true

# 4) 自检：两个脚本各恰好一条（幂等性证明）
n_cn=$(crontab -l | grep -c "scripts/cn_probe\.py" || true)
n_wd=$(crontab -l | grep -c "scripts/cron_watchdog\.py" || true)
if [ "$n_cn" != "1" ] || [ "$n_wd" != "1" ]; then
    echo "错误：crontab 条目数异常（cn_probe=$n_cn, cron_watchdog=$n_wd，应各为 1）" >&2
    exit 1
fi

echo "已安装 cron 槽位："
crontab -l | grep -A1 -E "$MARK_CN|$MARK_WD" || true
echo "cron 状态：$(service cron status 2>&1 | head -1 || true)"
