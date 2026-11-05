#!/usr/bin/env python3
"""本机（家宽 / Windows）定时实测入口（任务#121，2026-11-05）。

## 为什么要有它

`scripts/cn_probe.py` 是纯执行体，判断「该不该跑、上次跑成没成」原本靠三套
外部守护（shell + cron 看门狗 + HTTP 端点），全部长在 Linux 沙箱上。把实测
搬到本机后，Windows 侧需要一个同样口径的入口，且必须复用 `round_guard` 的
决策（资产龄期 + 指数退避 + 锁探测），不能另起一套。

本脚本就是那层薄壳：

    decide() → 跑 cn_probe（同步、日志直通）→ note_result()（按资产是否刷新判成败）

配合 Windows 任务计划程序定时调用即可，无需 cron/supervisord：

    schtasks /create /tn proxysub-cn-probe /sc hourly /mo 1 /f ^
        /tr "python D:\\...\\proxysub\\scripts\\local_round.py"

## 退出码

    0  跑完（无论 cn_probe 自身返回什么，成败记在 round_guard 状态里）
    0  不该跑（资产新鲜 / 退避中 / 已有实例）
          —— 用 `--verbose` 可看原因，与 Linux 守护同一套判据
    1  参数错误
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import round_guard  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CN_PROBE = os.path.join(HERE, "cn_probe.py")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="本机家宽实测（受 round_guard 决策调度）")
    ap.add_argument("--workdir", default=None, help="工作目录（默认同 cn_probe）")
    ap.add_argument("--stale-h", type=int, default=None,
                    help="资产龄期阈值小时数（默认取 PROXYSUB_STALE_H 或 3）")
    ap.add_argument("--budget", type=int, default=1800, help="单轮时间预算秒数")
    ap.add_argument("--max-wait", type=int, default=3,
                    help="等 CI 新轮次交接文档的最长分钟（本机建议短，默认 3）")
    ap.add_argument("--dry-run", action="store_true", help="只测不发布")
    ap.add_argument("--force", action="store_true",
                    help="无视决策强制跑一轮（排障用；仍受单实例锁保护）")
    ap.add_argument("--verbose", action="store_true", help="打印决策原因")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # 延迟导入：cn_probe 会初始化模块级常量（含 tag/路径），只在真要跑时付这个成本
    import cn_probe  # noqa: PLC0415

    workdir = args.workdir or cn_probe.default_workdir()
    os.makedirs(workdir, exist_ok=True)

    if not args.force:
        ok, why = round_guard.decide(workdir, stale_h=args.stale_h)
        if not ok:
            print(f"[local-round] 不跑：{why}")
            return 0
        if args.verbose:
            print(f"[local-round] 决策：补跑（{why}）")

    round_guard.note_attempt(workdir)
    env = dict(os.environ)
    # 默认 vantage 标签：本机家宽与沙箱是不同的测量环境，报告必须可区分
    env.setdefault("PROXYSUB_VANTAGE", "cn-home")
    env.setdefault("CN_PROBE_WORKDIR", workdir)
    cmd = [sys.executable, "-u", CN_PROBE,
           "--workdir", workdir, "--budget", str(args.budget),
           "--max-wait", str(args.max_wait)]
    if args.dry_run:
        cmd.append("--dry-run")
    print(f"[local-round] 启动：{' '.join(cmd)}")
    try:
        rc = subprocess.run(cmd, env=env).returncode
    except KeyboardInterrupt:
        rc = 130
    state = round_guard.note_result(workdir, rc)
    print(f"[local-round] 结束：cn_probe 退出码 {rc}；"
          f"资产已刷新={state.get('last_result_refreshed')}，"
          f"连续失败={state.get('fail_streak')}，"
          f"下次最早 {round_guard.backoff_min(int(state.get('fail_streak') or 0))} 分钟后")
    return 0


if __name__ == "__main__":
    sys.exit(main())
