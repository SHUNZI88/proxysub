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
import time

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
    ap.add_argument("--reset-pool", action="store_true",
                    help="清空库存（节点库/用户池/检查点）后再跑，从订阅源候选重建；"
                         "原文件移到 <workdir>/reset_backup_<时间>/")
    ap.add_argument("--log", default=None,
                    help="追加日志文件（默认 <workdir>/local_round.log）；"
                         "任务计划程序不保存 stdout，本机排障全靠它")
    return ap


def _make_logger(path: str | None):
    """返回 log(msg)：同时打到 stdout 与日志文件（失败只打 stdout）。"""
    def log(msg: str) -> None:
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
        print(line, flush=True)
        if not path:
            return
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
    return log


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # 延迟导入：cn_probe 会初始化模块级常量（含 tag/路径），只在真要跑时付这个成本
    import cn_probe  # noqa: PLC0415

    workdir = args.workdir or cn_probe.default_workdir()
    os.makedirs(workdir, exist_ok=True)
    log = _make_logger(args.log or os.path.join(workdir, "local_round.log"))

    if args.reset_pool:
        # 「全部重新从订阅源拉取」：库存即历史结论，清空后才不会反复把
        # 旧结论（含用坏判据得出的）带回来。先备份再清，可回退。
        # 候选文档（pending_probe.json）**保留**——它才是订阅源侧的最新输入。
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = os.path.join(workdir, f"reset_backup_{stamp}")
        os.makedirs(backup, exist_ok=True)
        moved = []
        for name in ("node_library.json", "user_verified_pool.json",
                     "probe_checkpoint.json", "verification_report.json",
                     "round_guard.json", "prev_verification_report.json"):
            src = os.path.join(workdir, name)
            if os.path.exists(src):
                try:
                    os.replace(src, os.path.join(backup, name))
                    moved.append(name)
                except OSError:
                    pass
        log(f"库存重置：已备份并移走 {len(moved)} 个文件（{', '.join(moved) or '无'}）"
            f"→ {backup}；候选文档保留，下轮从订阅源重建")

    if not args.force:
        ok, why = round_guard.decide(workdir, stale_h=args.stale_h)
        if not ok:
            log(f"不跑：{why}")
            return 0
        log(f"决策：补跑（{why}）")

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
    log("启动：" + " ".join(cmd))
    # 子进程输出必须落盘（任务#133）：计划任务里没有控制台，stdout 直接丢弃。
    # 实证 2026-11-07 13:14 的定时轮次返回 3（mihomo 未就绪）却没有任何日志可查，
    # 只能看到一个退出码——排障成本极高，而这类失败会让订阅静默停更。
    round_log = os.path.join(workdir, "cn_probe_last.log")
    # 直接写文件而不是先 pipe 再落盘：pipe 版本要等子进程结束才写，
    # 运行期间完全看不到进度（实测当天就踩到，一轮 10 分钟内无从观察）。
    try:
        with open(round_log, "w", encoding="utf-8") as lf:
            rc = subprocess.run(cmd, env=env, stdout=lf,
                                stderr=subprocess.STDOUT).returncode
        if rc != 0:
            try:
                with open(round_log, encoding="utf-8") as lf:
                    tail = "\n".join(list(lf)[-12:])
            except OSError:
                tail = "(日志读取失败)"
            log(f"子进程失败（退出码 {rc}），日志尾部：\n{tail}")
        else:
            log(f"子进程日志：{round_log}")
    except KeyboardInterrupt:
        rc = 130
    state = round_guard.note_result(workdir, rc)
    log(f"结束：cn_probe 退出码 {rc}；"
        f"资产已刷新={state.get('last_result_refreshed')}，"
        f"连续失败={state.get('fail_streak')}，"
        f"下次最早 {round_guard.backoff_min(int(state.get('fail_streak') or 0))} 分钟后")
    return 0


if __name__ == "__main__":
    sys.exit(main())
