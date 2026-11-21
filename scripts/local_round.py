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

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cn_probe  # noqa: E402  - 健康抽查复用其探测/端口/mihomo 逻辑
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
    ap.add_argument("--health-check", dest="health_check", action="store_true",
                    default=True, help="资产未超龄时抽查已发布节点，腐烂则提前重发")
    ap.add_argument("--no-health-check", dest="health_check", action="store_false")
    ap.add_argument("--health-min-age-h", type=float, default=2.0,
                    help="资产龄期达到该值才做健康抽查（默认 2h，避免频繁起 mihomo）")
    ap.add_argument("--reset-pool", action="store_true",
                    help="清空库存（节点库/用户池/检查点）后再跑，从订阅源候选重建；"
                         "原文件移到 <workdir>/reset_backup_<时间>/")
    ap.add_argument("--log", default=None,
                    help="追加日志文件（默认 <workdir>/local_round.log）；"
                         "任务计划程序不保存 stdout，本机排障全靠它")
    return ap


def quick_health(workdir: str, sample: int = 6, ttfb_max: int | None = None,
                timeout: float = 3.0) -> dict:
    """抽查已发布集合的前 N 个节点，判断列表是否已经「腐烂」（任务#137）。

    为什么需要它：静态发布 + 12 小时周期，实测 20 个节点 8 小时后只剩 35%
    可用（意大利 ss 存活最好，美国/荷兰/瑞典 vless 全灭）。光靠「资产龄期」
    判断该不该跑，会让用户在最后几个小时里对着一份几乎全死的名单。

    判据：TTFB ≤ 阈值且状态 2xx/3xx 算可用；可用数低于 max(2, 2/3 样本) 判腐坏。
    只抽前 N 个（列表按实测速率排序，前面的就是用户最可能点的）。

    **端点必须与发布判据一致（2026-11-21 修）**：原先硬编码 gstatic，
    与主判据（推特）不一致——"gstatic 通、推特不通"的节点会被误判健康，
    腐烂名单一路用到 stale-h(10h)。改用 cn_probe.GENERATE_204（推特主判据）。
    腐坏线同时从「≤ sample//3」提到「< 2/3 样本」：用户实测 32 个里 20+ 超时
    是明确不可接受，6 个里要 ≥4 个可用才算健康，宁可提前重发。
    """
    lim = int(ttfb_max or getattr(cn_probe.config, "TARGET_TTFB_MAX_MS", 2000))
    probe_url = cn_probe.GENERATE_204
    path = os.path.join(workdir, "verified_clash.yaml")
    if not os.path.exists(path):
        return {"checked": 0, "usable": 0, "degraded": False, "why": "无本地发布集"}
    try:
        cfg = yaml.safe_load(open(path, encoding="utf-8")) or {}
    except Exception as e:
        return {"checked": 0, "usable": 0, "degraded": False, "why": f"读取失败 {e}"}
    proxies = (cfg.get("proxies") or [])[:max(1, sample)]
    if not proxies:
        return {"checked": 0, "usable": 0, "degraded": False, "why": "发布集为空"}

    test_cfg = {
        "mixed-port": cn_probe.alloc_port(26890, set()),
        "allow-lan": False, "mode": "rule", "log-level": "silent",
        "external-controller": f"127.0.0.1:{cn_probe.alloc_port(26990, set())}",
        "proxies": proxies,
        "proxy-groups": [{"name": "PROBE", "type": "select",
                          "proxies": [p["name"] for p in proxies]}],
        "rules": ["MATCH,PROBE"],     # 去掉 GEOIP：本机无 geoip 库，且与节点无关
    }
    tmp = os.path.join(workdir, "_health_cfg.yaml")
    with open(tmp, "w", encoding="utf-8") as f:
        yaml.dump(test_cfg, f, allow_unicode=True, sort_keys=False)
    exe = cn_probe.ensure_mihomo(workdir)
    if not exe:
        return {"checked": 0, "usable": 0, "degraded": False, "why": "mihomo 不可用"}
    api = test_cfg["external-controller"].split(":")[-1]
    mixed = test_cfg["mixed-port"]
    proc = subprocess.Popen([exe, "-d", workdir, "-f", tmp],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    usable, ttfbs = 0, []
    try:
        if not cn_probe.wait_controller(int(api), timeout=30):
            return {"checked": 0, "usable": 0, "degraded": False, "why": "mihomo 未就绪"}
        proxy = f"http://127.0.0.1:{mixed}"
        for pr in proxies:
            if not cn_probe.api_put(int(api), "/proxies/PROBE", {"name": pr["name"]}):
                continue
            code, ms = cn_probe._http_probe_via_proxy(
                probe_url, proxy, timeout)
            if code and 200 <= int(code) < 400 and ms is not None and ms <= lim:
                usable += 1
                ttfbs.append(ms)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except Exception:
            proc.kill()
    checked = len(proxies)
    # 健康线：6 个里至少 4 个可用（2/3），低于它就算腐烂 → 提前重发。
    # 旧线 usable <= max(1, checked//3) 太松：6 个里 3 个可用仍算健康，
    # 用户体感就是「一半超时」，与本次反馈一致。
    need_ok = max(2, (checked * 2 + 2) // 3)
    return {"checked": checked, "usable": usable,
            "median": sorted(ttfbs)[len(ttfbs) // 2] if ttfbs else None,
            "degraded": usable < need_ok,
            "why": f"抽查 {checked} 个，可用 {usable}（健康线 ≥{need_ok}，"
                   f"判据 {probe_url}）"}


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

    workdir = args.workdir or cn_probe.default_workdir()
    os.makedirs(workdir, exist_ok=True)
    _moved = cn_probe.migrate_legacy_workdir(workdir)
    if _moved:
        print(f"[local-round] 工作目录迁移：从旧 %TEMP% 复制 {len(_moved)} 个文件 → {workdir}")
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

    # 池子保活（2026-11-21）：必须放在 round_guard 决策之前。
    # 否则「资产未超龄」跳过本轮时 cn_probe 根本不启动，CI 池无人刷新，
    # 一路放旧到 POOL_MAX_AGE_H(4h) 后会被判定「过旧不使用」，产出悄悄下滑。
    try:
        cn_probe.pool_keepalive(workdir)
    except Exception as e:  # noqa: BLE001 - 保活失败绝不影响本轮决策
        log(f"池子保活失败（{type(e).__name__}），不影响本轮决策")

    if not args.force:
        ok, why = round_guard.decide(workdir, stale_h=args.stale_h)
        if not ok:
            # 健康度兜底（任务#137）：资产还算"新鲜"，但列表可能已经腐烂。
            # 12 小时固定周期的代价是「后半段全死」，只有抽查才能发现。
            # 只在「资产新鲜」这一种"不跑"原因下做健康抽查。
            # 退避中（连续失败）不能走这里——否则健康抽查会把退避绕过，
            # 失败轮次被每小时重试一次，白烧拨测预算。
            if args.health_check and "新鲜" in why:
                age = round_guard.asset_age_h(workdir)
                if age is not None and age >= args.health_min_age_h:
                    h = quick_health(workdir)
                    log(f"健康抽查：{h['why']}")
                    if h["degraded"]:
                        log("决策：提前重发（已发布列表已大面积失效）")
                        ok = True
                    else:
                        log(f"不跑：{why}；健康度尚可（{h['why']}）")
                        return 0
                else:
                    log(f"不跑：{why}（资产龄期 {age if age is not None else '?'}h，"
                        f"未到健康抽查线 {args.health_min_age_h}h）")
                    return 0
            else:
                log(f"不跑：{why}")
                return 0
        if ok:
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
    #
    # 编码必须强制 UTF-8（任务#134）：Windows 子进程默认按 cp936 写 stdout，
    # 而本文件按 UTF-8 读——中文日志会解码失败、抛异常，直接**吃掉后面的
    # 「结束」记录与 note_result**。实测 2026-11-07 19:14 起连续 6 轮定时任务
    # 只有「启动」没有「结束」，守护状态停在旧值，排障时完全看不出轮次结果。
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        with open(round_log, "w", encoding="utf-8", errors="replace") as lf:
            rc = subprocess.run(cmd, env=env, stdout=lf,
                                stderr=subprocess.STDOUT).returncode
        if rc != 0:
            tail = "(日志读取失败)"
            try:
                with open(round_log, encoding="utf-8", errors="replace") as lf:
                    tail = "\n".join(list(lf)[-12:])
            except OSError as e:
                tail = f"(日志读取失败: {e})"
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
