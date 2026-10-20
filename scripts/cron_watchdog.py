#!/usr/bin/env python3
"""cron 看门狗：cron 守护进程保活 + cn_probe 漏跑补测 + 状态留痕。

背景（2026-10-20 事故复盘）：cron 服务未运行导致 cn_probe 沙箱实测中断，
verification_report 陈旧超阈（24h），CI 兜底把候选集覆盖主资产——
「美国能通、国内不通」的质量闸门一度失效。本脚本把「cron 存活 + 实测
连续性」保障固化为制度，四层触发互为兜底（详见 docs/cn_probe.md §2）：

  L1 系统 cron 4 槽（01:18/07:18/13:18/19:18 CST）：cn_probe 正式轮；
  L2 本看门狗（crontab 每 2h 一拍）：① cron 守护进程死亡则自动拉起；
     ② 距最后活动超过阈值（槽间隔 6h + 宽限 2h）判定漏跑，立即补测；
  L3 WorkBuddy 云端自动化任务：沙箱休眠期间由云端调度补跑（不依赖本机 cron）；
  L4 CI 兜底：验证陈旧时候选集发布到主资产，订阅永不枯竭（降级，非目标态）。

设计约束：
  - 不碰仓库任何状态文件；唯一持久化副作用是 /tmp/cn_probe/ 下的日志与状态；
  - 任何异常都吞掉记日志，退出码恒 0——看门狗自身失败不得污染 cron 邮件；
  - 补测经 cn_probe 单实例锁（fcntl.flock）与定时轮天然互斥，不会重入；
  - 补测冷却 3h：连续失败时最密每 3h 重试一次（看门狗 2h 一拍，冷却保证
    失败风暴下也不会每拍都打）；
  - 全新环境（无任何活动记录）不补测——没有证据表明漏跑，首轮应交由定时
    槽或人工触发（scripts/cn_probe.py）。

用法：
    python3 scripts/cron_watchdog.py            # 正常巡检（cron 调用）
    python3 scripts/cron_watchdog.py --dry-run  # 只报告不动作（调试/测试）
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = Path("/tmp/cn_probe")
CRON_LOG = LOG_DIR / "cron.log"
REPORT = LOG_DIR / "verification_report.json"
STATE_FILE = LOG_DIR / "watchdog_state.json"
WATCHDOG_LOG = LOG_DIR / "watchdog.log"
CN_PROBE = REPO_ROOT / "scripts" / "cn_probe.py"
PAT_FILE = Path("/root/.github_pat")

# 漏跑判定阈值 = cron 槽间隔（6h）+ 宽限（2h）：槽间隔内属正常节律，
# 超过 8h 无活动才认为漏跑（沙箱休眠恢复后由本脚本补上）。
CATCHUP_THRESHOLD_S = 8 * 3600
# 补测冷却：两次补测触发之间至少间隔，防失败风暴下的高频重试。
CATCHUP_COOLDOWN_S = 3 * 3600
# 看门狗日志滚动保留行数（防 /tmp 无限增长）。
WATCHDOG_LOG_MAX_LINES = 500


def log(msg: str) -> None:
    """带时间戳打印（cron 重定向到 watchdog.log；手动运行直接看 stdout）。"""
    print(f"[watchdog {time.strftime('%m-%d %H:%M:%S')}] {msg}", flush=True)


def cron_alive() -> bool:
    """cron 守护进程是否存活。pgrep 不可用（极端裁剪环境）时保守返回 True，
    避免误判死亡而反复执行无用功——拉起动作本身有退出码兜底。"""
    if shutil.which("pgrep") is None:
        return True
    try:
        return subprocess.run(
            ["pgrep", "-x", "cron"], capture_output=True
        ).returncode == 0
    except OSError:
        return True


def restart_cron() -> str:
    """尝试拉起 cron 守护进程，返回所用命令（空串 = 全部失败）。"""
    for cmd in (["service", "cron", "start"], ["service", "cron", "restart"], ["cron"]):
        try:
            if subprocess.run(cmd, capture_output=True).returncode == 0:
                return " ".join(cmd)
        except OSError:
            continue
    return ""


def last_activity_age_s(log_dir: Path, now: float | None = None) -> float | None:
    """距最后活动的秒数。活动 = max(cron.log mtime, verification_report.json mtime)。

    取两者较大值：cron.log 覆盖「跑过但没发布」（自检通过即写日志），
    verification_report.json 覆盖「发布成功」。任一较新都说明链路活着。
    返回 None = 从未活动（全新沙箱/日志被清），调用方应保守不补测。
    """
    now = time.time() if now is None else now
    mtimes: list[float] = []
    for p in (log_dir / CRON_LOG.name, log_dir / REPORT.name):
        try:
            mtimes.append(p.stat().st_mtime)
        except OSError:
            pass
    if not mtimes:
        return None
    return max(0.0, now - max(mtimes))


def load_state(path: Path) -> dict:
    """读看门狗状态（上次补测时间等）。损坏/缺失返回空 dict（保守：当作没补过）。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(path: Path, state: dict) -> None:
    """写看门狗状态。失败仅吞掉（状态丢失的最坏后果是补测冷却失效）。"""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def should_catchup(
    age_s: float | None, state: dict, now: float | None = None
) -> tuple[bool, str]:
    """(是否补测, 人类可读原因)。

    - age_s=None（无活动记录）：不补测——没有漏跑证据；
    - age_s < 阈值：不补测——正常节律内；
    - 冷却期内（上次补测距今 < CATCHUP_COOLDOWN_S）：不补测——防失败风暴。
    """
    now = time.time() if now is None else now
    if age_s is None:
        return False, "无活动记录（全新环境），不补测"
    hours = age_s / 3600.0
    if age_s < CATCHUP_THRESHOLD_S:
        return False, f"活动 {hours:.1f}h 前，未超漏跑阈值 {CATCHUP_THRESHOLD_S // 3600}h"
    last = state.get("last_catchup_ts")
    if isinstance(last, (int, float)) and now - last < CATCHUP_COOLDOWN_S:
        return False, f"补测冷却中（上次补测 {(now - last) / 60:.0f} 分钟前）"
    return True, f"活动 {hours:.1f}h 前，超过漏跑阈值 {CATCHUP_THRESHOLD_S // 3600}h"


def run_catchup(repo_root: Path) -> int:
    """同步执行一轮 cn_probe（单实例锁防重入；GH_TOKEN 从持久化 PAT 注入）。

    返回 cn_probe 退出码。同步执行而非后台化：看门狗 cron 槽无超时约束，
    且同步才能在日志里留下本轮结果（后台化会把结果丢进无人读的管道）。
    """
    env = dict(os.environ)
    try:
        if PAT_FILE.exists():
            env["GITHUB_TOKEN"] = env["GH_TOKEN"] = PAT_FILE.read_text().strip()
    except OSError:
        pass
    return subprocess.run(
        [sys.executable, "-u", str(repo_root / CN_PROBE.name)], env=env
    ).returncode


def rotate_log(path: Path, max_lines: int = WATCHDOG_LOG_MAX_LINES) -> None:
    """滚动保留最近 max_lines 行。失败静默（日志丢了不致命）。"""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    if len(lines) > max_lines:
        try:
            path.write_text("\n".join(lines[-max_lines:]) + "\n", encoding="utf-8")
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="cron 看门狗：cron 保活 + cn_probe 漏跑补测 + 状态留痕"
    )
    ap.add_argument(
        "--dry-run", action="store_true", help="只报告不动作（调试/测试用）"
    )
    args = ap.parse_args(argv)

    now = time.time()
    try:
        _inspect(now, args.dry_run)
    except Exception as exc:  # noqa: BLE001 —— 看门狗自身故障必须死在自己身上
        log(f"巡检异常（已吞掉，退出码仍为 0）：{type(exc).__name__}: {exc}")
    rotate_log(WATCHDOG_LOG)
    return 0


def _inspect(now: float, dry_run: bool) -> None:
    """一轮巡检：保活 + 漏跑检测。异常上抛给 main() 统一兜底。"""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass  # /tmp 不可写时后续各步自有兜底，看门狗不因此崩溃

    # A. cron 守护进程保活
    if cron_alive():
        log("cron 守护进程运行中")
    elif dry_run:
        log("cron 守护进程未运行（dry-run，不拉起）")
    else:
        how = restart_cron()
        if how:
            log(f"cron 守护进程未运行，已拉起（{how}）")
        else:
            log("cron 守护进程未运行，拉起失败（需人工介入：service cron start）")

    # B. 漏跑检测与补测
    age_s = last_activity_age_s(LOG_DIR, now)
    state = load_state(STATE_FILE)
    need, why = should_catchup(age_s, state, now)
    if not need:
        log(f"无需补测：{why}")
    elif dry_run:
        log(f"待补测：{why}（dry-run，不执行）")
    else:
        log(f"触发漏跑补测：{why}")
        rc = run_catchup(REPO_ROOT)
        state["last_catchup_ts"] = now
        state["last_catchup_rc"] = rc
        save_state(STATE_FILE, state)
        log(f"补测结束（cn_probe 退出码 {rc}）")


if __name__ == "__main__":
    sys.exit(main())
