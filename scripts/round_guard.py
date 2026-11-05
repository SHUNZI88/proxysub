#!/usr/bin/env python3
"""补跑决策与存活探测的唯一事实源（任务#120，2026-11-05）。

## 为什么需要这个模块

2026-11-05 实测断点：线上主资产停在 00:24，13 小时未刷新。执行侧有两条
互相独立的失效路径，且**都源于同一个设计错误——把「开跑」当成「完成」**：

1. 冷却语义错位。`cron_supervisor.sh` 与 `wake_trigger.py` 都在**启动运行
   之前** touch `.last_round_start`，又拿这个文件的 mtime 当「距上次成功
   发布」的冷却依据。于是一轮被杀 → 标记刷新 → 空等 COOLDOWN_H(2h) →
   再被断，形成死循环。资产龄期（真正该看的信号）反而被忽略。
2. 存活探测不可靠。两者都用 `pgrep -f "scripts/cn_probe.py"`：
   * **自匹配**：调用方命令行自身含该字符串时命中自己（2026-11-05 实证：
     一次手工核查把 shell 自己判成"已在跑"，于是根本没有起新的轮次）；
   * **冻结误判**：沙箱休眠是 SIGSTOP/冻结而非 kill，冻结进程仍在进程表里，
     `pgrep` 照样返回 0，于是守护永远认为"已有实例在跑"，永不补跑。

## 本模块的语义（三个判据，按顺序）

* **在跑？** —— 探测 cn_probe 的 flock 单实例锁，而不是猜进程名。
  能拿到锁 = 没有实例；拿不到 = 有进程持锁（并把持锁者的 PID/轮次读出来）。
* **新鲜？** —— 看 `main_asset_published_at`（上一次**成功发布**），
  这才是「距上次有效产出」的唯一正确口径。
* **该退避？** —— 连续失败按 10/20/40/80/120 分钟指数退避，**成功即清零**。
  失败不该被罚 2 小时禁赛，也不该每 5 分钟重打一次。

## 命令行（供 shell 守护与 HTTP 端点共用，避免同一策略写两遍）

    python3 scripts/round_guard.py decide        # 退出码 0=该跑 1=不跑；原因打 stdout
    python3 scripts/round_guard.py note-attempt  # 记录本次尝试起点（含当时资产时间）
    python3 scripts/round_guard.py note-result --rc 0   # 记录结果，按「资产是否刷新」判成败
    python3 scripts/round_guard.py status        # 人读状态（排障用）

设计约束：不 import cn_probe（那会拖进 mihomo/网络依赖），只读写状态文件；
任何异常都退化为「不跑」并打印原因——守护的职责是保守，不是激进。
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time

STALE_H_DEFAULT = 3
DEBOUNCE_MIN_DEFAULT = 10
BACKOFF_MAX_MIN_DEFAULT = 120
STATE_FILE = "round_guard.json"
REPORT_FILE = "verification_report.json"
LOCK_FILE = "cn_probe.lock"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def parse_ts(text: str) -> datetime.datetime | None:
    """解析报告时间戳（UTC，Z 结尾）。无法解析返回 None。"""
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except (TypeError, ValueError):
            continue
    return None


def asset_published_at(workdir: str) -> str | None:
    """上一次成功发布主资产的时间（UTC 字符串）。缺失/损坏返回 None。

    只认 `main_asset_published_at`：`generated_at` 是「本轮生成了报告」，
    熔断轮也会更新它，拿它当产出信号正是「以为在跑其实没产出」的来源。
    """
    try:
        with open(os.path.join(workdir, REPORT_FILE), encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(report, dict):
        return None
    value = report.get("main_asset_published_at")
    return value if isinstance(value, str) and value else None


def asset_age_h(workdir: str, now: float | None = None) -> float:
    """资产龄期（小时）。无法判定返回一个很大的数（=按超龄处理，逼其补跑）。

    取不到时返回 999 而不是 0：宁可多跑一轮，也不要因为读不到报告就静默
    认为「还很新鲜」——后者会让订阅无限期停留在旧资产上。
    """
    ts = parse_ts(asset_published_at(workdir) or "")
    if ts is None:
        return 999.0
    ref = (datetime.datetime.fromtimestamp(float(now), datetime.timezone.utc)
           if now is not None else datetime.datetime.now(datetime.timezone.utc))
    return max(0.0, (ref - ts).total_seconds() / 3600.0)


def probe_lock_state(workdir: str) -> dict:
    """探测 cn_probe 单实例锁。返回 {"state": idle|running|unknown, "holder": str}。

    判据是**锁**不是进程名：能非阻塞拿到锁 → 没有实例持锁 → idle；
    拿不到 → 有进程持锁（无论它是在正常跑还是被冻结），把锁文件里的
    `pid=... round=...` 读出来供排障。非 POSIX 或无法判定时返回 unknown，
    由调用方按「不跑」处理（保守）。
    """
    lock_path = os.path.join(workdir, LOCK_FILE)
    try:
        import fcntl  # noqa: PLC0415 - 仅 POSIX 有，按需导入
    except ImportError:
        return {"state": "unknown", "holder": "", "why": "非 POSIX 平台，无 flock"}
    if not os.path.exists(lock_path):
        return {"state": "idle", "holder": ""}
    try:
        fh = open(lock_path, "a+", encoding="utf-8")
    except OSError:
        return {"state": "unknown", "holder": "", "why": "锁文件不可读"}
    try:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            holder = ""
            try:
                fh.seek(0)
                holder = fh.read().strip()
            except (OSError, ValueError):
                pass
            return {"state": "running", "holder": holder}
        # 拿到了：说明没有实例持锁，立即释放，不改变文件内容
        fcntl.flock(fh, fcntl.LOCK_UN)
        return {"state": "idle", "holder": ""}
    finally:
        try:
            fh.close()
        except OSError:
            pass


def load_state(workdir: str) -> dict:
    try:
        with open(os.path.join(workdir, STATE_FILE), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(workdir: str, state: dict) -> None:
    path = os.path.join(workdir, STATE_FILE)
    tmp = path + ".tmp"
    try:
        os.makedirs(workdir, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except OSError:
        pass


def backoff_min(streak: int, base_min: int | None = None,
                max_min: int | None = None) -> int:
    """连续失败 streak 次后的等待分钟数：10, 10, 20, 40, 80, 120（封顶）。

    第一次失败后只等 base（默认 10 分钟），而不是 v3 的 2 小时——被休眠
    打断是环境问题不是节点问题，罚太久的禁赛只会让资产继续陈旧；只有
    「反复失败」才逐步升级，避免失败风暴下每 5 分钟重打一次。
    """
    base = _env_int("PROXYSUB_DEBOUNCE_MIN", DEBOUNCE_MIN_DEFAULT) \
        if base_min is None else base_min
    cap = _env_int("PROXYSUB_BACKOFF_MAX_MIN", BACKOFF_MAX_MIN_DEFAULT) \
        if max_min is None else max_min
    if streak <= 1:
        return base
    return int(min(cap, base * (2 ** min(streak - 1, 8))))


def decide(workdir: str, *, stale_h: int | None = None,
           now: float | None = None) -> tuple[bool, str]:
    """(是否该补跑, 原因)。纯读，不写状态——动作与决策分离，便于测试。"""
    stale = _env_int("PROXYSUB_STALE_H", STALE_H_DEFAULT) if stale_h is None else stale_h
    now_ts = _now(now)

    lock = probe_lock_state(workdir)
    if lock["state"] == "unknown":
        return False, f"无法判定实例状态（{lock.get('why')}），保守跳过"
    if lock["state"] == "running":
        holder = lock.get("holder") or "锁文件无持有者信息"
        return False, f"已有实例持锁在跑（{holder}）"

    age = asset_age_h(workdir, now_ts)
    if age < stale:
        return False, f"资产新鲜（{age:.1f}h < {stale}h），无需补跑"

    state = load_state(workdir)
    last = state.get("last_attempt_ts")
    streak = state.get("fail_streak") or 0
    if isinstance(last, (int, float)):
        wait = backoff_min(int(streak))
        elapsed_min = (now_ts - float(last)) / 60.0
        if elapsed_min < wait:
            return False, (f"退避中（连续失败 {streak} 次，需等 {wait} 分钟，"
                           f"已过 {elapsed_min:.0f} 分钟）")
    return True, f"资产龄期 {age:.1f}h ≥ {stale}h，可以补跑"


def note_attempt(workdir: str, now: float | None = None) -> dict:
    """记录一次尝试起点，并快照当时的「成功发布」时间戳（供 note-result 比对）。"""
    state = load_state(workdir)
    state["last_attempt_ts"] = _now(now)
    state["attempt_published_at"] = asset_published_at(workdir)
    state["attempts"] = int(state.get("attempts") or 0) + 1
    save_state(workdir, state)
    return state


def note_result(workdir: str, rc: int, now: float | None = None) -> dict:
    """记录一次尝试结果。

    成败判据不是退出码，而是**资产有没有真的刷新**：cn_probe 在多条路径上
    都会以 0 退出（例如"另一实例持锁，退出"），把 rc==0 当成功会让失败
    静默累积、退避永不生效。
    """
    state = load_state(workdir)
    before = state.get("attempt_published_at")
    after = asset_published_at(workdir)
    refreshed = bool(after) and after != before
    if refreshed:
        state["fail_streak"] = 0
        state["last_success_ts"] = _now(now)
    else:
        state["fail_streak"] = int(state.get("fail_streak") or 0) + 1
    state["last_rc"] = int(rc)
    state["last_result_refreshed"] = refreshed
    state["last_result_ts"] = _now(now)
    save_state(workdir, state)
    return state


def _now(now: float | None = None) -> float:
    return time.time() if now is None else float(now)


def _status_text(workdir: str) -> str:
    state = load_state(workdir)
    lock = probe_lock_state(workdir)
    age = asset_age_h(workdir)
    lines = [
        f"资产龄期: {age:.1f}h（main_asset_published_at="
        f"{asset_published_at(workdir) or '缺失'}）",
        f"实例状态: {lock['state']}"
        + (f"（{lock.get('holder')}）" if lock.get("holder") else ""),
        f"连续失败: {state.get('fail_streak') or 0} 次，"
        f"当前退避 {backoff_min(int(state.get('fail_streak') or 0))} 分钟",
        f"累计尝试: {state.get('attempts') or 0} 次，"
        f"上次退出码: {state.get('last_rc')}，"
        f"上次是否刷新资产: {state.get('last_result_refreshed')}",
    ]
    ok, why = decide(workdir)
    lines.append(f"决策: {'补跑' if ok else '不补跑'}——{why}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="补跑决策与存活探测（proxysub 任务#120）")
    ap.add_argument("command",
                    choices=["decide", "note-attempt", "note-result", "status"])
    ap.add_argument("--workdir", default="/tmp/cn_probe")
    ap.add_argument("--stale-h", type=int, default=None)
    ap.add_argument("--rc", type=int, default=0)
    args = ap.parse_args(argv)

    if args.command == "decide":
        ok, why = decide(args.workdir, stale_h=args.stale_h)
        print(why)
        return 0 if ok else 1
    if args.command == "note-attempt":
        note_attempt(args.workdir)
        print("已记录尝试起点")
        return 0
    if args.command == "note-result":
        state = note_result(args.workdir, args.rc)
        print(f"已记录结果：刷新={state.get('last_result_refreshed')} "
              f"连续失败={state.get('fail_streak')}")
        return 0
    print(_status_text(args.workdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
