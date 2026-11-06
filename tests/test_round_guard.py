"""补跑决策模块（任务#120）回归测试。

对应事故：主资产 13 小时未刷新。两个根因各锁一组断言：
  1. 冷却语义 —— 失败尝试不得成为 2 小时禁赛的依据（退避要短、成功后清零）；
  2. 存活探测 —— 不得再用 `pgrep -f` 判进程（自匹配 + 冻结误判）。
另加一条「防回退」断言：直接扫源码，禁止 pgrep/.last_round_start 复辟。
"""

import datetime
import json
import os
import pathlib
import re

import pytest

from scripts import round_guard as rg


def _write_report(workdir, published_at):
    payload = {"round_id": "R", "generated_at": "2026-11-05T00:00:00Z",
               "main_asset_published_at": published_at}
    pathlib.Path(workdir).mkdir(parents=True, exist_ok=True)
    (pathlib.Path(workdir) / rg.REPORT_FILE).write_text(
        json.dumps(payload), encoding="utf-8")


def _ts(text):
    dt = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc)
    return dt.timestamp()


# ------------------------------------------------------------------ 时间解析
def test_parse_ts_ok_and_bad():
    assert rg.parse_ts("2026-11-05T00:24:00Z").year == 2026
    assert rg.parse_ts("") is None
    assert rg.parse_ts("not-a-time") is None
    assert rg.parse_ts(None) is None


# ------------------------------------------------------------------ 资产龄期
def test_asset_age_missing_report_is_stale(tmp_path):
    """读不到报告时按超龄处理：宁可多跑一轮，也不要静默认为「还新鲜」。"""
    assert rg.asset_age_h(str(tmp_path)) == 999.0


def test_asset_age_uses_published_at_not_generated_at(tmp_path):
    _write_report(tmp_path, "2026-11-05T00:24:00Z")
    now = _ts("2026-11-05T13:24:00Z")
    assert rg.asset_age_h(str(tmp_path), now) == pytest.approx(13.0, abs=0.01)


def test_asset_age_ignores_generated_at_only_report(tmp_path):
    """只有 generated_at（熔断轮也会写）不算产出信号——这正是「以为在跑」的来源。"""
    (pathlib.Path(tmp_path) / rg.REPORT_FILE).write_text(
        json.dumps({"generated_at": "2026-11-05T13:00:00Z"}), encoding="utf-8")
    assert rg.asset_age_h(str(tmp_path)) == 999.0


# ------------------------------------------------------------------ 退避曲线
def test_backoff_progression_and_cap():
    # 0=从未失败（纯防抖）、1=首次失败后 10 分钟即可重试，之后逐次翻倍
    assert [rg.backoff_min(s, base_min=10, max_min=120) for s in range(6)] == \
        [10, 10, 20, 40, 80, 120]


def test_backoff_never_zero():
    assert rg.backoff_min(-3, base_min=10, max_min=120) >= 10


# ------------------------------------------------------------------ 决策
def test_decide_fresh_asset_skips(tmp_path, monkeypatch):
    monkeypatch.setattr(rg, "probe_lock_state", lambda _w: {"state": "idle"})
    _write_report(tmp_path, "2026-11-05T13:00:00Z")
    ok, why = rg.decide(str(tmp_path), stale_h=3, now=_ts("2026-11-05T13:30:00Z"))
    assert ok is False and "新鲜" in why


def test_decide_stale_asset_runs(tmp_path, monkeypatch):
    monkeypatch.setattr(rg, "probe_lock_state", lambda _w: {"state": "idle"})
    _write_report(tmp_path, "2026-11-05T00:24:00Z")
    ok, why = rg.decide(str(tmp_path), stale_h=3, now=_ts("2026-11-05T13:24:00Z"))
    assert ok is True and "13.0h" in why


def test_decide_blocked_by_running_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(rg, "probe_lock_state",
                        lambda _w: {"state": "running", "holder": "pid=1 round=R"})
    _write_report(tmp_path, "2026-11-05T00:24:00Z")
    ok, why = rg.decide(str(tmp_path), stale_h=3, now=_ts("2026-11-05T13:24:00Z"))
    assert ok is False and "持锁" in why


def test_decide_unknown_lock_is_conservative(tmp_path, monkeypatch):
    monkeypatch.setattr(rg, "probe_lock_state",
                        lambda _w: {"state": "unknown", "why": "非 POSIX"})
    _write_report(tmp_path, "2026-11-05T00:24:00Z")
    ok, _ = rg.decide(str(tmp_path), stale_h=3, now=_ts("2026-11-05T13:24:00Z"))
    assert ok is False


def test_decide_retries_soon_after_failed_attempt(tmp_path, monkeypatch):
    """核心修复：一轮被杀后只退避 10 分钟，而不是 v3 的 2 小时。"""
    monkeypatch.setattr(rg, "probe_lock_state", lambda _w: {"state": "idle"})
    _write_report(tmp_path, "2026-11-05T00:24:00Z")
    t0 = _ts("2026-11-05T13:24:00Z")
    rg.note_attempt(str(tmp_path), now=t0)
    rg.note_result(str(tmp_path), rc=0, now=t0 + 60)   # 未刷新资产 → 失败

    # 5 分钟后：仍在退避中（10 分钟窗口）
    ok, why = rg.decide(str(tmp_path), stale_h=3, now=t0 + 300)
    assert ok is False and "退避" in why
    # 11 分钟后：允许重试
    ok, _ = rg.decide(str(tmp_path), stale_h=3, now=t0 + 660)
    assert ok is True


def test_decide_backoff_grows_with_streak(tmp_path, monkeypatch):
    monkeypatch.setattr(rg, "probe_lock_state", lambda _w: {"state": "idle"})
    _write_report(tmp_path, "2026-11-05T00:24:00Z")
    t0 = _ts("2026-11-05T13:24:00Z")
    for i in range(3):                     # 连续 3 次失败 → 退避 40 分钟
        rg.note_attempt(str(tmp_path), now=t0 + i * 7200)
        rg.note_result(str(tmp_path), rc=0, now=t0 + i * 7200 + 60)
    state = rg.load_state(str(tmp_path))
    assert state["fail_streak"] == 3
    assert rg.backoff_min(3) == 40
    last = t0 + 2 * 7200                  # 最后一次尝试发生在 i=2
    ok, _ = rg.decide(str(tmp_path), stale_h=3, now=last + 1800)
    assert ok is False                     # 30 分钟 < 40 分钟
    ok, _ = rg.decide(str(tmp_path), stale_h=3, now=last + 3600)
    assert ok is True


# ------------------------------------------------------------------ 成败判据
def test_note_result_success_is_asset_refresh_not_exit_code(tmp_path):
    _write_report(tmp_path, "2026-11-05T00:24:00Z")
    rg.note_attempt(str(tmp_path), now=1.0)
    # 非零退出码但资产确实刷新了 → 判成功，清空失败计数
    _write_report(tmp_path, "2026-11-05T01:24:00Z")
    state = rg.note_result(str(tmp_path), rc=3, now=2.0)
    assert state["last_result_refreshed"] is True
    assert state["fail_streak"] == 0


def test_note_result_zero_exit_without_refresh_is_failure(tmp_path):
    """cn_probe 在多条路径上以 0 退出（如「另一实例持锁」）——不得算成功。"""
    _write_report(tmp_path, "2026-11-05T00:24:00Z")
    rg.note_attempt(str(tmp_path), now=1.0)
    state = rg.note_result(str(tmp_path), rc=0, now=2.0)
    assert state["last_result_refreshed"] is False
    assert state["fail_streak"] == 1


def test_success_resets_streak(tmp_path):
    _write_report(tmp_path, "2026-11-05T00:00:00Z")
    rg.note_attempt(str(tmp_path), now=1.0)
    rg.note_result(str(tmp_path), rc=1, now=2.0)
    assert rg.load_state(str(tmp_path))["fail_streak"] == 1
    rg.note_attempt(str(tmp_path), now=3.0)
    _write_report(tmp_path, "2026-11-05T01:00:00Z")
    rg.note_result(str(tmp_path), rc=0, now=4.0)
    assert rg.load_state(str(tmp_path))["fail_streak"] == 0


# ------------------------------------------------------------------ 锁探测
def test_lock_state_idle_without_file(tmp_path):
    state = rg.probe_lock_state(str(tmp_path))
    # 非 POSIX 平台无 flock → unknown（保守不跑）；POSIX 下无文件 → idle
    assert state["state"] in ("idle", "unknown")


@pytest.mark.skipif(os.name != "posix", reason="flock 仅 POSIX")
def test_lock_state_detects_held_lock(tmp_path):
    import fcntl
    path = pathlib.Path(tmp_path) / rg.LOCK_FILE
    path.write_text("pid=999 round=R1\n", encoding="utf-8")
    holder = path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = rg.probe_lock_state(str(tmp_path))
        assert state["state"] == "running"
        assert "pid=999" in state["holder"]      # 能报出谁在持锁
    finally:
        holder.close()
    # 释放后应恢复 idle
    assert rg.probe_lock_state(str(tmp_path))["state"] == "idle"


# ------------------------------------------------------------------ 防回退
def _executable_text(path: pathlib.Path) -> str:
    """剥掉注释与 docstring，只留可执行代码——注释里提到旧写法是允许的
    （那正是解释为什么废弃的记录），我们防的是「代码里又抄回去」。"""
    text = path.read_text(encoding="utf-8")
    text = re.sub(r'"""(?:.|\n)*?"""', "", text)
    text = re.sub(r"'''(?:.|\n)*?'''", "", text)
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def test_guardians_do_not_reintroduce_pgrep_or_start_mark():
    """防回退断言：守护入口的可执行代码里不得再出现 pgrep 判存活 /
    .last_round_start 判冷却。

    2026-11-05 的两次误判（自匹配、冻结当在跑）都出自这两处，且分散在
    多个文件里各写一遍。这里是唯一能阻止「下次又抄回去」的断言。
    """
    root = pathlib.Path(__file__).resolve().parent.parent
    targets = [root / "scripts" / "cron_supervisor.sh",
               root / "scripts" / "wake_trigger.py",
               root / "scripts" / "round_guard.py"]
    offenders = []
    for p in targets:
        code = _executable_text(p)
        for pat in ("pgrep -f", ".last_round_start"):
            if pat in code:
                offenders.append(f"{p.name}: {pat}")
    assert not offenders, "守护仍在用被证伪的判据: " + "; ".join(offenders)


def test_status_cli_reports_decision(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(rg, "probe_lock_state", lambda _w: {"state": "idle"})
    _write_report(tmp_path, "2026-11-05T00:24:00Z")
    rc = rg.main(["status", "--workdir", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "资产龄期" in out and "决策" in out


def test_decide_cli_exit_codes(tmp_path, monkeypatch, capsys):
    """退出码契约：0=该跑，1=不跑。

    时间戳必须相对「现在」构造——写死日期会在跨过那一刻后必然失败
    （2026-11-06 实测：写死 11-05T13:00Z 的用例在次日全红，报「龄期 12.9h」）。
    """
    import datetime as _dt
    monkeypatch.setattr(rg, "probe_lock_state", lambda _w: {"state": "idle"})

    def _ago(hours: float) -> str:
        t = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=hours)
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    _write_report(tmp_path, _ago(1))     # 1 小时前 → 新鲜，不跑
    assert rg.main(["decide", "--workdir", str(tmp_path), "--stale-h", "3"]) == 1
    _write_report(tmp_path, _ago(20))    # 20 小时前 → 超龄，该跑
    assert rg.main(["decide", "--workdir", str(tmp_path), "--stale-h", "3"]) == 0
    capsys.readouterr()
