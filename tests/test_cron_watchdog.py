"""scripts/cron_watchdog.py 专项测试：cron 保活判定、漏跑检测、补测冷却、
日志滚动、main() 两态（dry-run 只报告 / 正常巡检会动作）。

全部走 mock/tmp_path：不碰真实 cron、不真跑 cn_probe、不读 /tmp/cn_probe。
"""

from __future__ import annotations

import json
import time
import types

import pytest

from scripts import cron_watchdog as wd


# ---------------------------------------------------------------- cron_alive
def test_cron_alive_pgrep_ok(monkeypatch):
    monkeypatch.setattr(wd.shutil, "which", lambda n: "/usr/bin/pgrep")
    monkeypatch.setattr(
        wd.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=0)
    )
    assert wd.cron_alive() is True


def test_cron_alive_pgrep_no_match(monkeypatch):
    monkeypatch.setattr(wd.shutil, "which", lambda n: "/usr/bin/pgrep")
    monkeypatch.setattr(
        wd.subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=1)
    )
    assert wd.cron_alive() is False


def test_cron_alive_no_pgrep_is_conservative(monkeypatch):
    """pgrep 缺失时保守判活——避免误判死亡反复执行无用功。"""
    monkeypatch.setattr(wd.shutil, "which", lambda n: None)
    assert wd.cron_alive() is True


# ---------------------------------------------------------------- restart_cron
def test_restart_cron_first_success(monkeypatch):
    calls = []

    def _run(cmd, **k):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(wd.subprocess, "run", _run)
    assert wd.restart_cron() == "service cron start"
    assert calls == [["service", "cron", "start"]]


def test_restart_cron_all_fail(monkeypatch):
    monkeypatch.setattr(
        wd.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=1),
    )
    assert wd.restart_cron() == ""


# ---------------------------------------------------------------- last_activity_age_s
def test_last_activity_none_when_no_files(tmp_path):
    assert wd.last_activity_age_s(tmp_path, now=1_000.0) is None


def test_last_activity_uses_max_of_two_mtimes(tmp_path):
    old = 1_000.0 - 5 * 3600
    new = 1_000.0 - 3600
    (tmp_path / "cron.log").write_text("x", encoding="utf-8")
    (tmp_path / "verification_report.json").write_text("{}", encoding="utf-8")
    import os

    os.utime(tmp_path / "cron.log", (old, old))
    os.utime(tmp_path / "verification_report.json", (new, new))
    assert wd.last_activity_age_s(tmp_path, now=1_000.0) == pytest.approx(3600.0)


def test_last_activity_future_mtime_clamped(tmp_path):
    (tmp_path / "cron.log").write_text("x", encoding="utf-8")
    import os

    os.utime(tmp_path / "cron.log", (5_000.0, 5_000.0))
    # mtime 在未来（时钟跳变）时钳为 0，不得产出负年龄触发假漏跑
    assert wd.last_activity_age_s(tmp_path, now=1_000.0) == 0.0


def test_last_activity_only_cron_log(tmp_path):
    (tmp_path / "cron.log").write_text("x", encoding="utf-8")
    import os

    os.utime(tmp_path / "cron.log", (1_000.0 - 7200, 1_000.0 - 7200))
    assert wd.last_activity_age_s(tmp_path, now=1_000.0) == pytest.approx(7200.0)


# ---------------------------------------------------------------- should_catchup
def test_should_catchup_no_activity_record():
    ok, why = wd.should_catchup(None, {}, now=1_000.0)
    assert ok is False
    assert "全新环境" in why


def test_should_catchup_fresh_within_slot_rhythm():
    ok, _ = wd.should_catchup(5 * 3600, {}, now=1_000.0)
    assert ok is False


def test_should_catchup_stale_triggers():
    ok, why = wd.should_catchup(9 * 3600, {}, now=1_000.0)
    assert ok is True
    assert "9.0h" in why


def test_should_catchup_cooldown_blocks():
    state = {"last_catchup_ts": 1_000.0 - wd.CATCHUP_COOLDOWN_S + 60}
    ok, why = wd.should_catchup(9 * 3600, state, now=1_000.0)
    assert ok is False
    assert "冷却" in why


def test_should_catchup_cooldown_expired_allows():
    state = {"last_catchup_ts": 1_000.0 - wd.CATCHUP_COOLDOWN_S - 1}
    ok, _ = wd.should_catchup(9 * 3600, state, now=1_000.0)
    assert ok is True


# ---------------------------------------------------------------- state io
def test_state_roundtrip_and_corrupt(tmp_path):
    p = tmp_path / "watchdog_state.json"
    wd.save_state(p, {"last_catchup_ts": 123.0, "last_catchup_rc": 0})
    assert wd.load_state(p) == {"last_catchup_ts": 123.0, "last_catchup_rc": 0}
    p.write_text("{ 坏 JSON", encoding="utf-8")
    assert wd.load_state(p) == {}
    assert wd.load_state(tmp_path / "missing.json") == {}


# ---------------------------------------------------------------- rotate_log
def test_rotate_log_under_limit_unchanged(tmp_path):
    p = tmp_path / "watchdog.log"
    p.write_text("a\nb\n", encoding="utf-8")
    wd.rotate_log(p, max_lines=10)
    assert p.read_text(encoding="utf-8") == "a\nb\n"


def test_rotate_log_over_limit_keeps_tail(tmp_path):
    p = tmp_path / "watchdog.log"
    p.write_text("\n".join(str(i) for i in range(20)), encoding="utf-8")
    wd.rotate_log(p, max_lines=5)
    assert p.read_text(encoding="utf-8").splitlines() == ["15", "16", "17", "18", "19"]


def test_rotate_log_missing_file_noop(tmp_path):
    wd.rotate_log(tmp_path / "nope.log")  # 不得抛


# ---------------------------------------------------------------- main()
def _patch_quiet(monkeypatch, tmp_path):
    """把 main() 的副作用全部导向 tmp_path + mock，返回调用记录 dict。"""
    rec = {"restart": 0, "catchup": 0}
    monkeypatch.setattr(wd, "LOG_DIR", tmp_path)
    monkeypatch.setattr(wd, "STATE_FILE", tmp_path / "watchdog_state.json")
    monkeypatch.setattr(wd, "WATCHDOG_LOG", tmp_path / "watchdog.log")
    monkeypatch.setattr(wd, "cron_alive", lambda: True)
    monkeypatch.setattr(
        wd, "restart_cron", lambda: (rec.__setitem__("restart", rec["restart"] + 1) or "service cron start")
    )
    monkeypatch.setattr(
        wd, "run_catchup", lambda root: (rec.__setitem__("catchup", rec["catchup"] + 1) or 0)
    )
    return rec


def test_main_dry_run_stale_reports_without_acting(monkeypatch, tmp_path, capsys):
    rec = _patch_quiet(monkeypatch, tmp_path)
    monkeypatch.setattr(wd, "cron_alive", lambda: False)
    # 伪造陈旧活动：10h 前
    import os

    (tmp_path / "cron.log").write_text("x", encoding="utf-8")
    os.utime(tmp_path / "cron.log", (time.time() - 10 * 3600,) * 2)

    rc = wd.main(["--dry-run"])

    assert rc == 0
    assert rec["restart"] == 0  # dry-run 不拉起 cron
    assert rec["catchup"] == 0  # dry-run 不补测
    out = capsys.readouterr().out
    assert "dry-run" in out
    assert not (tmp_path / "watchdog_state.json").exists()  # 不写状态


def test_main_restarts_dead_cron(monkeypatch, tmp_path):
    rec = _patch_quiet(monkeypatch, tmp_path)
    monkeypatch.setattr(wd, "cron_alive", lambda: False)

    rc = wd.main([])

    assert rc == 0
    assert rec["restart"] == 1
    assert rec["catchup"] == 0  # 活动记录不存在（None）→ 不补测


def test_main_triggers_catchup_when_stale(monkeypatch, tmp_path):
    rec = _patch_quiet(monkeypatch, tmp_path)
    import os

    (tmp_path / "cron.log").write_text("x", encoding="utf-8")
    os.utime(tmp_path / "cron.log", (time.time() - 10 * 3600,) * 2)

    rc = wd.main([])

    assert rc == 0
    assert rec["catchup"] == 1
    state = json.loads((tmp_path / "watchdog_state.json").read_text(encoding="utf-8"))
    assert state["last_catchup_rc"] == 0
    assert isinstance(state["last_catchup_ts"], float)


def test_main_cooldown_blocks_second_catchup(monkeypatch, tmp_path):
    rec = _patch_quiet(monkeypatch, tmp_path)
    import os

    (tmp_path / "cron.log").write_text("x", encoding="utf-8")
    os.utime(tmp_path / "cron.log", (time.time() - 10 * 3600,) * 2)

    assert wd.main([]) == 0
    assert rec["catchup"] == 1
    # 第二次：状态已写，冷却期内 → 不再触发
    assert wd.main([]) == 0
    assert rec["catchup"] == 1


def test_main_fresh_does_nothing(monkeypatch, tmp_path):
    rec = _patch_quiet(monkeypatch, tmp_path)
    import os

    (tmp_path / "cron.log").write_text("x", encoding="utf-8")
    os.utime(tmp_path / "cron.log", (time.time() - 3600,) * 2)

    rc = wd.main([])

    assert rc == 0
    assert rec["catchup"] == 0
    assert rec["restart"] == 0


def test_main_swallows_internal_error_and_returns_zero(monkeypatch, tmp_path):
    """看门狗自身异常不得冒泡——退出码恒 0（不污染 cron 邮件）。"""
    monkeypatch.setattr(wd, "LOG_DIR", tmp_path)
    monkeypatch.setattr(wd, "STATE_FILE", tmp_path / "s.json")
    monkeypatch.setattr(wd, "WATCHDOG_LOG", tmp_path / "w.log")

    def _boom():
        raise RuntimeError("boom")

    monkeypatch.setattr(wd, "cron_alive", _boom)

    assert wd.main([]) == 0
