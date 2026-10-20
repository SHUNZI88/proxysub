"""scripts/verification_fresh.py 测试：CI 主资产所有权切换的判定逻辑。"""

import datetime
import json


from scripts import verification_fresh as vf

NOW = datetime.datetime(2026, 10, 14, 6, 0, 0, tzinfo=datetime.timezone.utc)


def _report(hours_ago: float, passed: int) -> dict:
    gen = NOW - datetime.timedelta(hours=hours_ago)
    return {"generated_at": gen.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "counts": {"passed": passed}}


def test_fresh_report_passes():
    assert vf.is_fresh(_report(1, 50), now=NOW) is True


def test_stale_report_rejected():
    # 阈值 VERIFICATION_MAX_AGE_S=24h（2026-10-17 由 12h 上调：容忍沙箱漏跑
    # 一轮，防 cron 停摆/劣质运行误触 CI 兜底覆盖实测集）。25h > 24h → 不新鲜。
    assert vf.is_fresh(_report(25, 50), now=NOW) is False


def test_low_passed_rejected():
    assert vf.is_fresh(_report(1, 5), now=NOW) is False


def test_missing_generated_at():
    assert vf.is_fresh({"counts": {"passed": 99}}, now=NOW) is False


def test_bad_timestamp():
    assert vf.is_fresh({"generated_at": "not-a-time", "counts": {"passed": 99}},
                       now=NOW) is False


def test_future_timestamp_rejected():
    # 时钟漂移产生的未来时间戳：age<0 视为不新鲜（宁保守勿误判）
    assert vf.is_fresh(_report(-1, 50), now=NOW) is False


def test_naive_timestamp_treated_as_utc():
    gen = (NOW - datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")
    assert vf.is_fresh({"generated_at": gen, "counts": {"passed": 20}},
                       now=NOW) is True


def test_cli_exit_codes(tmp_path):
    # CLI 路径用真实时钟判定，数据必须相对真实 now 构造
    real_now = datetime.datetime.now(datetime.timezone.utc)
    fresh = real_now - datetime.timedelta(hours=1)
    good = tmp_path / "good.json"
    good.write_text(json.dumps({
        "generated_at": fresh.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": {"passed": 30}}), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    missing = tmp_path / "missing.json"

    def cli(path):
        import subprocess
        import sys
        import os
        script = os.path.join(os.path.dirname(vf.__file__), "verification_fresh.py")
        r = subprocess.run([sys.executable, script, str(path)],
                           capture_output=True, cwd=os.path.dirname(script))
        return r.returncode

    assert cli(good) == 0
    assert cli(bad) == 1
    assert cli(missing) == 1


# ------------------------------------------------- 第二层：最近有效发布信号
def _report_with_main(hours_ago, passed, main_hours_ago, main_passed, **extra):
    r = _report(hours_ago, passed)
    if main_hours_ago is not None:
        mp = NOW - datetime.timedelta(hours=main_hours_ago)
        r["main_asset_published_at"] = mp.strftime("%Y-%m-%dT%H:%M:%SZ")
        r["main_asset_passed"] = main_passed
    r.update(extra)
    return r


def test_main_asset_signal_saves_when_current_low():
    """2026-10-17 回归：本轮 passed<15，但最近有效发布仍新鲜 → 不兜底。

    修复前：cron 一轮 passed=12 上传 published=False，CI 误判并兜底 150
    候选集覆盖实测集。修复后：main_asset_passed=17 且在 24h 窗口内，信任沙箱。
    """
    r = _report_with_main(2, 12, 3, 17, published=True)
    assert vf.is_fresh(r, now=NOW) is True


def test_main_asset_stale_does_not_save():
    """最近有效发布已超 24h 窗口 → 即使 main_asset_passed≥15 也视为不新鲜。"""
    r = _report_with_main(25, 12, 25, 17, published=True)
    assert vf.is_fresh(r, now=NOW) is False


def test_low_passed_and_no_main_asset_rejected():
    """本轮 passed<15 且无 main_asset 字段 → 不新鲜（不应兜底，订阅可暂空）。"""
    assert vf.is_fresh(_report(1, 5), now=NOW) is False


def test_main_asset_published_false_not_saved():
    """最近有效发布信号但 published=False → 不信任（防止伪造信号）。"""
    r = _report_with_main(2, 12, 3, 17, published=False)
    assert vf.is_fresh(r, now=NOW) is False
