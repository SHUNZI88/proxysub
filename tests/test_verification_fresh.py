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
    assert vf.is_fresh(_report(13, 50), now=NOW) is False


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
