#!/usr/bin/env python3
"""判定最新实测验证报告是否新鲜——CI 发布步骤据此切换主资产所有权。

用法: python3 scripts/verification_fresh.py <report.json>
退出码 0 = 新鲜（主资产 p_* 归沙箱实测集所有，CI 不覆盖）；
       1 = 陈旧/缺失/不可解析（CI 兜底：候选集发布到主资产，订阅不枯竭）。

新鲜 = generated_at 在 VERIFICATION_MAX_AGE_S 内 且 通过数 ≥ VERIFICATION_MIN_PASSED。
判定逻辑集中在此（而非散在 YAML 里）以便单测与两侧阈值一致。
"""

from __future__ import annotations

import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # noqa: E402


def is_fresh(report: dict, now: datetime.datetime | None = None) -> bool:
    """报告是否新鲜：时间窗内且通过数达标。任何解析失败都视为不新鲜。"""
    try:
        gen = datetime.datetime.fromisoformat(
            str(report["generated_at"]).replace("Z", "+00:00"))
    except Exception:
        return False
    if gen.tzinfo is None:
        gen = gen.replace(tzinfo=datetime.timezone.utc)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    age = (now - gen).total_seconds()
    passed = int((report.get("counts") or {}).get("passed", 0) or 0)
    return 0 <= age < config.VERIFICATION_MAX_AGE_S and passed >= config.VERIFICATION_MIN_PASSED


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            _report = json.load(f)
    except Exception:
        sys.exit(1)
    sys.exit(0 if is_fresh(_report) else 1)
