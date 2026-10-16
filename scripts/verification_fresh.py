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
    """报告是否新鲜：时间窗内且通过数达标。任何解析失败都视为不新鲜。

    判定分两层（2026-10-17 修复）：
      1) 本轮实测：generated_at 新鲜 且 counts.passed ≥ 下限；
      2) 最近有效发布（main_asset_* 字段）：即便本轮不达标，只要最近一次
         成功发布到主资产的验证集仍新鲜（main_asset_passed ≥ 下限），也不应
         让 CI 兜底覆盖——否则一轮劣质运行（节点池波动导致 passed<15）会撤销
         "实测集在场"信号，使 150 候选集覆盖实测集。
    """
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
    current_ok = 0 <= age < config.VERIFICATION_MAX_AGE_S and passed >= config.VERIFICATION_MIN_PASSED
    if current_ok:
        return True
    # 第二层：最近有效发布是否仍新鲜（须 published 背书，防伪造/历史报告）
    mp_at = report.get("main_asset_published_at")
    mp_passed = int(report.get("main_asset_passed", 0) or 0)
    if mp_at and report.get("published"):
        try:
            mp_gen = datetime.datetime.fromisoformat(
                str(mp_at).replace("Z", "+00:00"))
            if mp_gen.tzinfo is None:
                mp_gen = mp_gen.replace(tzinfo=datetime.timezone.utc)
            mp_age = (now - mp_gen).total_seconds()
            if 0 <= mp_age < config.VERIFICATION_MAX_AGE_S and mp_passed >= config.VERIFICATION_MIN_PASSED:
                return True
        except Exception:
            pass
    return False


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(1)
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            _report = json.load(f)
    except Exception:
        sys.exit(1)
    sys.exit(0 if is_fresh(_report) else 1)
