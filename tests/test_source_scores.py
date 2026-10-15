"""源评分系统（source_scores.json）的回归测试。"""

import os
import tempfile

import sources_manager as sm


def _run_in_tmp(fn):
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as td:
        os.chdir(td)
        try:
            return fn()
        finally:
            os.chdir(cwd)


def test_update_source_scores_good_source_increases():
    """成功 + 高独有 + 高真实通过 + 零蜜罐 → 分数应上升（>50）。"""
    def body():
        per_src = {
            "u1": {"ok": True, "alive": 10, "unique_alive": 10,
                   "real_ok": 9, "probed": 10, "tamper": 0, "role": "official"},
        }
        scores = sm.update_source_scores({}, per_src, {})
        assert scores["u1"]["score"] > 50.0
        assert scores["u1"]["runs"] == 1
        return scores["u1"]["score"]
    _run_in_tmp(body)


def test_update_source_scores_bad_source_decreases():
    """抓取失败 + 高蜜罐比 → 分数应低于 50。"""
    def body():
        per_src = {
            "u2": {"ok": False, "alive": 0, "unique_alive": 0,
                   "real_ok": 0, "probed": 10, "tamper": 8, "role": "official"},
        }
        scores = sm.update_source_scores({}, per_src, {})
        assert scores["u2"]["score"] < 50.0
    _run_in_tmp(body)


def test_update_source_scores_is_bounded_and_persistent():
    """分数必须落在 [0,100]，且重复运行会累积（持久化到文件）。"""
    def body():
        per_src = {"u": {"ok": True, "alive": 10, "unique_alive": 10,
                         "real_ok": 10, "probed": 10, "tamper": 0}}
        scores = sm.update_source_scores({}, per_src, {})
        sm.save_json(sm.SOURCE_SCORES_FILE, scores)
        for _ in range(20):
            scores = sm.update_source_scores({}, per_src, {})
            sm.save_json(sm.SOURCE_SCORES_FILE, scores)
        assert 0.0 <= scores["u"]["score"] <= 100.0
        assert scores["u"]["runs"] == 21
        assert scores["u"]["score"] > 95.0
    _run_in_tmp(body)


def test_update_source_scores_tolerates_corrupt_file():
    """source_scores.json 损坏时应自愈，不抛异常。"""
    def body():
        with open(sm.SOURCE_SCORES_FILE, "w", encoding="utf-8") as f:
            f.write("{not json")
        scores = sm.update_source_scores({}, {"u": {"ok": True, "alive": 1,
                                                    "unique_alive": 1, "real_ok": 1,
                                                    "probed": 1, "tamper": 0}}, {})
        assert scores["u"]["score"] > 0
    _run_in_tmp(body)


def test_source_scores_file_constant_exists():
    assert sm.SOURCE_SCORES_FILE == "source_scores.json"


def test_update_source_scores_preserves_cn_dimension():
    """重构条目时须保留进化引擎写入的 cn_* 维度。

    两处写入方（evolution.update_source_scores_cn 写 cn_*、
    sources_manager.update_source_scores 写 score/runs/role）共用同一 URL 主键，
    本函数每轮重建条目若不带 cn_*，会把刚反哺回来的中国实测通过率抹掉，
    使 cn 维度「隔轮即失」。此处固化「合并而非覆盖」这一不变量。
    """
    def body():
        per_src = {"u": {"ok": True, "alive": 1, "unique_alive": 1,
                         "real_ok": 1, "probed": 1, "tamper": 0,
                         "role": "official"}}
        sm.save_json(sm.SOURCE_SCORES_FILE, {
            "u": {"score": 70.0, "runs": 3,
                  "cn_tested": 50, "cn_passed": 10,
                  "cn_pass_rate": 0.2, "cn_last": "2026-10-15T00:00:00Z"},
        })
        scores = sm.update_source_scores({}, per_src, {})
        assert scores["u"]["cn_pass_rate"] == 0.2
        assert scores["u"]["cn_tested"] == 50
        assert "cn_last" in scores["u"]
        # 正常维度照常更新
        assert scores["u"]["runs"] == 4
    _run_in_tmp(body)
