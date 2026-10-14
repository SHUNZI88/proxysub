"""Phase 2 进化引擎单元测试。

验证 4 个反哺闭环的护栏：陈旧守卫、源级聚合、门槛自学习（样本门限/幅度
减半/有界/审计）、审计行格式。
"""
import datetime
import json
import os
import sys


import common
import evolution

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


def _now_iso() -> str:
    """当前 UTC 时刻（进化引擎各处陈旧守卫均为 12h 窗口，夹具必须
    相对“现在”生成——硬编码历史时刻会在跨日后被守卫拒绝，曾致 7 项
    测试在 2026-10-15 集体失败）。"""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mk_report(tested=200, passed=40, with_lat=True, stale=False):
    nodes = []
    for i in range(tested):
        ok = i < passed
        cn = {"ok": ok}
        if ok and with_lat:
            cn["latency_ms"] = 1000 + (i % 30) * 100  # 1000~3900ms
        if ok:
            cn["exit_loc"] = "中国 上海"
        nodes.append({"fp": f"fp{i}",
                     "src": "owner/repo" if i % 2 == 0 else "other/src",
                     "cn": cn, "proxy": {"type": "hysteria2"}})
    return {
        "round_id": "20261014T0702Z",
        "tested_round": "20261014T0640Z",
        "generated_at": "2020-01-01T00:00:00Z" if stale else _now_iso(),
        "vantage": "cn-hn-sandbox",
        "counts": {
            "tested": tested, "passed": passed,
            "by_origin": {"pending": passed, "rescue": 0, "carryover": 0},
            "by_source": {"owner/repo": {"tested": tested // 2, "passed": passed // 2},
                          "other/src": {"tested": tested - tested // 2,
                                        "passed": passed - passed // 2}},
            "by_protocol": {"hysteria2": {"tested": tested, "passed": passed}},
        },
        "nodes": nodes,
    }


def test_src_key_github_raw():
    assert common.src_key(
        "https://raw.githubusercontent.com/Au1rxx/free-vpn/main/clash.yaml") == "Au1rxx/free-vpn"
    assert common.src_key("https://github.com/Au1rxx/free-vpn/blob/main/a.yaml") == "Au1rxx/free-vpn"
    assert common.src_key("") == "?"


def test_update_cn_history_stale_skipped(tmp_path):
    report = _mk_report(stale=True)
    out = str(tmp_path / "cn_history.json")
    good = {"fp0": {"cn_ok": True, "cn_streak": 3, "cn_runs": 3, "cn_pass": 3}}
    with open(out, "w") as f:
        json.dump(good, f)
    res = evolution.update_cn_history(report, out)
    assert res == good  # 陈旧 -> 原样返回，不覆盖


def test_update_cn_history_merges(tmp_path):
    report = _mk_report(tested=10, passed=4)
    out = str(tmp_path / "cn_history.json")
    res = evolution.update_cn_history(report, out)
    assert len(res) == 10
    assert res["fp0"]["cn_ok"] is True
    assert res["fp0"]["cn_streak"] == 1 and res["fp0"]["cn_pass"] == 1
    assert res["fp0"]["cn_runs"] == 1
    assert res["fp5"]["cn_ok"] is False and res["fp5"]["cn_fails"] == 1


def test_cn_stability_bonus_stale_zero():
    old = {"fp1": {"cn_streak": 5, "cn_last": "2020-01-01T00:00:00Z"}}
    assert evolution.cn_stability_bonus_ms("fp1", old) == 0.0


def test_cn_stability_bonus_sign():
    ok = {"fp2": {"cn_ok": True, "cn_streak": 3, "cn_last": _now_iso()}}
    assert evolution.cn_stability_bonus_ms("fp2", ok) > 0
    bad = {"fp3": {"cn_ok": False, "cn_fails": 2, "cn_last": _now_iso()}}
    assert evolution.cn_stability_bonus_ms("fp3", bad) < 0


def test_update_source_scores_cn(tmp_path):
    report = _mk_report(tested=200, passed=40)
    out = str(tmp_path / "source_scores.json")
    scores = {"owner/repo": {"score": 100.0, "runs": 5},
              "other/src": {"score": 80.0, "runs": 2}}
    with open(out, "w") as f:
        json.dump(scores, f)
    res = evolution.update_source_scores_cn(report, out)
    assert res["owner/repo"]["cn_pass_rate"] == 0.2
    assert "cn_last" in res["owner/repo"]
    assert res["other/src"]["cn_tested"] == 100


def test_cn_source_bonus():
    scores = {"good": {"cn_pass_rate": 0.4}, "bad": {"cn_pass_rate": 0.01},
              "zero": {"cn_pass_rate": 0.05}}
    assert evolution.cn_source_bonus("good", scores) > 0
    assert evolution.cn_source_bonus("bad", scores) < 0
    assert evolution.cn_source_bonus("zero", scores) == 0.0  # 阈值边界归零
    assert evolution.cn_source_bonus(None, scores) == 0.0


def test_learn_thresholds_sample_too_small(tmp_path):
    report = _mk_report(tested=20, passed=5)
    out = str(tmp_path / "learned.json")
    hist = str(tmp_path / "th.json")
    params = evolution.learn_thresholds(report, out, hist)
    assert params["CN_LATENCY_CAP_MS"] == evolution.LEARNED_PARAMS["CN_LATENCY_CAP_MS"]["default"]
    assert not os.path.exists(hist) or json.load(open(hist)) == []


def test_learn_thresholds_healthy_tightens(tmp_path):
    report = _mk_report(tested=200, passed=120)  # pass_rate 60%
    out = str(tmp_path / "learned.json")
    hist = str(tmp_path / "th.json")
    before = evolution.LEARNED_PARAMS["CN_LATENCY_CAP_MS"]["default"]  # 4500
    params = evolution.learn_thresholds(report, out, hist)
    new = params["CN_LATENCY_CAP_MS"]
    # p90 of [1000..3900] ~ 3700; 幅度减半渐进 -> 4500 + (3700-4500)*0.5 = 4100
    assert new < before
    assert new > 3700.0  # 不一次到位（减半渐进）
    spec = evolution.LEARNED_PARAMS["CN_LATENCY_CAP_MS"]
    assert spec["min"] <= new <= spec["max"]
    h = json.load(open(hist))
    assert any(e["param"] == "CN_LATENCY_CAP_MS" for e in h)


def test_learn_thresholds_bounded(tmp_path):
    report = _mk_report(tested=200, passed=180)
    for n in report["nodes"]:
        if n["cn"].get("ok"):
            n["cn"]["latency_ms"] = 100
    out = str(tmp_path / "learned.json")
    hist = str(tmp_path / "th.json")
    params = evolution.learn_thresholds(report, out, hist)
    spec = evolution.LEARNED_PARAMS["CN_LATENCY_CAP_MS"]
    assert params["CN_LATENCY_CAP_MS"] >= spec["min"]


def test_learn_thresholds_stale_noop(tmp_path):
    report = _mk_report(tested=200, passed=120, stale=True)
    out = str(tmp_path / "learned.json")
    hist = str(tmp_path / "th.json")
    params = evolution.learn_thresholds(report, out, hist)
    assert params["CN_LATENCY_CAP_MS"] == evolution.LEARNED_PARAMS["CN_LATENCY_CAP_MS"]["default"]
    assert not os.path.exists(hist)


def test_append_probe_history(tmp_path):
    report = _mk_report(tested=200, passed=40)
    out = str(tmp_path / "probe_history.jsonl")
    line = evolution.append_probe_history(report, out)
    assert line["tested"] == 200 and line["passed"] == 40
    assert abs(line["pass_rate"] - 0.2) < 1e-3
    assert len(line["top_sources"]) <= 5
    with open(out) as f:
        rows = [json.loads(l) for l in f if l.strip()]
    assert len(rows) == 1 and rows[0]["round"] == "20261014T0640Z"


def test_run_evolution_orchestrator(tmp_path):
    report = _mk_report(tested=200, passed=40)
    summary = evolution.run_evolution(report, str(tmp_path))
    assert summary["cn_history_nodes"] == 200
    assert summary["source_scores_with_cn"] == 2
    assert "CN_LATENCY_CAP_MS" in summary["learned"]
    assert summary["probe_history_line"]


def test_update_source_scores_cn_skips_and_purges_unknown_key(tmp_path):
    """回归（2026-10-14 真实数据）：无源伪键 "?" 不得写入，且要清理历史残留。

    修复前的报告含 by_source["?"]（carryover 无源节点），已污染 source_scores.json
    产生 "?" 条目（0.5333）。该键不代表任何真实源，评分时也无法命中，
    属脏数据——故固化「跳过写入 + 清理残留」两条不变量。
    """
    path = str(tmp_path / "source_scores.json")
    # 预置历史残留 "?" 条目
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"?": {"cn_pass_rate": 0.5333},
                   "old/repo": {"cn_pass_rate": 0.1}}, f)

    report = {
        "generated_at": _now_iso(),
        "counts": {
            "by_source": {
                "?": {"tested": 30, "passed": 16},
                "good/repo": {"tested": 50, "passed": 40},
            },
        },
    }
    scores = evolution.update_source_scores_cn(report, path)
    assert "?" not in scores, "无源伪键 '?' 必须被清理"
    assert scores["good/repo"]["cn_pass_rate"] == 0.8
    # 其它既有源不受影响
    assert scores["old/repo"]["cn_pass_rate"] == 0.1
