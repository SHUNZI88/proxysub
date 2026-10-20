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


def test_learn_thresholds_new_caps_registered(tmp_path):
    """P3-3：参数注册表扩展——US/SCORE 两类延迟上限默认即学、默认即取。"""
    report = _mk_report(tested=20, passed=5)
    out = str(tmp_path / "learned.json")
    hist = str(tmp_path / "th.json")
    params = evolution.learn_thresholds(report, out, hist)
    for name in ("US_LATENCY_CAP_MS", "SCORE_LATENCY_CAP_MS"):
        assert name in params
        assert params[name] == evolution.LEARNED_PARAMS[name]["default"]


def test_learn_thresholds_healthy_tightens_cn_us(tmp_path):
    """通过率健康且 p90≈2600ms（落在 CN/US 各自 [min,default) 内）-> 两类上限同构收紧。

    注：SCORE_LATENCY_CAP_MS 默认仅 600ms，远小于真实延迟水位，本场景下不收紧
    （p90 低于其 min），属设计正确——它衡量的是排序贡献上限而非真实延迟阈值。
    """
    report = _mk_report(tested=200, passed=180)
    for i, n in enumerate(report["nodes"]):
        if n["cn"].get("ok"):
            n["cn"]["latency_ms"] = 2600 + (i % 10) * 10  # p90 ≈ 2680ms
    out = str(tmp_path / "learned.json")
    hist = str(tmp_path / "th.json")
    params = evolution.learn_thresholds(report, out, hist)
    h = json.load(open(hist))
    for name in ("CN_LATENCY_CAP_MS", "US_LATENCY_CAP_MS"):
        spec = evolution.LEARNED_PARAMS[name]
        assert params[name] < spec["default"]
        assert spec["min"] <= params[name] <= spec["max"]
        assert any(e["param"] == name for e in h)
    # SCORE 不收紧（p90 远低于其阈值窗口），维持默认
    assert params["SCORE_LATENCY_CAP_MS"] == evolution.LEARNED_PARAMS["SCORE_LATENCY_CAP_MS"]["default"]


def test_learn_thresholds_healthy_tightens_score_cap(tmp_path):
    """p90≈500ms（落在 SCORE 的 [min,default) 内）-> 排序贡献上限收紧，CN/US 不动。"""
    report = _mk_report(tested=200, passed=180)
    for i, n in enumerate(report["nodes"]):
        if n["cn"].get("ok"):
            n["cn"]["latency_ms"] = 500 + (i % 10)  # p90 ≈ 508ms
    out = str(tmp_path / "learned.json")
    hist = str(tmp_path / "th.json")
    params = evolution.learn_thresholds(report, out, hist)
    spec = evolution.LEARNED_PARAMS["SCORE_LATENCY_CAP_MS"]
    assert params["SCORE_LATENCY_CAP_MS"] < spec["default"]
    assert spec["min"] <= params["SCORE_LATENCY_CAP_MS"] <= spec["max"]
    assert any(e["param"] == "SCORE_LATENCY_CAP_MS" for e in json.load(open(hist)))
    # CN/US 默认上限远大于真实 p90，本场景不收紧
    assert params["CN_LATENCY_CAP_MS"] == evolution.LEARNED_PARAMS["CN_LATENCY_CAP_MS"]["default"]
    assert params["US_LATENCY_CAP_MS"] == evolution.LEARNED_PARAMS["US_LATENCY_CAP_MS"]["default"]


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


def test_update_source_scores_cn_maps_src_key_to_url(tmp_path):
    """键口径修复：传入 url_by_src 时，cn 维度须落到「完整 URL 主键」而非 owner/repo。

    真实现象（2026-10-15 取证）：source_scores.json 主键是完整订阅 URL，
    而报告 by_source 键是 owner/repo；旧实现直把 owner/repo 当键写入，
    导致主键 URL 永远拿不到 cn 维度（79 源仅 27 有 cn，头部高分配额源恰在盲区）。
    """
    path = str(tmp_path / "source_scores.json")
    url = "https://raw.githubusercontent.com/Au1rxx/xxx/main/sub.txt"
    # 主键是 URL，且已带 score/role（由 update_source_scores 写入）
    with open(path, "w", encoding="utf-8") as f:
        json.dump({url: {"score": 100.0, "runs": 9, "role": "official"}}, f)

    report = {
        "generated_at": _now_iso(),
        "counts": {"by_source": {"Au1rxx/xxx": {"tested": 100, "passed": 5}}},
    }
    scores = evolution.update_source_scores_cn(report, path, {"Au1rxx/xxx": url})
    # cn 维度落到 URL 主键
    assert scores[url]["cn_pass_rate"] == 0.05
    assert scores[url]["cn_tested"] == 100
    # 关键：不得新造 owner/repo 影子条目
    assert "Au1rxx/xxx" not in scores
    # 关键：不得抹掉主键上已有的 score/role/runs
    assert scores[url]["score"] == 100.0
    assert scores[url]["runs"] == 9
    assert scores[url]["role"] == "official"


def test_update_source_scores_cn_falls_back_when_no_mapping(tmp_path):
    """未传 url_by_src 时退回旧行为（镜像键），保证既有调用与测试不回归。"""
    path = str(tmp_path / "source_scores.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({}, f)
    report = {
        "generated_at": _now_iso(),
        "counts": {"by_source": {"owner/repo": {"tested": 40, "passed": 40}}},
    }
    scores = evolution.update_source_scores_cn(report, path)
    assert scores["owner/repo"]["cn_pass_rate"] == 1.0


def test_update_source_scores_cn_purges_mirror_keys(tmp_path):
    """Phase C：有 URL 主键对应的历史镜像键（owner/repo）被清理，零数据损失。

    真实现象：键口径修复前 source_scores.json 积累了 33 个 owner/repo 短键，
    与 URL 主键指向同一源，使 cn_source_stats 输出混入重复条目。
    """
    path = str(tmp_path / "source_scores.json")
    url = "https://raw.githubusercontent.com/Au1rxx/xxx/main/sub.txt"
    with open(path, "w", encoding="utf-8") as f:
        json.dump({url: {"score": 100.0, "cn_tested": 50},
                   "Au1rxx/xxx": {"score": 42.0, "cn_tested": 30}}, f)
    report = {
        "generated_at": _now_iso(),
        "counts": {"by_source": {"Au1rxx/xxx": {"tested": 100, "passed": 5}}},
    }
    scores = evolution.update_source_scores_cn(report, path, {"Au1rxx/xxx": url})
    # 镜像键删除，URL 主键的 cn 维度与历史 score 都在
    assert "Au1rxx/xxx" not in scores
    assert scores[url]["cn_pass_rate"] == 0.05
    assert scores[url]["score"] == 100.0


def test_update_source_scores_cn_keeps_orphan_mirror_key(tmp_path):
    """无 URL 主键对应的短键保守保留（源可能尚未入 official，待 URL 键出现后自愈）。"""
    path = str(tmp_path / "source_scores.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"orphan/repo": {"score": 10.0}}, f)
    report = {
        "generated_at": _now_iso(),
        "counts": {"by_source": {"other/repo": {"tested": 10, "passed": 1}}},
    }
    scores = evolution.update_source_scores_cn(report, path, {"other/repo":
                                            "https://raw.githubusercontent.com/other/repo/main/s.txt"})
    assert "orphan/repo" in scores


def test_prune_cn_history_removes_stale_never_passed(tmp_path):
    """清理「已陈旧且从未通过」的 cn_history 记录（控制体积，零评分损失）。

    cn_stability_bonus_ms 对 cn_last 超过 12h 的记录整条归零，故这类记录
    对评分零贡献却随每轮 CI 进 git（实测 1331/2654 条）。注意 cn_history
    仅用于评分加成，不用于"跳过已测节点"，删除不造成重复测试。
    """
    stale = "2020-01-01T00:00:00Z"
    fresh = _now_iso()
    hist = {
        # 陈旧 + 从未通过 → 剔除
        "zombie": {"cn_ok": False, "cn_streak": 0, "cn_fails": 5,
                   "cn_runs": 5, "cn_pass": 0, "cn_last": stale},
        # 曾有通过史 → 保留（无论多旧）
        "passed": {"cn_ok": True, "cn_streak": 2, "cn_fails": 1,
                   "cn_runs": 5, "cn_pass": 3, "cn_last": stale},
        # 新鲜 + 从未通过 → 保留（仍在评分窗口内）
        "freshfail": {"cn_ok": False, "cn_streak": 0, "cn_fails": 1,
                      "cn_runs": 1, "cn_pass": 0, "cn_last": fresh},
    }
    out = evolution.prune_cn_history(hist)
    assert set(out) == {"passed", "freshfail"}
    assert "zombie" not in out


def test_prune_cn_history_respects_max_age_override():
    """max_age_s 可覆盖：阈值放宽后，原本陈旧的记录可被保留。"""
    hist = {"x": {"cn_pass": 0, "cn_last": "2020-01-01T00:00:00Z"}}
    assert "x" not in evolution.prune_cn_history(hist)
    # 阈值放大到 100 年 → 视为新鲜
    assert "x" in evolution.prune_cn_history(hist, max_age_s=100 * 365 * 24 * 3600)


def test_prune_cn_history_no_op_on_empty():
    assert evolution.prune_cn_history({}) == {}


# ---------------------------------------------------------------- P2-b 跨轮协议聚合
def test_update_protocol_history_accumulates_across_rounds(tmp_path):
    """P2-b：不同轮次的 by_protocol 必须累加，并记录 rounds/recent。"""
    p = str(tmp_path / "protocol_history.json")
    r1 = _mk_report(tested=200, passed=40)
    r1["counts"]["by_protocol"] = {"hysteria2": {"tested": 100, "passed": 20},
                                   "anytls": {"tested": 8, "passed": 7}}
    r1["tested_round"] = "20261014T0600Z"
    evolution.update_protocol_history(r1, p)

    r2 = _mk_report(tested=300, passed=60)
    r2["counts"]["by_protocol"] = {"hysteria2": {"tested": 150, "passed": 30},
                                   "anytls": {"tested": 10, "passed": 8}}
    r2["tested_round"] = "20261014T1200Z"
    hist = evolution.update_protocol_history(r2, p)

    assert hist["hysteria2"]["rounds"] == 2
    assert hist["hysteria2"]["tested"] == 250
    assert hist["hysteria2"]["passed"] == 50
    assert hist["anytls"]["tested"] == 18
    assert len(hist["hysteria2"]["recent"]) == 2


def test_update_protocol_history_idempotent_same_round(tmp_path):
    """同一轮重复执行不得重复累加（CI 重试/重跑场景）。"""
    p = str(tmp_path / "protocol_history.json")
    r = _mk_report(tested=200, passed=40)
    r["counts"]["by_protocol"] = {"hysteria2": {"tested": 100, "passed": 20}}
    r["tested_round"] = "20261014T0600Z"
    evolution.update_protocol_history(r, p)
    hist = evolution.update_protocol_history(r, p)  # 同轮再来一次
    assert hist["hysteria2"]["rounds"] == 1
    assert hist["hysteria2"]["tested"] == 100


def test_update_protocol_history_skips_stale(tmp_path):
    """陈旧报告不得写入（与其余反哺闭环一致的守卫）。"""
    p = str(tmp_path / "protocol_history.json")
    stale = _mk_report(stale=True)
    stale["counts"]["by_protocol"] = {"hysteria2": {"tested": 100, "passed": 20}}
    assert evolution.update_protocol_history(stale, p) == {}
    assert not os.path.exists(p)


def test_update_protocol_history_keeps_recent_bounded(tmp_path):
    """recent 列表必须被裁剪到 PROTOCOL_HISTORY_KEEP_ROUNDS，控制体积。"""
    import config
    p = str(tmp_path / "protocol_history.json")
    n = config.PROTOCOL_HISTORY_KEEP_ROUNDS + 5
    for i in range(n):
        r = _mk_report(tested=100, passed=20)
        r["counts"]["by_protocol"] = {"hysteria2": {"tested": 100, "passed": 20}}
        r["tested_round"] = f"20261014T{i:04d}Z"
        r["generated_at"] = _now_iso()   # 保持新鲜
        evolution.update_protocol_history(r, p)
    hist = json.load(open(p))
    assert hist["hysteria2"]["rounds"] == n          # 累计不丢
    assert len(hist["hysteria2"]["recent"]) == config.PROTOCOL_HISTORY_KEEP_ROUNDS
