"""scripts/cn_probe.py 纯函数测试：地理证据解析、去重、验证集配置构建。"""

import json
import os
import subprocess
import unittest.mock as mock

import yaml

import config

from scripts import cn_probe


def _proxy(name="HK 01", type_="hysteria2", server="a.example", **extra):
    p = {"name": name, "type": type_, "server": server, "port": 443}
    p.update(extra)
    return p


# ---------------------------------------------------------------- _parse_geo
def test_parse_geo_cip_cc():
    text = "IP\t: 118.25.10.211\n地址\t: 中国 湖南 长沙"
    ev = cn_probe._parse_geo(text)
    assert ev["exit_ip"] == "118.25.10.211"
    assert "湖南" in ev["exit_loc"]


def test_parse_geo_ipip():
    text = "当前 IP：1.2.3.4  来自于: 中国 香港 "
    ev = cn_probe._parse_geo(text)
    assert ev["exit_ip"] == "1.2.3.4"


def test_parse_geo_no_ip():
    assert cn_probe._parse_geo("service unavailable") == {}


# ---------------------------------------------------------------- node_evidence
def test_node_evidence_single_switch_and_merges_geo_ai(monkeypatch):
    """任务#91 合并版：一次切组 + GEO 3 源/AI 5 域并行，两类证据合并返回。

    同时是 P0-1 回归防线（2026-10-15）：GEO 请求必须经
    build_opener(ProxyHandler) 建立的 opener 发出——裸 urlopen 直连拿到
    的恒为沙箱自身出口，该字段对节点真实落地毫无判别力。
    """
    puts = []
    monkeypatch.setattr(cn_probe, "api_put",
                        lambda *a, **k: puts.append(a) or True)
    geo_calls, ai_calls = [], []

    def _fake_geo(url, proxy, timeout):
        geo_calls.append((url, proxy))
        return {"exit_ip": "9.9.9.9", "exit_loc": "中国 香港"}

    def _fake_ai(url, proxy, timeout):
        ai_calls.append((url, proxy))
        codes = {"chatgpt": 403, "claude": 200, "gemini": None,
                 "copilot": 302, "openai_api": 401}
        return codes[next(k for k, v in cn_probe.AI_TARGETS.items() if v == url)]

    monkeypatch.setattr(cn_probe, "_geo_evidence_via_proxy", _fake_geo)
    monkeypatch.setattr(cn_probe, "_http_status_via_proxy", _fake_ai)
    out = cn_probe.node_evidence(9097, 7897, "node-x")
    # 恰好一次切组（selector=PROBE）——GEO 与 AI 合并后不得重复切组
    assert len(puts) == 1 and puts[0][1] == "/proxies/PROBE"
    # 8 路并行全部发出：GEO 3 源 + AI 5 域，且都经 mixed-port 代理
    assert len(geo_calls) == 3 and len(ai_calls) == 5
    assert all(p == "http://127.0.0.1:7897" for _, p in geo_calls + ai_calls)
    # GEO 证据合并（首个成功源的 via 归属）
    assert out["geo"]["exit_ip"] == "9.9.9.9"
    assert out["geo"]["via"] == cn_probe.GEO_URLS[0]
    # AI 证据合并（openai_api=401 ⇒ API 层可用）
    assert out["ai"]["ai_reachable"] is True
    assert out["ai"]["ai_api"] is True
    assert set(out["ai"]["reach"]) == {"chatgpt", "claude", "copilot", "openai_api"}


def test_node_evidence_geo_first_success_wins(monkeypatch):
    """GEO 多源回退：首个失败的源跳过，首个成功源的 URL 记入 via。"""
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: True)

    def _fake_geo(url, proxy, timeout):
        if url == cn_probe.GEO_URLS[0]:
            return {}                      # 第一个源失败
        if url == cn_probe.GEO_URLS[1]:
            return {"exit_ip": "8.8.8.8"}  # 第二个源成功
        return {}

    monkeypatch.setattr(cn_probe, "_geo_evidence_via_proxy", _fake_geo)
    monkeypatch.setattr(cn_probe, "_http_status_via_proxy",
                        lambda url, proxy, timeout: None)
    out = cn_probe.node_evidence(9097, 7897, "node-x")
    assert out["geo"] == {"exit_ip": "8.8.8.8", "via": cn_probe.GEO_URLS[1]}
    assert out["ai"]["ai_reachable"] is False   # 全部 None ⇒ 不可达但不丢证据


def test_node_evidence_geo_all_fail_keeps_ai(monkeypatch):
    """GEO 全失败时 geo={} 但 AI 证据仍返回——两类证据互不阻断。"""
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: True)
    monkeypatch.setattr(cn_probe, "_geo_evidence_via_proxy",
                        lambda url, proxy, timeout: {})
    monkeypatch.setattr(cn_probe, "_http_status_via_proxy",
                        lambda url, proxy, timeout: 401)
    out = cn_probe.node_evidence(9097, 7897, "node-x")
    assert out["geo"] == {}
    assert out["ai"]["ai_api"] is True


def test_node_evidence_group_switch_failure_returns_empty(monkeypatch):
    """切组失败（API 故障）时返回空 dict，且不得发出任何证据请求。"""
    geo_calls, ai_calls = [], []
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: False)
    monkeypatch.setattr(cn_probe, "_geo_evidence_via_proxy",
                        lambda *a, **k: geo_calls.append(1) or {})
    monkeypatch.setattr(cn_probe, "_http_status_via_proxy",
                        lambda *a, **k: ai_calls.append(1) or 200)
    assert cn_probe.node_evidence(9097, 7897, "node-x") == {}
    assert not geo_calls and not ai_calls


def test_geo_evidence_via_proxy_uses_proxy_not_direct(monkeypatch):
    """_geo_evidence_via_proxy：必须经 ProxyHandler opener（P0-1 回归）。

    与 _http_status_via_proxy 同一模式：HTTPError 之外的异常吞掉返回 {}，
    绝不向上抛（证据收集不构成闸门）。
    """
    captured = {}

    class _Resp:
        status = 200

        def read(self):
            return "IP\t: 9.9.9.9\n地址\t: 中国 香港".encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Opener:
        def open(self, req, timeout=None):
            captured["proxied"] = True
            return _Resp()

    def _fake_build_opener(handler):
        captured["handler"] = handler
        return _Opener()

    monkeypatch.setattr(cn_probe.urllib.request, "build_opener", _fake_build_opener)
    ev = cn_probe._geo_evidence_via_proxy(
        "https://cip.cc", "http://127.0.0.1:7897", 8)
    assert captured.get("proxied") is True
    assert ev["exit_ip"] == "9.9.9.9"


def test_hard_timeout_call_truncates_slow_response():
    """回归（2026-10-21 实测复踩）：urllib socket timeout 是每次 recv 超时，
    龟速节点上的滴流响应可把单请求拖到 24s+（gemini 302 链实测 24.31s）。
    _hard_timeout_call 必须线程级强制截断：超时返回 None。"""
    import time

    def _slow():
        time.sleep(5)
        return "late"

    t0 = time.time()
    assert cn_probe._hard_timeout_call(_slow, 0.2) is None
    assert time.time() - t0 < 3          # 硬截断生效，没等满 5s
    assert cn_probe._hard_timeout_call(lambda: "ok", 1) == "ok"


# ---------------------------------------------------------------- dedup_nodes
def test_dedup_nodes_priority_and_unique_names():
    dup = _proxy(name="same", server="a.example")
    other = _proxy(name="same", server="b.example")  # 同名不同节点
    groups = [
        ("pending", [{"fp": "fp1", "name": "n1", "proxy": dup,
                      "origin": "pending", "final": True, "us_ok": True}]),
        ("rescue", [{"fp": "fp2", "name": "same", "proxy": other,
                     "origin": "rescue", "final": False, "us_ok": False}]),
        ("carryover", [{"fp": "fp1", "name": "n1-old", "proxy": dup,
                        "origin": "carryover", "final": True, "us_ok": False}]),
    ]
    out = cn_probe.dedup_nodes(groups)
    # fp1 去重保留 pending 记录（优先组）；探测名唯一
    assert len(out) == 2
    by_fp = {n["fp"]: n for n in out}
    assert by_fp["fp1"]["origin"] == "pending"
    assert by_fp["fp1"]["name"] == "n1"
    names = [n["probe_name"] for n in out]
    assert len(set(names)) == 2  # 同名冲突已加后缀


def test_dedup_nodes_carryover_wins_duplicate_fp():
    """回归（任务#99，2026-10-24）：调用方分组顺序改为 carryover 最先——
    已发布节点与 pending 重复时必须保留 carryover 身份（cap_test_set 不裁剪），
    否则时间预算吃紧时好节点被「静默消失」（实测 50 发布节点仅 37 进测试集）。"""
    dup = _proxy(name="same", server="a.example")
    groups = [
        ("carryover", [{"fp": "fp1", "name": "n1-old", "proxy": dup,
                        "origin": "carryover", "final": False, "us_ok": False}]),
        ("pending", [{"fp": "fp1", "name": "n1", "proxy": dup,
                      "origin": "pending", "final": True, "us_ok": True}]),
    ]
    out = cn_probe.dedup_nodes(groups)
    assert len(out) == 1
    assert out[0]["origin"] == "carryover"
    assert out[0]["name"] == "n1-old"


def test_dedup_nodes_suffixed_original_name_no_collision():
    """回归：原始名已带 `#2` 后缀时，不得与计数生成名撞车（2026-10-16 修复）。

    旧实现用 `used_names[base] += 1` 生成 `base#n`，当存在原始名 `base#2`
    且另有多个同名 `base` 节点时，计数会把第二个 `base` 也命名为 `base#2`，
    与原始 `base#2` 撞名，mihomo 报 duplicate name 拒绝启动。新实现用全局
    已用名集合保证任何生成名都不重复。
    """
    a = _proxy(name="X#2", server="a.example")   # 原始名已带 #2
    b = _proxy(name="X", server="b.example")
    c = _proxy(name="X", server="c.example")     # 第二个同名，旧实现会生成 X#2 撞车
    groups = [("pending", [
        {"fp": "fa", "name": "X#2", "proxy": a, "origin": "pending",
         "final": True, "us_ok": True},
        {"fp": "fb", "name": "X", "proxy": b, "origin": "pending",
         "final": True, "us_ok": True},
        {"fp": "fc", "name": "X", "proxy": c, "origin": "pending",
         "final": True, "us_ok": True},
    ])]
    out = cn_probe.dedup_nodes(groups)
    names = [n["probe_name"] for n in out]
    assert len(names) == len(set(names))          # 全部唯一
    assert len(out) == 3
    assert names.count("X#2") == 1                # 原始 X#2 只出现一次



# ---------------------------------------------------------------- build_verified_config
def test_build_verified_config_groups():
    nodes = [
        {"proxy": _proxy(name="🇭🇰 香港 01", server="a.example")},
        {"proxy": _proxy(name="🇯🇵 日本 02", server="b.example")},
        {"proxy": _proxy(name="SG 03", server="c.example",
                         **{"skip-cert-verify": True})},
    ]
    cfg = cn_probe.build_verified_config(nodes)
    names = [g["name"] for g in cfg["proxy-groups"]]
    assert "🚀 节点选择" in names and "♻️ 自动选择" in names
    # Insecure 独立隔离，不进自动组
    auto = next(g for g in cfg["proxy-groups"] if g["name"] == "♻️ 自动选择")
    assert "SG 03" not in auto["proxies"]
    insecure = next(g for g in cfg["proxy-groups"]
                    if g["name"] == config.INSECURE_GROUP)
    assert insecure["proxies"] == ["SG 03"]
    assert len(cfg["proxies"]) == 3


def test_build_verified_config_ai_group():
    """AI 可用组（2026-10-24）：有 ai_reachable 证据的节点进「🤖 AI 可用」
    url-test 组并置于节点选择首位；无 results/无证据时不出现该组。"""
    nodes = [
        {"proxy": _proxy(name="HK 01", server="a.example"), "probe_name": "p0"},
        {"proxy": _proxy(name="SG 02", server="b.example"), "probe_name": "p1"},
    ]
    results = {"p0": {"ok": True, "ai": {"ai_reachable": True}},
               "p1": {"ok": True, "ai": {}}}
    cfg = cn_probe.build_verified_config(nodes, results)
    gnames = [g["name"] for g in cfg["proxy-groups"]]
    assert "🤖 AI 可用" in gnames
    ai = next(g for g in cfg["proxy-groups"] if g["name"] == "🤖 AI 可用")
    assert ai["proxies"] == ["HK 01"]
    sel = next(g for g in cfg["proxy-groups"] if g["name"] == "🚀 节点选择")
    assert sel["proxies"][0] == "🤖 AI 可用"
    # 无证据 → 无 AI 组
    cfg2 = cn_probe.build_verified_config(nodes)
    assert "🤖 AI 可用" not in [g["name"] for g in cfg2["proxy-groups"]]


def test_build_verified_config_region_groups():
    nodes = [{"proxy": _proxy(name=f"🇭🇰 香港 0{i}", server=f"s{i}")}
             for i in range(3)]
    cfg = cn_probe.build_verified_config(nodes)
    hk = [g for g in cfg["proxy-groups"] if g["name"].startswith("🇭🇰")]
    assert hk and len(hk[0]["proxies"]) == 3  # 同区 ≥2 个才建地区组


# ---------------------------------------------------------------- 文档装载
def test_load_doc_nodes(tmp_path):
    doc = {"generated_at": "2026-10-14T00:17:42Z", "nodes": [
        {"fp": "fp1", "name": "HK 01", "final": True, "us_ok": True,
         "proxy": _proxy(name="HK 01")},
        {"fp": "fp2", "proxy": {"server": ""}},      # 缺 server，丢弃
        {"fp": "fp3", "proxy": None},                 # 非 dict，丢弃
    ]}
    p = tmp_path / "pending_probe.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    nodes = cn_probe.load_doc_nodes(str(p), "pending")
    assert len(nodes) == 1
    assert nodes[0]["fp"] == "fp1" and nodes[0]["origin"] == "pending"
    assert nodes[0]["us_ok"] is True


def test_load_doc_nodes_missing_file(tmp_path):
    assert cn_probe.load_doc_nodes(str(tmp_path / "nope.json"), "pending") == []


def test_load_carryover_parses_main_asset(tmp_path):
    cfg = {"proxies": [_proxy(name="HK 01"), _proxy(name="SG 02")]}
    p = tmp_path / "main_clash.yaml"
    p.write_text(yaml.dump(cfg, allow_unicode=True), encoding="utf-8")
    nodes = cn_probe.load_carryover(str(p))
    assert [n["origin"] for n in nodes] == ["carryover", "carryover"]
    # final 语义修正（任务#96）：carryover 继承节点不再硬编码 final=True，
    # 只有本轮实测通过才置位——上一轮通过≠本轮通过。
    assert nodes[0]["final"] is False


# ---------------------------------------------------------------- 杂项
def test_default_tag_matches_anti_crawl():
    # 用绝对路径读取（不依赖进程 cwd——全量运行时前面测试可能切过目录）
    with open(os.path.join(cn_probe.REPO_ROOT, "anti_crawl.json"), encoding="utf-8") as f:
        expected = json.load(f).get("release_tag") or "sub"
    assert cn_probe.default_tag() == expected


def test_parse_ts_variants():
    assert cn_probe.parse_ts("2026-10-14T00:17:42Z") is not None
    assert cn_probe.parse_ts("2026-10-14T00:17:42") is not None
    assert cn_probe.parse_ts("") is None
    assert cn_probe.parse_ts(None) is None


# ---------------------------------------------------------------- 新鲜度闸门
def test_poll_window_default_fits_task_timeout():
    # 定时任务超时上限 1800s：轮询 20min + 有界工作（自检/下载/拨测/
    # 取证/发布 ≈6.5min）+ 代理开销，必须留余量；等不到新轮次由轮次
    # 闸门顺延到下一实测轮（不丢失），不依赖长轮询。
    args = cn_probe.build_parser().parse_args([])
    assert args.max_wait == cn_probe.PENDING_POLL_WINDOW_MIN
    assert cn_probe.PENDING_POLL_WINDOW_MIN <= 20


def test_max_wait_override_still_honored():
    args = cn_probe.build_parser().parse_args(["--max-wait", "5"])
    assert args.max_wait == 5


# ---------------------------------------------------------------- 轮次闸门
def test_gate_decision_new_round_tests_regardless_of_age():
    # 文档只是节点清单、活性靠实时拨测：轮次没测过就立即测，与年龄无关
    assert cn_probe.gate_decision("R2", "R1") == "test"
    assert cn_probe.gate_decision("R1", None) == "test"  # 首轮无历史


def test_gate_decision_same_round_waits():
    assert cn_probe.gate_decision("R1", "R1") == "wait"


def test_gate_decision_missing_doc_waits():
    assert cn_probe.gate_decision(None, "R1") == "wait"
    assert cn_probe.gate_decision(None, None) == "wait"


def test_doc_round_id(tmp_path):
    p = tmp_path / "pending_probe.json"
    p.write_text(json.dumps({"round_id": "20261014T0017Z", "nodes": []}),
                 encoding="utf-8")
    assert cn_probe.doc_round_id(str(p)) == "20261014T0017Z"
    assert cn_probe.doc_round_id(str(tmp_path / "nope.json")) is None
    p.write_text("{bad json", encoding="utf-8")
    assert cn_probe.doc_round_id(str(p)) is None
    p.write_text(json.dumps({"nodes": []}), encoding="utf-8")  # 缺 round_id
    assert cn_probe.doc_round_id(str(p)) is None


def test_resolve_tested_round_carries_forward():
    # 本轮消费 -> 记录本轮；仅测 carryover -> 继承上轮（防丢已测信息）
    assert cn_probe.resolve_tested_round("R2", "R1") == "R2"
    assert cn_probe.resolve_tested_round(None, "R1") == "R1"
    assert cn_probe.resolve_tested_round(None, None) is None


# ----------------------------------------------------------- 测试集预算裁剪
def _mk(origin, n):
    return [{"fp": f"{origin}-{i}", "name": f"{origin}{i}",
             "proxy": {"server": "1.2.3.4"}, "origin": origin,
             "final": False, "us_ok": False} for i in range(n)]


def test_cap_test_set_under_budget_unchanged():
    nodes = _mk("pending", 100) + _mk("rescue", 20) + _mk("carryover", 10)
    kept, dropped = cn_probe.cap_test_set(nodes, budget_s=1000.0, per_node_s=1.0)
    assert dropped == 0
    assert len(kept) == len(nodes)


def test_cap_test_set_trims_rescue_before_pending():
    # 预算只够 60 节点：carryover 全留(10)，剩 50 名额给 pending(100)，
    # rescue(20) 因排在 pending 之后被全部裁掉
    nodes = _mk("pending", 100) + _mk("rescue", 20) + _mk("carryover", 10)
    kept, dropped = cn_probe.cap_test_set(nodes, budget_s=60.0, per_node_s=1.0)
    assert dropped == 70  # 100-50 pending + 20 rescue
    origins = {n["origin"] for n in kept}
    assert origins == {"pending", "carryover"}
    assert sum(1 for n in kept if n["origin"] == "pending") == 50
    assert sum(1 for n in kept if n["origin"] == "carryover") == 10


def test_cap_test_set_keeps_all_carryover():
    nodes = _mk("pending", 50) + _mk("rescue", 30) + _mk("carryover", 21)
    kept, dropped = cn_probe.cap_test_set(nodes, budget_s=35.0, per_node_s=1.0)
    # 35 名额：carryover 21 最高优先全留，剩 14 给 pending，rescue 全裁
    assert sum(1 for n in kept if n["origin"] == "carryover") == 21
    assert sum(1 for n in kept if n["origin"] == "rescue") == 0
    assert sum(1 for n in kept if n["origin"] == "pending") == 14
    assert dropped == 66  # 101 - 35


def test_cap_test_set_zero_budget_returns_empty():
    # 预算耗尽：硬保 1800s 不击穿，返回空集；main() 据此跳过本轮、
    # 保留上一轮已发布验证集（不发布失控规模的拨测）
    nodes = _mk("pending", 80) + _mk("rescue", 20) + _mk("carryover", 5)
    kept, dropped = cn_probe.cap_test_set(nodes, budget_s=0.0, per_node_s=1.0)
    assert kept == []
    assert dropped == 105


def test_cap_test_set_carryover_over_cap_trims_carryover():
    nodes = _mk("carryover", 200)
    kept, dropped = cn_probe.cap_test_set(nodes, budget_s=50.0, per_node_s=1.0)
    assert len(kept) == 50
    assert dropped == 150


def test_cap_test_set_negative_budget_no_negative_index():
    nodes = _mk("pending", 10)
    kept, dropped = cn_probe.cap_test_set(nodes, budget_s=-100.0, per_node_s=1.0)
    assert kept == [] and dropped == 10


# ---------------------------------------------------------------- Phase 2.2 源级聚合（by_source 生产者）
def test_agg_two_by_source_tested_and_passed():
    """_agg_two 必须按 src 同时统计 tested(全部节点) 与 passed(verified 子集)。"""
    nodes = [
        {"src": "SHUNzi88/proxysub"}, {"src": "SHUNzi88/proxysub"},
        {"src": "SHUNzi88/proxysub"}, {"src": "raw.githubusercontent.com/abc/def"},
        {"src": "raw.githubusercontent.com/abc/def"},
    ]
    verified = [
        {"src": "SHUNzi88/proxysub"}, {"src": "SHUNzi88/proxysub"},
        {"src": "raw.githubusercontent.com/abc/def"},
    ]
    out = cn_probe._agg_two(nodes, verified, key_fn=lambda n: n.get("src") or "?")
    assert out["SHUNzi88/proxysub"] == {"tested": 3, "passed": 2}
    assert out["raw.githubusercontent.com/abc/def"] == {"tested": 2, "passed": 1}
    assert "?" not in out  # 所有节点都带 src，不应落入兜底键（否则源级加成为 0）


# ---------------------------------------------------------------- P2-a 协议置信区间
def test_agg_two_with_ci_adds_stats_fields():
    """P2-a：with_ci=True 时必须给出 pass_rate / 95%CI / sample_ok。"""
    nodes = [{"proto": "anytls"}] * 8 + [{"proto": "vless"}] * 40
    verified = [{"proto": "anytls"}] * 7 + [{"proto": "vless"}] * 2
    out = cn_probe._agg_two(nodes, verified, key_fn=lambda n: n["proto"], with_ci=True)
    a = out["anytls"]
    assert a["tested"] == 8 and a["passed"] == 7
    assert a["pass_rate"] == round(7 / 8, 4)
    assert 0.0 <= a["ci95_low"] < a["pass_rate"] < a["ci95_high"] <= 1.0
    assert a["sample_ok"] is False          # 8 < PROTOCOL_MIN_SAMPLE(30)
    assert out["vless"]["sample_ok"] is True  # 40 >= 30


def test_agg_two_default_no_ci_fields():
    """向后兼容：默认 with_ci=False 时不得新增字段（旧消费方不受影响）。"""
    nodes = [{"p": "x"}]
    out = cn_probe._agg_two(nodes, nodes, key_fn=lambda n: n["p"])
    assert out["x"] == {"tested": 1, "passed": 1}


def test_wilson_ci_edge_cases():
    """Wilson 区间边界：n=0 返回 (0,0)；全通过时上界应为 1 且下界明显<1。"""
    assert cn_probe._wilson_ci(0, 0) == (0.0, 0.0)
    lo, hi = cn_probe._wilson_ci(8, 8)
    assert hi == 1.0 and lo < 1.0  # 小样本全通过也不能断言 100%
    lo2, hi2 = cn_probe._wilson_ci(0, 10)
    assert lo2 == 0.0 and hi2 < 0.5  # 全失败时上界仍留不确定性


def test_passed_verified_subset_preserves_src():
    """复刻主流程关键不变量：passed=[n for n in nodes if ok]; verified=sorted(passed)。

    verified 节点必须保留 src 字段，否则 by_source 的 passed 计数会被算成 0，
    源级聚合（cn_source_bonus）将静默失效而不报错。
    """
    nodes = [
        {"src": "SHUNzi88/proxysub", "probe_name": f"p{i}"} for i in range(4)
    ]
    nodes[1]["src"] = "raw.githubusercontent.com/abc/def"
    results = {n["probe_name"]: {"ok": (i % 2 == 0)} for i, n in enumerate(nodes)}
    passed = [n for n in nodes if results.get(n["probe_name"], {}).get("ok")]
    verified = sorted(passed, key=lambda n: n["probe_name"])
    # 不变量：verified 全部保留 src
    assert all("src" in n and n["src"] for n in verified)
    by_source = cn_probe._agg_two(nodes, verified, key_fn=lambda n: n.get("src") or "?")
    # A 源 3 测 2 过（index0/index2 通过，index3 不通过）；B 源 1 测 0 过（index1 失败）
    # passed=0 被正确统计而非丢失，证明 verified 保留 src 的不变量成立
    assert by_source["SHUNzi88/proxysub"] == {"tested": 3, "passed": 2}
    assert by_source["raw.githubusercontent.com/abc/def"] == {"tested": 1, "passed": 0}


def test_by_source_excludes_nodes_without_src():
    """回归（2026-10-14 真实报告发现）：无 src 节点（carryover 等）不得进入 by_source。

    真实报告曾出现 by_source 首项为 "?"（51 测 29 过），即无源节点被归入伪源 "?"，
    会污染源级评分（为 "?" 生成无意义条目）。修法：聚合前过滤掉无 src 的节点。
    """
    nodes = [
        {"src": "SHUNzi88/proxysub"}, {"src": "SHUNzi88/proxysub"},
        {"src": None}, {"src": ""}, {},           # 无源（carryover）
    ]
    verified = [{"src": "SHUNzi88/proxysub"}, {"src": None}]
    src_nodes = [n for n in nodes if n.get("src")]
    src_verified = [n for n in verified if n.get("src")]
    by_source = cn_probe._agg_two(src_nodes, src_verified, key_fn=lambda n: n["src"])
    assert "?" not in by_source
    assert by_source == {"SHUNzi88/proxysub": {"tested": 2, "passed": 1}}


# ---------------------------------------------------------------- 任务#92 分源 AI 证据口径
def test_agg_source_ai_adds_three_ai_fields():
    """_agg_source_ai：by_source 每行在 tested/passed 之外扩出
    ai_tested/ai_reachable/ai_api 三口径（2026-10-21，任务#92）。

    AI 口径只覆盖**有 ai 数据的通过节点**（证据收集仅对通过节点执行、
    受预算约束可能跳过尾部）；排序沿用 tested/passed 口径。
    """
    nodes = [
        {"src": "srcA", "probe_name": "a1"}, {"src": "srcA", "probe_name": "a2"},
        {"src": "srcA", "probe_name": "a3"}, {"src": "srcB", "probe_name": "b1"},
        {"src": "srcB", "probe_name": "b2"},
    ]
    verified = [
        {"src": "srcA", "probe_name": "a1"}, {"src": "srcA", "probe_name": "a2"},
        {"src": "srcB", "probe_name": "b1"},
    ]
    results = {
        "a1": {"ok": True, "ai": {"ai_reachable": True, "ai_api": True}},
        "a2": {"ok": True, "ai": {"ai_reachable": True, "ai_api": False}},
        # a3 未通过；b1 通过但无 ai 数据（探测被预算跳过）
        "b1": {"ok": True},
    }
    out = cn_probe._agg_source_ai(nodes, verified, results)
    assert out["srcA"]["tested"] == 3 and out["srcA"]["passed"] == 2
    assert out["srcA"]["ai_tested"] == 2
    assert out["srcA"]["ai_reachable"] == 2
    assert out["srcA"]["ai_api"] == 1
    # srcB：1 通过但无 AI 证据 ⇒ 三项记 0 而非缺键（「无证据」与「零」可区分）
    assert out["srcB"] == {"tested": 2, "passed": 1,
                           "ai_tested": 0, "ai_reachable": 0, "ai_api": 0}
    # 排序不变量：通过数降序
    assert list(out) == ["srcA", "srcB"]


def test_agg_source_ai_ignores_ai_on_unverified_nodes():
    """回归防线：未通过节点的 ai 数据（若存在）不得计入分源 AI 口径——
    证据收集只对通过节点执行，防未来误接线把死节点算成源效率。"""
    nodes = [{"src": "srcA", "probe_name": "a1"}]
    verified: list[dict] = []                    # 全部未通过
    results = {"a1": {"ok": False,
                      "ai": {"ai_reachable": True, "ai_api": True}}}
    out = cn_probe._agg_source_ai(nodes, verified, results)
    assert out["srcA"] == {"tested": 1, "passed": 0,
                           "ai_tested": 0, "ai_reachable": 0, "ai_api": 0}


def test_report_node_record_keeps_src_field():
    """回归：报告 nodes 记录必须保留 src 字段（供溯源与未来按源回放）。

    曾遗漏 src，导致报告 nodes 全无源归属，但 counts.by_source 仍有数据——
    这是隐蔽不一致，故固化该不变量。
    """
    n = {"fp": "abc", "name": "n1", "origin": "pending", "final": True,
         "us_ok": True, "src": "SHUNzi88/proxysub", "probe_name": "p0"}
    rec = {"fp": n["fp"], "name": n["name"], "origin": n["origin"],
           "final": n["final"], "us_ok": n["us_ok"], "src": n.get("src")}
    assert rec["src"] == "SHUNzi88/proxysub"


def test_auth_selfcheck_falls_back_to_persisted_pat(monkeypatch, tmp_path):
    """回归（2026-10-15 复盘）：环境变量无 token 时，应自动从持久化 PAT 兜底。

    背景：曾因 env 为空而误判"没有 token"。现要求 env 缺失时自动读 PERSISTED_PAT_PATH。
    """
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    pat = tmp_path / "github_pat"
    pat.write_text("ghp_from_file\n", encoding="utf-8")
    monkeypatch.setattr(cn_probe, "PERSISTED_PAT_PATH", str(pat))
    with mock.patch.object(
        cn_probe, "run",
        return_value=subprocess.CompletedProcess(["gh"], 0, stdout="ok", stderr=""),
    ):
        assert cn_probe.auth_selfcheck() is True
    # 兜底成功后应写回环境变量，供后续 gh/curl 调用复用
    assert cn_probe.os.environ.get("GH_TOKEN") == "ghp_from_file"


def test_auth_selfcheck_no_token_anywhere(monkeypatch, tmp_path):
    """回归：env 与持久化文件均无 token 时，才判失败（且不误判为"没有 token"）。"""
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        cn_probe, "PERSISTED_PAT_PATH", str(tmp_path / "not_exist"))
    assert cn_probe.auth_selfcheck() is False


def test_auth_selfcheck_gh_status_failure(monkeypatch):
    """GH_TOKEN 存在但 gh auth status 失败（如 401 失效）应判失败。"""
    monkeypatch.setenv("GH_TOKEN", "ghp_dummy")
    with mock.patch.object(
        cn_probe, "run",
        return_value=subprocess.CompletedProcess(
            ["gh"], 1, stdout="", stderr="graphql: 401 Unauthorized"),
    ):
        assert cn_probe.auth_selfcheck() is False


def test_auth_selfcheck_ok(monkeypatch):
    """GH_TOKEN 存在且 gh auth status 成功应判通过。"""
    monkeypatch.setenv("GH_TOKEN", "ghp_dummy")
    with mock.patch.object(
        cn_probe, "run",
        return_value=subprocess.CompletedProcess(
            ["gh"], 0, stdout="Logged in to github.com", stderr=""),
    ):
        assert cn_probe.auth_selfcheck() is True


def test_gh_download_falls_back_to_curl(monkeypatch, tmp_path):
    """回归（grok 2.4）：gh 失败时应自动回退 curl 并成功下载。"""
    dest = tmp_path / "asset.json"
    calls = {"n": 0}

    def fake_run(cmd, **kw):
        calls["n"] += 1
        if cmd[0] == "gh":
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="timeout")
        # curl 回退：真写一个文件模拟下载成功
        dest.write_text('{"ok": true}')
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setenv("GH_TOKEN", "ghp_dummy")
    with mock.patch.object(cn_probe, "run", side_effect=fake_run):
        assert cn_probe.gh_download("sub", "asset.json", str(dest)) is True
    assert dest.exists()
    assert calls["n"] == 2  # gh 一次 + curl 一次


def test_gh_download_timeout_falls_back_to_curl(monkeypatch, tmp_path):
    """回归（2026-10-16）：gh 挂起表现为抛 TimeoutExpired 异常，而非非零返回码。

    早期实现只判 returncode、未捕获该异常，于是一次网络抖动就让 gh_download
    抛异常、整脚本崩溃，curl 回退永不执行——导致 pending_probe.json / 主资产
    等关键下载静默失败，carryover=0、实测集也发不出。本测试钉死「gh 超时
    也必须回退 curl 并成功」。
    """
    dest = tmp_path / "asset.json"
    calls = {"n": 0}

    def fake_run(cmd, **kw):
        calls["n"] += 1
        if cmd[0] == "gh":
            # 真实场景：gh 长时间挂起 -> subprocess 超时抛异常
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 90))
        dest.write_text('{"ok": true}')
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setenv("GH_TOKEN", "ghp_dummy")
    with mock.patch.object(cn_probe, "run", side_effect=fake_run):
        assert cn_probe.gh_download("sub", "asset.json", str(dest)) is True
    assert dest.exists()
    assert calls["n"] == 2  # gh(超时异常) 一次 + curl 一次


def test_gh_download_both_fail_returns_false(monkeypatch, tmp_path):
    """gh 与 curl 均失败应返回 False，不误判成功。"""
    dest = tmp_path / "asset.json"
    monkeypatch.setenv("GH_TOKEN", "ghp_dummy")
    with mock.patch.object(
        cn_probe, "run",
        return_value=subprocess.CompletedProcess(["x"], 1, stdout="", stderr=""),
    ):
        assert cn_probe.gh_download("sub", "asset.json", str(dest)) is False
    assert not dest.exists()


def test_report_declares_dimension_semantics():
    """回归（口径修正 #5）：报告须显式声明 us_ok / cn.ok 语义不同。

    us_ok（美西拨测可达性）与 cn.ok（中国实测可用性）是两次不同测量，
    探测目标/判定标准不同，但历史文档中常被并列误读为同一维度的两次观测。
    故在报告里加入 dimensions 说明块，固化"不可互相替代或合并统计"这一口径。
    """
    import inspect
    src = inspect.getsource(cn_probe.main)
    assert '"dimensions"' in src, "报告须含 dimensions 语义说明块"
    assert '"us_ok"' in src and "美西" in src
    assert '"cn_ok"' in src and "中国" in src
    assert "不可互相替代" in src or "note" in src


# ---------------------------------------------------------------- real_traffic_test
class _FakeResp:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, n=-1):
        return self._body[:n] if n > 0 else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_real_traffic_test_download_ok(monkeypatch):
    """回归（2026-10-17 收紧）：真实流量闸门改为硬超时真实下载，预算内下载量
    达 REAL_MIN_BYTES 时应判为可用；下载目标必须是 speed.cloudflare.com 真实数据。"""
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: True)
    captured = {}

    def _fake_download(proxy, url, timeout, min_bytes):
        captured["url"] = url
        captured["timeout"] = timeout
        captured["min_bytes"] = min_bytes
        return min_bytes  # 恰好达到阈值

    monkeypatch.setattr(cn_probe, "_timed_download", _fake_download)
    res = cn_probe.real_traffic_test(9097, 7897, "node-x")
    assert res["ok"] is True
    assert res["bytes"] >= cn_probe.REAL_MIN_BYTES
    assert "speed.cloudflare.com" in captured["url"]


def test_real_traffic_test_slow_node_rejected(monkeypatch):
    """回归（2026-10-17）：能握手但下载龟速/不足阈值的节点必须剔除——
    这是旧「几行字 + 403 兜底」判据漏放、用户本地实测暴露无效的那类伪可用。"""
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: True)
    monkeypatch.setattr(cn_probe, "_timed_download",
                        lambda *a, **k: cn_probe.REAL_MIN_BYTES - 1)
    res = cn_probe.real_traffic_test(9097, 7897, "node-x")
    assert res["ok"] is False


def test_real_traffic_test_degraded_tier(monkeypatch):
    """双档闸门（任务#97）：下载量在 [REAL_SLOW_MIN_BYTES, REAL_MIN_BYTES)
    区间时判 degraded=True（能连但慢），ok 恒 False——不进主资产但汇入
    第二资产；低于慢档阈值则无 degraded 标记。"""
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: True)
    # 慢档区间内 → degraded
    monkeypatch.setattr(cn_probe, "_timed_download",
                        lambda *a, **k: cn_probe.REAL_SLOW_MIN_BYTES)
    res = cn_probe.real_traffic_test(9097, 7897, "node-x")
    assert res["ok"] is False and res["degraded"] is True
    assert res["bytes"] == cn_probe.REAL_SLOW_MIN_BYTES
    # 快档下限-1 仍属慢档
    monkeypatch.setattr(cn_probe, "_timed_download",
                        lambda *a, **k: cn_probe.REAL_MIN_BYTES - 1)
    res = cn_probe.real_traffic_test(9097, 7897, "node-x")
    assert res["ok"] is False and res["degraded"] is True
    # 低于慢档阈值 → 彻底失败，无 degraded 标记
    monkeypatch.setattr(cn_probe, "_timed_download",
                        lambda *a, **k: cn_probe.REAL_SLOW_MIN_BYTES - 1)
    res = cn_probe.real_traffic_test(9097, 7897, "node-x")
    assert res["ok"] is False and "degraded" not in res


def test_real_traffic_test_all_unreachable_returns_false(monkeypatch):
    """所有真实流量目标均不可达（下载 0 字节）时，必须返回失败，禁止假阳性。"""
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: True)
    monkeypatch.setattr(cn_probe, "_timed_download", lambda *a, **k: 0)
    res = cn_probe.real_traffic_test(9097, 7897, "node-x")
    assert res["ok"] is False


def test_real_traffic_test_api_put_failure_returns_false(monkeypatch):
    """若 mihomo API 切换节点失败，真实流量测试直接失败。"""
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: False)
    res = cn_probe.real_traffic_test(9097, 7897, "node-x")
    assert res["ok"] is False


# ---------------------------------------------------------------- AI 可达性探测
# 2026-10-20：沙箱诊断发现 29 个已发布节点中 13 个对全部 AI 域无响应，
# 而既有闸门只测 Google/Cloudflare——新增 AI 维度探测（不构成闸门）。
def test_ai_targets_use_root_paths():
    """回归（v1 诊断坑③）：探针 URL 必须是站点根路径——早期用
    /cdn-cgi/trace，非 Cloudflare 站点（gemini/copilot）没有该路径，
    404 被误读为「不可达」。且 openai_api 必须打 /v1/models（有判据价值）。"""
    assert set(cn_probe.AI_TARGETS) == {
        "chatgpt", "claude", "gemini", "copilot", "openai_api"}
    for label, url in cn_probe.AI_TARGETS.items():
        assert url.startswith("https://"), label
        assert "cdn-cgi" not in url, label
    assert cn_probe.AI_TARGETS["openai_api"].endswith("/v1/models")


def test_classify_ai_all_none_is_unreachable():
    codes = {k: None for k in cn_probe.AI_TARGETS}
    out = cn_probe.classify_ai(codes)
    assert out["ai_reachable"] is False
    assert out["ai_api"] is False
    assert out["reach"] == []


def test_classify_ai_403_counts_as_reachable():
    """403（Cloudflare 区域拦截）是有效响应 = 可达，但不是 API 可用——
    chatgpt 403 与 api.openai.com 401 必须分开判（v1 诊断坑②）。"""
    out = cn_probe.classify_ai({"chatgpt": 403})
    assert out["ai_reachable"] is True
    assert out["ai_api"] is False
    assert out["reach"] == ["chatgpt"]


def test_classify_ai_openai_401_means_api_ok():
    """api.openai.com 返回 401（无密钥的正常响应）⇒ API 层未被区域封锁，
    是「真 AI 可用」的最强信号。"""
    out = cn_probe.classify_ai({"chatgpt": 403, "openai_api": 401})
    assert out["ai_reachable"] is True
    assert out["ai_api"] is True


def test_classify_ai_openai_403_means_api_blocked():
    out = cn_probe.classify_ai({"openai_api": 403})
    assert out["ai_reachable"] is True   # 有响应
    assert out["ai_api"] is False        # 但 API 层被区域封锁


def test_http_status_via_proxy_returns_error_code(monkeypatch):
    """HTTPError（401/403 等）必须返回真实状态码而非 None——用 urllib 的
    抛异常路径判失败正是 v1 诊断失真的原因之一。"""

    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def _fake_opener(*a, **k):
        class _O:
            def open(self, req, timeout=None):
                raise urllib.error.HTTPError(
                    req.full_url, 401, "Unauthorized", {}, None)
        return _O()

    import urllib.error
    monkeypatch.setattr(cn_probe.urllib.request, "build_opener", _fake_opener)
    assert cn_probe._http_status_via_proxy(
        "https://api.openai.com/v1/models", "http://127.0.0.1:7897", 8) == 401


def test_http_status_via_proxy_success_status(monkeypatch):
    import urllib.error  # noqa: F401  （与失败路径保持同一导入面）

    class _Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def _fake_opener(*a, **k):
        class _O:
            def open(self, req, timeout=None):
                return _Resp()
        return _O()

    monkeypatch.setattr(cn_probe.urllib.request, "build_opener", _fake_opener)
    assert cn_probe._http_status_via_proxy(
        "https://chatgpt.com/", "http://127.0.0.1:7897", 8) == 200


def test_http_status_via_proxy_timeout_returns_none(monkeypatch):
    """连接失败/超时 = 无响应 = None（与 403 严格区分）。"""
    def _fake_opener(*a, **k):
        class _O:
            def open(self, req, timeout=None):
                raise TimeoutError("timed out")
        return _O()

    monkeypatch.setattr(cn_probe.urllib.request, "build_opener", _fake_opener)
    assert cn_probe._http_status_via_proxy(
        "https://chatgpt.com/", "http://127.0.0.1:7897", 8) is None


def test_verified_rank_ai_first_then_vantage_then_latency():
    """排序：AI API 可用 > AI 可达 > 无数据；同级内保持原「双 vantage
    强者 + 低延迟」序。AI 维度只影响排序、不淘汰（无硬闸门）。"""
    node = {"probe_name": "x", "us_ok": True, "final": True}

    def results(ai):
        return {"x": {"ok": True, "latency_ms": 100, "ai": ai}}

    r_api = cn_probe.verified_rank(node, results({"ai_api": True}))
    r_reach = cn_probe.verified_rank(node, results({"ai_reachable": True}))
    r_none = cn_probe.verified_rank(node, results({}))
    r_missing = cn_probe.verified_rank(
        node, {"x": {"ok": True, "latency_ms": 100}})
    assert r_api < r_reach < r_none == r_missing
    # 次级判据（任务#96）：双 vantage 强者 > carryover 复测存活 > 仅本轮新通过
    weak = {"probe_name": "y", "us_ok": False, "final": False, "origin": "pending"}
    assert cn_probe.verified_rank(node, results({"ai_reachable": True})) < \
        cn_probe.verified_rank(weak, results({"ai_reachable": True}))
    survivor = {"probe_name": "s", "us_ok": False, "final": True, "origin": "carryover"}
    assert cn_probe.verified_rank(survivor, results({"ai_reachable": True})) < \
        cn_probe.verified_rank(weak, results({"ai_reachable": True}))
    slow = {"probe_name": "z", "us_ok": True, "final": True, "origin": "pending"}
    res_slow = {"z": {"ok": True, "latency_ms": 900, "ai": {}}}
    res_fast = {"z": {"ok": True, "latency_ms": 10, "ai": {}}}
    assert cn_probe.verified_rank(slow, res_fast) < cn_probe.verified_rank(slow, res_slow)


def test_report_includes_ai_fields():
    """报告契约：dimensions.ai 语义说明 + counts.ai 统计 + nodes[].ai 字段
    均为新增增量字段，CI 侧（evolution.py）只读既有键，不受影响。"""
    src = open(cn_probe.__file__, encoding="utf-8").read()
    assert '"ai": ' in src and 'ai_reachable' in src
    assert 'EVIDENCE_BUDGET_S' in src and 'EVIDENCE_CONCURRENCY' in src
    assert 'def node_evidence' in src      # 任务#91：GEO+AI 单次切组合并
    # 旧顺序循环（各 120s 预算、各覆盖一半节点）已下线，禁止复活
    assert 'def exit_evidence' not in src and 'def ai_probe' not in src


def test_verified_rank_prefers_higher_measured_bytes():
    """2026-10-24：同 AI/同 vantage 档位内，实测下载量高者排前（速度代理）。"""
    fast = {"probe_name": "f", "us_ok": False, "final": True, "origin": "carryover"}
    slow = {"probe_name": "s", "us_ok": False, "final": True, "origin": "carryover"}
    rf = {"f": {"ok": True, "latency_ms": 900,
                "real_traffic": {"ok": True, "bytes": 900 * 1024}, "ai": {}}}
    rs = {"s": {"ok": True, "latency_ms": 900,
                "real_traffic": {"ok": True, "bytes": 300 * 1024}, "ai": {}}}
    assert cn_probe.verified_rank(fast, rf) < cn_probe.verified_rank(slow, rs)
    # 无测速数据者不因缺字段报错，按 0 处理排后
    rn = {"n": {"ok": True, "latency_ms": 900, "ai": {}}}
    no_rt = {"probe_name": "n", "us_ok": False, "final": True, "origin": "carryover"}
    assert cn_probe.verified_rank(fast, rf) < cn_probe.verified_rank(no_rt, rn)


def test_real_min_bytes_threshold_tightened():
    """2026-10-24 实证改判：快档门槛 ≥768KB/8s（≈96KB/s），31KB/s 旧口径
    在沙箱判通过、用户本地不可用。慢档（AI 提级路径）保持 32KB 不变。"""
    assert cn_probe.REAL_MIN_BYTES >= 768 * 1024
    assert cn_probe.REAL_SLOW_MIN_BYTES == 32 * 1024
    assert cn_probe.CN_MAX_PUBLISH_LATENCY_MS == 2500
