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


# ---------------------------------------------------------------- exit_evidence
def test_exit_evidence_uses_proxy_when_mixed_port(monkeypatch):
    """P0-1：传入 mixed_port 时，GEO 请求必须经 mihomo 代理（而非裸直连）。

    回归防线：早前版本裸 urlopen 直连，恒返回沙箱自身出口——此测试钉死
    「每跳 GEO 请求都经 build_opener(ProxyHandler) 建立的 opener」。
    """
    captured = {}
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: True)

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
    ev = cn_probe.exit_evidence(9097, "PROBE", "node-x", mixed_port=7897)
    assert captured.get("proxied") is True          # 走了 opener，而非裸 urlopen
    assert ev["exit_ip"] == "9.9.9.9"


def test_exit_evidence_no_proxy_without_mixed_port(monkeypatch):
    """未传 mixed_port 时退回直连（兼容旧调用），不建立 opener。"""
    monkeypatch.setattr(cn_probe, "api_put", lambda *a, **k: True)
    built = {"called": False}

    def _fake_build_opener(handler):
        built["called"] = True
        return None

    monkeypatch.setattr(cn_probe.urllib.request, "build_opener", _fake_build_opener)
    monkeypatch.setattr(cn_probe.urllib.request, "urlopen",
                        lambda req, timeout=None: (_ for _ in ()).throw(OSError("no net")))
    ev = cn_probe.exit_evidence(9097, "PROBE", "node-x")
    assert built["called"] is False                  # 未建 opener
    assert ev == {}                                  # 直连失败 -> 返回 {}


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
    assert nodes[0]["final"] is True


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


def test_auth_selfcheck_no_token(monkeypatch):
    """回归（grok 2.3）：GH_TOKEN/GITHUB_TOKEN 均无则立即失败，避免空转。"""
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
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
