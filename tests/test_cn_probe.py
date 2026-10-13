"""scripts/cn_probe.py 纯函数测试：地理证据解析、去重、验证集配置构建。"""

import json
import os

import pytest
import yaml

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
                    if g["name"] == cn_probe.common.INSECURE_GROUP)
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
