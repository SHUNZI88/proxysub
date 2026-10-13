"""反爬与防搜索（anti_crawl）的回归测试。

覆盖：轮换 token 的确定性与周期切换、诱饵节点形态、诱饵订阅文件生成、
诱饵回流检测、robots.txt、环境变量击杀开关、配置类型兜底。
全部使用 tmp_path + monkeypatch.chdir，不触碰真实仓库状态。
"""

import base64
import json
import os
from datetime import date, timedelta

import pytest
import yaml

import anti_crawl
import common
import filter_clash as fc


TODAY = date(2026, 10, 13)


@pytest.fixture
def in_tmp(tmp_path, monkeypatch):
    """在临时目录中运行（anti_crawl 全部基于 CWD 的相对路径）。"""
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _enabled_cfg(**over):
    cfg = anti_crawl.default_config()
    cfg.update({"enabled": True, "token_seed": "seed-for-test", "token": ""})
    cfg.update(over)
    return cfg


# ====================== 开关与配置 ======================

def test_default_disabled(in_tmp):
    cfg = anti_crawl.load_config()
    assert cfg["enabled"] is False
    assert anti_crawl.is_enabled(cfg) is False


def test_env_kill_switch(in_tmp, monkeypatch):
    monkeypatch.setenv("PROXYSUB_ANTI_CRAWL", "0")
    cfg = _enabled_cfg()
    assert anti_crawl.is_enabled(cfg) is False


def test_load_config_type_fallback(in_tmp):
    """手误/损坏的字段回退默认值，不崩溃。"""
    anti_crawl.save_json(anti_crawl.CONFIG_FILE, {
        "enabled": True, "rotate_days": "abc", "decoy_count": None,
        "bait_host": "", "bait_nodes": "not-a-list", "token_seed": "s",
    })
    cfg = anti_crawl.load_config()
    assert cfg["rotate_days"] == anti_crawl.DEFAULT_ROTATE_DAYS
    assert cfg["decoy_count"] == anti_crawl.DEFAULT_DECOY_COUNT
    assert cfg["bait_host"] == anti_crawl.DEFAULT_BAIT_HOST
    assert cfg["bait_nodes"] == []


# ====================== 轮换 token 与文件名 ======================

def test_rotate_token_stable_within_epoch(in_tmp):
    cfg = _enabled_cfg(rotate_days=3)
    t0 = anti_crawl.rotate_token(cfg, TODAY)
    assert anti_crawl.rotate_token(cfg, TODAY + timedelta(days=2)) == t0
    assert anti_crawl.rotate_token(cfg, TODAY + timedelta(days=3)) != t0


def test_rotated_name_format(in_tmp):
    assert anti_crawl.rotated_name("clean_clash.yaml", "abc123") == "clean_clash.abc123.yaml"
    assert anti_crawl.rotated_name("clean_singbox.json", "abc123") == "clean_singbox.abc123.json"
    assert anti_crawl.rotated_name("clean_v2ray.txt", "abc123") == "clean_v2ray.abc123.txt"


def test_make_namer(in_tmp):
    cfg = _enabled_cfg(token="tok")
    namer = anti_crawl.make_namer(cfg)
    assert namer("clean_clash.yaml") == "clean_clash.tok.yaml"


# ====================== 诱饵节点与诱饵订阅 ======================

def test_decoy_nodes_shape(in_tmp):
    cfg = _enabled_cfg(decoy_count=9, bait_host="my.bait.example")
    nodes = anti_crawl.gen_decoy_nodes(9, "TOK", cfg)
    assert len(nodes) == 9
    types = [n["type"] for n in nodes]
    assert set(types) == {"vless", "trojan", "hysteria2"}
    for i, n in enumerate(nodes):
        assert n["name"].startswith(anti_crawl.BAIT_TAG)
        assert "TOK" in n["name"]
        assert n["server"].endswith(".my.bait.example")
        assert n["port"] == 443
        if n["type"] == "vless":
            assert common.UUID_RE.match(n["uuid"])
            assert common.X25519_PUBLIC_KEY_RE.match(n["reality-opts"]["public-key"])
            assert common.SHORT_ID_RE.match(n["reality-opts"]["short-id"])
        else:
            assert n["password"]


def test_decoy_config_structure(in_tmp):
    cfg = _enabled_cfg(decoy_count=6)
    nodes = anti_crawl.gen_decoy_nodes(6, "TOK", cfg)
    conf = anti_crawl.build_decoy_config(nodes)
    assert len(conf["proxies"]) == 6
    assert conf["rules"][-1] == "MATCH,🚀 节点选择"
    assert any(g["type"] == "url-test" for g in conf["proxy-groups"])
    # 必须可被 yaml 序列化（爬虫按文本形态判断）
    text = yaml.dump(conf, allow_unicode=True)
    assert "proxies" in text


def test_write_decoy_outputs(in_tmp):
    """诱饵写 4 个固定名文件，且与真实输出完全同构（可被正常解析）。"""
    cfg = _enabled_cfg(decoy_count=12)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    stat = anti_crawl.write_decoy_outputs(cfg)
    assert stat["total"] == 12
    assert stat["proxies_only"] == 12
    assert stat["singbox"] == 12
    assert stat["links"] == 12

    clash = yaml.safe_load(open("clean_clash.yaml", encoding="utf-8"))
    assert len(clash["proxies"]) == 12
    assert all(p["name"].startswith(anti_crawl.BAIT_TAG) for p in clash["proxies"])

    po = yaml.safe_load(open("clean_proxies_only.yaml", encoding="utf-8"))
    assert len(po["proxies"]) == 12

    sb = json.load(open("clean_singbox.json", encoding="utf-8"))
    assert len(sb["outbounds"]) == 13  # 12 + direct
    assert sb["outbounds"][-1]["type"] == "direct"

    raw = open("clean_v2ray.txt", encoding="utf-8").read().strip()
    links = base64.b64decode(raw).decode().splitlines()
    assert len(links) == 12
    assert all(l.startswith(("vless://", "trojan://", "hysteria2://")) for l in links)


# ====================== begin_run 轮换推进 ======================

def test_begin_run_rotation_and_cleanup(in_tmp):
    cfg = _enabled_cfg(rotate_days=3, decoy_count=6)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    first_outputs = list(cfg["current_outputs"])
    first_token = cfg["token"]
    assert first_token
    assert len(first_outputs) == 4
    assert all(anti_crawl.rotated_name(b, first_token) == p
               for b, p in zip(anti_crawl.OUTPUT_BASENAMES, first_outputs))
    assert cfg["stale_outputs"] == []

    # 同周期再跑：token / 输出名 / 诱饵都不变
    cfg2 = anti_crawl.begin_run(cfg, TODAY + timedelta(days=1))
    assert cfg2["token"] == first_token
    assert cfg2["current_outputs"] == first_outputs
    assert cfg2["bait_nodes"] == cfg["bait_nodes"]

    # 跨周期：旧输出名进入 stale、真实文件被删除、token 更换
    for p in first_outputs:
        open(p, "w").write("x")
    cfg3 = anti_crawl.begin_run(cfg2, TODAY + timedelta(days=3))
    assert cfg3["token"] != first_token
    assert cfg3["stale_outputs"] == first_outputs
    for p in first_outputs:
        assert not os.path.exists(p)
    assert len(cfg3["bait_history"]) == 2


def test_begin_run_disabled_no_side_effect(in_tmp):
    cfg = anti_crawl.default_config()
    out = anti_crawl.begin_run(cfg, TODAY)
    assert out is cfg  # 原样返回，不落盘
    assert not os.path.exists(anti_crawl.CONFIG_FILE)
    assert not os.path.exists(anti_crawl.ROBOTS_FILE)


def test_bait_history_capped(in_tmp):
    cfg = _enabled_cfg(rotate_days=1, decoy_count=3)
    for d in range(5):
        cfg = anti_crawl.begin_run(cfg, TODAY + timedelta(days=d))
    assert len(cfg["bait_history"]) == anti_crawl.BAIT_HISTORY_KEEP


# ====================== 诱饵回流检测 ======================

def test_bait_fingerprints(in_tmp):
    cfg = _enabled_cfg(decoy_count=6)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    fps = anti_crawl.bait_fingerprints(cfg, common.fingerprint)
    assert len(fps) == 6


def test_detect_bait_reuse(in_tmp):
    cfg = _enabled_cfg(decoy_count=6)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    bait = cfg["bait_nodes"][0]
    fps = anti_crawl.bait_fingerprints(cfg, common.fingerprint)
    staged = {
        "https://evil.example/sub.yaml": [dict(bait)],                      # 转载诱饵
        "https://good.example/sub.yaml": [
            {"name": "ok", "type": "trojan", "server": "1.2.3.4", "port": 443,
             "password": "pw", "sni": "a.com"},
        ],
    }
    flags = fc.detect_bait_reuse(staged, fps, common.fingerprint)
    assert flags == {"https://evil.example/sub.yaml": ["bait_reuse"]}
    # 空指纹集合 -> 不检测
    assert fc.detect_bait_reuse(staged, set(), common.fingerprint) == {}


def test_detect_bait_reuse_ignores_bad_node(in_tmp):
    """指纹计算异常的节点不会让检测崩溃。"""
    fps = {"x"}
    staged = {"u": [{"name": "broken"}]}  # 无 server/port，fingerprint 仍可算；确保无异常路径
    flags = fc.detect_bait_reuse(staged, fps, common.fingerprint)
    assert flags == {}


# ====================== robots / summary ======================

def test_write_robots(in_tmp):
    path = anti_crawl.write_robots(".")
    assert os.path.exists(path)
    text = open(path, encoding="utf-8").read()
    assert "User-agent: *" in text
    assert "Disallow: /" in text


def test_summary_lines(in_tmp, monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "SHUNZI88/proxysub")
    cfg = _enabled_cfg(decoy_count=6)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    lines = anti_crawl.summary_lines(cfg)
    text = "\n".join(lines)
    assert "https://raw.githubusercontent.com/SHUNZI88/proxysub/main/clean_clash." in text
    assert cfg["token"] in text
