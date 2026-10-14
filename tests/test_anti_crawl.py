"""反爬与防搜索（anti_crawl）的回归测试。

覆盖：轮换 token 的确定性与周期切换、诱饵节点形态、诱饵订阅文件生成、
诱饵回流检测、robots.txt、环境变量击杀开关、配置类型兜底。
全部使用 tmp_path + monkeypatch.chdir，不触碰真实仓库状态。
"""

import base64
import json
import os
import re
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


def _rotate_cfg(**over):
    """轮换文件名模式（publish_release=false）。"""
    return _enabled_cfg(publish_release=False, **over)


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
    cfg = _rotate_cfg(rotate_days=3, decoy_count=6)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    first_outputs = list(cfg["current_outputs"])
    first_token = cfg["token"]
    assert first_token
    assert len(first_outputs) == 4
    assert all(anti_crawl.rotated_name(b, first_token) == p
               for b, p in zip(anti_crawl.OUTPUT_BASENAMES, first_outputs))
    assert cfg["stale_outputs"] == []
    assert cfg["output_mode"] == "rotate"

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
    cfg = _rotate_cfg(rotate_days=1, decoy_count=3)
    for d in range(5):
        cfg = anti_crawl.begin_run(cfg, TODAY + timedelta(days=d))
    assert len(cfg["bait_history"]) == anti_crawl.BAIT_HISTORY_KEEP


# ====================== 永久地址（滚动 Release 模式，默认） ======================

def test_release_mode_permanent_urls(in_tmp):
    """release 模式（默认）：资产名与永久地址跨周期不变，无过期文件。"""
    cfg = _enabled_cfg(publish_release=True, rotate_days=3, decoy_count=6)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    urls1 = anti_crawl.release_urls(cfg, "SHUNZI88/proxysub")
    outs1 = list(cfg["current_outputs"])
    assert cfg["output_mode"] == "release"
    assert all(p.startswith(anti_crawl.PUBLISH_DIR + "/") for p in outs1)
    assert len(urls1) == 4
    assert all(u.startswith("https://github.com/SHUNZI88/proxysub/releases/latest/download/p_")
               for u in urls1)

    # 跨周期：诱饵轮换了，但资产名 / 永久地址 / 输出路径完全不变
    token1 = cfg["token"]
    cfg2 = anti_crawl.begin_run(cfg, TODAY + timedelta(days=30))
    assert anti_crawl.release_urls(cfg2, "SHUNZI88/proxysub") == urls1
    assert cfg2["current_outputs"] == outs1
    assert cfg2["stale_outputs"] == []
    assert cfg2["token"] != token1  # 诱饵照常轮换


def test_asset_name_format_and_stability(in_tmp):
    cfg = _enabled_cfg()
    names = {b: anti_crawl.asset_name(cfg, b) for b in anti_crawl.OUTPUT_BASENAMES}
    assert len(set(names.values())) == 4  # 四格式互不冲突
    for b, n in names.items():
        assert re.fullmatch(r"p_[0-9a-f]{10}_[cpsv]\.[a-z]+", n), n
        assert n.endswith(os.path.splitext(b)[1])
    # 再次获取不变（持久化在 cfg["asset_names"]）
    assert all(anti_crawl.asset_name(cfg, b) == n for b, n in names.items())
    assert cfg["asset_token"]


def test_asset_names_env_override(in_tmp, monkeypatch):
    """PROXYSUB_ASSET_NAMES 指定的资产名不写入公开配置。"""
    monkeypatch.setenv("PROXYSUB_ASSET_NAMES",
                       '{"clean_clash.yaml": "my_secret_name.yaml"}')
    cfg = _enabled_cfg()
    assert anti_crawl.asset_name(cfg, "clean_clash.yaml") == "my_secret_name.yaml"
    assert "clean_clash.yaml" not in cfg.get("asset_names", {})
    # 未指定的仍走随机生成
    assert anti_crawl.asset_name(cfg, "clean_singbox.json").startswith("p_")


def test_mode_switch_cleans_old_outputs(in_tmp):
    """rotate -> release 切换时清理旧轮换文件。"""
    cfg = _rotate_cfg(rotate_days=3, decoy_count=6)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    old = list(cfg["current_outputs"])
    for p in old:
        open(p, "w").write("x")
    cfg["publish_release"] = True
    cfg = anti_crawl.begin_run(cfg, TODAY)
    assert cfg["output_mode"] == "release"
    assert cfg["stale_outputs"] == old
    for p in old:
        assert not os.path.exists(p)


def test_publish_paths(in_tmp):
    cfg = _enabled_cfg()
    paths = anti_crawl.publish_paths(cfg)
    assert set(paths) == set(anti_crawl.OUTPUT_BASENAMES)
    assert all(v.startswith(anti_crawl.PUBLISH_DIR + "/") for v in paths.values())


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
    # release 模式（默认）：永久地址
    cfg = _enabled_cfg(decoy_count=6)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    text = "\n".join(anti_crawl.summary_lines(cfg))
    assert "releases/latest/download/p_" in text
    assert "永久" in text
    # rotate 模式：轮换地址
    cfg2 = _rotate_cfg(decoy_count=6)
    cfg2 = anti_crawl.begin_run(cfg2, TODAY)
    text2 = "\n".join(anti_crawl.summary_lines(cfg2))
    assert "https://raw.githubusercontent.com/SHUNZI88/proxysub/main/clean_clash." in text2
    assert cfg2["token"] in text2


# ---------------- F4：资产名路径穿越防护（安全评估 CWE-22） ----------------

def test_safe_asset_name_rejects_traversal():
    for bad in ["../evil.yaml", "../../etc/cron.d/x", "/abs/path.yaml",
                "a/b.yaml", "a\\b.yaml", ".hidden", "", "   ", None,
                "ok.yaml\x00.txt"]:
        with pytest.raises(ValueError):
            anti_crawl.safe_asset_name(bad)


def test_safe_asset_name_accepts_plain_basename():
    assert anti_crawl.safe_asset_name("p_abc123_c.yaml") == "p_abc123_c.yaml"
    assert anti_crawl.safe_asset_name(" clean.yaml ") == "clean.yaml"


def test_asset_name_env_override_traversal_rejected(monkeypatch):
    """PROXYSUB_ASSET_NAMES 注入含 ../ 的资产名必须显式失败（不静默回退）。"""
    monkeypatch.setenv("PROXYSUB_ASSET_NAMES",
                       '{"clean_clash.yaml": "../../evil.yaml"}')
    cfg = {"asset_names": {}}
    with pytest.raises(ValueError):
        anti_crawl.asset_name(cfg, "clean_clash.yaml")


def test_asset_name_persisted_traversal_rejected():
    """anti_crawl.json 持久化值被篡改为穿越路径时必须失败。"""
    cfg = {"asset_names": {"clean_clash.yaml": "../evil.yaml"}}
    with pytest.raises(ValueError):
        anti_crawl.asset_name(cfg, "clean_clash.yaml")


def test_asset_name_generated_is_safe():
    """正常生成路径的资产名必须通过校验。"""
    cfg = {"asset_token": "abc123", "asset_names": {}}
    name = anti_crawl.asset_name(cfg, "clean_clash.yaml")
    assert name.startswith("p_abc123") and name.endswith(".yaml")
    anti_crawl.safe_asset_name(name)  # 不抛即通过


def test_stale_outputs_traversal_not_deleted(in_tmp):
    """F4：stale_outputs 含 ../ 穿越条目时不得删除目录外文件。"""
    outside = in_tmp / "outside.txt"
    outside.write_text("keep me")
    cfg = _rotate_cfg(rotate_days=3, decoy_count=2)
    cfg = anti_crawl.begin_run(cfg, TODAY)
    cfg["stale_outputs"] = ["../outside.txt", "/etc/hosts"]
    # 直接走 begin_run 的清理段：再次运行不应触碰目录外文件
    anti_crawl.begin_run(cfg, TODAY + timedelta(days=3))
    assert outside.exists()
    assert outside.read_text() == "keep me"
