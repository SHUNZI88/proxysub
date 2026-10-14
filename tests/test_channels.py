"""多渠道搜集（Telegram / 网页 / 静态源）与 vless 解析的回归测试。

通过 monkeypatch ``channels.requests.get`` 模拟外部抓取，避免真实网络请求。
另 mock ``net_safety.socket.getaddrinfo`` 返回公网 IP，使 SSRF 落点校验
（安全评估 F1）在测试中放行这些示例主机——校验逻辑本身由
``tests/test_net_safety.py`` 专项覆盖。
"""

import os

import pytest
import yaml

import channels
import common
import net_safety
from safe_io import save_json


def _write_channels(tmp_path, payload):
    save_json(str(tmp_path / channels.CHANNELS_FILE), payload)


class FakeResp:
    def __init__(self, text, status=200):
        self.status_code = status
        self.text = text
        self.content = text.encode("utf-8")
        self.encoding = "utf-8"
        self.apparent_encoding = "utf-8"


def _proxies_yaml(n=25):
    proxies = [
        {"name": f"n{i}", "type": "trojan", "server": f"1.2.{i}.4", "port": 443,
         "password": "pw", "sni": "example.com"}
        for i in range(n)
    ]
    return yaml.safe_dump({"proxies": proxies}, allow_unicode=True)


TG_HTML = """
<div class="tgme_widget_message_text">
免费节点订阅：https://raw.githubusercontent.com/foo/bar/main/clash.yaml
备用：https://example.com/sub/abc123
vless://uuid-1@1.1.1.1:443?encryption=none&security=reality&pbk=PUBKEY123&sid=01#HK节点
vmess://eyJhZGQiOiIyLjIuMi4yIn0=
</div>
"""

WEB_HTML = """
<html><body>
推荐订阅：https://raw.githubusercontent.com/baz/qux/master/mihomo.yaml
还有这个 https://proxy-site.net/api/v2ray
trojan://pass@3.3.3.3:443?sni=host.com#TJ
</body></html>
"""


@pytest.fixture
def fake_get(monkeypatch):
    # SSRF 落点校验的 DNS 解析：测试主机一律返回公网 IP（真实校验见
    # tests/test_net_safety.py）
    monkeypatch.setattr(
        net_safety.socket, "getaddrinfo",
        lambda host, *a, **kw: [(2, 1, 6, "", ("93.184.216.34", 0))])

    def _get(url, timeout=None, headers=None, **kw):
        # **kw 吸收 safe_http_get 传入的 allow_redirects=False
        if "/s/" in url:
            return FakeResp(TG_HTML)
        if "blog.example.com" in url:
            return FakeResp(WEB_HTML)
        if "example.com/sub" in url:
            return FakeResp("not a sub", status=200)  # 节点不足，应被拒
        if "proxy-site.net" in url:
            return FakeResp("nope", status=200)  # 节点不足，应被拒
        if "raw.githubusercontent" in url or url.endswith(".yaml"):
            return FakeResp(_proxies_yaml(25))
        return FakeResp("nf", status=404)
    monkeypatch.setattr(channels.requests, "get", _get)


# ---------------- URL 归一化 / 判定 ----------------

def test_norm_url_github_blob_to_raw():
    u = channels._norm_url("https://github.com/owner/repo/blob/main/clash.yaml")
    assert u == "https://raw.githubusercontent.com/owner/repo/main/clash.yaml"
    # 去尾部标点
    assert channels._norm_url("https://x.com/a.yaml。") == "https://x.com/a.yaml"
    # 非 http 返回 None
    assert channels._norm_url("ftp://x") is None


def test_looks_like_sub_heuristics():
    assert channels._looks_like_sub("https://raw.githubusercontent.com/a/b/main/clash.yaml")
    assert channels._looks_like_sub("https://sub.x.com/api/v2ray")
    assert channels._looks_like_sub("https://x.com/clash/config.yaml")
    assert not channels._looks_like_sub("https://example.com/about")
    assert not channels._looks_like_sub("https://x.com/photo.jpg")


def test_extract_sub_and_nodes():
    subs, nodes = channels._extract_sub_and_nodes(TG_HTML)
    assert "https://raw.githubusercontent.com/foo/bar/main/clash.yaml" in subs
    assert "https://example.com/sub/abc123" in subs
    assert any(n.startswith("vless://") for n in nodes)
    assert any(n.startswith("vmess://") for n in nodes)


# ---------------- vless 解析 ----------------

def test_parse_vless_uri_reality():
    uri = "vless://uuid-1@1.1.1.1:443?encryption=none&security=reality&pbk=PUBKEY123&sid=01&sni=host.com&fp=chrome#HK节点"
    p = common._parse_vless_uri(uri)
    assert p is not None
    assert p["type"] == "vless"
    assert p["server"] == "1.1.1.1" and p["port"] == 443
    assert p["uuid"] == "uuid-1"
    assert p["tls"] is True
    assert p["sni"] == "host.com"
    assert p["reality-opts"]["public-key"] == "PUBKEY123"
    assert p["reality-opts"]["short-id"] == "01"
    assert p["name"] == "HK节点"


def test_parse_subscription_text_parses_vless_line():
    uri = "vless://uuid-2@2.2.2.2:8443?security=reality&pbk=KEY#test"
    out = common.parse_subscription_text(uri)
    assert len(out) == 1 and out[0]["type"] == "vless"


# ---------------- 渠道发现（mock） ----------------

def test_discover_telegram_adds_candidate_and_nodes(tmp_path, fake_get, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_channels(tmp_path, {"enabled": True, "telegram": ["FreeNodes"], "web": [], "static_sources": []})
    sources = {"official": [], "removed": [], "deny_repos": []}
    cands = {"candidates": {}, "rejected": {}}
    rep = channels.discover_channels(sources, cands, common.parse_subscription_text, print)
    assert "https://raw.githubusercontent.com/foo/bar/main/clash.yaml" in cands["candidates"]
    assert rep["telegram"]["added"]
    assert rep["nodes_collected"] >= 1
    # 原始节点链接应写入 collected_nodes.txt
    assert os.path.exists(channels.COLLECTED_NODES_FILE)
    with open(channels.COLLECTED_NODES_FILE, encoding="utf-8") as f:
        txt = f.read()
    assert "vless://" in txt and "vmess://" in txt
    # 节点不足的候选（example.com/sub）应被拒
    assert "https://example.com/sub/abc123" in rep["telegram"]["rejected"]


def test_discover_web_adds_candidate(tmp_path, fake_get, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_channels(tmp_path, {"enabled": True, "telegram": [], "web": ["https://blog.example.com/nodes"], "static_sources": []})
    sources = {"official": [], "removed": [], "deny_repos": []}
    cands = {"candidates": {}, "rejected": {}}
    rep = channels.discover_channels(sources, cands, common.parse_subscription_text, print)
    assert "https://raw.githubusercontent.com/baz/qux/master/mihomo.yaml" in cands["candidates"]
    assert rep["web"]["added"]


def test_discover_channels_discovery_off(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PROXYSUB_DISCOVERY", "0")
    _write_channels(tmp_path, {"enabled": True, "telegram": ["X"], "web": [], "static_sources": []})
    sources = {"official": [], "removed": [], "deny_repos": []}
    cands = {"candidates": {}, "rejected": {}}
    rep = channels.discover_channels(sources, cands, common.parse_subscription_text, print)
    assert rep["telegram"] == {}
    assert "X" not in cands["candidates"]


def test_static_sources_promoted_to_official(tmp_path, fake_get, monkeypatch):
    monkeypatch.chdir(tmp_path)
    static_url = "https://raw.githubusercontent.com/static/feed/main/clash.yaml"
    _write_channels(tmp_path, {"enabled": True, "telegram": [], "web": [], "static_sources": [static_url]})
    sources = {"official": [], "removed": [], "deny_repos": []}
    cands = {"candidates": {}, "rejected": {}}
    rep = channels.discover_channels(sources, cands, common.parse_subscription_text, print)
    assert static_url in rep["static_added"]
    assert any(s.get("url") == static_url and s.get("origin") == "static_channel" for s in sources["official"])


def test_recently_removed_and_deny_respected(tmp_path, fake_get, monkeypatch):
    monkeypatch.chdir(tmp_path)
    removed_url = "https://raw.githubusercontent.com/foo/bar/main/clash.yaml"
    _write_channels(tmp_path, {"enabled": True, "telegram": ["FreeNodes"], "web": [], "static_sources": []})
    sources = {
        "official": [],
        "removed": [{"url": removed_url, "reason": "x", "date": "2099-01-01"}],
        "deny_repos": [],
    }
    cands = {"candidates": {}, "rejected": {}}
    channels.discover_channels(sources, cands, common.parse_subscription_text, print)
    # 该 URL 在 removed 冷却期内，不应被重新收录
    assert removed_url not in cands["candidates"]
