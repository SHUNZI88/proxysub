"""订阅解析（parse_subscription_text）回归测试：YAML / base64 / 分享链接。"""

import base64

import filter_clash as fc

YAML_FEED = """
proxies:
  - {name: HK-Hy2, type: hysteria2, server: hk.example.com, port: 443, password: pw1}
  - {name: JP-Reality, type: vless, server: jp.example.com, port: 443,
     uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, servername: www.apple.com,
     reality-opts: {public-key: AyM5bnZXlXxlyUftbnFwKJxBB6fvEffaO8BTazVhW28, short-id: "01"}}
"""

SS_URI = "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ss-node"
TROJAN_URI = "trojan://pass123@5.6.7.8:443?sni=www.microsoft.com#trojan-node"


def test_parse_yaml():
    nodes = fc.parse_subscription_text(YAML_FEED)
    assert len(nodes) == 2
    assert nodes[0]["type"] == "hysteria2"
    assert nodes[1]["reality-opts"]["public-key"]


def test_parse_base64_blob():
    blob = base64.b64encode(YAML_FEED.encode()).decode()
    nodes = fc.parse_subscription_text(blob)
    assert len(nodes) == 2


def test_parse_share_links():
    nodes = fc.parse_subscription_text(f"{SS_URI}\n{TROJAN_URI}")
    types = {n["type"] for n in nodes}
    assert "ss" in types
    assert "trojan" in types
    trojan = next(n for n in nodes if n["type"] == "trojan")
    assert trojan["password"] == "pass123"
    assert trojan["sni"] == "www.microsoft.com"


def test_parse_empty_and_garbage():
    assert fc.parse_subscription_text("") == []
    assert fc.parse_subscription_text("not a subscription at all\nrandom text") == []


def test_vmess_link_parsed_then_gated():
    """vmess 链接可以被解析（保持源发现能力），但会被协议门槛拒绝（白名单外）。"""
    import json as _json
    vmess_obj = {"ps": "vm-node", "add": "9.9.9.9", "port": "443",
                 "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0",
                 "scy": "auto", "net": "ws", "tls": "tls"}
    uri = "vmess://" + base64.b64encode(_json.dumps(vmess_obj).encode()).decode()
    nodes = fc.parse_subscription_text(uri)
    assert len(nodes) == 1
    assert nodes[0]["type"] == "vmess"
    # 静态门槛：vmess 不在白名单
    assert fc.protocol_gate_reason(nodes[0]).startswith("protocol_not_whitelisted")
