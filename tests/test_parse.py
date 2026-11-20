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


def test_share_link_list_not_treated_as_base64():
    """回归（CI/Python 3.12 实际触发）：

    多行分享链接包含 : / # @ 等非 base64 字符。旧实现直接对整段文本调用
    b64decode(validate=False)，丢弃非法字符后仍可能"解码成功"，返回垃圾并
    吞掉逐行解析，导致整源被解析为空。
    修复后：整段 base64 仅在正文只含 base64 字符集时尝试。
    """
    text = f"{SS_URI}\n{TROJAN_URI}\n" + "vmess://eyJwcyI6InYiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6IjQ0MyIsImlkIjoiYjgzMTM4MWQtNjMyNC00ZDUzLWFkNGYtOGNkYTQ4YjMwODExIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ0Y3AiLCJ0bHMiOiJ0bHMifQ=="
    nodes = fc.parse_subscription_text(text)
    types = {n["type"] for n in nodes}
    assert types == {"ss", "trojan", "vmess"}


def test_pure_base64_blob_still_decoded():
    """纯 base64 订阅（无 URI 特征）仍需正确整段解码。"""
    blob = base64.b64encode(f"{SS_URI}\n{TROJAN_URI}".encode()).decode()
    nodes = fc.parse_subscription_text(blob)
    assert {n["type"] for n in nodes} == {"ss", "trojan"}


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


# ---------------------------------------------------------------- ss 放行（任务#124）
def _ss(cipher="aes-256-gcm", password="pw", server="ss.example.com", port=8388):
    return {"name": "SS", "type": "ss", "cipher": cipher, "password": password,
            "server": server, "port": port}


def test_ss_aead_passes_static_gate():
    """家宽实测 ss 初筛通过率 8.3%、终筛 100%，质量优于 vless(3.3%)——
    白名单一刀切排除 ss 是产量的人为天花板，故放行 AEAD 档。"""
    for cipher in ("aes-256-gcm", "chacha20-ietf-poly1305",
                   "2022-blake3-aes-128-gcm"):
        assert fc.protocol_gate_reason(_ss(cipher=cipher)) is None


def test_ss_weak_cipher_still_rejected():
    """rc4/des/cfb 属已知不安全构造，放行等于推翻安全评估结论。"""
    for cipher in ("rc4-md5", "aes-256-cfb", "des-cfb", "", "none"):
        assert fc.protocol_gate_reason(_ss(cipher=cipher)).startswith(
            ("ss_cipher_rejected",))


def test_ss_requires_password_and_port():
    assert fc.protocol_gate_reason(_ss(password=" ")) == "ss_password_missing"
    assert fc.protocol_gate_reason(_ss(port=0)) == "ss_port_invalid"
    assert fc.protocol_gate_reason(_ss(port=70000)) == "ss_port_invalid"


def test_vmess_still_excluded_by_evidence():
    """vmess 家宽实测 0/80 通过——排除它是被数据支持的决定，不得顺手放开。"""
    node = {"name": "V", "type": "vmess", "server": "v.example.com", "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}
    assert fc.protocol_gate_reason(node).startswith("protocol_not_whitelisted")


# ---- 任务#140（2026-11-20）：ss 空查询串 / 2022-blake3 / hy2 / anytls ----
# 事故：v2rayfree 的 15 条 ss 有 10 条写成 `…@host:port?#name`，旧实现
# int("19999?") 抛错被吞 → 节点静默消失。丢的正是 202.50.253.x:19999 这一批
# 本机可用率最高的节点。解析层的静默丢包会让「供给不足」看起来像网络问题。

import common as cm


def _p(uri):
    got = cm.parse_subscription_text(uri)
    return got[0] if got else None


def test_ss_trailing_empty_query_parses():
    node = _p("ss://YWVzLTI1Ni1nY206cGFzcw==@202.50.253.45:19999?#DE%20SS-22")
    assert node is not None
    assert node["server"] == "202.50.253.45"
    assert node["port"] == 19999
    assert node["cipher"] == "aes-256-gcm"
    assert node["password"] == "pass"


def test_ss_trailing_slash_before_fragment_parses():
    node = _p("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388/#node")
    assert node is not None and node["port"] == 8388


def test_ss_2022_key_is_unquoted_and_normalized():
    """SIP002 里 2022 密钥常写成 URL 编码（%3D）；必须解回来再校验长度。"""
    key = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
    quoted = key.replace("=", "%3D")
    node = _p(f"ss://2022-blake3-chacha20-poly1305:{quoted}@1.2.3.4:443#k")
    assert node is not None
    assert node["password"] == key          # 标准 base64，mihomo 才认


def test_ss_2022_bad_key_length_rejected():
    """长度不对的密钥会让 mihomo fatal 退出、拖垮整份配置，必须静态拒绝。"""
    bad = base64.b64encode(b"tooshort").decode()
    assert _p(f"ss://2022-blake3-chacha20-poly1305:{bad}@1.2.3.4:443#k") is None
    assert _p("ss://2022-blake3-aes-128-gcm:notbase64!!@1.2.3.4:443#k") is None


def test_ss_plugin_is_mapped_to_mihomo_opts():
    node = _p("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388"
              "?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#o")
    assert node is not None
    assert node["plugin"] == "obfs"
    assert node["plugin-opts"]["mode"] == "http"
    assert node["plugin-opts"]["host"] == "bing.com"


def test_hysteria2_and_hy2_links_parse():
    for scheme in ("hysteria2", "hy2"):
        node = _p(f"{scheme}://pw@1.2.3.4:443?sni=a.example.com&insecure=1"
                  f"&obfs=salamander&obfs-password=x#H")
        assert node is not None, scheme
        assert node["type"] == "hysteria2"
        assert node["password"] == "pw"
        assert node["sni"] == "a.example.com"
        assert node["skip-cert-verify"] is True
        assert node["obfs"] == "salamander"
        assert node["obfs-password"] == "x"


def test_anytls_link_parses():
    node = _p("anytls://pw@5.6.7.8:8443?sni=b.example.com#AT")
    assert node is not None
    assert node["type"] == "anytls"
    assert node["port"] == 8443
    assert node["sni"] == "b.example.com"


def test_parse_keeps_all_schemes_in_one_feed():
    """一条订阅里混排 ss/hy2/vless 时不能只解析第一种。"""
    text = "\n".join([
        "ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:19999?#a",
        "hy2://pw@5.6.7.8:443?sni=x.com#b",
        "anytls://pw@9.9.9.9:8443?sni=y.com#c",
    ])
    types = sorted(n["type"] for n in cm.parse_subscription_text(text))
    assert types == ["anytls", "hysteria2", "ss"]
