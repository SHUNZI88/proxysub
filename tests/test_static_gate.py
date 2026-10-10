"""硬性静态门槛（协议白名单 + 关键参数校验）回归测试。"""

import pytest

import filter_clash as fc


def _hy2(**overrides):
    node = {
        "name": "HK-Hy2-01",
        "type": "hysteria2",
        "server": "hk.example.com",
        "port": 443,
        "password": "secretpass",
    }
    node.update(overrides)
    return node


def _vless_reality(**overrides):
    node = {
        "name": "HK-Reality-01",
        "type": "vless",
        "server": "hk.example.com",
        "port": 443,
        "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
        "flow": "xtls-rprx-vision",
        "servername": "www.microsoft.com",
        "tls": True,
        "network": "tcp",
        "reality-opts": {
            "public-key": "AyM5bnZXlXxlyUftbnFwKJxBB6fvEffaO8BTazVhW28",
            "short-id": "0123abcd",
        },
    }
    node.update(overrides)
    return node


# ---------- 协议白名单 ----------

@pytest.mark.parametrize("ptype", ["ss", "ssr", "vmess", "http", "socks5", "socks", "wireguard", "", "unknown-x"])
def test_legacy_or_unknown_protocols_rejected(ptype):
    node = {"name": "x", "type": ptype, "server": "a.example.com", "port": 443, "password": "p"}
    assert fc.protocol_gate_reason(node) is not None
    assert fc.protocol_gate_reason(node).startswith("protocol_not_whitelisted")


@pytest.mark.parametrize("ptype", ["hysteria2", "hy2", "vless", "trojan", "tuic", "anytls", "hysteria"])
def test_whitelisted_protocols_accepted(ptype):
    node = {"name": "x", "type": ptype, "server": "a.example.com", "port": 443, "password": "p"}
    # 白名单协议 + 合法密码（vless 需要额外 uuid，单独测）
    if ptype == "vless":
        assert fc.protocol_gate_reason(node) == "invalid_uuid"
    else:
        assert fc.protocol_gate_reason(node) is None


# ---------- Hysteria2 参数校验 ----------

def test_hy2_missing_password_rejected():
    assert fc.protocol_gate_reason(_hy2(password="")) == "missing_password"


def test_hy2_salamander_without_obfs_password_rejected():
    assert fc.protocol_gate_reason(_hy2(obfs="salamander")) == "missing_obfs_password"


def test_hy2_salamander_with_obfs_password_ok():
    node = _hy2(**{"obfs": "salamander", "obfs-password": "obfs123"})
    assert fc.protocol_gate_reason(node) is None


def test_hy2_unsupported_obfs_rejected():
    assert fc.protocol_gate_reason(_hy2(obfs="plain")) == "unsupported_obfs"


# ---------- VLESS / Reality 参数校验 ----------

def test_vless_reality_valid_passes():
    assert fc.protocol_gate_reason(_vless_reality()) is None


def test_vless_invalid_uuid_rejected():
    assert fc.protocol_gate_reason(_vless_reality(uuid="not-a-uuid")) == "invalid_uuid"


def test_vless_reality_bad_public_key_rejected():
    node = _vless_reality()
    node["reality-opts"] = {"public-key": "shortkey", "short-id": "0123abcd"}
    assert fc.protocol_gate_reason(node) == "invalid_reality_public_key"


def test_vless_reality_padded_public_key_accepted():
    node = _vless_reality()
    node["reality-opts"] = {
        "public-key": "AyM5bnZXlXxlyUftbnFwKJxBB6fvEffaO8BTazVhW28=",
        "short-id": "0123abcd",
    }
    assert fc.protocol_gate_reason(node) is None


def test_vless_reality_bad_short_id_rejected():
    node = _vless_reality()
    node["reality-opts"] = {"public-key": "AyM5bnZXlXxlyUftbnFwKJxBB6fvEffaO8BTazVhW28", "short-id": "xyz!"}
    assert fc.protocol_gate_reason(node) == "invalid_reality_short_id"


def test_vless_reality_odd_length_short_id_rejected():
    node = _vless_reality()
    node["reality-opts"] = {"public-key": "AyM5bnZXlXxlyUftbnFwKJxBB6fvEffaO8BTazVhW28", "short-id": "abc"}
    assert fc.protocol_gate_reason(node) == "invalid_reality_short_id"


def test_vless_reality_missing_sni_rejected():
    node = _vless_reality()
    node.pop("servername")
    node.pop("sni", None)
    assert fc.protocol_gate_reason(node) == "reality_missing_sni"


def test_vless_without_tls_rejected():
    node = {
        "name": "plain-vless", "type": "vless", "server": "a.example.com", "port": 80,
        "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
    }
    assert fc.protocol_gate_reason(node) == "vless_no_tls"


def test_vless_with_tls_ok():
    node = {
        "name": "tls-vless", "type": "vless", "server": "a.example.com", "port": 443,
        "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "tls": True,
        "servername": "www.apple.com",
    }
    assert fc.protocol_gate_reason(node) is None


def test_vless_unsupported_flow_rejected():
    assert fc.protocol_gate_reason(_vless_reality(flow="xtls-rprx-direct")) == "unsupported_flow"


# ---------- SNI 校验 ----------

def test_bad_sni_rejected():
    assert fc.protocol_gate_reason(_hy2(sni="not a valid sni!!")) == "bad_sni"


def test_ip_literal_sni_rejected():
    assert fc.protocol_gate_reason(_hy2(sni="1.2.3.4")) == "bad_sni"


def test_valid_sni_accepted():
    assert fc.protocol_gate_reason(_hy2(sni="www.microsoft.com")) is None


# ---------- 其他协议 ----------

def test_trojan_missing_password_rejected():
    node = {"name": "t", "type": "trojan", "server": "a.example.com", "port": 443, "password": ""}
    assert fc.protocol_gate_reason(node) == "missing_password"


def test_tuic_missing_credentials_rejected():
    node = {"name": "t", "type": "tuic", "server": "a.example.com", "port": 443}
    assert fc.protocol_gate_reason(node) == "missing_credentials"


def test_tuic_invalid_uuid_rejected():
    node = {"name": "t", "type": "tuic", "server": "a.example.com", "port": 443,
            "uuid": "bad", "password": "p"}
    assert fc.protocol_gate_reason(node) == "invalid_uuid"


# ---------- 端到端：静态门槛接入主过滤链 ----------

def test_gate_rejects_mixed_feed():
    """模拟一个混合源：ss/vmess 被整体拒绝，合规 hy2/reality 保留。"""
    feed = [
        {"name": "ss-01", "type": "ss", "server": "a.example.com", "port": 443,
         "cipher": "aes-128-gcm", "password": "x"},
        {"name": "vmess-01", "type": "vmess", "server": "b.example.com", "port": 443,
         "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "alterId": 0, "cipher": "auto"},
        _hy2(),
        _vless_reality(),
    ]
    kept = [p for p in feed if fc.protocol_gate_reason(p) is None]
    assert {p["name"] for p in kept} == {"HK-Hy2-01", "HK-Reality-01"}
