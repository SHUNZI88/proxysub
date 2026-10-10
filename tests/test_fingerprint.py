"""深度指纹去重回归测试。

验证「递归规范化 + 深度序列化」重构后的 fingerprint()：
- 仅嵌套参数（Reality 公钥 / WS 路径 / gRPC service-name）不同的节点必须得到不同指纹；
- 键顺序不同 / 仅名称不同 / 端口 int 与 str 表示不同的同一节点必须得到相同指纹。
"""

import pytest

import filter_clash as fc


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


def test_reality_public_key_changes_fingerprint():
    """改变 Reality 公钥后不能被误判为相同节点（旧实现的缺陷场景之一）。"""
    a = _vless_reality()
    b = _vless_reality()
    b["reality-opts"] = dict(b["reality-opts"])
    b["reality-opts"]["public-key"] = "CkX0bnZXlXxlyUftbnFwKJxBB6fvEffaO8BTazVhZ99"
    assert fc.fingerprint(a) != fc.fingerprint(b)


def test_reality_short_id_changes_fingerprint():
    a = _vless_reality()
    b = _vless_reality()
    b["reality-opts"] = dict(b["reality-opts"])
    b["reality-opts"]["short-id"] = "ffffeeee"
    assert fc.fingerprint(a) != fc.fingerprint(b)


def test_ws_path_changes_fingerprint():
    """改变 WS 路径后不能被误判为相同节点。"""
    a = {
        "name": "ws-01", "type": "trojan", "server": "s.example.com", "port": 443,
        "password": "pass", "network": "ws",
        "ws-opts": {"path": "/path1", "headers": {"Host": "cdn.example.com"}},
    }
    b = dict(a)
    b["ws-opts"] = {"path": "/path2", "headers": {"Host": "cdn.example.com"}}
    assert fc.fingerprint(a) != fc.fingerprint(b)


def test_ws_host_header_changes_fingerprint():
    a = {
        "name": "ws-01", "type": "trojan", "server": "s.example.com", "port": 443,
        "password": "pass", "network": "ws",
        "ws-opts": {"path": "/path1", "headers": {"Host": "cdn1.example.com"}},
    }
    b = dict(a)
    b["ws-opts"] = {"path": "/path1", "headers": {"Host": "cdn2.example.com"}}
    assert fc.fingerprint(a) != fc.fingerprint(b)


def test_grpc_service_name_changes_fingerprint():
    a = {
        "name": "g-01", "type": "trojan", "server": "s.example.com", "port": 443,
        "password": "pass", "network": "grpc",
        "grpc-opts": {"grpc-service-name": "svc1"},
    }
    b = dict(a)
    b["grpc-opts"] = {"grpc-service-name": "svc2"}
    assert fc.fingerprint(a) != fc.fingerprint(b)


def test_key_order_and_name_do_not_change_fingerprint():
    """键顺序不同、仅名称不同 -> 同一节点，指纹必须一致。"""
    a = _vless_reality()
    b = {k: a[k] for k in reversed(list(a.keys()))}
    b["name"] = "renamed-node"
    assert fc.fingerprint(a) == fc.fingerprint(b)


def test_port_str_vs_int_same_fingerprint():
    a = _vless_reality()
    b = _vless_reality()
    b["port"] = "443"
    assert fc.fingerprint(a) == fc.fingerprint(b)


def test_type_case_insensitive_same_fingerprint():
    a = _vless_reality()
    b = _vless_reality()
    b["type"] = "VLESS"
    assert fc.fingerprint(a) == fc.fingerprint(b)


def test_different_servers_different_fingerprint():
    a = _vless_reality()
    b = _vless_reality(server="jp.example.com")
    assert fc.fingerprint(a) != fc.fingerprint(b)


def test_stable_fingerprint_value():
    """指纹值必须稳定（哈希输入确定性），便于 survival.json 跨天关联。"""
    node = _vless_reality()
    assert fc.fingerprint(node) == fc.fingerprint(dict(node))
