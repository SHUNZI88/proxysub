"""多格式输出（分享链接 / sing-box / proxies-only）的回归测试。"""

import base64
import json
import os
import tempfile

import filter_clash as fc

VLESS_REALITY = {
    "name": "HK-01", "type": "vless", "server": "1.2.3.4", "port": 443,
    "uuid": "11111111-2222-3333-4444-555555555555", "tls": True, "network": "tcp",
    "servername": "www.microsoft.com", "flow": "xtls-rprx-vision",
    "reality-opts": {"public-key": "A" * 43, "short-id": "ab12"},
    "client-fingerprint": "chrome",
}
HY2 = {
    "name": "JP-02", "type": "hysteria2", "server": "5.6.7.8", "port": 8443,
    "password": "pw123", "sni": "dl.google.com", "obfs": "salamander",
    "obfs-password": "obf",
}
TROJAN = {
    "name": "SG-03", "type": "trojan", "server": "9.9.9.9", "port": 443,
    "password": "tp@ss", "sni": "apple.com", "network": "ws",
    "ws-opts": {"path": "/ws", "headers": {"Host": "a.com"}},
}


def test_share_link_vless_reality():
    link = fc.proxy_to_share_link(VLESS_REALITY)
    assert link.startswith("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?")
    assert "security=reality" in link
    assert f"pbk={'A' * 43}" in link
    assert "sid=ab12" in link
    assert "flow=xtls-rprx-vision" in link
    assert link.endswith("#HK-01")


def test_share_link_hysteria2():
    link = fc.proxy_to_share_link(HY2)
    assert link.startswith("hysteria2://pw123@5.6.7.8:8443?")
    assert "obfs=salamander" in link and "obfs-password=obf" in link


def test_share_link_trojan_escapes_password():
    """密码含 @ 必须转义，否则链接会被解析错误。"""
    link = fc.proxy_to_share_link(TROJAN)
    assert "trojan://tp%40ss@9.9.9.9:443?" in link
    assert "type=ws" in link and "host=a.com" in link


def test_share_link_rejects_unsupported_and_dangling():
    assert fc.proxy_to_share_link({"type": "ss", "server": "1.1.1.1", "port": 443}) is None
    assert fc.proxy_to_share_link({"type": "vless", "server": "1.1.1.1", "port": 443}) is None  # 无 uuid
    assert fc.proxy_to_share_link({"type": "hysteria2", "server": "1.1.1.1", "port": 443}) is None  # 无密码
    assert fc.proxy_to_share_link({"type": "vless", "server": "", "port": 0,
                                   "uuid": "x"}) is None


def test_singbox_vless_reality_structure():
    ob = fc.proxy_to_singbox(VLESS_REALITY)
    assert ob["type"] == "vless" and ob["server_port"] == 443
    assert ob["tls"]["reality"]["public_key"] == "A" * 43
    assert ob["tls"]["utls"]["fingerprint"] == "chrome"


def test_singbox_hy2_obfs():
    ob = fc.proxy_to_singbox(HY2)
    assert ob["type"] == "hysteria2"
    assert ob["obfs"] == {"type": "salamander", "password": "obf"}


def test_singbox_trojan_ws_transport():
    ob = fc.proxy_to_singbox(TROJAN)
    assert ob["type"] == "trojan" and ob["transport"]["type"] == "ws"
    assert ob["transport"]["headers"]["Host"] == "a.com"


def test_singbox_rejects_unsupported():
    assert fc.proxy_to_singbox({"type": "ss", "server": "1.1.1.1", "port": 1}) is None


def test_write_outputs_creates_three_files():
    """write_outputs 应生成 proxies-only / sing-box / v2ray 三类文件且内容自洽。"""
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as td:
        os.chdir(td)
        try:
            stat = fc.write_outputs([VLESS_REALITY, HY2, TROJAN])
            assert stat == {"proxies_only": 3, "singbox": 3, "links": 3}

            import yaml
            with open(fc.OUTPUT_PROXIES_ONLY, encoding="utf-8") as f:
                assert len(yaml.safe_load(f)["proxies"]) == 3

            with open(fc.OUTPUT_SINGBOX, encoding="utf-8") as f:
                obs = json.load(f)["outbounds"]
            assert obs[-1] == {"type": "direct", "tag": "direct"}
            assert {o["type"] for o in obs[:-1]} == {"vless", "hysteria2", "trojan"}

            with open(fc.OUTPUT_V2RAY, encoding="utf-8") as f:
                decoded = base64.b64decode(f.read()).decode("utf-8")
            assert len(decoded.splitlines()) == 3
            assert decoded.startswith("vless://")
        finally:
            os.chdir(cwd)


def test_write_outputs_skips_unconvertible():
    """不可转换节点（如 ss）应被跳过而不是中断输出。"""
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as td:
        os.chdir(td)
        try:
            stat = fc.write_outputs([VLESS_REALITY, {"type": "ss", "server": "1.1.1.1", "port": 1}])
            assert stat["proxies_only"] == 2   # proxies-only 保留全部
            assert stat["singbox"] == 1 and stat["links"] == 1
        finally:
            os.chdir(cwd)
