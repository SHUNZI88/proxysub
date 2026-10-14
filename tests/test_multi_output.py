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


# ===================== P0 修复回归测试 =====================

TROJAN_FP = {
    "name": "US-04", "type": "trojan", "server": "1.1.1.1", "port": 443,
    "password": "tp", "sni": "b.com", "client-fingerprint": "chrome",
}
TUIC_NODE = {
    "name": "JP-05", "type": "tuic", "server": "2.2.2.2", "port": 443,
    "uuid": "uuid-uuid", "password": "tuicpw", "sni": "c.com",
}
HY2_NONSTD_OBFS = {
    "name": "KR-06", "type": "hysteria2", "server": "3.3.3.3", "port": 8443,
    "password": "pw", "obfs": "Salamander", "obfs-password": "obf",
}


def test_p0_2_tuic_no_redundant_password_query():
    """P0-2：TUIC 密码已在 userinfo，query 不得再写 password 参数。"""
    link = fc.proxy_to_share_link(TUIC_NODE)
    assert link.startswith("tuic://uuid-uuid:tuicpw@2.2.2.2:443?")
    assert "password=" not in link
    assert "congestion_control" in link or "sni=c.com" in link


def test_p0_3_trojan_singbox_has_utls():
    """P0-3：Trojan sing-box 在 client-fingerprint 存在时应写 utls 指纹。"""
    ob = fc.proxy_to_singbox(TROJAN_FP)
    assert ob["type"] == "trojan"
    assert ob["tls"]["utls"] == {"enabled": True, "fingerprint": "chrome"}


def test_p0_3_trojan_singbox_no_utls_without_fp():
    """无 client-fingerprint 时不应写 utls（与 VLESS 行为一致）。"""
    ob = fc.proxy_to_singbox({"name": "x", "type": "trojan", "server": "1.1.1.1",
                              "port": 443, "password": "p", "sni": "s.com"})
    assert "utls" not in ob["tls"]


def test_p0_4_hy2_obfs_normalized_in_share_link():
    """P0-4：share_link 的 obfs 判定的严格化——大小写归一为 salamander。"""
    link = fc.proxy_to_share_link(HY2_NONSTD_OBFS)
    assert "obfs=salamander" in link
    # 与 singbox 分支的 == 'salamander' 判定保持一致
    ob = fc.proxy_to_singbox(HY2_NONSTD_OBFS)
    assert ob["obfs"] == {"type": "salamander", "password": "obf"}


def test_p0_4_hy2_obfs_passthrough_nonstandard():
    """非标准 obfs 名（非 salamander）两个函数均透传而非静默丢弃。"""
    node = {"name": "y", "type": "hysteria2", "server": "4.4.4.4", "port": 8443,
            "password": "pw", "obfs": "weird-obfs"}
    link = fc.proxy_to_share_link(node)
    assert "obfs=weird-obfs" in link
    ob = fc.proxy_to_singbox(node)
    assert "obfs" not in ob  # singbox 仅 salamander 合法，非标准不写 obfs 段


def test_p0_1_github_summary_survives_missing_keys(monkeypatch):
    """P0-1：write_github_summary 在 info 缺键时不应 KeyError（容错风格）。"""
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", "/tmp/_summary_test.md")
    # 构造一个只含部分键的 info，模拟调用方重构后漏传字段
    partial = {
        "final": 10, "tcp": 5, "real": 3, "https": 2,
        "probe_mode": "mihomo", "insecure": 0,
        "n_official": 2, "n_cands": 1,
        "anti_crawl": {"enabled": False},
    }
    # 不应抛 KeyError
    fc.write_github_summary(partial)
    with open("/tmp/_summary_test.md", encoding="utf-8") as f:
        content = f.read()
    assert "Final proxies" in content
    assert "Discovered" not in content or "Discovered (new candidates): **0**" in content
