"""UDP 协议豁免 / network 规范化 / 每源独占上限 回归测试。"""

import filter_clash as fc


# ---------- UDP 协议识别（TCP 存活检查豁免） ----------

def test_is_udp_protocol_matches():
    for t in ("hysteria2", "hy2", "tuic", "hysteria", "quic"):
        assert fc.is_udp_protocol({"type": t})
        assert fc.is_udp_protocol({"type": t.upper()})
        assert fc.is_udp_protocol({"type": f" {t} "})


def test_is_udp_protocol_rejects_tcp_protocols():
    for t in ("vless", "trojan", "anytls", "ss", "", None):
        assert not fc.is_udp_protocol({"type": t})


# ---------- network 字段规范化 ----------

def test_normalize_network_aliases_raw_to_tcp():
    p = {"type": "vless", "network": "raw"}
    assert fc.normalize_network(p) is True
    assert p["network"] == "tcp"


def test_normalize_network_keeps_valid():
    for net in ("tcp", "ws", "http", "h2", "grpc", "TCP", " WS "):
        p = {"type": "trojan", "network": net}
        assert fc.normalize_network(p) is True
        assert p["network"] == net.lower().strip()


def test_normalize_network_missing_or_empty_defaults_tcp():
    p1 = {"type": "trojan"}
    assert fc.normalize_network(p1) is True
    assert p1.get("network") is None  # 不新增字段
    p2 = {"type": "trojan", "network": ""}
    assert fc.normalize_network(p2) is True
    assert p2["network"] == "tcp"


def test_normalize_network_rejects_xhttp_and_garbage():
    for bad in ("xhttp", "tcp#5🔥@oneclickvpnkeys", "kcp", "quic"):
        assert fc.normalize_network({"type": "vless", "network": bad}) is False


# ---------- 每源独占上限 ----------

def _row(i):
    node = {
        "name": f"NODE-{i}",
        "type": "trojan",
        "server": f"s{i}.example.com",
        "port": 443,
        "password": "pw",
    }
    return (node, float(i), float(i), False, False, 1)


def test_cap_single_source_limits_single_source_nodes():
    rows = [_row(i) for i in range(10)]
    prov = {fc.fingerprint(r[0]): {"https://one.example/feed"} for r in rows}
    out, dropped = fc.cap_single_source(rows, prov, cap=4)
    assert len(out) == 4
    assert dropped == 6


def test_cap_single_source_multi_source_nodes_exempt():
    rows = [_row(i) for i in range(10)]
    prov = {
        fc.fingerprint(r[0]): ({"https://one.example/feed", "https://two.example/feed"}
                               if i < 5 else {"https://one.example/feed"})
        for i, r in enumerate(rows)
    }
    out, dropped = fc.cap_single_source(rows, prov, cap=4)
    # 前 5 个多源节点全部保留；单源节点仅占 4 个名额
    assert len(out) == 9
    assert dropped == 1
