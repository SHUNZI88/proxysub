"""honeypot 源结构聚类 / channels 候选校验与链接合并单测（P1-1d 收尾）。

source_cluster_flags 是蜜罐识别的核心启发式（/24、/16 网段聚集与共享
凭证），_validate_candidate 决定新渠道能否转正，_append_node_links 是
收集文件的唯一写入口——三者的分支逻辑此前提拔未覆盖。
"""

import channels
import honeypot
import pytest
import re


# ---------------------------------------------------------------------------
# honeypot.source_cluster_flags
# ---------------------------------------------------------------------------

def _p(server, uuid="u1"):
    return {"name": "n", "type": "vless", "server": server, "port": 443,
            "uuid": uuid}


def _resolved(servers):
    """server -> [自身 IP]（探测阶段已由 resolve_hosts 填充）。"""
    return {s: [s] for s in servers}


class TestSourceClusterFlags:
    def test_below_min_nodes_no_flags(self):
        n = honeypot.CLUSTER_MIN_NODES - 1
        proxies = [_p(f"1.2.3.{i}") for i in range(n)]
        assert honeypot.source_cluster_flags(proxies, _resolved(
            [p["server"] for p in proxies])) == []

    def test_slash24_cluster_flagged(self):
        n = honeypot.CLUSTER_MIN_NODES
        proxies = [_p(f"1.2.3.{i}", uuid=f"u{i}") for i in range(n)]
        flags = honeypot.source_cluster_flags(proxies, _resolved(
            [p["server"] for p in proxies]))
        assert flags == ["cluster_24:1.2.3.0/24"]

    def test_slash16_cluster_flagged(self):
        # 同 /16 下两个 /24 各占一半：/24 占比 0.5 < 0.6 不触发，
        # /16 占比 1.0 ≥ 0.85 触发 cluster_16。
        n = honeypot.CLUSTER_MIN_NODES
        proxies = [_p(f"1.2.{3 + i % 2}.{i}", uuid=f"u{i}") for i in range(n)]
        flags = honeypot.source_cluster_flags(proxies, _resolved(
            [p["server"] for p in proxies]))
        assert flags == ["cluster_16:1.2.0.0/16"]

    def test_shared_credential_flagged(self):
        # 每节点独立 /24（无网段聚集），但同一凭证铺满 ≥15 个服务器。
        n = honeypot.SHARED_CRED_MIN_SERVERS + 5
        proxies = [_p(f"{i}.2.3.4") for i in range(1, n + 1)]
        flags = honeypot.source_cluster_flags(proxies, _resolved(
            [p["server"] for p in proxies]))
        assert flags == [f"shared_cred:{n}/{n}"]

    def test_diverse_sources_clean(self):
        n = honeypot.CLUSTER_MIN_NODES
        proxies = [_p(f"{i}.2.3.4", uuid=f"u{i}") for i in range(1, n + 1)]
        assert honeypot.source_cluster_flags(proxies, _resolved(
            [p["server"] for p in proxies])) == []

    def test_unresolved_hosts_skip_cluster_math(self):
        n = honeypot.CLUSTER_MIN_NODES
        proxies = [_p(f"host{i}.example.com", uuid=f"u{i}") for i in range(n)]
        assert honeypot.source_cluster_flags(proxies, {}) == []


# ---------------------------------------------------------------------------
# honeypot.template_key / template_ip_cluster_flags （替代 ASN 的本地联合信号）
# ---------------------------------------------------------------------------

def _tp(server, **kw):
    """构造带模板字段的 proxy；未指定时给最小默认模板（type=vless/tcp）。"""
    base = {"name": "n", "type": "vless", "server": server, "port": 443,
            "uuid": "u1"}
    base.update(kw)
    return base


def _resolved_ips(proxies):
    """server 为 IPv4 字面量时 server->[自身]；域名则缺失（视作未解析）。"""
    out = {}
    for p in proxies:
        s = str(p["server"])
        ip = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})$", s)
        if ip:
            out[s] = [s]
    return out


class TestTemplateKey:
    def test_uuid_path_normalized_to_placeholder(self):
        a = _tp("1.2.3.4", network="ws", **{
            "ws-opts": {"path": "/vless/8a7b6c5d-1234-5678-90ab-cdef01234567"}})
        b = _tp("5.6.7.8", network="ws", **{
            "ws-opts": {"path": "/vless/11112222-3333-4444-5555-666677778888"}})
        assert honeypot.template_key(a) == honeypot.template_key(b)

    def test_wildcard_subdomain_host_normalized(self):
        a = _tp("1.2.3.4", network="ws", **{
            "ws-opts": {"path": "/x", "headers": {"Host": "us1.example.com"}}})
        b = _tp("5.6.7.8", network="ws", **{
            "ws-opts": {"path": "/x", "headers": {"Host": "us2.example.com"}}})
        assert honeypot.template_key(a) == honeypot.template_key(b)

    def test_different_type_yields_different_key(self):
        a = _tp("1.2.3.4")
        b = _tp("1.2.3.4", type="vmess")
        assert honeypot.template_key(a) != honeypot.template_key(b)

    def test_grpc_service_name_part_of_key(self):
        a = _tp("1.2.3.4", network="grpc",
                **{"grpc-opts": {"grpc-service-name": "svc-a"}})
        b = _tp("1.2.3.4", network="grpc",
                **{"grpc-opts": {"grpc-service-name": "svc-b"}})
        assert honeypot.template_key(a) != honeypot.template_key(b)


class TestTemplateIpClusterFlags:
    def test_below_min_nodes_no_flags(self):
        n = honeypot.CLUSTER_TEMPLATE_MIN - 1
        # 全部同模板、同 /24，但组规模不足下限 → 不判
        proxies = [_tp(f"1.2.3.{i}") for i in range(1, n + 1)]
        assert honeypot.template_ip_cluster_flags(
            proxies, _resolved_ips(proxies)) == []

    def test_diverse_ips_same_template_clean(self):
        # 知名聚合源典型情形：模板同质但节点散布各家 VPS（每节点独立 /24）
        n = honeypot.CLUSTER_TEMPLATE_MIN
        proxies = [_tp(f"{(i // 16) + 10}.{(i % 16) + 1}.{(i % 250) + 2}.4")
                   for i in range(n)]
        flags = honeypot.template_ip_cluster_flags(proxies, _resolved_ips(proxies))
        assert flags == []  # 单模板组内 /24 占比 ≤ 1/n < 0.5

    def test_concentrated_same_template_flagged(self):
        # 蜜罐/同运营者批量部署：同模板 + ≥20 节点聚在单 /24
        n = honeypot.CLUSTER_TEMPLATE_MIN
        proxies = [_tp(f"1.2.3.{i}") for i in range(1, n + 1)]
        flags = honeypot.template_ip_cluster_flags(proxies, _resolved_ips(proxies))
        assert len(flags) == 1
        assert flags[0].startswith("template_cluster:")
        assert "1.2.3.0/24" in flags[0]
        assert f"({n}/{n})" in flags[0]

    def test_template_group_split_concentration(self):
        # 两类模板各 20：A 模板聚单 /24（命中），B 模板 /24 分散（不命中）
        n = honeypot.CLUSTER_TEMPLATE_MIN
        a = [_tp(f"1.2.3.{i}", flow="xtls-rprx-vision") for i in range(1, n + 1)]
        b = [_tp(f"{(i % 250) + 20}.{(i % 16) + 1}.{(i % 250) + 2}.4")
             for i in range(n)]
        flags = honeypot.template_ip_cluster_flags(a + b, _resolved_ips(a + b))
        # 仅 A 模板组命中；B 模板组 /24 分散不命中
        assert len(flags) == 1
        assert "1.2.3.0/24" in flags[0]

    def test_unresolved_hosts_no_flags(self):
        n = honeypot.CLUSTER_TEMPLATE_MIN
        proxies = [_tp(f"host{i}.example.com") for i in range(1, n + 1)]
        assert honeypot.template_ip_cluster_flags(proxies, {}) == []


# ---------------------------------------------------------------------------
# channels._validate_candidate
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, status_code=200, content=b"x", encoding="utf-8",
                 apparent="utf-8", text="TEXT"):
        self.status_code = status_code
        self.content = content
        self.encoding = encoding
        self.apparent_encoding = apparent
        self.text = text


def _enough(text):
    return [{}] * channels.CHANNEL_MIN_NODES


class TestValidateCandidate:
    def test_fetch_exception(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("dns")
        monkeypatch.setattr(channels, "safe_http_get", boom)
        ok, why = channels._validate_candidate("https://s/x", _enough)
        assert ok is False and why.startswith("fetch:")

    def test_non_200(self, monkeypatch):
        monkeypatch.setattr(channels, "safe_http_get",
                            lambda *a, **k: _Resp(status_code=404))
        ok, why = channels._validate_candidate("https://s/x", _enough)
        assert (ok, why) == (False, "http404")

    def test_ok_when_nodes_reach_min(self, monkeypatch):
        monkeypatch.setattr(channels, "safe_http_get",
                            lambda *a, **k: _Resp())
        ok, why = channels._validate_candidate("https://s/x", _enough)
        assert (ok, why) == (True, "")

    def test_below_min_nodes(self, monkeypatch):
        monkeypatch.setattr(channels, "safe_http_get",
                            lambda *a, **k: _Resp())
        ok, why = channels._validate_candidate(
            "https://s/x", lambda t: [{}] * (channels.CHANNEL_MIN_NODES - 1))
        assert why == f"nodes={channels.CHANNEL_MIN_NODES - 1}"

    def test_parse_exception_counts_zero(self, monkeypatch):
        def bad_parse(text):
            raise ValueError("bad yaml")
        monkeypatch.setattr(channels, "safe_http_get",
                            lambda *a, **k: _Resp())
        ok, why = channels._validate_candidate("https://s/x", bad_parse)
        assert (ok, why) == (False, "nodes=0")

    def test_illegal_charset_falls_back_to_text(self, monkeypatch):
        # 非法 charset → decode 抛 LookupError → 回退 r.text 再解析
        monkeypatch.setattr(channels, "safe_http_get",
                            lambda *a, **k: _Resp(encoding="not-a-charset",
                                                  apparent=None))
        seen = {}
        channels._validate_candidate(
            "https://s/x", lambda t: seen.setdefault("t", t) and _enough(t))
        assert seen["t"] == "TEXT"


# ---------------------------------------------------------------------------
# channels._append_node_links
# ---------------------------------------------------------------------------

class TestAppendNodeLinks:
    @pytest.fixture
    def collected(self, monkeypatch, tmp_path):
        f = tmp_path / "collected_nodes.txt"
        monkeypatch.setattr(channels, "COLLECTED_NODES_FILE", str(f))
        return f

    def test_first_write_and_dedup(self, collected):
        assert channels._append_node_links({"a", "b"}) == 2
        assert channels._append_node_links({"b", "c"}) == 1
        lines = collected.read_text(encoding="utf-8").split()
        # 入参为 set，行序不保证——断言集合与条数
        assert sorted(lines) == ["a", "b", "c"]

    def test_empty_links_noop(self, collected):
        # 空输入仍会落一个空文件（原子写总是执行），但新增行数为 0
        assert channels._append_node_links(set()) == 0
        assert collected.read_text(encoding="utf-8").strip() == ""

    def test_max_cap_keeps_tail(self, collected, monkeypatch):
        monkeypatch.setattr(channels, "MAX_COLLECTED_NODES", 2)
        assert channels._append_node_links({"a", "b", "c"}) == 3
        lines = collected.read_text(encoding="utf-8").split()
        assert len(lines) == 2 and set(lines) <= {"a", "b", "c"}
