"""honeypot 源结构聚类 / channels 候选校验与链接合并单测（P1-1d 收尾）。

source_cluster_flags 是蜜罐识别的核心启发式（/24、/16 网段聚集与共享
凭证），_validate_candidate 决定新渠道能否转正，_append_node_links 是
收集文件的唯一写入口——三者的分支逻辑此前提拔未覆盖。
"""

import channels
import honeypot
import pytest


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
