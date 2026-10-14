"""fetch/probe/链接生成的边界单测（P1-1d 覆盖率补齐）。

三块此前提拔未覆盖的逻辑：
  - common.fetch_one：响应编码决策（charset 声明 / iso-8859-1 默认值 /
    apparent_encoding 探测 / 非法 charset 回落）与重试路径——中文节点名
    乱码问题曾根因于此，值得固定；
  - common.fetch_all_sources：并行聚合的 ok/err 统计；
  - probe：TCP 握手 / http-socks 穿透 / mihomo 可用性探测的 mock 路径；
  - output：vless/trojan/tuic/hysteria2 分享链接与 sing-box outbound
    的各 network/参数分支。
"""

import common
import output
import probe


# ---------------------------------------------------------------------------
# common.fetch_one / fetch_all_sources
# ---------------------------------------------------------------------------

class _Resp:
    """最小 requests.Response 替身（content/encoding/apparent_encoding/text）。"""

    def __init__(self, content=b"", encoding="utf-8", apparent="utf-8", text=""):
        self.content = content
        self.encoding = encoding
        self.apparent_encoding = apparent
        self.text = text

    def raise_for_status(self):
        pass


def _patch_http(monkeypatch, resp=None, exc=None):
    if exc is not None:
        monkeypatch.setattr(common, "safe_http_get",
                            lambda *a, **k: (_ for _ in ()).throw(exc))
    else:
        monkeypatch.setattr(common, "safe_http_get", lambda *a, **k: resp)


class TestFetchOne:
    def test_declared_charset_used(self, monkeypatch):
        _patch_http(monkeypatch, _Resp(content="节点A".encode("utf-8"),
                                       encoding="utf-8"))
        monkeypatch.setattr(common, "parse_subscription_text",
                            lambda text: [{"name": text}] if text else [])
        url, proxies, err = common.fetch_one("https://s/x")
        assert err is None and proxies == [{"name": "节点A"}]

    def test_iso8859_default_falls_back_to_apparent(self, monkeypatch):
        # requests 对未声明 charset 的 text/* 默认 iso-8859-1 → 必须走
        # apparent_encoding，否则中文名乱码、地区正则全部失配。
        _patch_http(monkeypatch, _Resp(content="香港".encode("utf-8"),
                                       encoding="ISO-8859-1",
                                       apparent="utf-8"))
        seen = {}
        monkeypatch.setattr(common, "parse_subscription_text",
                            lambda text: seen.setdefault("t", text) and [] or [])
        common.fetch_one("https://s/x")
        assert seen["t"] == "香港"

    def test_illegal_apparent_charset_falls_back_utf8(self, monkeypatch):
        _patch_http(monkeypatch, _Resp(content="x".encode("utf-8"),
                                       encoding=None, apparent="not-a-charset"))
        seen = {}
        monkeypatch.setattr(common, "parse_subscription_text",
                            lambda text: seen.setdefault("t", text) and [] or [])
        common.fetch_one("https://s/x")
        assert seen["t"] == "x"

    def test_empty_content_retries_base64_text(self, monkeypatch):
        _patch_http(monkeypatch, _Resp(content=b"", text="BASE64TEXT"))
        calls = []

        def _parse(text):
            calls.append(text)
            return [{"name": "n"}] if text == "BASE64TEXT" else []
        monkeypatch.setattr(common, "parse_subscription_text", _parse)
        url, proxies, err = common.fetch_one("https://s/x")
        assert err is None and proxies == [{"name": "n"}]
        assert calls == ["", "BASE64TEXT"]

    def test_unparsable_returns_error(self, monkeypatch):
        _patch_http(monkeypatch, _Resp(content=b"junk", text="junk"))
        monkeypatch.setattr(common, "parse_subscription_text", lambda text: [])
        url, proxies, err = common.fetch_one("https://s/x")
        assert err == "empty_or_unparsed" and proxies == []

    def test_exception_retries_then_reports(self, monkeypatch):
        _patch_http(monkeypatch, exc=RuntimeError("boom"))
        monkeypatch.setattr(common.time, "sleep", lambda s: None)
        url, proxies, err = common.fetch_one("https://s/x")
        assert err == "boom" and proxies == []


class TestFetchAllSources:
    def test_mixed_ok_and_error_stats(self, monkeypatch):
        def fake_fetch_one(url):
            if "bad" in url:
                return url, [], "timeout"
            return url, [{"name": "a"}], None
        monkeypatch.setattr(common, "fetch_one", fake_fetch_one)
        per_source, stats = common.fetch_all_sources(
            ["https://ok/x", "https://bad/y"])
        assert stats["https://ok/x"] == {"ok": True, "count": 1, "error": None}
        assert stats["https://bad/y"] == {"ok": False, "count": 0,
                                          "error": "timeout"}
        assert per_source["https://ok/x"] == [{"name": "a"}]
        assert per_source["https://bad/y"] == []


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------

class _Conn:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestTcpProbe:
    def test_missing_server_or_port(self):
        assert probe.tcp_probe({}) == (False, 9999.0)
        assert probe.tcp_probe({"server": "1.1.1.1"}) == (False, 9999.0)

    def test_success(self, monkeypatch):
        monkeypatch.setattr(probe.socket, "create_connection",
                            lambda addr, timeout: _Conn())
        ok, lat = probe.tcp_probe({"server": "1.1.1.1", "port": 443})
        assert ok and lat < 9999.0

    def test_failure(self, monkeypatch):
        def _boom(addr, timeout):
            raise OSError("refused")
        monkeypatch.setattr(probe.socket, "create_connection", _boom)
        assert probe.tcp_probe({"server": "1.1.1.1", "port": 443}) == (False, 9999.0)


class TestHttpSocksProbe:
    def test_missing_server(self):
        assert probe.http_socks_probe({"type": "http"}) == (False, 9999.0)

    def test_unsupported_type(self):
        p = {"type": "vmess", "server": "1.1.1.1", "port": 80}
        assert probe.http_socks_probe(p) == (False, 9999.0)

    def test_http_with_auth_ok(self, monkeypatch):
        seen = {}

        def fake_probe(px):
            seen.update(px)
            return True, 123.0, None, None
        monkeypatch.setattr(probe, "_probe_http_china_friendly", fake_probe)
        p = {"type": "http", "server": "1.1.1.1", "port": 8080,
             "username": "u", "password": "pw"}
        assert probe.http_socks_probe(p) == (True, 123.0)
        assert seen["http"] == "http://u:pw@1.1.1.1:8080"

    def test_socks_url_scheme(self, monkeypatch):
        seen = {}

        def fake_probe(px):
            seen.update(px)
            return False, None, None, None
        monkeypatch.setattr(probe, "_probe_http_china_friendly", fake_probe)
        p = {"type": "socks5", "server": "1.1.1.1", "port": 1080}
        assert probe.http_socks_probe(p) == (False, 9999.0)
        assert seen["https"] == "socks5h://1.1.1.1:1080"

    def test_inner_exception(self, monkeypatch):
        def boom(px):
            raise ValueError("x")
        monkeypatch.setattr(probe, "_probe_http_china_friendly", boom)
        p = {"type": "http", "server": "1.1.1.1", "port": 8080}
        assert probe.http_socks_probe(p) == (False, 9999.0)


class TestMihomoAvailable:
    def test_env_bin_hit(self, monkeypatch):
        monkeypatch.setenv("MIHOMO_BIN", "/opt/mihomo")
        monkeypatch.setattr(probe.subprocess, "run",
                            lambda *a, **k: type("R", (), {"returncode": 0})())
        assert probe.mihomo_available() == "/opt/mihomo"

    def test_path_hit(self, monkeypatch):
        monkeypatch.delenv("MIHOMO_BIN", raising=False)
        monkeypatch.setattr(probe.subprocess, "run",
                            lambda *a, **k: type("R", (), {"returncode": 0})())
        assert probe.mihomo_available() == "mihomo"

    def test_all_fail(self, monkeypatch):
        monkeypatch.delenv("MIHOMO_BIN", raising=False)

        def boom(*a, **k):
            raise FileNotFoundError("no mihomo")
        monkeypatch.setattr(probe.subprocess, "run", boom)
        assert probe.mihomo_available() is None


# ---------------------------------------------------------------------------
# output：分享链接 / sing-box outbound 分支
# ---------------------------------------------------------------------------

def _vless(name="HK-01", server="1.2.3.4", port=443, network="tcp",
           reality=True, flow="xtls-rprx-vision", ws_opts=None,
           grpc_opts=None, h2_opts=None, client_fingerprint="chrome", **over):
    p = {"name": name, "type": "vless", "server": server, "port": port,
         "uuid": "11111111-2222-3333-4444-555555555555", "tls": True,
         "network": network, "servername": "www.microsoft.com",
         "client-fingerprint": client_fingerprint}
    if reality:
        p["flow"] = flow
        p["reality-opts"] = {"public-key": "A" * 43, "short-id": "ab12"}
    if ws_opts:
        p["ws-opts"] = ws_opts
    if grpc_opts:
        p["grpc-opts"] = grpc_opts
    if h2_opts:
        p["h2-opts"] = h2_opts
    p.update(over)
    return p


class TestShareLinks:
    def test_vless_reality_tcp(self):
        link = output.proxy_to_share_link(_vless())
        assert link.startswith("vless://") and "security=reality" in link
        assert "flow=xtls-rprx-vision" in link and "fp=chrome" in link

    def test_vless_ws_with_host_header(self):
        p = _vless(network="ws", reality=False, flow=None,
                   ws_opts={"path": "/ws", "headers": {"Host": "a.com"}})
        link = output.proxy_to_share_link(p)
        assert "type=ws" in link and "path=%2Fws" in link and "host=a.com" in link

    def test_vless_grpc_service_name(self):
        p = _vless(network="grpc", reality=False, flow=None,
                   grpc_opts={"grpc-service-name": "svc"})
        assert "serviceName=svc" in output.proxy_to_share_link(p)

    def test_vless_h2_path(self):
        p = _vless(network="h2", reality=False, flow=None,
                   h2_opts={"path": "/h2"})
        assert "type=h2" in output.proxy_to_share_link(p)

    def test_trojan_link(self):
        p = {"name": "SG-01", "type": "trojan", "server": "9.9.9.9",
             "port": 443, "password": "tp@ss", "sni": "apple.com",
             "network": "ws", "ws-opts": {"path": "/ws"}}
        link = output.proxy_to_share_link(p)
        assert link.startswith("trojan://tp%40ss@9.9.9.9:443")
        assert "type=ws" in link

    def test_trojan_without_password_rejected(self):
        p = {"name": "x", "type": "trojan", "server": "9.9.9.9", "port": 443}
        assert output.proxy_to_share_link(p) is None

    def test_tuic_link_no_password_in_query(self):
        # P0-2：密码只在 userinfo，query 不重复写入
        p = {"name": "T-01", "type": "tuic", "server": "5.5.5.5", "port": 443,
             "uuid": "u-uuid", "password": "secret",
             "congestion-controller": "bbr", "sni": "s.example.com"}
        link = output.proxy_to_share_link(p)
        assert link.startswith("tuic://u-uuid:secret@5.5.5.5:443")
        assert "congestion_control=bbr" in link
        assert "password=" not in link

    def test_hysteria2_link_with_obfs(self):
        p = {"name": "JP-01", "type": "hysteria2", "server": "5.6.7.8",
             "port": 8443, "password": "pw", "sni": "dl.google.com",
             "obfs": "salamander", "obfs-password": "obf",
             "skip-cert-verify": True}
        link = output.proxy_to_share_link(p)
        assert link.startswith("hysteria2://pw@5.6.7.8:8443")
        assert "obfs=salamander" in link and "insecure=1" in link


class TestSingboxOutbound:
    def test_vless_reality_utls(self):
        ob = output.proxy_to_singbox(_vless())
        assert ob["type"] == "vless" and ob["tls"]["reality"]["enabled"] is True
        assert ob["tls"]["utls"]["fingerprint"] == "chrome"

    def test_vless_plain_tls(self):
        p = _vless(reality=False, flow=None, client_fingerprint=None)
        ob = output.proxy_to_singbox(p)
        assert ob["tls"]["enabled"] is True and "reality" not in ob["tls"]

    def test_bad_port_rejected(self):
        assert output.proxy_to_singbox(_vless(port=99999)) is None
        assert output.proxy_to_singbox(_vless(port=0)) is None

    def test_ws_transport(self):
        p = _vless(network="ws", reality=False, flow=None,
                   ws_opts={"path": "/ws", "headers": {"Host": "a.com"}})
        ob = output.proxy_to_singbox(p)
        assert ob["transport"]["type"] == "ws"
        assert ob["transport"]["path"] == "/ws"
