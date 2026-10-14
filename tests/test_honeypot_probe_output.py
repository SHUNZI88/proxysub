"""honeypot/probe/output 边界单测·第二批（P1-1d 覆盖率补齐）。

  - honeypot.resolve_hosts：IP 字面量直通 / 域名解析 / 不可解析降级；
  - probe._expected_probe_response：各探测 URL 的响应契约（连接检查
    页 / 热点门户 / generate_204 家族）——tamper 判定的核心依据；
  - probe._probe_http_china_friendly：成功 / 篡改疑似 / 异常 / 4xx 四条
    聚合路径；
  - output.write_outputs / write_github_summary：多格式落盘统计与
    Step Summary 反爬段（release / rotate / 过期清单）。
"""

import honeypot
import output
import probe


# ---------------------------------------------------------------------------
# honeypot.resolve_hosts
# ---------------------------------------------------------------------------

class TestResolveHosts:
    def test_ip_literals_pass_through(self, monkeypatch):
        def boom(*a, **k):
            raise AssertionError("IP 字面量不应触发 DNS")
        monkeypatch.setattr(honeypot.socket, "getaddrinfo", boom)
        out = honeypot.resolve_hosts({"1.2.3.4", "[::1]"})
        assert out == {"1.2.3.4": ["1.2.3.4"], "[::1]": ["::1"]}

    def test_hostname_resolved_sorted_dedup(self, monkeypatch):
        monkeypatch.setattr(
            honeypot.socket, "getaddrinfo",
            lambda h, *a, **k: [(2, 1, 6, "", ("5.6.7.8", 0)),
                                (2, 1, 6, "", ("1.2.3.4", 0)),
                                (2, 1, 6, "", ("5.6.7.8", 0))])
        out = honeypot.resolve_hosts({"example.com"})
        assert out == {"example.com": ["1.2.3.4", "5.6.7.8"]}

    def test_unresolvable_returns_empty(self, monkeypatch):
        def _fail(h, *a, **k):
            raise OSError("nxdomain")
        monkeypatch.setattr(honeypot.socket, "getaddrinfo", _fail)
        assert honeypot.resolve_hosts({"bad.invalid"}) == {"bad.invalid": []}


# ---------------------------------------------------------------------------
# probe：探测响应契约
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status_code=200, text="", content=b""):
        self.status_code = status_code
        self.text = text
        self.content = content


class TestExpectedProbeResponse:
    def test_connecttest_contract(self):
        ok = _FakeResp(200, text="Microsoft Connect Test")
        assert probe._expected_probe_response(
            "http://www.msftconnecttest.com/connecttest.txt", ok) is True
        short = _FakeResp(200, text="ok")
        assert probe._expected_probe_response(
            "http://www.msftconnecttest.com/connecttest.txt", short) is True
        wrong = _FakeResp(200, text="X" * 200)
        assert probe._expected_probe_response(
            "http://www.msftconnecttest.com/connecttest.txt", wrong) is False

    def test_hotspot_detect_contract(self):
        ok = _FakeResp(200, text="<HTML>Success</HTML>")
        assert probe._expected_probe_response(
            "http://captive.apple.com/hotspot-detect.html", ok) is True
        lower = _FakeResp(200, text="success")
        assert probe._expected_probe_response(
            "http://captive.apple.com/success.html", lower) is True

    def test_generate_204_family(self):
        assert probe._expected_probe_response(
            "http://wifi.vivo.com.cn/generate_204",
            _FakeResp(204, content=b"")) is True
        assert probe._expected_probe_response(
            "http://cp.cloudflare.com/generate_204",
            _FakeResp(200, content=b"")) is True
        assert probe._expected_probe_response(
            "http://cp.cloudflare.com/generate_204",
            _FakeResp(200, text="portal", content=b"portal")) is False


class TestProbeHttpChinaFriendly:
    def _patch_get(self, monkeypatch, handler):
        monkeypatch.setattr(probe.requests, "get", handler)

    def test_first_url_success_returns_ok(self, monkeypatch):
        def handler(url, **k):
            return _FakeResp(204, content=b"")
        self._patch_get(monkeypatch, handler)
        ok, lat, tamper, detail = probe._probe_http_china_friendly(
            {"http": "http://127.0.0.1:1"})
        assert ok is True and tamper is False and lat is not None
        assert detail.startswith("ok:")

    def test_all_tamper_like_flags_mitm(self, monkeypatch):
        def handler(url, **k):
            return _FakeResp(200, text="evil portal " * 20, content=b"x" * 500)
        self._patch_get(monkeypatch, handler)
        ok, lat, tamper, detail = probe._probe_http_china_friendly(
            {"http": "http://127.0.0.1:1"})
        assert ok is False and tamper is True

    def test_http_errors_counted_as_details(self, monkeypatch):
        def handler(url, **k):
            return _FakeResp(404, text="nf", content=b"nf")
        self._patch_get(monkeypatch, handler)
        ok, lat, tamper, detail = probe._probe_http_china_friendly(
            {"http": "http://127.0.0.1:1"})
        assert ok is False and tamper is False
        assert "404" in detail

    def test_exceptions_recorded(self, monkeypatch):
        def handler(url, **k):
            raise OSError("refused")
        self._patch_get(monkeypatch, handler)
        ok, lat, tamper, detail = probe._probe_http_china_friendly(
            {"http": "http://127.0.0.1:1"})
        assert ok is False and tamper is False
        assert "err:" in detail


# ---------------------------------------------------------------------------
# output：多格式落盘与 Step Summary
# ---------------------------------------------------------------------------

def _node(name="HK-01"):
    return {"name": name, "type": "vless", "server": "1.2.3.4", "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555", "tls": True,
            "network": "tcp", "servername": "www.microsoft.com",
            "flow": "xtls-rprx-vision",
            "reality-opts": {"public-key": "A" * 43, "short-id": "ab12"},
            "client-fingerprint": "chrome"}


class TestWriteOutputs:
    def test_fixed_names_and_stats(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        stat = output.write_outputs([_node(), _node("JP-02")])
        assert stat["proxies_only"] == 2
        assert stat["singbox"] == 2 and stat["links"] == 2
        for f in (output.OUTPUT_PROXIES_ONLY, output.OUTPUT_SINGBOX,
                  output.OUTPUT_V2RAY):
            assert (tmp_path / f).exists()

    def test_invalid_proxy_skipped_in_links(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        bad = _node("BAD")
        bad.pop("server")
        stat = output.write_outputs([_node(), bad])
        # 无法生成链接/outbound 的节点不计入对应统计（但不阻断写盘）
        assert stat["proxies_only"] == 2
        assert stat["links"] == 1
        assert stat["singbox"] == 1

    def test_namer_redirects_paths(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        sub = tmp_path / "pub"
        sub.mkdir()
        stat = output.write_outputs(
            [_node()], namer=lambda b: str(sub / f"renamed_{b}"))
        assert (sub / f"renamed_{output.OUTPUT_PROXIES_ONLY}").exists()
        assert stat["proxies_only"] == 1


class TestWriteGithubSummary:
    def _write(self, monkeypatch, tmp_path, info):
        p = tmp_path / "summary.md"
        monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(p))
        output.write_github_summary(info)
        return p.read_text(encoding="utf-8")

    def test_anti_crawl_release_section(self, monkeypatch, tmp_path):
        text = self._write(monkeypatch, tmp_path, {
            "anti_crawl": {"enabled": True, "mode": "release",
                           "release_urls": ["https://example.com/sub.yaml"]},
        })
        assert "https://example.com/sub.yaml" in text
        assert "rolling GitHub Release" in text

    def test_anti_crawl_rotate_and_stale_section(self, monkeypatch, tmp_path):
        text = self._write(monkeypatch, tmp_path, {
            "anti_crawl": {"enabled": True, "mode": "rotate", "rotate_days": 30,
                           "real_outputs": ["https://example.com/cur.yaml"],
                           "stale_outputs": ["old.yaml"]},
        })
        assert "https://example.com/cur.yaml" in text
        assert "old.yaml" in text
        assert "every 30 days" in text
