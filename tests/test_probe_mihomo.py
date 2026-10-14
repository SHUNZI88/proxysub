"""probe.py mihomo 探测分支单测（P1-2a 覆盖率补齐）。

覆盖此前低覆盖的四组分支：
  - mihomo_available：env 优先 / PATH 回退 / 全失败返回 None；
  - _probe_through：ok / tamper_http / fail / bad_egress / tls_mitm /
    CF 拦截标记 / egress trace 异常为软信号；
  - _mihomo_batch：进程早退判 None、controller 未就绪判 None、
    正常批量探测与清理；
  - mihomo_probe：正常映射 / 大批量二分重试 / 小批量放弃。

全部走 mock，不启动真实进程、不发真实请求。
"""

from __future__ import annotations

import subprocess

import probe


class _Resp:
    def __init__(self, status_code: int = 200, text: str = "", content: bytes = b""):
        self.status_code = status_code
        self.text = text
        self.content = content

    def json(self):
        return {}


class _Ok:
    returncode = 0


class _Proc:
    """subprocess.Popen 替身：poll 按序返回预设值，之后一直返回 None。"""

    def __init__(self, poll_values=None):
        self._polls = list(poll_values or [])
        self.terminated = False
        self.waited = 0
        self.killed = False

    def poll(self):
        return self._polls.pop(0) if self._polls else None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.waited += 1
        return 0

    def kill(self):
        self.killed = True


def _raise(exc):
    def _fn(*a, **k):
        raise exc
    return _fn


# ---------------------------------------------------------------------------
# mihomo_available
# ---------------------------------------------------------------------------

class TestMihomoAvailable:
    def test_env_bin_takes_priority(self, monkeypatch):
        monkeypatch.setenv("MIHOMO_BIN", "/opt/mihomo")
        seen = []

        def fake_run(cmd, **kw):
            seen.append(cmd)
            return _Ok()

        monkeypatch.setattr(probe.subprocess, "run", fake_run)
        assert probe.mihomo_available() == "/opt/mihomo"
        assert seen == [["/opt/mihomo", "-v"]]

    def test_falls_back_to_next_candidate(self, monkeypatch):
        monkeypatch.delenv("MIHOMO_BIN", raising=False)
        tried = []

        def fake_run(cmd, **kw):
            tried.append(cmd[0])
            if cmd[0] == "mihomo":
                raise FileNotFoundError("mihomo")
            return _Ok()

        monkeypatch.setattr(probe.subprocess, "run", fake_run)
        assert probe.mihomo_available() == "clash-meta"
        assert tried == ["mihomo", "clash-meta"]

    def test_empty_env_value_is_skipped(self, monkeypatch):
        monkeypatch.setenv("MIHOMO_BIN", "")
        tried = []

        def fake_run(cmd, **kw):
            tried.append(cmd[0])
            return _Ok()

        monkeypatch.setattr(probe.subprocess, "run", fake_run)
        assert probe.mihomo_available() == "mihomo"
        assert tried == ["mihomo"]

    def test_none_when_every_candidate_fails(self, monkeypatch):
        monkeypatch.setenv("MIHOMO_BIN", "/nope/mihomo")
        monkeypatch.setattr(probe.subprocess, "run", _raise(OSError("no such file")))
        assert probe.mihomo_available() is None


# ---------------------------------------------------------------------------
# _probe_through
# ---------------------------------------------------------------------------

class TestProbeThrough:
    @staticmethod
    def _china(monkeypatch, ok, lat=50.0, tamper=False, detail=""):
        monkeypatch.setattr(
            probe, "_probe_http_china_friendly",
            lambda px: (ok, lat if ok else None, tamper, detail),
        )

    def test_ok_with_egress_and_loc(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe.hp, "is_bad_ip", lambda ip: False)
        monkeypatch.setattr(probe, "PURITY_URL", "")  # 跳过 purity 分支

        def fake_get(url, **kw):
            assert url == probe.TRACE_URL
            return _Resp(200, "ip=1.2.3.4\nh=www.cloudflare.com\nloc=HK\n")

        monkeypatch.setattr(probe.requests, "get", fake_get)
        res = probe._probe_through(7890)
        assert res["status"] == "ok"
        assert res["latency"] == 50.0
        assert res["https_ok"] is True
        assert res["egress"] == "1.2.3.4"
        assert res["loc"] == "HK"

    def test_trace_without_ip_or_h_leaves_https_false(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe, "PURITY_URL", "")
        monkeypatch.setattr(probe.requests, "get", lambda *a, **k: _Resp(200, "fl=123f\n"))
        res = probe._probe_through(1)
        assert res["status"] == "ok" and res["https_ok"] is False

    def test_non_200_trace_leaves_https_false(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe, "PURITY_URL", "")
        monkeypatch.setattr(probe.requests, "get", lambda *a, **k: _Resp(301, "ip=1.2.3.4\nh=x\n"))
        assert probe._probe_through(1)["https_ok"] is False

    def test_tamper_short_circuits_and_truncates_detail(self, monkeypatch):
        self._china(monkeypatch, False, tamper=True, detail="bad200/" * 60)
        monkeypatch.setattr(probe.requests, "get", _raise(AssertionError("tamper 不应再走 trace")))
        res = probe._probe_through(1)
        assert res["status"] == "tamper_http"
        assert len(res["detail"]) <= 120

    def test_plain_fail_has_no_extra_keys(self, monkeypatch):
        self._china(monkeypatch, False)
        monkeypatch.setattr(probe, "PURITY_URL", "")
        monkeypatch.setattr(probe.requests, "get", _raise(AssertionError("fail 不应走 trace")))
        assert probe._probe_through(1) == {"status": "fail"}

    def test_bad_egress_vetoes_node(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe.hp, "is_bad_ip", lambda ip: True)
        monkeypatch.setattr(probe, "PURITY_URL", "")
        monkeypatch.setattr(probe.requests, "get", lambda *a, **k: _Resp(200, "ip=9.9.9.9\nh=x\n"))
        assert probe._probe_through(1) == {"status": "bad_egress", "detail": "9.9.9.9"}

    def test_tls_mitm_detected_from_ssl_error(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe, "PURITY_URL", "")
        msg = "HTTPSConnectionPool: certificate verify failed: self signed certificate"
        monkeypatch.setattr(probe.requests, "get", _raise(probe.requests.exceptions.SSLError(msg)))
        res = probe._probe_through(1)
        assert res["status"] == "tls_mitm"
        assert "certificate verify failed" in res["detail"]

    def test_trace_exception_is_soft_signal(self, monkeypatch, capsys):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe, "PURITY_URL", "")
        monkeypatch.setattr(probe.requests, "get", _raise(RuntimeError("egress down")))
        res = probe._probe_through(1)
        assert res["status"] == "ok"
        assert res["https_ok"] is False
        assert "egress trace 失败" in capsys.readouterr().out

    def test_cf_blocked_marked_by_body_signature(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe.hp, "is_bad_ip", lambda ip: False)
        monkeypatch.setattr(probe, "PURITY_URL", "https://grok.com/")

        def fake_get(url, **kw):
            if url == probe.TRACE_URL:
                return _Resp(200, "ip=1.2.3.4\nh=x\n")
            return _Resp(200, "<html>Error 1005</html>")

        monkeypatch.setattr(probe.requests, "get", fake_get)
        res = probe._probe_through(1)
        assert res["cf_blocked"] is True
        assert res["cf_detail"] == "http200"

    def test_cf_blocked_by_403_cloudflare(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe.hp, "is_bad_ip", lambda ip: False)
        monkeypatch.setattr(probe, "PURITY_URL", "https://grok.com/")

        def fake_get(url, **kw):
            if url == probe.TRACE_URL:
                return _Resp(200, "ip=1.2.3.4\nh=x\n")
            return _Resp(403, "cloudflare ray id")

        monkeypatch.setattr(probe.requests, "get", fake_get)
        assert probe._probe_through(1)["cf_blocked"] is True

    def test_clean_purity_body_not_flagged(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe.hp, "is_bad_ip", lambda ip: False)
        monkeypatch.setattr(probe, "PURITY_URL", "https://grok.com/")

        def fake_get(url, **kw):
            if url == probe.TRACE_URL:
                return _Resp(200, "ip=1.2.3.4\nh=x\n")
            return _Resp(200, "hello world")

        monkeypatch.setattr(probe.requests, "get", fake_get)
        assert "cf_blocked" not in probe._probe_through(1)

    def test_purity_failure_is_swallowed(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe.hp, "is_bad_ip", lambda ip: False)
        monkeypatch.setattr(probe, "PURITY_URL", "https://grok.com/")
        called = []

        def fake_get(url, **kw):
            called.append(url)
            if url == probe.TRACE_URL:
                return _Resp(200, "ip=1.2.3.4\nh=x\n")
            raise RuntimeError("purity down")

        monkeypatch.setattr(probe.requests, "get", fake_get)
        res = probe._probe_through(1)
        assert res["status"] == "ok" and "cf_blocked" not in res
        assert len(called) == 2

    def test_purity_disabled_when_url_empty(self, monkeypatch):
        self._china(monkeypatch, True)
        monkeypatch.setattr(probe.hp, "is_bad_ip", lambda ip: False)
        monkeypatch.setattr(probe, "PURITY_URL", "")
        urls = []

        def fake_get(url, **kw):
            urls.append(url)
            return _Resp(200, "ip=1.2.3.4\nh=x\n")

        monkeypatch.setattr(probe.requests, "get", fake_get)
        probe._probe_through(1)
        assert urls == [probe.TRACE_URL]


# ---------------------------------------------------------------------------
# _mihomo_batch
# ---------------------------------------------------------------------------

class TestMihomoBatch:
    def test_none_when_process_exits_immediately(self, monkeypatch):
        proc = _Proc(poll_values=[0])
        monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: proc)
        assert probe._mihomo_batch([{"type": "vmess"}], "/bin/true") is None
        assert proc.terminated is True  # finally 仍做清理

    def test_none_when_controller_never_ready(self, monkeypatch):
        proc = _Proc()
        monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: proc)
        monkeypatch.setattr(probe.time, "sleep", lambda s: None)
        monkeypatch.setattr(probe.requests, "get", _raise(OSError("refused")))
        assert probe._mihomo_batch([{"type": "vmess"}], "/bin/true") is None
        assert proc.terminated is True

    def test_probes_each_listener_once(self, monkeypatch):
        proc = _Proc()
        monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: proc)
        monkeypatch.setattr(probe.time, "sleep", lambda s: None)
        monkeypatch.setattr(probe.requests, "get", lambda *a, **k: _Resp(200, "v1"))
        ports = []
        monkeypatch.setattr(
            probe, "_probe_through",
            lambda port: (ports.append(port), {"status": "ok", "latency": 10.0})[1],
        )
        out = probe._mihomo_batch([{"type": "vmess"}, {"type": "trojan"}], "/bin/true")
        assert set(out) == {0, 1}
        assert all(v["status"] == "ok" for v in out.values())
        assert len(ports) == 2 and max(ports) - min(ports) == 1
        assert proc.terminated is True and proc.waited == 1 and proc.killed is False

    def test_kills_when_wait_times_out(self, monkeypatch):
        proc = _Proc()
        proc.wait = lambda timeout=None: (_ for _ in ()).throw(
            subprocess.TimeoutExpired("mihomo", timeout))
        monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: proc)
        monkeypatch.setattr(probe.time, "sleep", lambda s: None)
        monkeypatch.setattr(probe.requests, "get", lambda *a, **k: _Resp(200, "v1"))
        monkeypatch.setattr(probe, "_probe_through", lambda port: {"status": "ok"})
        assert len(probe._mihomo_batch([{"type": "vmess"}], "/bin/true")) == 1
        assert proc.terminated is True and proc.killed is True


# ---------------------------------------------------------------------------
# mihomo_probe
# ---------------------------------------------------------------------------

def _nodes(n, prefix="h"):
    return [
        {"server": f"{prefix}{i}.example.com", "port": 443 + i, "type": "vmess"}
        for i in range(n)
    ]


class TestMihomoProbe:
    def test_maps_fingerprint_to_result(self, monkeypatch):
        nodes = _nodes(3)
        monkeypatch.setattr(probe, "PROBE_BATCH", 100)
        monkeypatch.setattr(
            probe, "_mihomo_batch",
            lambda batch, bin_path: {i: {"status": "ok"} for i in range(len(batch))},
        )
        out = probe.mihomo_probe(nodes, "/bin/true")
        assert set(out) == {probe.fingerprint(n) for n in nodes}
        assert all(v["status"] == "ok" for v in out.values())

    def test_bisects_large_rejected_batch(self, monkeypatch):
        nodes = _nodes(10)
        monkeypatch.setattr(probe, "PROBE_BATCH", 10)
        attempts = []

        def fake_batch(batch, bin_path):
            attempts.append(len(batch))
            if len(batch) == 10:
                return None  # 配置被拒 → 二分
            return {i: {"status": "ok"} for i in range(len(batch))}

        monkeypatch.setattr(probe, "_mihomo_batch", fake_batch)
        out = probe.mihomo_probe(nodes, "/bin/true")
        assert attempts == [10, 5, 5]
        assert len(out) == 10

    def test_gives_up_on_small_rejected_batch(self, monkeypatch, capsys):
        nodes = _nodes(6)
        monkeypatch.setattr(probe, "PROBE_BATCH", 6)
        monkeypatch.setattr(probe, "_mihomo_batch", lambda b, p: None)
        assert probe.mihomo_probe(nodes, "/bin/true") == {}
        assert "跳过 6" in capsys.readouterr().out

    def test_empty_input_returns_empty(self, monkeypatch, capsys):
        monkeypatch.setattr(probe, "_mihomo_batch", _raise(AssertionError("空输入不应启动")))
        assert probe.mihomo_probe([], "/bin/true") == {}
