"""net_safety.safe_http_get 的 SSRF 防护测试（安全评估 F1 / CWE-918）。

覆盖：私网/回环/链路本地(元数据)/组播 IP 拦截、协议白名单、可信 GitHub
主机豁免、重定向目标重新校验（防公网→内网穿透）、跳数上限。
"""

import subprocess
import unittest.mock as mock

import pytest
import requests

import net_safety


# ---------------------------------------------------------------- is_blocked_ip
@pytest.mark.parametrize("ip,blocked", [
    ("169.254.169.254", True),    # 云元数据（链路本地）
    ("127.0.0.1", True),          # 回环
    ("10.0.0.5", True),           # 私网
    ("192.168.1.1", True),        # 私网
    ("172.16.0.1", True),         # 私网
    ("100.64.0.1", True),         # CGNAT（非全局）
    ("0.0.0.0", True),            # 未指定
    ("224.0.0.1", True),          # 组播
    ("::1", True),                # 回环 v6
    ("fe80::1", True),            # 链路本地 v6
    ("fd00::1", True),            # ULA v6
    ("8.8.8.8", False),           # 公网
    ("1.1.1.1", False),           # 公网
    ("2606:4700:4700::1111", False),  # 公网 v6
    ("not-an-ip", True),          # 解析失败一律不可信
])
def test_is_blocked_ip(ip, blocked):
    assert net_safety.is_blocked_ip(ip) is blocked


# ---------------------------------------------------------------- host_is_trusted
def test_trusted_hosts_cover_github_official():
    assert net_safety.host_is_trusted("raw.githubusercontent.com")
    assert net_safety.host_is_trusted("api.github.com")
    # 子域豁免（objects.githubusercontent.com 的直接子域场景）
    assert net_safety.host_is_trusted("RAW.GITHUBUSERCONTENT.COM".lower())
    assert not net_safety.host_is_trusted("t.me")
    assert not net_safety.host_is_trusted("evil-github.com")


# ---------------------------------------------------------------- validate_url_target
def test_validate_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        net_safety.validate_url_target("file:///etc/passwd")
    with pytest.raises(ValueError):
        net_safety.validate_url_target("gopher://127.0.0.1/")


def test_validate_rejects_private_ip_literal(monkeypatch):
    """主机名为 IP 字面量时无需 DNS 也应被拦截。"""
    with pytest.raises(ValueError):
        net_safety.validate_url_target("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ValueError):
        net_safety.validate_url_target("http://127.0.0.1:8080/admin")


def test_validate_dns_rebinding_to_private(monkeypatch):
    """DNS 解析到私网 IP 时必须拒绝（重绑定场景）。"""
    def fake_getaddrinfo(host, *_a, **_kw):
        return [(2, 1, 6, "", ("10.1.2.3", 0))]
    monkeypatch.setattr(net_safety.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError):
        net_safety.validate_url_target("http://evil.example.com/sub")


def test_validate_trusted_host_skips_dns(monkeypatch):
    """可信 GitHub 主机免 DNS 校验（不应调用 getaddrinfo）。"""
    def boom(*_a, **_kw):
        raise AssertionError("trusted host must not resolve DNS")
    monkeypatch.setattr(net_safety.socket, "getaddrinfo", boom)
    net_safety.validate_url_target(
        "https://raw.githubusercontent.com/o/r/main/x.yaml")


def test_validate_public_ip_literal_ok(monkeypatch):
    """公网 IP 字面量直接放行。"""
    net_safety.validate_url_target("https://8.8.8.8/ok")


# ---------------------------------------------------------------- safe_http_get
def _resp(status, headers=None):
    r = requests.Response()
    r.status_code = status
    r.headers.update(headers or {})
    return r


def test_safe_get_blocks_private_target(monkeypatch):
    """安全评估 F1 验收：指向元数据/内网的 URL 必须被拦截且不发请求。"""
    sent = []
    monkeypatch.setattr(net_safety.requests, "get",
                        lambda *a, **kw: sent.append(a) or _resp(200))
    with pytest.raises(ValueError):
        net_safety.safe_http_get("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ValueError):
        net_safety.safe_http_get("http://127.0.0.1:9000/")
    assert sent == []  # 被拦截的请求根本没有发出


def test_safe_get_allows_public_url(monkeypatch):
    monkeypatch.setattr(net_safety.requests, "get",
                        lambda *a, **kw: _resp(200))
    r = net_safety.safe_http_get("https://8.8.8.8/x")
    assert r.status_code == 200


def test_safe_get_follows_redirect_with_revalidation(monkeypatch):
    """公网 302 → 内网 Location 必须被重新校验拦截（防穿透）。"""
    calls = {"n": 0}

    def fake_get(url, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return _resp(302, {"Location": "http://169.254.169.254/"})
        return _resp(200)

    monkeypatch.setattr(net_safety.requests, "get", fake_get)
    with pytest.raises(ValueError):
        net_safety.safe_http_get("https://8.8.8.8/start")
    assert calls["n"] == 1  # 第二次请求从未发出


def test_safe_get_follows_redirect_to_public(monkeypatch):
    """公网 302 → 另一个公网地址应正常跟随。"""
    seen = []

    def fake_get(url, **kw):
        seen.append(url)
        if len(seen) == 1:
            return _resp(302, {"Location": "https://1.1.1.1/final"})
        return _resp(200)

    monkeypatch.setattr(net_safety.requests, "get", fake_get)
    r = net_safety.safe_http_get("https://8.8.8.8/start")
    assert r.status_code == 200
    assert seen == ["https://8.8.8.8/start", "https://1.1.1.1/final"]


def test_safe_get_redirect_loop_capped(monkeypatch):
    """重定向跳数超上限应抛错，不无限循环。"""
    monkeypatch.setattr(net_safety.requests, "get",
                        lambda url, **kw: _resp(302, {"Location": url}))
    with pytest.raises(ValueError):
        net_safety.safe_http_get("https://8.8.8.8/loop", max_redirects=3)


def test_safe_get_never_auto_follows(monkeypatch):
    """必须显式 allow_redirects=False（requests 默认 True，防漏配）。"""
    captured = {}

    def fake_get(url, **kw):
        captured.update(kw)
        return _resp(200)

    monkeypatch.setattr(net_safety.requests, "get", fake_get)
    net_safety.safe_http_get("https://8.8.8.8/x")
    assert captured.get("allow_redirects") is False


# ---------------------------------------------------------------- 接线核验
def test_no_raw_gets_in_fetch_paths():
    """回归：外部可控抓取点不得再使用裸 requests.get（F1 接线固化）。

    豁免：probe.py 的节点拨测（常量 URL + 走代理）与 cn_probe.py 的
    自检/取证（常量 URL）不属于外部可控输入面。
    """
    import re
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for fname in ("channels.py", "common.py", "sources_manager.py"):
        src = (root / fname).read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*requests\.get\(", src, re.M):
            line_no = src[:m.start()].count("\n") + 1
            raise AssertionError(f"{fname}:{line_no} 仍在使用裸 requests.get")
