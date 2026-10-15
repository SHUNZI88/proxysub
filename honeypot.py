#!/usr/bin/env python3
"""Anti-honeypot helpers for proxysub.

Layers (cheap -> expensive):
  1. Static host checks: bogus hostnames, IP literals in private/reserved/
     loopback/CGNAT/multicast ranges, invalid ports.
  2. DNS checks: domains resolving to non-global IPs are dropped.
  3. Blocklist: manual domains/ips/cidrs/keywords + auto entries (with expiry)
     from honeypot_blocklist.json.
  4. Source-level cluster checks: one /24 (or /16) dominating a source, or a
     single credential reused across many distinct servers.
  5. Probe-level checks live in filter_clash.py (HTTP 204 body/redirect
     tampering, TLS cert verification via mihomo, egress IP sanity).

None of this can guarantee a node is not a honeypot: a malicious operator
that forwards traffic faithfully is indistinguishable from an honest one.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from typing import Any

BLOCKLIST_FILE = "honeypot_blocklist.json"
AUTO_BLOCK_DAYS = 14

BOGUS_SUFFIXES = (
    ".local", ".lan", ".home", ".internal", ".intranet", ".corp", ".localdomain",
    ".test", ".invalid", ".example", ".onion", ".arpa", ".localhost",
)
BOGUS_HOSTS = {"localhost", "example.com", "example.org", "example.net", "0.0.0.0", "1.1.1.1.1"}
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$", re.I)

# Source-level cluster thresholds (only applied when a source has enough nodes)
CLUSTER_MIN_NODES = 20
CLUSTER_24_RATIO = 0.6
CLUSTER_16_RATIO = 0.85
SHARED_CRED_RATIO = 0.6
SHARED_CRED_MIN_SERVERS = 15
# 模板×网段联合聚集（2026-10-15 替代 ASN 方案的落点）：
# 单模板组内 /24 集中度阈值 + 组规模下限。阈值依据真实数据实验
# （15 个正式源全部实测）：正常聚合源的单模板组内最大 /24 占比最高
# 45.4%（Eternity/NoMoreWalls 等模板同质但节点散布各家 VPS），
# 而 /24 全局聚集在当代免费源已高度分散（最大占比 8.9%，0.6 阈值
# 休眠）。取 0.5 留 4.6 个百分点余量；组 <20 个不判（小样本噪声大）。
CLUSTER_TEMPLATE_MIN = 20
CLUSTER_TEMPLATE_IP_RATIO = 0.5

CRED_KEYS = ("uuid", "password", "passwd", "auth", "auth-str", "psk", "token")


def default_blocklist() -> dict:
    return {
        "_doc": (
            "Manual entries: domains (suffix match), ips, cidrs, keywords (substring of server). "
            "auto: keyed by server host, or fp:<node fingerprint> for shared CDN hosts; added by the cleaner when a node tampers with probe traffic or fails TLS "
            "verification; each auto entry expires after its 'expires' date."
        ),
        "domains": [],
        "ips": [],
        "cidrs": [],
        "keywords": [],
        "auto": {},
    }


def is_bad_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
    except ValueError:
        return False
    return (not ip.is_global) or ip.is_multicast or ip.is_unspecified


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def static_reject_reason(proxy: dict) -> str | None:
    """Cheap syntactic checks without network."""
    host = str(proxy.get("server") or "").strip().lower().rstrip(".")
    if not host:
        return "no_server"
    try:
        port = int(proxy.get("port"))
    except Exception:
        return "bad_port"
    if not (1 <= port <= 65535):
        return "bad_port"
    if host in BOGUS_HOSTS or host.endswith(BOGUS_SUFFIXES):
        return "bogus_host"
    if _is_ip(host):
        return "reserved_ip" if is_bad_ip(host) else None
    if not HOST_RE.match(host):
        return "bogus_host"
    return None


def resolve_hosts(hosts: set[str], workers: int = 64) -> dict[str, list[str]]:
    """host -> list of IPs ([] if unresolvable). IP literals map to themselves."""
    out: dict[str, list[str]] = {}
    todo = []
    for h in hosts:
        if _is_ip(h):
            out[h] = [h.strip("[]")]
        else:
            todo.append(h)

    def _res(h: str) -> tuple[str, list[str]]:
        try:
            infos = socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)
            return h, sorted({i[4][0] for i in infos})
        except Exception:
            return h, []

    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(4)
    try:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for h, ips in ex.map(_res, todo):
                out[h] = ips
    finally:
        socket.setdefaulttimeout(old)
    return out


class Blocklist:
    def __init__(self, data: dict | None):
        base = default_blocklist()
        if isinstance(data, dict):
            base.update({k: v for k, v in data.items() if k in base})
        self.data = base
        self._nets = []
        for c in self.data.get("cidrs", []):
            try:
                self._nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
        self.added_this_run: list[str] = []

    def prune_expired(self) -> int:
        today = date.today().isoformat()
        auto = self.data.setdefault("auto", {})
        expired = [k for k, v in auto.items() if str(v.get("expires", "9999")) < today]
        for k in expired:
            auto.pop(k, None)
        return len(expired)

    def match(self, host: str, ips: list[str], fp: str | None = None) -> str | None:
        host = (host or "").lower().rstrip(".")
        auto = self.data.get("auto", {})
        if fp and f"fp:{fp}" in auto:
            return f"auto:{auto[f'fp:{fp}'].get('reason')}"
        if host in auto:
            return f"auto:{auto[host].get('reason')}"
        for d in self.data.get("domains", []):
            d = d.lower().lstrip(".")
            if host == d or host.endswith("." + d):
                return "manual_domain"
        for kw in self.data.get("keywords", []):
            if kw and kw.lower() in host:
                return "manual_keyword"
        manual_ips = set(self.data.get("ips", []))
        for ip in ips:
            if ip in auto:
                return f"auto:{auto[ip].get('reason')}"
            if ip in manual_ips:
                return "manual_ip"
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(addr in n for n in self._nets):
                return "manual_cidr"
        return None

    def auto_add(self, key: str, reason: str, source: str | None = None) -> None:
        if not key:
            return
        auto = self.data.setdefault("auto", {})
        today = date.today()
        auto[key] = {
            "reason": reason,
            "added": today.isoformat(),
            "expires": (today + timedelta(days=AUTO_BLOCK_DAYS)).isoformat(),
            "source": source,
        }
        self.added_this_run.append(key)


def credential_of(proxy: dict) -> str | None:
    for k in CRED_KEYS:
        v = proxy.get(k)
        if v not in (None, ""):
            return f"{str(proxy.get('type', '')).lower()}:{v}"
    return None


def source_cluster_flags(proxies: list[dict], resolved: dict[str, list[str]]) -> list[str]:
    """Return list of suspicious-structure flags for one source's node set."""
    flags: list[str] = []
    if len(proxies) < CLUSTER_MIN_NODES:
        return flags
    n24: Counter = Counter()
    n16: Counter = Counter()
    v4 = 0
    for p in proxies:
        ips = resolved.get(str(p.get("server", "")).lower().rstrip("."), [])
        ip4 = next((i for i in ips if ":" not in i), None)
        if not ip4:
            continue
        v4 += 1
        parts = ip4.split(".")
        n24[".".join(parts[:3])] += 1
        n16[".".join(parts[:2])] += 1
    if v4 >= CLUSTER_MIN_NODES:
        if n24 and n24.most_common(1)[0][1] / v4 >= CLUSTER_24_RATIO:
            flags.append(f"cluster_24:{n24.most_common(1)[0][0]}.0/24")
        elif n16 and n16.most_common(1)[0][1] / v4 >= CLUSTER_16_RATIO:
            flags.append(f"cluster_16:{n16.most_common(1)[0][0]}.0.0/16")

    servers_by_cred: dict[str, set] = {}
    all_servers = set()
    for p in proxies:
        c = credential_of(p)
        s = str(p.get("server", "")).lower()
        all_servers.add(s)
        if c:
            servers_by_cred.setdefault(c, set()).add(s)
    if servers_by_cred and len(all_servers) >= SHARED_CRED_MIN_SERVERS:
        top = max(len(v) for v in servers_by_cred.values())
        if top >= SHARED_CRED_MIN_SERVERS and top / len(all_servers) >= SHARED_CRED_RATIO:
            flags.append(f"shared_cred:{top}/{len(all_servers)}")
    return flags


def template_key(proxy: dict) -> str:
    """配置模板指纹：同一套生成器导出的节点倾向于共享 type/network/
    ws-path(归一)/Host(泛子域归一)/sni/flow/alpn/obfs/grpc-service-name。
    只取「与运营者部署模板相关、而与服务端点无关」的字段——不含 server/
    port/uuid 等逐节点差异项——从而把同源不同服务器的同模板节点归到一组。
    """
    def _ws_path() -> str:
        net = str(proxy.get("network", "tcp")).lower()
        if net != "ws":
            return ""
        path = str((proxy.get("ws-opts", {}) or {}).get("path", ""))
        # UUID/数字序列归一：同一生成器的路径模板常形如 /<uuid> 或
        # /v2ray/20240601 → 归一成占位符，避免逐节点随机串破坏分组。
        path = re.sub(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "<uuid>", path)
        return re.sub(r"\d+", "<n>", path)

    def _host() -> str:
        net = str(proxy.get("network", "tcp")).lower()
        if net != "ws":
            return ""
        host = str(((proxy.get("ws-opts", {}) or {}).get("headers", {}) or {}).get("Host", ""))
        host = (host or "").strip().lower().rstrip(".")
        labels = host.split(".")
        # 泛子域归一：us1.example.com / us2.example.com → example.com
        return ".".join(labels[-2:]) if len(labels) >= 2 else host

    def _grpc() -> str:
        net = str(proxy.get("network", "tcp")).lower()
        if net != "grpc":
            return ""
        return str((proxy.get("grpc-opts", {}) or {}).get("grpc-service-name", ""))

    def _alpn() -> str:
        alpn = proxy.get("alpn")
        if isinstance(alpn, (list, tuple)):
            return ",".join(sorted(str(a).lower() for a in alpn))
        return str(alpn or "").lower()

    parts = [
        str(proxy.get("type", "")).lower(),
        str(proxy.get("network", "tcp")).lower(),
        _ws_path(),
        _host(),
        str(proxy.get("sni", "")).lower(),
        str(proxy.get("flow", "")).lower(),
        _alpn(),
        str(proxy.get("obfs", "")).lower(),
        str(proxy.get("obfs-param", "")).lower(),
        _grpc(),
    ]
    return "|".join(parts)


def template_ip_cluster_flags(proxies: list[dict], resolved: dict[str, list[str]]) -> list[str]:
    """模板×网段联合聚集：同一配置模板（template_key 相同）的节点若还
    集中在少数 /24 内，则是同运营者批量部署的强信号——区别于「知名聚合源
    模板同质但节点散布各家 VPS」的正常情形。

    单模板组触发门槛（均为硬下限，二者皆满足才标 template_cluster）：
      - 组内节点数 ≥ CLUSTER_TEMPLATE_MIN(20)：小样本噪声大，不判；
      - 组内 IPv4 /24 集中度 ≥ CLUSTER_TEMPLATE_IP_RATIO(0.5)：阈值留 4.6
        个百分点余量（真实实测正常聚合源单模板组内最大 /24 占比 45.4%）。
    此联合信号是 ASN 方案的替代落点：零外部数据依赖，纯本地配置+解析。
    """
    if len(proxies) < CLUSTER_TEMPLATE_MIN:
        return []
    by_key: dict[str, list[dict]] = {}
    for p in proxies:
        by_key.setdefault(template_key(p), []).append(p)
    flags: list[str] = []
    for key, group in by_key.items():
        if len(group) < CLUSTER_TEMPLATE_MIN:
            continue
        v4 = 0
        n24: Counter = Counter()
        for p in group:
            ips = resolved.get(str(p.get("server", "")).lower().rstrip("."), [])
            ip4 = next((i for i in ips if ":" not in i), None)
            if not ip4:
                continue
            v4 += 1
            n24[".".join(ip4.split(".")[:3])] += 1
        if v4 >= CLUSTER_TEMPLATE_MIN and n24:
            top_cidr, top_n = n24.most_common(1)[0]
            if top_n / v4 >= CLUSTER_TEMPLATE_IP_RATIO:
                sig = hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]
                flags.append(
                    f"template_cluster:{sig}:{top_cidr}.0/24({top_n}/{v4})")
    return flags


def summarize_reasons(reasons: dict[str, int]) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(reasons.items(), key=lambda x: -x[1])) or "-"


__all__: list[Any] = [
    "Blocklist", "default_blocklist", "static_reject_reason", "resolve_hosts",
    "source_cluster_flags", "template_key", "template_ip_cluster_flags",
    "credential_of", "is_bad_ip", "BLOCKLIST_FILE",
]
