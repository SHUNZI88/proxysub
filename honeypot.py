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


def summarize_reasons(reasons: dict[str, int]) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(reasons.items(), key=lambda x: -x[1])) or "-"


__all__: list[Any] = [
    "Blocklist", "default_blocklist", "static_reject_reason", "resolve_hosts",
    "source_cluster_flags", "credential_of", "is_bad_ip", "BLOCKLIST_FILE",
]
