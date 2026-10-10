#!/usr/bin/env python3
"""Clean and rank free Clash/Mihomo subscription proxies."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

import honeypot as hp
import sources_manager as sm

# ====================== 配置区 ======================
# 订阅源已移到 sources.json（正式源）和 candidate_sources.json（候选/试用源），
# 由 sources_manager.py 负责自动发现、试用、晋升与淘汰。

EXCLUDE_KEYWORDS = r"(官网|流量|到期|过期|剩余|测试|无效|假|防失联|127\.0\.0|IPv6|试用|公告|电报|TG|频道)"

REGION_RULES = {
    # Order matters: first match wins. AI-oriented regions first.
    "🇭🇰 香港": r"(香港|HK|Hong Kong|HongKong)",
    "🇺🇸 美国": r"(美国|US|United States|USA|America)",
    "🇸🇬 新加坡": r"(新加坡|SG|Singapore|狮城)",
    "🇯🇵 日本": r"(日本|JP|Japan|东京|大阪|Tokyo|Osaka)",
    "🇰🇷 韩国": r"(韩国|韓國|KR|Korea|首尔|首爾|Seoul)",
    "🇹🇼 台湾": r"(台湾|台灣|TW|Taiwan)",
    "🇬🇧 英国": r"(英国|英國|UK|United Kingdom|London|伦敦)",
}

# Per-region caps for AI use: more HK/US capacity, add KR/UK, keep purity via survival+probe ranking.
REGION_QUOTAS = {
    "🇭🇰 香港": 45,
    "🇺🇸 美国": 45,
    "🇸🇬 新加坡": 35,
    "🇯🇵 日本": 30,
    "🇰🇷 韩国": 25,
    "🇹🇼 台湾": 20,
    "🇬🇧 英国": 15,
}
MAX_OTHER = 30  # EU/CA/AU and misc; still ranked by latency+survival

TCP_TIMEOUT = 3.5
PROBE_TIMEOUT = 8.0
MAX_WORKERS = 60
FETCH_WORKERS = 8
FETCH_RETRIES = 2  # at most 2 attempts per source per run
FETCH_TIMEOUT = 25

# url-test / fallback intervals (seconds)
URLTEST_INTERVAL = 150
FALLBACK_INTERVAL = 180

OUTPUT_FILE = "clean_clash.yaml"
SURVIVAL_FILE = "survival.json"
SOURCE_STATS_FILE = "source_stats.json"
BAD_SOURCES_FILE = "bad_sources.json"
PROBE_URL = "http://www.gstatic.com/generate_204"
PROBE_URL_2 = "http://cp.cloudflare.com/generate_204"   # second opinion before calling a node "tampering"
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"  # HTTPS with cert verification + egress IP/loc
PROBE_LIMIT_OFFICIAL = 720
PROBE_PER_CANDIDATE = 16
PROBE_BATCH = 100
PROBE_CONCURRENCY = 32
# Reserve real-probe slots per region so HK/JP/KR/SG/TW are not starved by low-TCP-latency US nodes.
PROBE_RESERVE_PER_REGION = {
    "🇭🇰 香港": 90,
    "🇺🇸 美国": 90,
    "🇸🇬 新加坡": 70,
    "🇯🇵 日本": 70,
    "🇰🇷 韩国": 55,
    "🇹🇼 台湾": 50,
    "🇬🇧 英国": 40,
    "🌐 其他": 40,
}
CANDIDATE_ONLY_PENALTY = 600.0   # nodes only offered by probation sources rank lower
NO_HTTPS_PENALTY = 300.0         # HTTP ok but HTTPS (needed by AI sites) failed
NO_REAL_PROBE_PENALTY = 5000.0   # effectively exclude TCP-only when mihomo is available
MULTI_SOURCE_BONUS = 80.0        # ms-equivalent: appear in multiple official sources
SEEN_DAYS_WEIGHT = 25            # longevity: lifetime seen_days (capped)
MAX_PER_CREDENTIAL = 6           # diversity: same uuid/password across many servers
MAX_PER_EGRESS_IP = 2            # diversity: many nodes exiting from one IP = one operator
TAMPER_STATUSES = ("tamper_http", "tamper_https", "tls_mitm", "bad_egress")
# When mihomo is present, only real-probe OK nodes enter the final subscription (usable rate).
REQUIRE_REAL_PROBE_IN_OUTPUT = True

# Cross-day survival: each consecutive day seen alive adds this many "score" points
SURVIVAL_WEIGHT = 120  # ms-equivalent bonus per consecutive day (lower score = better)
MAX_SURVIVAL_DAYS = 21

# ====================================================


def _today() -> str:
    return date.today().isoformat()


def load_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def fingerprint(proxy: dict) -> str:
    """Stable id from protocol + credentials (not just server:port)."""
    ptype = str(proxy.get("type", "")).lower()
    server = str(proxy.get("server", ""))
    port = str(proxy.get("port", ""))
    parts = [ptype, server, port]

    for key in (
        "uuid",
        "password",
        "passwd",
        "auth",
        "psk",
        "public-key",
        "private-key",
        "short-id",
        "token",
        "auth-str",
        "obfs-password",
    ):
        if proxy.get(key) is not None:
            parts.append(f"{key}={proxy.get(key)}")

    # ss / ssr cipher + password already covered; include network/flow/sni for vless
    for key in ("cipher", "network", "flow", "servername", "sni", "alpn"):
        if proxy.get(key) is not None:
            parts.append(f"{key}={proxy.get(key)}")

    raw = "|".join(parts)
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()


def _try_b64_decode(text: str) -> str | None:
    s = "".join(text.strip().split())
    if not s:
        return None
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        try:
            return base64.b64decode(s).decode("utf-8", errors="ignore")
        except Exception:
            return None


def _parse_ss_uri(uri: str) -> dict | None:
    # ss://BASE64(method:pass@host:port)#name  or ss://method:pass@host:port
    try:
        if not uri.startswith("ss://"):
            return None
        rest = uri[5:]
        name = "ss"
        if "#" in rest:
            rest, name = rest.split("#", 1)
            name = unquote(name)
        if "@" not in rest:
            decoded = _try_b64_decode(rest)
            if not decoded or "@" not in decoded:
                return None
            rest = decoded
        userinfo, hostport = rest.rsplit("@", 1)
        if ":" not in hostport:
            return None
        host, port = hostport.rsplit(":", 1)
        # userinfo may still be base64
        if ":" not in userinfo:
            d = _try_b64_decode(userinfo)
            if d and ":" in d:
                userinfo = d
        method, password = userinfo.split(":", 1)
        return {
            "name": name or f"ss-{host}",
            "type": "ss",
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": password,
        }
    except Exception:
        return None


def _parse_vmess_uri(uri: str) -> dict | None:
    try:
        if not uri.startswith("vmess://"):
            return None
        raw = _try_b64_decode(uri[8:])
        if not raw:
            return None
        obj = json.loads(raw)
        net = obj.get("net") or "tcp"
        proxy = {
            "name": obj.get("ps") or f"vmess-{obj.get('add')}",
            "type": "vmess",
            "server": obj.get("add"),
            "port": int(obj.get("port")),
            "uuid": obj.get("id"),
            "alterId": int(obj.get("aid") or 0),
            "cipher": obj.get("scy") or "auto",
            "network": net,
            "tls": True if obj.get("tls") in ("tls", True, "1") else False,
        }
        if obj.get("sni") or obj.get("host"):
            proxy["servername"] = obj.get("sni") or obj.get("host")
        return proxy
    except Exception:
        return None


def _parse_trojan_uri(uri: str) -> dict | None:
    try:
        if not uri.startswith("trojan://"):
            return None
        u = urlparse(uri)
        password = unquote(u.username or "")
        host = u.hostname
        port = u.port or 443
        qs = parse_qs(u.query)
        name = unquote(u.fragment) if u.fragment else f"trojan-{host}"
        proxy = {
            "name": name,
            "type": "trojan",
            "server": host,
            "port": int(port),
            "password": password,
        }
        sni = (qs.get("sni") or qs.get("peer") or [None])[0]
        if sni:
            proxy["sni"] = sni
        return proxy
    except Exception:
        return None


def parse_subscription_text(text: str) -> list[dict]:
    """Parse Clash YAML, base64 blob, or line-based share links."""
    text = text.strip()
    if not text:
        return []

    # Try YAML first
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            proxies = data.get("proxies")
            if isinstance(proxies, list):
                return [p for p in proxies if isinstance(p, dict)]
            # some feeds are just a list under other keys
            for key in ("Proxy", "proxy"):
                if isinstance(data.get(key), list):
                    return [p for p in data[key] if isinstance(p, dict)]
        if isinstance(data, list) and data and isinstance(data[0], dict) and "server" in data[0]:
            return [p for p in data if isinstance(p, dict)]
    except Exception:
        pass

    # Maybe whole body is base64
    decoded = _try_b64_decode(text)
    if decoded and decoded != text:
        return parse_subscription_text(decoded)

    # Line-based URIs
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for parser in (_parse_ss_uri, _parse_vmess_uri, _parse_trojan_uri):
            p = parser(line)
            if p:
                out.append(p)
                break
    return out


def fetch_one(url: str) -> tuple[str, list[dict], str | None]:
    """Return (url, proxies, error)."""
    last_err = None
    for attempt in range(1, FETCH_RETRIES + 1):
        try:
            r = requests.get(
                url,
                timeout=FETCH_TIMEOUT,
                headers={"User-Agent": "proxysub-cleaner/2.0"},
            )
            r.raise_for_status()
            # prefer text; some feeds mislabel encoding
            content = r.content.decode(r.encoding or "utf-8", errors="ignore")
            proxies = parse_subscription_text(content)
            if not proxies:
                # try raw bytes as base64
                proxies = parse_subscription_text(r.text)
            return url, proxies, None if proxies else "empty_or_unparsed"
        except Exception as e:
            last_err = str(e)
            time.sleep(0.6 * attempt)
    return url, [], last_err or "unknown"


def fetch_all_sources(urls: list[str]) -> tuple[dict[str, list[dict]], dict]:
    stats: dict[str, Any] = {}
    per_source: dict[str, list[dict]] = {}
    print(f"并行拉取 {len(urls)} 个源（workers={FETCH_WORKERS}, retries={FETCH_RETRIES})...")
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        futs = {ex.submit(fetch_one, u): u for u in urls}
        for fut in as_completed(futs):
            url, proxies, err = fut.result()
            stats[url] = {"ok": err is None, "count": len(proxies), "error": err}
            per_source[url] = proxies if not err else []
            print(f"{'失败' if err else '拉取'}: {url} -> {err or len(proxies)}")
    return per_source, stats


def tcp_probe(proxy: dict) -> tuple[bool, float]:
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False, 9999.0
    try:
        start = time.time()
        with socket.create_connection((server, int(port)), timeout=TCP_TIMEOUT):
            return True, round((time.time() - start) * 1000, 1)
    except Exception:
        return False, 9999.0


def http_socks_probe(proxy: dict) -> tuple[bool, float]:
    """Real request through http/socks proxies when possible."""
    ptype = str(proxy.get("type", "")).lower()
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False, 9999.0

    auth = ""
    user = proxy.get("username")
    password = proxy.get("password")
    if user is not None:
        auth = f"{user}:{password}@"

    if ptype in ("http", "https"):
        proxy_url = f"http://{auth}{server}:{port}"
    elif ptype in ("socks5", "socks5h", "socks"):
        proxy_url = f"socks5h://{auth}{server}:{port}"
    else:
        return False, 9999.0

    try:
        start = time.time()
        r = requests.get(
            PROBE_URL,
            proxies={"http": proxy_url, "https": proxy_url},
            timeout=PROBE_TIMEOUT,
            allow_redirects=False,
        )
        # 204 or any response means tunnel worked
        if r.status_code in (204, 200, 301, 302, 404):
            return True, round((time.time() - start) * 1000, 1)
        return False, 9999.0
    except Exception:
        return False, 9999.0


def mihomo_available() -> str | None:
    for cand in (
        os.environ.get("MIHOMO_BIN"),
        "mihomo",
        "clash-meta",
        "/usr/local/bin/mihomo",
        "/usr/bin/mihomo",
    ):
        if not cand:
            continue
        try:
            subprocess.run(
                [cand, "-v"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            return cand
        except Exception:
            continue
    return None


def _probe_through(port: int) -> dict:
    """Probe one local mihomo listener. Verifies content, not just reachability."""
    px = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
    res: dict[str, Any] = {"status": "fail"}
    try:
        t0 = time.time()
        r = requests.get(PROBE_URL, proxies=px, timeout=PROBE_TIMEOUT, allow_redirects=False)
        lat = round((time.time() - t0) * 1000, 1)
    except Exception:
        return res
    if r.status_code >= 400:
        return res  # dial failure / error page: unusable, not counted as tampering
    if r.status_code != 204 or r.content:
        # second opinion from a different endpoint before calling it tampering
        try:
            t0 = time.time()
            r2 = requests.get(PROBE_URL_2, proxies=px, timeout=PROBE_TIMEOUT, allow_redirects=False)
            lat = round((time.time() - t0) * 1000, 1)
        except Exception:
            return res
        if r2.status_code >= 400:
            return res  # error pages: unusable, but not proof of tampering
        if r2.status_code != 204 or r2.content:
            return {"status": "tamper_http", "detail": f"{r.status_code}/{r2.status_code}"}
    res = {"status": "ok", "latency": lat, "https_ok": False}
    try:
        t = requests.get(TRACE_URL, proxies=px, timeout=PROBE_TIMEOUT, allow_redirects=False)
        body = t.text if t.status_code == 200 else ""
        kv = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        if t.status_code == 200 and kv.get("ip") and kv.get("h"):
            if hp.is_bad_ip(kv["ip"]):
                return {"status": "bad_egress", "detail": kv["ip"]}
            res.update(https_ok=True, egress=kv["ip"], loc=kv.get("loc"))
        elif 300 <= t.status_code < 400 or t.status_code == 200:
            return {"status": "tamper_https", "detail": str(t.status_code)}
    except requests.exceptions.SSLError as e:
        msg = str(e)
        if re.search(r"CERTIFICATE_VERIFY_FAILED|certificate verify failed|hostname mismatch|doesn't match", msg, re.I):
            m = re.search(r"(certificate verify failed[^)'\"]*|hostname mismatch[^)'\"]*)", msg, re.I)
            return {"status": "tls_mitm", "detail": (m.group(1) if m else msg[-120:])[:120]}
    except Exception:
        pass
    return res


def _mihomo_batch(batch: list[dict], bin_path: str) -> dict[int, dict] | None:
    """Start one mihomo with one listener per node; probe concurrently. None => config rejected."""
    base_port, controller = 21000, "127.0.0.1:19090"
    named = []
    for i, p in enumerate(batch):
        q = dict(p)
        q["name"] = f"n{i}"
        named.append(q)
    cfg = {
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "ipv6": False,
        "external-controller": controller,
        "proxies": named,
        "listeners": [
            {"name": f"in{i}", "type": "mixed", "listen": "127.0.0.1", "port": base_port + i, "proxy": f"n{i}"}
            for i in range(len(named))
        ],
        "rules": ["MATCH,DIRECT"],
    }
    with tempfile.TemporaryDirectory(prefix="mihomo-probe-") as td:
        cfg_path = Path(td) / "config.yaml"
        cfg_path.write_text(yaml.dump(cfg, allow_unicode=True), encoding="utf-8")
        proc = subprocess.Popen([bin_path, "-d", td, "-f", str(cfg_path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ready = False
            for _ in range(60):
                if proc.poll() is not None:
                    return None
                try:
                    requests.get(f"http://{controller}/version", timeout=0.5)
                    ready = True
                    break
                except Exception:
                    time.sleep(0.2)
            if not ready:
                return None
            time.sleep(0.5)
            out: dict[int, dict] = {}
            with ThreadPoolExecutor(max_workers=PROBE_CONCURRENCY) as ex:
                futs = {ex.submit(_probe_through, base_port + i): i for i in range(len(named))}
                for fut in as_completed(futs):
                    out[futs[fut]] = fut.result()
            return out
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


def mihomo_probe(proxies: list[dict], bin_path: str) -> dict[str, dict]:
    """fingerprint -> probe result. Bad node configs are isolated by bisecting a failed batch."""
    results: dict[str, dict] = {}
    queue = [proxies[i:i + PROBE_BATCH] for i in range(0, len(proxies), PROBE_BATCH)]
    skipped = 0
    while queue:
        batch = queue.pop(0)
        out = _mihomo_batch(batch, bin_path)
        if out is None:
            if len(batch) <= 6:
                skipped += len(batch)
                continue
            mid = len(batch) // 2
            queue[:0] = [batch[:mid], batch[mid:]]
            continue
        for i, r in out.items():
            results[fingerprint(batch[i])] = r
    ok = sum(1 for r in results.values() if r["status"] == "ok")
    print(f"mihomo 真实探测: ok {ok}/{len(proxies)}，配置无法加载跳过 {skipped}")
    return results


def is_preferred(proxy: dict) -> bool:
    ptype = proxy.get("type", "").lower()
    name = proxy.get("name", "").lower()
    if ptype in ("hysteria2", "hy2"):
        return True
    if ptype == "vless":
        if "reality-opts" in proxy or proxy.get("reality-opts"):
            return True
        if "reality" in name:
            return True
        if proxy.get("flow") and "reality" in str(proxy.get("servername", "")).lower():
            return True
    return False


def classify_proxy(name: str) -> str:
    for region, pattern in REGION_RULES.items():
        if re.search(pattern, name, re.IGNORECASE):
            return region
    return "🌐 其他"


def latency_tag(ms: float) -> str:
    if ms >= 9000:
        return ""
    return f" {int(ms)}ms"


def update_survival(alive_fps: set[str], survival: dict) -> dict:
    today = _today()
    updated = dict(survival)
    for fp in list(updated.keys()):
        rec = updated[fp]
        last = rec.get("last_seen")
        if fp in alive_fps:
            if last == today:
                pass
            else:
                # consecutive day?
                try:
                    last_d = date.fromisoformat(last) if last else None
                except Exception:
                    last_d = None
                if last_d and (date.today() - last_d).days == 1:
                    rec["streak"] = int(rec.get("streak", 1)) + 1
                elif last_d and (date.today() - last_d).days == 0:
                    pass
                else:
                    rec["streak"] = 1
                rec["last_seen"] = today
                rec["seen_days"] = int(rec.get("seen_days", 0)) + (0 if last == today else 1)
            updated[fp] = rec
        else:
            # decay: if missing > 2 days, reset streak
            try:
                last_d = date.fromisoformat(last) if last else None
                if last_d and (date.today() - last_d).days > 2:
                    rec["streak"] = 0
                    updated[fp] = rec
            except Exception:
                pass

    for fp in alive_fps:
        if fp not in updated:
            updated[fp] = {"streak": 1, "last_seen": today, "seen_days": 1}
    return updated


def survival_bonus_ms(fp: str, survival: dict) -> float:
    rec = survival.get(fp, {})
    streak = int(rec.get("streak", 0))
    streak = max(0, min(streak, MAX_SURVIVAL_DAYS))
    seen = int(rec.get("seen_days", 0))
    seen = max(0, min(seen, MAX_SURVIVAL_DAYS))
    # higher streak / lifetime => lower effective score (prefer long-lived nodes)
    return -SURVIVAL_WEIGHT * streak - SEEN_DAYS_WEIGHT * seen


def write_github_summary(info: dict) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    d, c, o = info["discovery"], info["cand_rep"], info["off_rep"]
    lines = [
        "# proxysub clean summary",
        "",
        f"- Time (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"- Final proxies: **{info['final']}** | TCP alive: **{info['tcp']}** | real probe ok: **{info['real']}** (HTTPS ok {info['https']})",
        "",
        "## Sources lifecycle",
        "",
        f"- Official sources: **{info['n_official']}** | active candidates: **{info['n_cands']}**",
        f"- Discovered (new candidates): **{len(d['added'])}** (repos scanned {d['searched_repos']}, API calls {d['api_calls']}, repo rejects {len(d['rejected'])})",
        f"- Promoted: **{len(c['promoted'])}** | candidates rejected: **{len(c['rejected'])}** | official demoted: **{len(o['demoted'])}**",
    ]
    for u in d["added"]:
        lines.append(f"  - discovered `{u}`")
    for u in c["promoted"]:
        lines.append(f"  - promoted `{u}`")
    for u, why in c["rejected"].items():
        lines.append(f"  - candidate rejected `{u}`: {why}")
    for u, why in o["demoted"].items():
        lines.append(f"  - demoted `{u}`: {why}")
    if d.get("errors"):
        lines.append(f"- Discovery notes: {'; '.join(d['errors'][:5])}")
    lines += [
        "",
        "## Anti-honeypot",
        "",
        f"- Nodes rejected before probing: **{sum(info['pre_reasons'].values())}** ({hp.summarize_reasons(info['pre_reasons'])})",
        f"- Nodes rejected by probe (tamper/MITM/bad egress): **{sum(info['probe_reasons'].values())}** ({hp.summarize_reasons(info['probe_reasons'])})",
        f"- Auto-blocklisted this run: **{info['auto_added']}** | expired auto entries pruned: {info['expired']}",
        f"- Diversity caps dropped: {info['diversity_dropped']}",
        f"- Suspicious source structure: {info['flags'] or '-'}",
        "",
        "## Sources",
        "",
        "| Source | Role | OK | Count | Alive | Unique | Real ok | Tamper | Error |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for url, s in info["per_src"].items():
        err = (s.get("error") or "").replace("|", "/")
        lines.append(
            f"| `{url}` | {s.get('role')} | {s.get('ok')} | {s.get('count')} | {s.get('alive', 0)} | "
            f"{s.get('unique_alive', s.get('unique_new', 0))} | {s.get('real_ok', 0)} | {s.get('tamper', 0)} | {err} |"
        )
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    sources = sm.load_sources()
    cands = sm.load_candidates()
    blocklist = hp.Blocklist(load_json(hp.BLOCKLIST_FILE, None))
    expired = blocklist.prune_expired()
    stats_file = load_json(SOURCE_STATS_FILE, {})
    history = stats_file.get("history", {}) if isinstance(stats_file, dict) else {}

    # ---- 1. discovery ----
    disc = sm.discover(sources, cands, parse_subscription_text, os.environ.get("GITHUB_TOKEN"))
    print(f"自动发现: 新增候选 {len(disc['added'])}，扫描仓库 {disc['searched_repos']}")

    off_urls = sm.official_urls(sources)
    cand_urls = [u for u in sm.active_candidate_urls(cands) if u not in off_urls]
    off_set = set(off_urls)

    # ---- 2. fetch ----
    per_source, fstats = fetch_all_sources(off_urls + cand_urls)
    print(f"原始节点总数: {sum(len(v) for v in per_source.values())}")

    bad_sources = load_json(BAD_SOURCES_FILE, {})
    bad_sources = {u: v for u, v in bad_sources.items() if u in fstats}
    for url, s in fstats.items():
        rec = bad_sources.get(url, {"fail_streak": 0})
        rec["fail_streak"] = 0 if s.get("ok") else int(rec.get("fail_streak", 0)) + 1
        rec["last_error"] = s.get("error")
        rec["last_count"] = s.get("count", 0)
        bad_sources[url] = rec

    # ---- 3. static + DNS + blocklist filters ----
    exclude_re = re.compile(EXCLUDE_KEYWORDS, re.IGNORECASE)
    pre_reasons: dict[str, int] = defaultdict(int)
    staged: dict[str, list[dict]] = {}
    for url, plist in per_source.items():
        keep = []
        for p in plist:
            if not p.get("server") or not p.get("port") or exclude_re.search(str(p.get("name", ""))):
                continue
            why = hp.static_reject_reason(p)
            if why:
                pre_reasons[why] += 1
                continue
            keep.append(p)
        staged[url] = keep
    hosts = {str(p["server"]).strip().lower().rstrip(".") for pl in staged.values() for p in pl}
    print(f"解析 {len(hosts)} 个主机名...")
    resolved = hp.resolve_hosts(hosts)
    # Guard against fake-IP DNS environments (198.18.0.0/15 etc.): if most domains
    # "resolve" to reserved space, DNS answers are meaningless -> skip that check.
    doms = [h for h in hosts if not h.replace(".", "").isdigit() and ":" not in h]
    bad_dns = sum(1 for h in doms if any(hp.is_bad_ip(i) for i in resolved.get(h, [])))
    dns_trusted = not doms or bad_dns / len(doms) < 0.3
    if not dns_trusted:
        print(f"警告: {bad_dns}/{len(doms)} 个域名解析到保留地址，疑似 fake-ip DNS，跳过 DNS 保留地址检查与源网段聚集检查")

    unique: dict[str, dict] = {}
    prov: dict[str, set] = defaultdict(set)
    src_flags: dict[str, list[str]] = {}
    for url, plist in staged.items():
        flags = hp.source_cluster_flags(plist, resolved) if dns_trusted else []
        if flags:
            src_flags[url] = flags
        for p in plist:
            host = str(p["server"]).strip().lower().rstrip(".")
            ips = resolved.get(host, [])
            if not ips:
                pre_reasons["unresolvable"] += 1
                continue
            if dns_trusted and any(hp.is_bad_ip(ip) for ip in ips):
                pre_reasons["dns_to_reserved_ip"] += 1
                continue
            hit = blocklist.match(host, ips if dns_trusted else [], fingerprint(p))
            if hit:
                pre_reasons[f"blocklist:{hit.split(':')[0]}"] += 1
                continue
            fp = fingerprint(p)
            unique.setdefault(fp, p)
            prov[fp].add(url)
    official_fps = {fp for fp, s in prov.items() if s & off_set}
    candidates = list(unique.values())
    print(f"去重+过滤后: {len(candidates)}（预过滤拒绝 {sum(pre_reasons.values())}）")

    # ---- 4. TCP ----
    print("开始 TCP 连通性与延迟检测...")
    tcp_lat: dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        fut_map = {executor.submit(tcp_probe, p): fp for fp, p in unique.items()}
        for fut in as_completed(fut_map):
            alive, latency = fut.result()
            if alive:
                tcp_lat[fut_map[fut]] = latency
    print(f"TCP 存活节点: {len(tcp_lat)}")

    # ---- 5. real probe (region-stratified official sample + per-candidate budget) ----
    survival_pre = load_json(SURVIVAL_FILE, {})

    def _probe_rank(fp: str) -> tuple:
        # Prefer known survivors, then low TCP latency.
        rec = survival_pre.get(fp, {})
        streak = int(rec.get("streak", 0))
        seen = int(rec.get("seen_days", 0))
        return (-streak, -seen, tcp_lat[fp])

    alive_sorted = sorted(tcp_lat, key=_probe_rank)
    # Stratify: fill per-region reserves first so Asia is actually probed.
    by_region: dict[str, list[str]] = defaultdict(list)
    for fp in alive_sorted:
        if fp not in official_fps:
            continue
        by_region[classify_proxy(unique[fp].get("name", ""))].append(fp)
    sample: list[str] = []
    chosen: set[str] = set()
    for region, reserve in PROBE_RESERVE_PER_REGION.items():
        for fp in by_region.get(region, [])[:reserve]:
            if fp not in chosen:
                sample.append(fp)
                chosen.add(fp)
    for fp in alive_sorted:
        if len(sample) >= PROBE_LIMIT_OFFICIAL:
            break
        if fp in official_fps and fp not in chosen:
            sample.append(fp)
            chosen.add(fp)
    for cu in cand_urls:
        extra = [fp for fp in alive_sorted if cu in prov[fp] and fp not in official_fps and fp not in chosen]
        extra = extra[:PROBE_PER_CANDIDATE]
        sample += extra
        chosen.update(extra)

    probe: dict[str, dict] = {}
    bin_path = mihomo_available()
    if bin_path:
        print(f"使用 mihomo 真实探测 {len(sample)} 个节点: {bin_path}")
        probe = mihomo_probe([unique[fp] for fp in sample], bin_path)
    else:
        print("未找到 mihomo，对 http/socks 做简单真实探测，其余用 TCP 延迟")
        hs = [fp for fp in sample if str(unique[fp].get("type", "")).lower() in ("http", "https", "socks5", "socks5h", "socks")]
        with ThreadPoolExecutor(max_workers=40) as ex:
            fut_map = {ex.submit(http_socks_probe, unique[fp]): fp for fp in hs}
            for fut in as_completed(fut_map):
                ok, lat = fut.result()
                if ok:
                    probe[fut_map[fut]] = {"status": "ok", "latency": lat, "https_ok": False}

    probe_reasons: dict[str, int] = defaultdict(int)
    tampered: set[str] = set()
    host_users: dict[str, int] = defaultdict(int)
    for p in unique.values():
        host_users[str(p["server"]).strip().lower().rstrip(".")] += 1
    for fp, r in probe.items():
        if r["status"] in TAMPER_STATUSES:
            tampered.add(fp)
            probe_reasons[r["status"]] += 1
            host = str(unique[fp]["server"]).strip().lower().rstrip(".")
            # shared hosts (CDN front domains / anycast IPs) are blocked per node, not per host
            key = host if host_users[host] <= 2 else f"fp:{fp}"
            blocklist.auto_add(key, f"{r['status']}:{r.get('detail', '')}"[:100], sorted(prov[fp])[0])
    real_ok = {fp: r for fp, r in probe.items() if r["status"] == "ok"}

    # ---- 6. per-source metrics ----
    per_src: dict[str, dict] = {}
    for url in off_urls + cand_urls:
        fps = [fp for fp, s in prov.items() if url in s]
        alive = [fp for fp in fps if fp in tcp_lat]
        is_off = url in off_set
        m = dict(fstats.get(url, {}))
        m.update(
            role="official" if is_off else "candidate",
            alive=len(alive),
            real_ok=sum(1 for fp in alive if fp in real_ok),
            probed=sum(1 for fp in fps if fp in probe),
            tamper=sum(1 for fp in fps if fp in tampered),
            flags=src_flags.get(url, []),
        )
        if is_off:
            m["unique_alive"] = sum(1 for fp in alive if len(prov[fp] & off_set) == 1)
        else:
            usable = [fp for fp in alive if (fp in real_ok if bin_path else True)]
            m["usable"] = len(usable)
            m["unique_new"] = sum(1 for fp in usable if fp not in official_fps)
        per_src[url] = m

    cand_rep = sm.evaluate_candidates(cands, {u: per_src[u] for u in cand_urls}, sources)
    off_rep = sm.update_official(sources, history, {u: per_src[u] for u in off_urls})
    for u in cand_rep["promoted"]:
        print(f"候选源晋升为正式源: {u}")
    for u, why in {**cand_rep["rejected"], **off_rep["demoted"]}.items():
        print(f"移除源: {u} -> {why}")

    # ---- 7. scoring ----
    survival = survival_pre
    scored: list[tuple[dict, float, float, bool, bool]] = []
    for fp, tlat in tcp_lat.items():
        if fp in tampered:
            continue
        cand_only = fp not in official_fps
        r = real_ok.get(fp)
        if bin_path and REQUIRE_REAL_PROBE_IN_OUTPUT and not r:
            continue  # usable-rate: drop TCP-only / unprobed from final pool
        if cand_only and bin_path and not r:
            continue  # probation-source nodes must pass the real probe
        display = r["latency"] if r else tlat
        penalty = 0.0 if r or not bin_path else NO_REAL_PROBE_PENALTY
        if r and bin_path and not r.get("https_ok"):
            penalty += NO_HTTPS_PENALTY
        if cand_only:
            penalty += CANDIDATE_ONLY_PENALTY
        multi = len(prov[fp] & off_set)
        if multi >= 2:
            penalty -= MULTI_SOURCE_BONUS * min(multi - 1, 3)
        score = display + penalty + survival_bonus_ms(fp, survival)
        scored.append((unique[fp], score, display, is_preferred(unique[fp]), bool(r)))

    scored.sort(key=lambda x: (not x[3], x[1]))
    alive_fps = {fingerprint(p) for p, *_ in scored}
    survival = update_survival(alive_fps, survival)

    # diversity caps: one credential / one egress IP must not dominate the output
    cred_n: dict[str, int] = defaultdict(int)
    egress_n: dict[str, int] = defaultdict(int)
    diversified = []
    diversity_dropped = 0
    for item in scored:
        fp = fingerprint(item[0])
        cred = hp.credential_of(item[0])
        eg = (real_ok.get(fp) or {}).get("egress")
        if (cred and cred_n[cred] >= MAX_PER_CREDENTIAL) or (eg and egress_n[eg] >= MAX_PER_EGRESS_IP):
            diversity_dropped += 1
            continue
        if cred:
            cred_n[cred] += 1
        if eg:
            egress_n[eg] += 1
        diversified.append(item)
    scored = diversified

    region_dict: dict[str, list] = defaultdict(list)
    for item in scored:
        region_dict[classify_proxy(item[0].get("name", ""))].append(item)

    final_proxies: list[dict] = []
    for region, nodes in region_dict.items():
        quota = REGION_QUOTAS.get(region, MAX_OTHER)
        if bin_path and REQUIRE_REAL_PROBE_IN_OUTPUT:
            # Prefer HTTPS-verified egress when the region has enough; else any real-ok.
            https_first = []
            other_real = []
            for item in nodes:
                fp = fingerprint(item[0])
                r = real_ok.get(fp) or {}
                if r.get("https_ok"):
                    https_first.append(item)
                elif item[4]:
                    other_real.append(item)
            pool = https_first + other_real
            # Soft fill: if https pool is tiny, still take other real-ok to avoid empty region.
            selected = pool[:quota]
        else:
            selected = nodes[:quota]
        for proxy, _score, display, _pref, _real in selected:
            base = re.sub(r"\s+\d+ms$", "", str(proxy.get("name", "node")))
            np = dict(proxy)
            np["name"] = f"{base}{latency_tag(display)}"
            if not np["name"].strip():
                np["name"] = f"node{latency_tag(display)}"
            final_proxies.append(np)
        pref_count = sum(1 for _, _, _, p, _ in selected if p)
        real_count = sum(1 for _, _, _, _, r in selected if r)
        print(f"{region}: 保留 {len(selected)}（优先 {pref_count}，真实探测 {real_count}）")

    seen_names: dict[str, int] = {}
    for p in final_proxies:
        n = p["name"]
        if n in seen_names:
            seen_names[n] += 1
            p["name"] = f"{n}#{seen_names[n]}"
        else:
            seen_names[n] = 1

    print(f"\n最终精简节点数: {len(final_proxies)}")
    names = [p["name"] for p in final_proxies]
    groups = [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": ["♻️ 自动选择", "🔯 故障转移", "DIRECT"] + list(REGION_RULES.keys()) + ["🌐 其他"],
        },
        {"name": "♻️ 自动选择", "type": "url-test", "proxies": names, "url": PROBE_URL,
         "interval": URLTEST_INTERVAL, "tolerance": 50},
        {"name": "🔯 故障转移", "type": "fallback", "proxies": names, "url": PROBE_URL,
         "interval": FALLBACK_INTERVAL},
    ]
    for region in list(REGION_RULES.keys()) + ["🌐 其他"]:
        region_names = []
        for p in final_proxies:
            raw = re.sub(r"\s+\d+ms(?:#\d+)?$", "", p.get("name", ""))
            if classify_proxy(raw) == region:
                region_names.append(p["name"])
        region_names = list(dict.fromkeys(region_names))
        if region_names:
            groups.append({"name": region, "type": "url-test", "proxies": region_names,
                           "url": PROBE_URL, "interval": URLTEST_INTERVAL})
    # a select group referencing an empty region group would break the config
    present = {g["name"] for g in groups}
    groups[0]["proxies"] = [n for n in groups[0]["proxies"] if n in present or n == "DIRECT"]

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": final_proxies,
        "proxy-groups": groups,
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }

    # ---- 8. persist ----
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    save_json(SURVIVAL_FILE, survival)
    save_json(BAD_SOURCES_FILE, bad_sources)
    save_json(SOURCE_STATS_FILE, {"date": _today(), "sources": per_src, "history": history})
    sm.save_json(sm.SOURCES_FILE, sources)
    sm.save_json(sm.CANDIDATES_FILE, cands)
    sm.save_json(hp.BLOCKLIST_FILE, blocklist.data)

    print(f"\n✅ 已生成: {OUTPUT_FILE}")
    write_github_summary({
        "final": len(final_proxies), "tcp": len(tcp_lat), "real": len(real_ok),
        "https": sum(1 for r in real_ok.values() if r.get("https_ok")),
        "n_official": len(sources["official"]), "n_cands": len(cands["candidates"]),
        "discovery": disc, "cand_rep": cand_rep, "off_rep": off_rep,
        "pre_reasons": dict(pre_reasons), "probe_reasons": dict(probe_reasons),
        "auto_added": len(blocklist.added_this_run), "expired": expired,
        "diversity_dropped": diversity_dropped,
        "flags": "; ".join(f"{u.split('/')[3] if '//' in u else u}: {','.join(f)}" for u, f in src_flags.items()),
        "per_src": per_src,
    })


if __name__ == "__main__":
    main()
