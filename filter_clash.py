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

# ====================== 配置区 ======================
SOURCE_URLS = [
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml",
    "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml",
    "https://raw.githubusercontent.com/PuddinCat/BestClash/refs/heads/main/proxies.yaml",
    "https://raw.githubusercontent.com/yy1588133/proxy-pool/main/clash.yaml",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
    "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/clash_config.yaml",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.meta.yml",
    "https://raw.githubusercontent.com/Russ534/clash/cdf534db8f8c9306d61c630b840d0a1936d09dd2/bp.yaml",
    "https://raw.githubusercontent.com/shaoyouvip/free/main/mihomo.yaml",
    "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml",
    "https://blog.ermao.net/sub/clash/ermao.net",
    "https://raw.githubusercontent.com/lanzm/MetaFetch/master/list.meta.yml",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.meta.yml",
]

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
FETCH_RETRIES = 3
FETCH_TIMEOUT = 25

# url-test / fallback intervals (seconds)
URLTEST_INTERVAL = 150
FALLBACK_INTERVAL = 180

OUTPUT_FILE = "clean_clash.yaml"
SURVIVAL_FILE = "survival.json"
SOURCE_STATS_FILE = "source_stats.json"
BAD_SOURCES_FILE = "bad_sources.json"
PROBE_URL = "http://www.gstatic.com/generate_204"

# Cross-day survival: each consecutive day seen alive adds this many "score" points
SURVIVAL_WEIGHT = 55  # ms-equivalent bonus per consecutive day (lower score = better)
MAX_SURVIVAL_DAYS = 14

# Demote sources that fail this many consecutive runs
BAD_SOURCE_THRESHOLD = 3
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


def fetch_all_sources(urls: list[str]) -> tuple[list[dict], dict]:
    stats: dict[str, Any] = {}
    all_proxies: list[dict] = []
    print(f"并行拉取 {len(urls)} 个源（workers={FETCH_WORKERS}, retries={FETCH_RETRIES})...")
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        futs = {ex.submit(fetch_one, u): u for u in urls}
        for fut in as_completed(futs):
            url, proxies, err = fut.result()
            stats[url] = {
                "ok": err is None,
                "count": len(proxies),
                "error": err,
            }
            if err:
                print(f"失败: {url} -> {err}")
            else:
                print(f"拉取: {url} -> {len(proxies)}")
                all_proxies.extend(proxies)
    return all_proxies, stats


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


def mihomo_batch_probe(proxies: list[dict], bin_path: str, limit: int = 500) -> dict[str, float]:
    """
    Start a temporary mihomo with external-controller, switch each proxy, measure PROBE_URL.
    Returns fingerprint -> latency_ms for successes.
    """
    results: dict[str, float] = {}
    sample = proxies[:limit]
    if not sample:
        return results

    # unique names for mihomo
    named = []
    for i, p in enumerate(sample):
        q = dict(p)
        q["name"] = f"n{i}"
        named.append(q)

    controller = "127.0.0.1:19090"
    mixed_port = 17890
    cfg = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "global",
        "log-level": "error",
        "external-controller": controller,
        "proxies": named,
        "proxy-groups": [
            {
                "name": "PROBE",
                "type": "select",
                "proxies": [p["name"] for p in named],
            }
        ],
        "rules": ["MATCH,PROBE"],
    }

    with tempfile.TemporaryDirectory(prefix="mihomo-probe-") as td:
        cfg_path = Path(td) / "config.yaml"
        cfg_path.write_text(yaml.dump(cfg, allow_unicode=True), encoding="utf-8")
        proc = subprocess.Popen(
            [bin_path, "-d", td, "-f", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            # wait for API
            api = f"http://{controller}"
            ready = False
            for _ in range(40):
                try:
                    requests.get(f"{api}/version", timeout=0.5)
                    ready = True
                    break
                except Exception:
                    time.sleep(0.15)
            if not ready:
                print("mihomo API 未就绪，跳过真实探测")
                return results

            proxy_url = f"http://127.0.0.1:{mixed_port}"
            for i, original in enumerate(sample):
                name = f"n{i}"
                try:
                    requests.put(
                        f"{api}/proxies/PROBE",
                        json={"name": name},
                        timeout=2,
                    )
                    start = time.time()
                    r = requests.get(
                        PROBE_URL,
                        proxies={"http": proxy_url, "https": proxy_url},
                        timeout=PROBE_TIMEOUT,
                        allow_redirects=False,
                    )
                    if r.status_code in (204, 200, 301, 302, 404):
                        results[fingerprint(original)] = round((time.time() - start) * 1000, 1)
                except Exception:
                    continue
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
    print(f"mihomo 真实探测成功: {len(results)}/{len(sample)}")
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
    streak = int(survival.get(fp, {}).get("streak", 0))
    streak = max(0, min(streak, MAX_SURVIVAL_DAYS))
    # higher streak => lower effective score
    return -SURVIVAL_WEIGHT * streak


def write_github_summary(stats: dict, final_count: int, tcp_n: int, real_n: int) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    lines = [
        "# proxysub clean summary",
        "",
        f"- Final proxies: **{final_count}**",
        f"- TCP alive: **{tcp_n}**",
        f"- Real probe ok: **{real_n}**",
        f"- Time (UTC): {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Sources",
        "",
        "| Source | OK | Count | Error |",
        "|---|---|---|---|",
    ]
    for url, s in stats.items():
        err = (s.get("error") or "").replace("|", "/")
        lines.append(f"| `{url}` | {s.get('ok')} | {s.get('count')} | {err} |")
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    bad_sources = load_json(BAD_SOURCES_FILE, {})
    # demote: put repeatedly-failing sources at end; still try them
    urls = list(SOURCE_URLS)
    urls.sort(key=lambda u: int(bad_sources.get(u, {}).get("fail_streak", 0)), reverse=False)

    all_proxies, stats = fetch_all_sources(urls)
    print(f"原始节点总数: {len(all_proxies)}")

    # update bad source streaks
    for url, s in stats.items():
        rec = bad_sources.get(url, {"fail_streak": 0})
        if s.get("ok"):
            rec["fail_streak"] = 0
        else:
            rec["fail_streak"] = int(rec.get("fail_streak", 0)) + 1
        rec["last_error"] = s.get("error")
        rec["last_count"] = s.get("count", 0)
        bad_sources[url] = rec
    save_json(BAD_SOURCES_FILE, bad_sources)
    save_json(SOURCE_STATS_FILE, {"date": _today(), "sources": stats})

    demoted = [u for u, r in bad_sources.items() if int(r.get("fail_streak", 0)) >= BAD_SOURCE_THRESHOLD]
    if demoted:
        print(f"持续失败降权源 ({BAD_SOURCE_THRESHOLD}+): {len(demoted)}")

    exclude_re = re.compile(EXCLUDE_KEYWORDS, re.IGNORECASE)
    unique: dict[str, dict] = {}
    for p in all_proxies:
        name = p.get("name", "")
        if not p.get("server") or not p.get("port"):
            continue
        if exclude_re.search(str(name)):
            continue
        fp = fingerprint(p)
        # keep first for now; after latency we may replace with faster
        if fp not in unique:
            unique[fp] = p

    candidates = list(unique.values())
    print(f"去重(协议+凭证)+关键词过滤后: {len(candidates)}")

    print("开始 TCP 连通性与延迟检测...")
    tcp_alive: list[tuple[dict, float]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        fut_map = {executor.submit(tcp_probe, p): p for p in candidates}
        for fut in as_completed(fut_map):
            proxy = fut_map[fut]
            alive, latency = fut.result()
            if alive:
                tcp_alive.append((proxy, latency))
    print(f"TCP 存活节点: {len(tcp_alive)}")

    # Real probe: prefer mihomo; else http/socks direct probe; else TCP latency
    real_latency: dict[str, float] = {}
    bin_path = mihomo_available()
    if bin_path:
        print(f"使用 mihomo 真实探测: {bin_path}")
        # probe up to 500 fastest TCP nodes to bound runtime
        tcp_alive.sort(key=lambda x: x[1])
        real_latency = mihomo_batch_probe([p for p, _ in tcp_alive], bin_path, limit=500)
    else:
        print("未找到 mihomo，对 http/socks 做真实探测，其余用 TCP 延迟")
        http_socks = [(p, lat) for p, lat in tcp_alive if str(p.get("type", "")).lower() in ("http", "https", "socks5", "socks5h", "socks")]
        with ThreadPoolExecutor(max_workers=min(40, MAX_WORKERS)) as ex:
            fut_map = {ex.submit(http_socks_probe, p): (p, lat) for p, lat in http_socks}
            for fut in as_completed(fut_map):
                p, _tcp = fut_map[fut]
                ok, lat = fut.result()
                if ok:
                    real_latency[fingerprint(p)] = lat

    survival = load_json(SURVIVAL_FILE, {})
    scored: list[tuple[dict, float, float, bool, bool]] = []
    # proxy, sort_score, display_latency, preferred, real_ok
    for proxy, tcp_lat in tcp_alive:
        fp = fingerprint(proxy)
        real_ok = fp in real_latency
        display = real_latency.get(fp, tcp_lat)
        # prefer real-ok nodes: add penalty if only TCP
        penalty = 0.0 if real_ok or not bin_path else 1000.0
        score = display + penalty + survival_bonus_ms(fp, survival)
        scored.append((proxy, score, display, is_preferred(proxy), real_ok))

    # Dedup again preferring lower score (better latency / survival)
    best_by_fp: dict[str, tuple[dict, float, float, bool, bool]] = {}
    for item in scored:
        fp = fingerprint(item[0])
        prev = best_by_fp.get(fp)
        if prev is None or item[1] < prev[1]:
            best_by_fp[fp] = item
    scored = list(best_by_fp.values())

    scored.sort(key=lambda x: (not x[3], x[1]))
    alive_fps = {fingerprint(p) for p, *_ in scored}
    survival = update_survival(alive_fps, survival)
    save_json(SURVIVAL_FILE, survival)

    region_dict: dict[str, list] = defaultdict(list)
    for item in scored:
        region = classify_proxy(item[0].get("name", ""))
        region_dict[region].append(item)

    final_proxies: list[dict] = []
    for region, nodes in region_dict.items():
        limit = REGION_QUOTAS.get(region, MAX_OTHER)
        selected = nodes[:limit]
        for proxy, _score, display, preferred, real_ok in selected:
            # rename with latency for client-side readability
            base = re.sub(r"\s+\d+ms$", "", str(proxy.get("name", "node")))
            tag = latency_tag(display)
            extra = ""
            if real_ok:
                extra = ""
            np = dict(proxy)
            np["name"] = f"{base}{tag}{extra}"
            # avoid empty names
            if not np["name"].strip():
                np["name"] = f"node{tag}"
            final_proxies.append(np)
        pref_count = sum(1 for _, _, _, p, _ in selected if p)
        real_count = sum(1 for _, _, _, _, r in selected if r)
        print(f"{region}: 保留 {len(selected)}（优先 {pref_count}，真实探测 {real_count}）")

    # Ensure unique names
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
            "proxies": ["♻️ 自动选择", "🔯 故障转移", "DIRECT"]
            + list(REGION_RULES.keys())
            + ["🌐 其他"],
        },
        {
            "name": "♻️ 自动选择",
            "type": "url-test",
            "proxies": names,
            "url": PROBE_URL,
            "interval": URLTEST_INTERVAL,
            "tolerance": 50,
        },
        {
            "name": "🔯 故障转移",
            "type": "fallback",
            "proxies": names,
            "url": PROBE_URL,
            "interval": FALLBACK_INTERVAL,
        },
    ]

    for region in list(REGION_RULES.keys()) + ["🌐 其他"]:
        region_names = []
        for p in final_proxies:
            raw = re.sub(r"\s+\d+ms(?:#\d+)?$", "", p.get("name", ""))
            if classify_proxy(raw) == region:
                region_names.append(p["name"])
        region_names = list(dict.fromkeys(region_names))
        if region_names:
            groups.append(
                {
                    "name": region,
                    "type": "url-test",
                    "proxies": region_names,
                    "url": PROBE_URL,
                    "interval": URLTEST_INTERVAL,
                }
            )

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": final_proxies,
        "proxy-groups": groups,
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"\n✅ 已生成: {OUTPUT_FILE}")
    write_github_summary(stats, len(final_proxies), len(tcp_alive), len(real_latency))


if __name__ == "__main__":
    main()
