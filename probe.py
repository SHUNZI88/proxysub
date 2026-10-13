#!/usr/bin/env python3
"""proxysub 探测层：TCP/QUIC 存活检查与 mihomo 真实拨测。仅依赖 common。"""
from __future__ import annotations

import random
import re
import socket
import subprocess
import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import yaml

import honeypot as hp
from common import (
    is_udp_protocol,
    fingerprint,
    UDP_PROTOCOLS,
    LIGHT_PROBE_CONCURRENCY,
    LIGHT_PROBE_TIMEOUT,
    TCP_TIMEOUT,
    PROBE_URLS,
    PROBE_PASS_NEED,
    PROBE_TIMEOUT,
    TRACE_URL,
    PURITY_URL,
    PURITY_TIMEOUT,
    PROBE_CONCURRENCY,
    PROBE_BATCH,
)

def light_http_probe(proxy: dict) -> bool:
    """阶段 1 轻量探活：TCP 可达性粗筛（UDP 协议豁免，交阶段 2 的 QUIC 拨测）。"""
    if is_udp_protocol(proxy):
        return True
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False
    try:
        with socket.create_connection((server, int(port)), timeout=LIGHT_PROBE_TIMEOUT):
            return True
    except Exception:
        return False

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

    px = {"http": proxy_url, "https": proxy_url}
    try:
        ok, lat, _tamper, _d = _probe_http_china_friendly(px)
        if ok and lat is not None:
            return True, lat
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

def _expected_probe_response(url: str, r: requests.Response) -> bool:
    """True when response matches the connectivity-check contract for that URL."""
    if "connecttest.txt" in url:
        body = (r.text or "").strip()
        return r.status_code == 200 and ("Microsoft" in body or "Connect Test" in body or len(body) < 80)
    if "hotspot-detect" in url or "success.html" in url:
        body = (r.text or "")
        return r.status_code == 200 and ("Success" in body or "success" in body.lower() or len(body.strip()) < 120)
    # generate_204 family: empty 204 (some CDNs return 200 empty)
    if r.status_code == 204 and not r.content:
        return True
    if r.status_code == 200 and not r.content:
        return True
    return False

def _probe_http_china_friendly(px: dict) -> tuple[bool, float | None, bool, str]:
    """Try PROBE_URLS; pass if PROBE_PASS_NEED succeed. Returns (ok, latency, tamper, detail)."""
    successes = 0
    tamper_like = 0
    lat: float | None = None
    details: list[str] = []
    for url in PROBE_URLS:
        try:
            t0 = time.time()
            r = requests.get(url, proxies=px, timeout=PROBE_TIMEOUT, allow_redirects=False)
            lat_i = round((time.time() - t0) * 1000, 1)
        except Exception as e:
            details.append(f"err:{type(e).__name__}")
            continue
        if r.status_code >= 400:
            details.append(f"{r.status_code}")
            continue
        if _expected_probe_response(url, r):
            successes += 1
            if lat is None:
                lat = lat_i
            if successes >= PROBE_PASS_NEED:
                return True, lat, False, f"ok:{successes}"
        else:
            tamper_like += 1
            details.append(f"bad{r.status_code}")
    if successes >= PROBE_PASS_NEED:
        return True, lat, False, f"ok:{successes}"
    if successes == 0 and tamper_like >= 2:
        return False, None, True, "/".join(details[:4])
    return False, None, False, "/".join(details[:4])

def _probe_through(port: int) -> dict:
    """Probe one local mihomo listener. China-friendly HTTP URLs; CF HTTPS is soft."""
    px = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
    ok, lat, tamper, detail = _probe_http_china_friendly(px)
    if tamper:
        return {"status": "tamper_http", "detail": detail[:120]}
    if not ok:
        return {"status": "fail"}
    res: dict[str, Any] = {"status": "ok", "latency": lat if lat is not None else 9999.0, "https_ok": False}
    # Soft CF HTTPS trace: useful for egress IP/loc, NOT a sole veto.
    try:
        t = requests.get(TRACE_URL, proxies=px, timeout=PROBE_TIMEOUT, allow_redirects=False)
        body = t.text if t.status_code == 200 else ""
        kv = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        if t.status_code == 200 and kv.get("ip") and kv.get("h"):
            if hp.is_bad_ip(kv["ip"]):
                return {"status": "bad_egress", "detail": kv["ip"]}
            res.update(https_ok=True, egress=kv["ip"], loc=kv.get("loc"))
        # wrong/redirect body: leave https_ok=False (soft), do not hard-fail
    except requests.exceptions.SSLError as e:
        msg = str(e)
        if re.search(r"CERTIFICATE_VERIFY_FAILED|certificate verify failed|hostname mismatch|doesn't match", msg, re.I):
            m = re.search(r"(certificate verify failed[^)'\"]*|hostname mismatch[^)'\"]*)", msg, re.I)
            return {"status": "tls_mitm", "detail": (m.group(1) if m else msg[-120:])[:120]}
    except Exception as e:
        # 排障可见性：egress 探测失败不再静默吞掉（soft 信号，不影响死活判定）
        print(f"  [debug] egress trace 失败: {type(e).__name__}: {str(e)[:80]}")
    # Soft purity: flag CF blocks; keep node (China-usable nodes are often CF-risked).
    if PURITY_URL:
        try:
            pr = requests.get(
                PURITY_URL,
                proxies=px,
                timeout=PURITY_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; proxysub-purity/1.0)"},
            )
            body = (pr.text or "")[:4000]
            blocked = bool(re.search(
                r"Error 1005|Access Denied|access denied|cf-error-details|Sorry, you have been blocked",
                body,
                re.I,
            ))
            if blocked or (pr.status_code in (403, 503) and "cloudflare" in body.lower()):
                res["cf_blocked"] = True
                res["cf_detail"] = f"http{pr.status_code}"
        except Exception:
            pass
    return res

def _mihomo_batch(batch: list[dict], bin_path: str) -> dict[int, dict] | None:
    """Start one mihomo with one listener per node; probe concurrently. None => config rejected."""
    # 每批随机化本地端口：固定端口在上一批进程意外残留（terminate 超时后仍占端口）
    # 时会让下一批启动冲突，导致整批被误判为「配置无法加载」而进入二分重试
    base_port = random.randint(30000, 45000)
    controller = f"127.0.0.1:{random.randint(46000, 60000)}"
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
