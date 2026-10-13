#!/usr/bin/env python3
"""proxysub 输出层：分享链接 / sing-box 转换与多格式文件、健康报告。依赖 common + score。"""
from __future__ import annotations

import base64
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import quote, quote_plus

import yaml

import honeypot as hp
from common import (
    _sni_of,
    _truthy,
    _has_reality,
    MIN_FINAL,
    OUTPUT_PROXIES_ONLY,
    OUTPUT_SINGBOX,
    OUTPUT_V2RAY,
    STATS_MD,
)
from score import classify_proxy

def _link_query(params: dict) -> str:
    from urllib.parse import urlencode
    return urlencode({k: v for k, v in params.items() if v not in (None, "", False)},
                     quote_via=quote_plus)

def proxy_to_share_link(p: dict) -> str | None:
    """mihomo proxy dict -> 标准分享链接（vless/trojan/hysteria2/tuic/ss）。"""
    ptype = str(p.get("type", "")).lower().strip()
    server = str(p.get("server") or "").strip()
    try:
        port = int(p.get("port"))
    except (TypeError, ValueError):
        return None
    if not server or not (0 < port < 65536):
        return None
    name = quote(str(p.get("name") or "node"), safe="")
    sni = _sni_of(p) or server

    if ptype == "vless":
        uuid_v = str(p.get("uuid") or "").strip()
        if not uuid_v:
            return None
        params: dict = {"type": str(p.get("network") or "tcp"), "security": "none"}
        if _has_reality(p) or p.get("reality-opts"):
            ro = p.get("reality-opts") or {}
            params["security"] = "reality"
            params["pbk"] = ro.get("public-key") or ""
            params["sid"] = ro.get("short-id") or ""
            params["sni"] = sni
            if p.get("flow"):
                params["flow"] = p["flow"]
        elif _truthy(p.get("tls")):
            params["security"] = "tls"
            params["sni"] = sni
            if p.get("flow"):
                params["flow"] = p["flow"]
            if p.get("alpn"):
                params["alpn"] = ",".join(p["alpn"]) if isinstance(p["alpn"], list) else str(p["alpn"])
            if p.get("client-fingerprint"):
                params["fp"] = p["client-fingerprint"]
        net = str(p.get("network") or "tcp").lower()
        if net == "ws":
            wo = p.get("ws-opts") or {}
            params["path"] = wo.get("path") or "/"
            host = (wo.get("headers") or {}).get("Host")
            if host:
                params["host"] = host
        elif net == "grpc":
            go = p.get("grpc-opts") or {}
            params["serviceName"] = go.get("grpc-service-name") or ""
        elif net == "h2":
            params["path"] = (p.get("h2-opts") or {}).get("path") or "/"
        return f"vless://{uuid_v}@{server}:{port}?{_link_query(params)}#{name}"

    if ptype == "trojan":
        pw = str(p.get("password") or "").strip()
        if not pw:
            return None
        params = {"security": "tls", "sni": sni}
        if p.get("alpn"):
            params["alpn"] = ",".join(p["alpn"]) if isinstance(p["alpn"], list) else str(p["alpn"])
        if p.get("client-fingerprint"):
            params["fp"] = p["client-fingerprint"]
        net = str(p.get("network") or "tcp").lower()
        if net == "ws":
            wo = p.get("ws-opts") or {}
            params["type"] = "ws"
            params["path"] = wo.get("path") or "/"
            host = (wo.get("headers") or {}).get("Host")
            if host:
                params["host"] = host
        return f"trojan://{quote(pw, safe='')}@{server}:{port}?{_link_query(params)}#{name}"

    if ptype in ("hysteria2", "hy2"):
        pw = str(p.get("password") or "").strip()
        if not pw:
            return None
        params = {"sni": sni}
        if p.get("obfs"):
            params["obfs"] = p["obfs"]
            if p.get("obfs-password"):
                params["obfs-password"] = p["obfs-password"]
        if p.get("skip-cert-verify"):
            params["insecure"] = "1"
        # hysteria2 的 auth 位即密码
        return f"hysteria2://{quote(pw, safe='')}@{server}:{port}?{_link_query(params)}#{name}"

    if ptype == "tuic":
        uuid_v = str(p.get("uuid") or "").strip()
        if not uuid_v:
            return None
        params = {"sni": sni}
        if p.get("password"):
            params["password"] = p["password"]
        if p.get("congestion-controller"):
            params["congestion_control"] = p["congestion-controller"]
        return f"tuic://{uuid_v}:{quote(str(p.get('password') or ''), safe='')}@{server}:{port}?{_link_query(params)}#{name}"

    return None

def proxy_to_singbox(p: dict) -> dict | None:
    """mihomo proxy dict -> sing-box outbound（支持 vless/trojan/hysteria2/tuic）。"""
    ptype = str(p.get("type", "")).lower().strip()
    server = str(p.get("server") or "").strip()
    try:
        port = int(p.get("port"))
    except (TypeError, ValueError):
        return None
    if not server or not (0 < port < 65536):
        return None
    name = str(p.get("name") or "node")
    sni = _sni_of(p) or server
    tls: dict = {"enabled": True, "server_name": sni}
    if p.get("alpn"):
        tls["alpn"] = p["alpn"] if isinstance(p["alpn"], list) else [str(p["alpn"])]
    if _truthy(p.get("skip-cert-verify")):
        tls["insecure"] = True

    if ptype == "vless":
        uuid_v = str(p.get("uuid") or "").strip()
        if not uuid_v:
            return None
        ob: dict = {"type": "vless", "tag": name, "server": server, "server_port": port, "uuid": uuid_v}
        if p.get("flow"):
            ob["flow"] = p["flow"]
        net = str(p.get("network") or "tcp").lower()
        if _has_reality(p) or p.get("reality-opts"):
            ro = p.get("reality-opts") or {}
            tls["reality"] = {"enabled": True, "public_key": ro.get("public-key") or "",
                              "short_id": ro.get("short-id") or ""}
            if p.get("client-fingerprint"):
                tls["utls"] = {"enabled": True, "fingerprint": p["client-fingerprint"]}
            ob["tls"] = tls
        elif _truthy(p.get("tls")):
            if p.get("client-fingerprint"):
                tls["utls"] = {"enabled": True, "fingerprint": p["client-fingerprint"]}
            ob["tls"] = tls
        if net == "ws":
            wo = p.get("ws-opts") or {}
            host = (wo.get("headers") or {}).get("Host")
            ob["transport"] = {"type": "ws", "path": wo.get("path") or "/",
                               **({"headers": {"Host": host}} if host else {})}
        elif net == "grpc":
            ob["transport"] = {"type": "grpc",
                               "service_name": (p.get("grpc-opts") or {}).get("grpc-service-name") or ""}
        return ob

    if ptype == "trojan":
        pw = str(p.get("password") or "").strip()
        if not pw:
            return None
        ob = {"type": "trojan", "tag": name, "server": server, "server_port": port,
              "password": pw, "tls": tls}
        if str(p.get("network") or "").lower() == "ws":
            wo = p.get("ws-opts") or {}
            host = (wo.get("headers") or {}).get("Host")
            ob["transport"] = {"type": "ws", "path": wo.get("path") or "/",
                               **({"headers": {"Host": host}} if host else {})}
        return ob

    if ptype in ("hysteria2", "hy2"):
        pw = str(p.get("password") or "").strip()
        if not pw:
            return None
        ob = {"type": "hysteria2", "tag": name, "server": server, "server_port": port,
              "password": pw, "tls": tls}
        if p.get("obfs") == "salamander" and p.get("obfs-password"):
            ob["obfs"] = {"type": "salamander", "password": p["obfs-password"]}
        return ob

    if ptype == "tuic":
        uuid_v = str(p.get("uuid") or "").strip()
        if not uuid_v:
            return None
        ob = {"type": "tuic", "tag": name, "server": server, "server_port": port,
              "uuid": uuid_v, "password": str(p.get("password") or ""), "tls": tls}
        if p.get("congestion-controller"):
            ob["congestion_control"] = p["congestion-controller"]
        return ob

    return None

def write_outputs(final_proxies: list[dict], namer: Callable[[str], str] | None = None) -> dict:
    """生成多格式输出：proxies-only / sing-box / v2ray 分享链接。返回统计信息。

    namer：可选的 basename -> 实际文件名 映射（反爬文件名轮换时由 anti_crawl 提供；
    不传则使用固定名，行为与原来完全一致）。
    """
    stat = {"proxies_only": 0, "singbox": 0, "links": 0}
    _name = namer or (lambda b: b)

    # 1) proxies-only（供客户端 proxy-providers 直接引用）
    with open(_name(OUTPUT_PROXIES_ONLY), "w", encoding="utf-8") as f:
        yaml.dump({"proxies": final_proxies}, f, allow_unicode=True, sort_keys=False)
    stat["proxies_only"] = len(final_proxies)

    # 2) sing-box outbounds
    outbounds = []
    for p in final_proxies:
        ob = proxy_to_singbox(p)
        if ob:
            outbounds.append(ob)
    # 末尾补一个 direct，便于用户直接组合使用
    outbounds.append({"type": "direct", "tag": "direct"})
    with open(_name(OUTPUT_SINGBOX), "w", encoding="utf-8") as f:
        json.dump({"outbounds": outbounds}, f, ensure_ascii=False, indent=2)
    stat["singbox"] = len(outbounds) - 1

    # 3) v2ray/nekobox 分享链接（base64 整段）
    links = []
    for p in final_proxies:
        link = proxy_to_share_link(p)
        if link:
            links.append(link)
    payload = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
    with open(_name(OUTPUT_V2RAY), "w", encoding="utf-8") as f:
        f.write(payload + "\n")
    stat["links"] = len(links)

    print(f"多格式输出: proxies-only {stat['proxies_only']} | sing-box {stat['singbox']} | "
          f"分享链接 {stat['links']}")
    return stat

def write_stats_md(info: dict) -> None:
    """生成人可读的健康报告 stats.md。"""
    final_proxies = info.get("final_proxies", [])
    real_probe_ok = max(0, int(info.get("real", 0)))
    probed = max(0, int(info.get("probed_total", 0)))
    rate = (real_probe_ok / probed) if probed else 0.0

    proto_n: dict[str, int] = defaultdict(int)
    region_n: dict[str, int] = defaultdict(int)
    for p in final_proxies:
        t = str(p.get("type", "")).lower()
        proto_n["Hysteria2" if t in ("hysteria2", "hy2") else
                "VLESS-Reality" if (t == "vless" and _has_reality(p)) else
                "VLESS-TLS" if t == "vless" else t.capitalize()] += 1
        region_n[classify_proxy(p.get("name", ""))] += 1

    per_src = info.get("per_src", {})
    src_ranked = sorted(
        ((u, m) for u, m in per_src.items() if m.get("role") == "official"),
        key=lambda kv: (kv[1].get("real_ok", 0), kv[1].get("unique_alive", 0)),
        reverse=True,
    )[:10]

    L = [
        "# proxysub 健康报告",
        "",
        f"更新时间：{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"运行模式：**{info.get('probe_mode', 'n/a')}**",
        "",
        "## 概览",
        "",
        f"- 最终节点：**{info.get('final', 0)}**"
        f"（合规 {info.get('compliant', 0)}，高风险隔离 {info.get('insecure', 0)}）",
        f"- 真实拨测通过率：**{rate:.1%}**（{real_probe_ok}/{probed}）",
        f"- TCP 存活：{info.get('tcp', 0)} | 正式源 {info.get('n_official', 0)} 个 | "
        f"候选源 {info.get('n_cands', 0)} 个",
        "",
        "## 协议分布",
        "",
        "| 协议 | 数量 |",
        "|---|---|",
    ]
    for k in sorted(proto_n, key=lambda x: -proto_n[x]):
        L.append(f"| {k} | {proto_n[k]} |")

    L += ["", "## 区域分布", "", "| 区域 | 数量 |", "|---|---|"]
    for k in sorted(region_n, key=lambda x: -region_n[x]):
        L.append(f"| {k} | {region_n[k]} |")

    L += ["", "## 源贡献 Top 10（正式源）", "",
          "| 源 | 真实通过 | 独有存活 | 存活 |", "|---|---|---|---|"]
    for u, m in src_ranked:
        short = u.split("/")[3] + "/" + u.split("/")[4] if u.count("/") >= 4 else u
        L.append(f"| `{short}` | {m.get('real_ok', 0)} | {m.get('unique_alive', 0)} | {m.get('alive', 0)} |")

    L += ["", "## 警告", ""]
    demoted = info.get("off_rep", {}).get("demoted", {})
    if demoted:
        for u, why in list(demoted.items())[:10]:
            L.append(f"- 淘汰源 `{u}`：{why}")
    else:
        L.append("- 本轮无源被淘汰")
    flags = info.get("flags") or ""
    if flags:
        L.append(f"- 可疑源结构：{flags}")
    if info.get("final", 0) < MIN_FINAL:
        L.append(f"- ⚠️ 最终节点数 {info.get('final')} 低于下限 {MIN_FINAL}（候选池不足）")
    L.append("")

    with open(STATS_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"健康报告已生成: {STATS_MD}")

def write_github_summary(info: dict) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    d, c, o = info["discovery"], info["cand_rep"], info["off_rep"]
    lines = [
        "# proxysub clean summary",
        "",
        f"- Time (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"- Probe mode: **{info.get('probe_mode', 'n/a')}** (final liveness/speed testing is done client-side)",
        f"- Final proxies: **{info['final']}** (compliant {info.get('compliant', info['final'])}, "
        f"insecure-isolated {info.get('insecure', 0)}) | TCP alive: **{info['tcp']}** | real probe ok: **{info['real']}** (HTTPS ok {info['https']})",
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
    ]

    # 反爬状态：真实订阅地址只写在本页（仅仓库所有者可见），不进入任何公开文件
    ac = info.get("anti_crawl") or {}
    if ac.get("enabled"):
        repo = os.environ.get("GITHUB_REPOSITORY", "OWNER/REPO")
        lines += [
            "## Anti-crawl (real URLs are ONLY shown here — do not share)",
            "",
            f"- Fixed-name files (`clean_clash.yaml` etc.) are **decoy content** "
            f"({(ac.get('decoy') or {}).get('total', 0)} bait nodes); rotation every "
            f"{ac.get('rotate_days', '?')} days",
        ]
        lines += [f"- `https://raw.githubusercontent.com/{repo}/main/{p}`"
                  for p in ac.get("real_outputs", []) if p]
        if ac.get("stale_outputs"):
            lines.append(f"- Expired (deleted): {', '.join(ac['stale_outputs'])}")
        lines.append("")

    lines += [
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
