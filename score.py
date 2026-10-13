#!/usr/bin/env python3
"""proxysub 评分层：协议分层、中美路径惩罚、跨天存活与历史稳定性。仅依赖 common。"""
from __future__ import annotations

from collections import defaultdict
from datetime import date

import re

from common import (
    _has_reality,
    fingerprint,
    _today,
    REGION_RULES,
    US_HOST_HINTS,
    ASIA_REGIONS,
    SNI_WHITELIST_SUFFIXES,
    SNI_BONUS,
    FRIENDLY_PORTS,
    PORT_BONUS,
    REALITY_FP_BONUS,
    US_REGION_DELAY_PENALTY,
    US_EGRESS_PENALTY_HY2_REALITY,
    US_EGRESS_PENALTY_MID,
    US_EGRESS_PENALTY_SS_VMESS,
    MAX_SURVIVAL_DAYS,
    SURVIVAL_WEIGHT,
    SEEN_DAYS_WEIGHT,
    HISTORY_PASS_RATE_BONUS,
    SURVIVAL_PASS_WINDOW,
)

def is_preferred(proxy: dict) -> bool:
    """Hysteria2 / VLESS+Reality — user-requested keep-priority protocols."""
    ptype = str(proxy.get("type", "")).lower()
    if ptype in ("hysteria2", "hy2"):
        return True
    if ptype == "vless" and _has_reality(proxy):
        return True
    return False

def cap_single_source(scored_rows: list, prov: dict, cap: int) -> tuple[list, int]:
    """每个订阅源最多贡献 cap 个节点，防单一聚合源灌满输出。

    实测：VPN-Subcription-Links 一家就 905 个 TCP 存活、Au1rxx 742 个唯一存活，
    不限制就会垄断整个输出（单一源挂掉 = 输出团灭）。节点归属其来源 URL 集合；
    仅出现在一个源里的节点占该源名额，多源节点不占任何单源名额。"""
    out: list = []
    dropped = 0
    src_n: dict[str, int] = defaultdict(int)
    for item in scored_rows:
        urls = sorted(prov.get(fingerprint(item[0]), set()))
        if len(urls) == 1:
            if src_n[urls[0]] >= cap:
                dropped += 1
                continue
            src_n[urls[0]] += 1
        out.append(item)
    return out, dropped

def protocol_tier(proxy: dict) -> int:
    """0=best (hy2/reality), 1=tls modern, 2=legacy encrypted, 3=open/plain junk."""
    ptype = str(proxy.get("type", "")).lower()
    if ptype in ("hysteria2", "hy2"):
        return 0
    if ptype == "vless" and _has_reality(proxy):
        return 0
    if ptype in ("anytls", "tuic", "hysteria", "trojan"):
        return 1
    if ptype == "vless":
        return 1
    if ptype == "vmess":
        tls = proxy.get("tls") in (True, "tls", "1", 1)
        return 2 if tls else 3
    if ptype in ("ss", "ssr"):
        return 3
    if ptype in ("http", "https", "socks5", "socks5h", "socks"):
        return 3
    return 2

def protocol_penalty(proxy: dict) -> float:
    ptype = str(proxy.get("type", "")).lower()
    if ptype in ("hysteria2", "hy2"):
        return PROTOCOL_BONUS_HY2
    if ptype == "vless" and _has_reality(proxy):
        return PROTOCOL_BONUS_REALITY
    if ptype == "trojan":
        return PROTOCOL_BONUS_TROJAN
    if ptype in ("anytls", "tuic", "hysteria"):
        return PROTOCOL_BONUS_TLS_OK
    if ptype == "vless":
        return PROTOCOL_BONUS_TLS_OK
    if ptype == "vmess":
        return PROTOCOL_PENALTY_VMESS
    if ptype in ("ss", "ssr"):
        return PROTOCOL_PENALTY_SS
    if ptype in ("http", "https", "socks5", "socks5h", "socks"):
        return PROTOCOL_PENALTY_HTTP_SOCKS
    return PROTOCOL_PENALTY_OTHER_LOW

def china_feature_bonus(proxy: dict) -> float:
    """SNI whitelist / common ports / Reality chrome|firefox fingerprint."""
    bonus = 0.0
    sni = str(proxy.get("servername") or proxy.get("sni") or "").lower().strip(".")
    if sni and any(sni == s or sni.endswith("." + s) for s in SNI_WHITELIST_SUFFIXES):
        bonus += SNI_BONUS
    try:
        port = int(proxy.get("port", 0))
    except Exception:
        port = 0
    if port in FRIENDLY_PORTS:
        bonus += PORT_BONUS
    cfp = str(proxy.get("client-fingerprint") or proxy.get("client_fingerprint") or "").lower()
    if not cfp:
        ro = proxy.get("reality-opts") or {}
        if isinstance(ro, dict):
            cfp = str(ro.get("client-fingerprint") or ro.get("fingerprint") or "").lower()
    if _has_reality(proxy) and cfp in ("chrome", "firefox", "safari", "ios", "edge", "android"):
        bonus += REALITY_FP_BONUS
    return bonus

def is_us_node(proxy: dict, probe_result: dict | None = None) -> bool:
    """US by region name, CF trace loc, or common US VPS host hints."""
    if classify_proxy(str(proxy.get("name", ""))) == "🇺🇸 美国":
        return True
    if probe_result and str(probe_result.get("loc") or "").upper() == "US":
        return True
    blob = f"{proxy.get('name', '')} {proxy.get('server', '')}"
    if US_HOST_HINTS.search(blob):
        return True
    return False

def us_china_penalty(proxy: dict, probe_result: dict | None = None) -> float:
    """Extra ms penalty for US egress/region when ranking for China clients."""
    region = classify_proxy(str(proxy.get("name", "")))
    pen = 0.0
    if region == "🇺🇸 美国":
        pen += US_REGION_DELAY_PENALTY
    elif region in ASIA_REGIONS:
        pen += ASIA_SCORE_BONUS
    if not is_us_node(proxy, probe_result):
        return pen
    # Already counted region penalty; add egress-style protocol-tiered penalty once.
    # If region was not US but egress/host is US, apply full egress penalty.
    ptype = str(proxy.get("type", "")).lower()
    if ptype in ("hysteria2", "hy2") or (ptype == "vless" and _has_reality(proxy)):
        egress_pen = US_EGRESS_PENALTY_HY2_REALITY
    elif ptype in ("ss", "ssr", "vmess") or ptype in ("http", "https", "socks5", "socks5h", "socks"):
        egress_pen = US_EGRESS_PENALTY_SS_VMESS
    else:
        egress_pen = US_EGRESS_PENALTY_MID
    if region == "🇺🇸 美国":
        # region already +400; add only the delta so Hy2 US is lighter than SS US overall
        # Hy2: 400+300=700, SS: 400+600=1000, Mid: 400+450=850
        pen += egress_pen
    else:
        pen += egress_pen
    return pen

def classify_proxy(name: str) -> str:
    for region, pattern in REGION_RULES.items():
        if re.search(pattern, name, re.IGNORECASE):
            return region
    return "🌐 其他"

def update_survival(alive_fps: set[str], survival: dict,
                    real_ok_fps: set[str] | None = None) -> dict:
    """更新跨天存活与「真实拨测通过率」滑动窗口。

    alive_fps: 本轮 TCP 存活（含 UDP 豁免）节点指纹。
    real_ok_fps: 本轮真实拨测通过的节点指纹（None 表示本轮未做拨测，跳过通过率统计）。
    """
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
                # 真实拨测结果按「运行次数」计入滑动窗口（同一天多次运行也计）
                if real_ok_fps is not None:
                    hist = list(rec.get("real_hist", []))
                    hist.append(1 if fp in real_ok_fps else 0)
                    rec["real_hist"] = hist[-SURVIVAL_PASS_WINDOW:]
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
            rec = {"streak": 1, "last_seen": today, "seen_days": 1}
            if real_ok_fps is not None:
                rec["real_hist"] = [1 if fp in real_ok_fps else 0]
            updated[fp] = rec
    return updated

def survival_bonus_ms(fp: str, survival: dict) -> float:
    rec = survival.get(fp, {})
    streak = int(rec.get("streak", 0))
    streak = max(0, min(streak, MAX_SURVIVAL_DAYS))
    seen = int(rec.get("seen_days", 0))
    seen = max(0, min(seen, MAX_SURVIVAL_DAYS))
    # higher streak / lifetime => lower effective score (prefer long-lived nodes)
    return -SURVIVAL_WEIGHT * streak - SEEN_DAYS_WEIGHT * seen

def history_bonus(fp: str, survival: dict) -> float:
    """历史真实通过率加成：过去若干次拨测中持续通过的节点更可信（负值 = 排更前）。

    与 survival_bonus_ms 互补：后者看「存活天数」，本函数看「真实拨测通过率」。
    """
    rec = survival.get(fp, {})
    hist = rec.get("real_hist") or []
    if not hist:
        return 0.0
    pass_rate = sum(hist) / len(hist)
    # 全部通过 → 满额加成；从不通过 → 无加成（不惩罚，交由拨测闸门裁决）
    return -HISTORY_PASS_RATE_BONUS * pass_rate
