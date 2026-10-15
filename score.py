#!/usr/bin/env python3
"""proxysub 评分层：协议分层、中美路径惩罚、跨天存活与历史稳定性。仅依赖 common。"""
from __future__ import annotations

from collections import defaultdict
from datetime import date

import re

from common import _has_reality, _today, fingerprint
from config import (
    ASIA_REGIONS,
    ASIA_SCORE_BONUS,
    FRIENDLY_PORTS,
    HISTORY_PASS_RATE_BONUS,
    MAX_SURVIVAL_DAYS,
    PORT_BONUS,
    PROTOCOL_BONUS_HY2,
    PROTOCOL_BONUS_REALITY,
    PROTOCOL_BONUS_TLS_OK,
    PROTOCOL_BONUS_TROJAN,
    PROTOCOL_PENALTY_HTTP_SOCKS,
    PROTOCOL_PENALTY_OTHER_LOW,
    PROTOCOL_PENALTY_SS,
    PROTOCOL_PENALTY_VMESS,
    REALITY_FP_BONUS,
    REGION_RULES,
    SEEN_DAYS_WEIGHT,
    SNI_BONUS,
    SNI_WHITELIST_SUFFIXES,
    SURVIVAL_PASS_WINDOW,
    SURVIVAL_PRUNE_IDLE_DAYS,
    SURVIVAL_PRUNE_KEEP_SEEN,
    SURVIVAL_PRUNE_ZOMBIE_SEEN_MAX,
    SURVIVAL_STREAK_FORCE_PROBE,
    SURVIVAL_WEIGHT,
    US_EGRESS_PENALTY_HY2_REALITY,
    US_EGRESS_PENALTY_MID,
    US_EGRESS_PENALTY_SS_VMESS,
    US_HOST_HINTS,
    US_REGION_DELAY_PENALTY,
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
    """中美路径软惩罚（ms 等价，供中国客户端视角排序）。

    两层可叠加（区域项为负即加成）：
      1. 区域名：美国 +US_REGION_DELAY_PENALTY；亚洲区域 +ASIA_SCORE_BONUS；
      2. 出口证据（拨测 loc=US 或主机名线索判 US）时按协议分层追加出口惩罚：
         Hy2 / vless+Reality 最轻（现代协议在美出口下延迟更稳），
         SS/VMess/HTTP/SOCKS 最重，其余（trojan 等）居中。
    无美国出口证据时提前返回——区域项不与出口惩罚叠加。
    """
    region = classify_proxy(str(proxy.get("name", "")))
    pen = 0.0
    if region == "🇺🇸 美国":
        pen += US_REGION_DELAY_PENALTY
    elif region in ASIA_REGIONS:
        pen += ASIA_SCORE_BONUS
    if not is_us_node(proxy, probe_result):
        return pen
    ptype = str(proxy.get("type", "")).lower()
    if ptype in ("hysteria2", "hy2") or (ptype == "vless" and _has_reality(proxy)):
        egress_pen = US_EGRESS_PENALTY_HY2_REALITY
    elif ptype in ("ss", "ssr", "vmess", "http", "https", "socks5", "socks5h", "socks"):
        egress_pen = US_EGRESS_PENALTY_SS_VMESS
    else:
        egress_pen = US_EGRESS_PENALTY_MID
    return pen + egress_pen

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
    return prune_survival(updated, today=today)


def prune_survival(survival: dict, *, today: str | None = None,
                   max_idle_days: int = SURVIVAL_PRUNE_IDLE_DAYS,
                   max_lifespan_for_zombie: int = SURVIVAL_PRUNE_ZOMBIE_SEEN_MAX) -> dict:
    """清理长期未出现 / 已中断的「僵尸」存活记录（**修正评分信号 + 控制体积**）。

    为什么必须清理（不只是省空间）：
    `survival_bonus_ms` 的 `seen_days` 是**终身累计、从不重置**的字段——
    一条僵尸记录（如 last_seen=10-10、seen_days=1、streak=0）虽已死，但该 fp
    若日后「诈尸」重新出现，会立刻白得 `-SEEN_DAYS_WEIGHT×seen_days` 的历史
    长寿加成（实测 55ms/seen_day），建立在**早已中断的历史**上。

    实测（2026-10-15）：survival.json 7285 条中，5005 条属此类僵尸——last_seen
    停在 3+ 天前、streak 已归零、seen_days≤2、且无真实拨测通过史。它们对当前
    排序零贡献，却携带陈旧 seen_days 作为未来加成隐患，并占大量体积随每轮
    CI 提交进 git。

    两条剔除判据（满足任一即剔除，但均受「高价值豁免」保护）：
      判据 A（长期机制）`last_seen` 距今 > `max_idle_days`；
      判据 B（当前阶段）**已中断**（last_seen≠today 且 streak=0）且
        `seen_days <= max_lifespan_for_zombie`（短寿，历史无厚度）。
      A 面向长期运行（数据积累超过 idle 天数后自动生效）；B 在项目早期
      （数据仅数天、A 尚不触发）即可清理，二者互补。

    高价值豁免（三选一，宁留勿删）：
      1. `seen_days >= SURVIVAL_PRUNE_KEEP_SEEN`（长寿节点）；
      2. `real_hist` 含真实拨测通过记录（质量证据，滚动窗口需延续，不计判据 B）；
      3. `streak >= SURVIVAL_STREAK_FORCE_PROBE`（连续存活已被强制拨测标记）。
    """
    if not survival:
        return survival
    try:
        today_d = date.fromisoformat(today) if today else date.today()
    except Exception:
        today_d = date.today()
    today_s = today_d.isoformat()
    out: dict = {}
    for fp, rec in survival.items():
        last = rec.get("last_seen")
        try:
            last_d = date.fromisoformat(last) if last else None
        except Exception:
            last_d = None
        # ---- 高价值豁免（任一命中即保留）----
        if int(rec.get("seen_days", 0)) >= SURVIVAL_PRUNE_KEEP_SEEN:
            out[fp] = rec
            continue
        if any(rec.get("real_hist") or []):
            out[fp] = rec
            continue
        if int(rec.get("streak", 0)) >= SURVIVAL_STREAK_FORCE_PROBE:
            out[fp] = rec
            continue
        # ---- 剔除判据 ----
        idle = (last_d is not None and (today_d - last_d).days > max_idle_days)
        interrupted_short = (last != today_s
                             and int(rec.get("streak", 0)) == 0
                             and int(rec.get("seen_days", 0)) <= max_lifespan_for_zombie)
        if idle or interrupted_short:
            continue
        out[fp] = rec
    if len(out) != len(survival):
        _prune_log(f"存活历史清理: {len(survival)} -> {len(out)}"
                   f"（剔除 {len(survival) - len(out)} 条僵尸记录）")
    return out


def _prune_log(msg: str) -> None:
    """轻量日志（避免 score.py 依赖 filter_clash 的打印约定）。"""
    try:
        print(msg)
    except Exception:
        pass

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
