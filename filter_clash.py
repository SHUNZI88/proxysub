#!/usr/bin/env python3
"""proxysub —— 高纯度订阅清洗与结构规范化工具（编排入口）。

本文件是流水线入口：仅保留 main() 编排逻辑；具体实现分散在
common / probe / score / output 四个模块。运行方式不变：
    python filter_clash.py
测试仍通过 `import filter_clash as fc` 访问全部符号（本文件 re-export）。
"""


from __future__ import annotations

import os
import re
import sys
from collections import defaultdict

import common
import output
import probe
import score


def _reexport(*mods) -> None:
    """把子模块的全部公开符号注入本模块命名空间，保持 `import filter_clash as fc` 兼容。"""
    ns = sys.modules[__name__].__dict__
    for m in mods:
        for name, val in vars(m).items():
            if not name.startswith("__"):
                ns.setdefault(name, val)


_reexport(common, probe, score, output)

def main() -> None:
    sources = sm.load_sources()
    cands = sm.load_candidates()
    blocklist = hp.Blocklist(load_json(hp.BLOCKLIST_FILE, None))
    expired = blocklist.prune_expired()
    stats_file = load_json(SOURCE_STATS_FILE, {})
    history = stats_file.get("history", {}) if isinstance(stats_file, dict) else {}

    # ---- 1. discovery ----
    disc = sm.discover(sources, cands, parse_subscription_text, os.environ.get("GITHUB_TOKEN"))
    _ch = disc.get("channels", {}) or {}
    print(
        f"自动发现: 新增候选 {len(disc['added'])}"
        f"（GitHub {len(disc['added']) - len(_ch.get('added', []))} + 多渠道 {len(_ch.get('added', []))}），"
        f"扫描仓库 {disc['searched_repos']}；多渠道搜集节点 {_ch.get('nodes_collected', 0)} 条"
        f"，静态源加入 {len(_ch.get('static_added', []))}"
    )

    off_urls = sm.official_urls(sources)
    cand_urls = [u for u in sm.active_candidate_urls(cands) if u not in off_urls]
    off_set = set(off_urls)

    # ---- 2. fetch ----
    per_source, fstats = fetch_all_sources(off_urls + cand_urls)
    print(f"原始节点总数: {sum(len(v) for v in per_source.values())}")

    # ---- 2b. 多渠道搜集到的原始节点（Telegram / 网页分享链接） ----
    # 这些节点已写入 collected_nodes.txt，此处 ingest 后与正式源走完全相同的
    # 静态门槛 + 死活闸门清洗，仅白名单协议且通过拨测的节点才会进入最终输出。
    INGEST_MAX_NODES = 300
    _collected_path = "collected_nodes.txt"
    if os.path.exists(_collected_path):
        try:
            with open(_collected_path, encoding="utf-8") as _cf:
                _lines = [ln.strip() for ln in _cf if ln.strip()][-INGEST_MAX_NODES:]
            _plist: list[dict] = []
            for _ln in _lines:
                _plist.extend(parse_subscription_text(_ln))
            if _plist:
                _key = "__channel_nodes__"
                per_source[_key] = _plist
                fstats[_key] = {"ok": True, "count": len(_plist), "error": None, "ingested": True}
                print(f"多渠道节点: 解析 {len(_plist)} 个（来自 {_collected_path}，上限 {INGEST_MAX_NODES}）")
        except Exception as e:
            print(f"警告: 多渠道节点解析失败（不影响其他源）: {type(e).__name__}: {e}")

    bad_sources = load_json(BAD_SOURCES_FILE, {})
    bad_sources = {u: v for u, v in bad_sources.items() if u in fstats}
    for url, s in fstats.items():
        rec = bad_sources.get(url, {"fail_streak": 0})
        rec["fail_streak"] = 0 if s.get("ok") else int(rec.get("fail_streak", 0)) + 1
        rec["last_error"] = s.get("error")
        rec["last_count"] = s.get("count", 0)
        bad_sources[url] = rec

    # ---- 3. static filters: keyword / honeypot / 协议白名单与关键参数硬性门槛 ----
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
            if not normalize_network(p):
                pre_reasons["network_unsupported"] += 1
                continue
            why = protocol_gate_reason(p)
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

    # ---- 4. 存活性检查 ----
    # TCP 协议（vless/trojan/anytls…）：TCP 握手作在线信号。
    # UDP 协议（hy2/tuic）：豁免 TCP 检查，由拨测闸门（QUIC）验证死活。
    print("开始存活性检测（TCP 协议走 TCP 握手；UDP 协议交由拨测闸门验证）...")
    tcp_lat: dict[str, float] = {}
    tcp_candidates = {fp: p for fp, p in unique.items() if not is_udp_protocol(p)}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        fut_map = {executor.submit(tcp_probe, p): fp for fp, p in tcp_candidates.items()}
        for fut in as_completed(fut_map):
            alive, latency = fut.result()
            if alive:
                tcp_lat[fut_map[fut]] = latency
    udp_exempt = 0
    for fp, p in unique.items():
        if is_udp_protocol(p):
            tcp_lat[fp] = 9999.0  # 中性延迟：不参与排序，仅使其进入拨测管道
            udp_exempt += 1
    print(f"TCP 存活节点: {len(tcp_lat) - udp_exempt} | UDP 协议（hy2/tuic，交拨测验证）: {udp_exempt}")

    # ---- 5. real probe (OPTIONAL, local-only) ----
    # GitHub Actions（美西机房）无法穿越防火墙，测得的「真实连通性」对中国大陆
    # 用户没有参考价值，反而会误选美国垃圾节点。CI 通过 PROXYSUB_DISABLE_PROBE=1
    # 彻底禁用本环节（见 .github/workflows/daily-update.yml）；仅本地手动运行且
    # 装有 mihomo 时才做真实探测。最终活性测试由用户本地客户端完成。
    survival_pre = load_json(SURVIVAL_FILE, {})
    probe: dict[str, dict] = {}
    bin_path = mihomo_available() if real_probe_enabled() else None
    if not real_probe_enabled():
        print("云端真实流量拨测已禁用（PROXYSUB_DISABLE_PROBE=1）：仅保留 TCP 存活检查，"
              "最终测速/优选由本地客户端通过 gstatic generate_204 完成")
    if not real_probe_enabled():
        sample: list[str] = []
    else:
        # ---- 阶段 1：轻量探活（高并发 TCP 粗筛）----
        # tcp_lat 中仅含 TCP 存活 + UDP 豁免节点；此处再做一次统一的高并发复筛，
        # 结果用于在拨测样本有限时优先保留真正可达的节点。
        print(f"阶段1：轻量探活 {len(tcp_lat)} 个节点（并发 {LIGHT_PROBE_CONCURRENCY}）...")
        light_ok: set[str] = set()
        with ThreadPoolExecutor(max_workers=LIGHT_PROBE_CONCURRENCY) as ex:
            futs = {ex.submit(light_http_probe, unique[fp]): fp for fp in tcp_lat}
            for fut in as_completed(futs):
                if fut.result():
                    light_ok.add(futs[fut])
        print(f"阶段1完成：轻量探活通过 {len(light_ok)}/{len(tcp_lat)}，进入阶段2真实拨测")

        def _probe_rank(fp: str) -> tuple:
            # 历史稳定节点（streak >= 阈值）强制优先进入拨测样本；
            # 其次轻量探活通过者；再看协议层级/存活时长/TCP 延迟。
            rec = survival_pre.get(fp, {})
            streak = int(rec.get("streak", 0))
            seen = int(rec.get("seen_days", 0))
            tier = protocol_tier(unique[fp])
            stable = 0 if streak >= SURVIVAL_STREAK_FORCE_PROBE else 1
            light = 0 if fp in light_ok else 1
            return (stable, light, tier, -streak, -seen, tcp_lat[fp])

        alive_sorted = sorted(tcp_lat, key=_probe_rank)
        # Stratify: fill per-region reserves first so Asia is actually probed.
        # Within region: take preferred (hy2/reality) quota first, then rest by rank.
        by_region: dict[str, list[str]] = defaultdict(list)
        for fp in alive_sorted:
            if fp not in official_fps:
                continue
            by_region[classify_proxy(unique[fp].get("name", ""))].append(fp)
        sample = []
        chosen: set[str] = set()
        for region, reserve in PROBE_RESERVE_PER_REGION.items():
            pool = by_region.get(region, [])
            pref_n = PROBE_PREFERRED_PER_REGION.get(region, 0)
            pref = [fp for fp in pool if is_preferred(unique[fp])]
            rest = [fp for fp in pool if fp not in pref]
            ordered = pref[:pref_n] + rest + pref[pref_n:]
            for fp in ordered[:reserve]:
                if fp not in chosen:
                    sample.append(fp)
                    chosen.add(fp)
        # UDP protocols (hy2/tuic) skipped TCP probe — force them into the probe
        # sample, otherwise the dead-or-alive gate can never verify them.
        udp_sorted = sorted(
            (fp for fp in alive_sorted if is_udp_protocol(unique[fp]) and fp in official_fps),
            key=_probe_rank,
        )
        for fp in udp_sorted:
            if len(sample) >= PROBE_LIMIT_OFFICIAL:
                break
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

    if bin_path:
        print(f"使用 mihomo 真实探测 {len(sample)} 个节点: {bin_path}")
        probe = mihomo_probe([unique[fp] for fp in sample], bin_path)
    elif real_probe_enabled():
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
            cf_blocked=sum(1 for fp in fps if (probe.get(fp) or {}).get("cf_blocked")),
            preferred_ok=sum(1 for fp in alive if fp in real_ok and is_preferred(unique[fp])),
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
    # Real-probe OK ranks first; TCP-alive (esp. Asia / Hy2/Reality) stays eligible
    # so China-path quotas and MIN_FINAL can be filled when US-runner probe is sparse.
    survival = survival_pre
    scored: list[tuple[dict, float, float, bool, bool, int]] = []
    for fp, tlat in tcp_lat.items():
        if fp in tampered:
            continue
        cand_only = fp not in official_fps
        r = real_ok.get(fp)
        if bin_path and REQUIRE_REAL_PROBE_IN_OUTPUT and not r:
            continue  # legacy hard gate (off by default for China-path floor)
        if cand_only and bin_path and not r:
            continue  # probation-source nodes must pass the real probe
        if bin_path and REQUIRE_HTTPS_OK_IN_OUTPUT and r and not r.get("https_ok"):
            continue  # AI/CF sites need working HTTPS egress
        display = r["latency"] if r else tlat
        us_like = is_us_node(unique[fp], r)
        lat_cap = MAX_ACCEPT_LATENCY_MS_US if us_like else MAX_ACCEPT_LATENCY_MS
        if r and display > lat_cap:
            continue  # extreme outlier on runner RTT
        # Drop open http/socks from final when we have mihomo purity path
        tier = protocol_tier(unique[fp])
        if bin_path and tier >= 3 and str(unique[fp].get("type", "")).lower() in (
            "http", "https", "socks5", "socks5h", "socks",
        ):
            continue
        penalty = 0.0 if r or not bin_path else NO_REAL_PROBE_PENALTY
        if r and bin_path and not r.get("https_ok"):
            penalty += NO_HTTPS_PENALTY  # soft: CF HTTPS not sole veto
        if r and r.get("cf_blocked"):
            penalty += CF_BLOCKED_PENALTY  # soft purity
        if cand_only:
            penalty += CANDIDATE_ONLY_PENALTY
        multi = len(prov[fp] & off_set)
        if multi >= 2:
            penalty -= MULTI_SOURCE_BONUS * min(multi - 1, 3)
        penalty += protocol_penalty(unique[fp])
        penalty += china_feature_bonus(unique[fp])
        penalty += us_china_penalty(unique[fp], r)
        bonus = survival_bonus_ms(fp, survival)
        bonus += history_bonus(fp, survival)  # 历史真实通过率（持续通过的节点排更前）
        if is_preferred(unique[fp]):
            bonus *= 1.5  # keep long-lived hy2/reality even harder
        # TCP 延迟（美西 Runner 测得，≠国内真实路径）仅作粗排信号：贡献设上限，
        # 排序主要由协议质量 / 存活时长 / 多源 / 亚洲路径等静态特征决定。
        score = min(display, TCP_LATENCY_CAP_IN_SCORE) + penalty + bonus
        scored.append((unique[fp], score, display, is_preferred(unique[fp]), bool(r), tier))

    scored.sort(key=lambda x: (x[5], not x[3], x[1]))
    alive_fps = {fingerprint(p) for p, *_ in scored}
    # 传入本轮真实拨测通过集合，用于维护「真实通过率滑动窗口」（real_hist）
    survival = update_survival(alive_fps, survival,
                               set(real_ok.keys()) if (bin_path or real_probe_enabled()) else None)

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

    # per-source cap: one aggregator feed must not dominate the output
    scored, src_dropped = cap_single_source(scored, prov, MAX_PER_SOURCE_FINAL)
    if src_dropped:
        print(f"单一源独占上限 {MAX_PER_SOURCE_FINAL}: 再去掉 {src_dropped} 个（防聚合源垄断）")

    region_dict: dict[str, list] = defaultdict(list)
    for item in scored:
        region_dict[classify_proxy(item[0].get("name", ""))].append(item)

    def _bucketize(nodes: list) -> tuple[list, list, list, list, list]:
        """Split into: preferred+real, high+real, preferred+TCP, high+TCP, low."""
        pref_real, high_real, pref_tcp, high_tcp, low = [], [], [], [], []
        for item in nodes:
            fp = fingerprint(item[0])
            r = real_ok.get(fp) or {}
            if REQUIRE_HTTPS_OK_IN_OUTPUT and item[4] and not r.get("https_ok"):
                continue
            tier = item[5] if len(item) > 5 else protocol_tier(item[0])
            preferred = bool(item[3] or tier == 0)
            real = bool(item[4])
            if preferred and real:
                pref_real.append(item)
            elif tier <= 1 and real:
                high_real.append(item)
            elif preferred and not real:
                pref_tcp.append(item)
            elif tier <= 1 and not real:
                high_tcp.append(item)
            else:
                low.append(item)
        return pref_real, high_real, pref_tcp, high_tcp, low

    region_selected: dict[str, list] = {}
    for region, nodes in region_dict.items():
        quota = REGION_QUOTAS.get(region, MAX_OTHER)
        # China-path fill order: preferred real → high real → preferred TCP → high TCP → low.
        # TCP tiers let Asia quotas fill when US-runner real probe under-samples Asia.
        pref_real, high_real, pref_tcp, high_tcp, low = _bucketize(nodes)
        selected: list = []
        for bucket in (pref_real, high_real, pref_tcp, high_tcp):
            for item in bucket:
                if len(selected) >= quota:
                    break
                selected.append(item)
            if len(selected) >= quota:
                break
        low_added = 0
        if len(selected) < quota:
            for item in low:
                if len(selected) >= quota or low_added >= MAX_LOW_TIER_PER_REGION:
                    break
                selected.append(item)
                low_added += 1
        region_selected[region] = selected
        pref_count = sum(1 for row in selected if row[3])
        real_count = sum(1 for row in selected if row[4])
        print(
            f"{region}: 候选 {len(selected)}（优先 {pref_count}，真实探测 {real_count}，"
            f"tier0 {sum(1 for r in selected if (r[5] if len(r)>5 else 9)==0)}）"
        )

    # Cap US share of final list (China path: US often unusable).
    flat: list[tuple] = []
    for region, selected in region_selected.items():
        for row in selected:
            flat.append((region, row))
    # Prefer non-US first when trimming
    def _us_rank(pair):
        region, row = pair
        proxy = row[0]
        fp = fingerprint(proxy)
        us = region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fp))
        return (1 if us else 0, row[1])  # non-US first, then better score
    flat.sort(key=_us_rank)
    max_us = max(1, int(len(flat) * MAX_US_SHARE + 0.999)) if flat else 0
    kept: list[tuple] = []
    us_n = 0
    for region, row in flat:
        proxy = row[0]
        fp = fingerprint(proxy)
        us = region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fp))
        if us:
            if us_n >= max_us:
                continue
            us_n += 1
        kept.append((region, row))
    # Re-group for naming/output stability by region order
    final_by_region: dict[str, list] = defaultdict(list)
    for region, row in kept:
        final_by_region[region].append(row)
    us_dropped = len(flat) - len(kept)
    if us_dropped:
        print(f"美国占比上限 {MAX_US_SHARE:.0%}: 再去掉 {us_dropped} 个美国/美国出口节点")

    # ---- enforce MIN_FINAL / MAX_FINAL (100–200) ----
    selected_fps = {fingerprint(row[0]) for _, row in kept}
    total_now = len(selected_fps)

    def _fill_key(item) -> tuple:
        proxy = item[0]
        region = classify_proxy(str(proxy.get("name", "")))
        asia = 0 if region in ASIA_REGIONS else 1
        real = 0 if item[4] else 1
        pref = 0 if item[3] else 1
        us = 1 if (region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fingerprint(proxy)))) else 0
        return (us, asia, real, pref, item[5] if len(item) > 5 else 9, item[1])

    if total_now < MIN_FINAL:
        pool = [item for item in scored if fingerprint(item[0]) not in selected_fps]
        pool.sort(key=_fill_key)
        added = 0
        for item in pool:
            if total_now >= MIN_FINAL or total_now >= MAX_FINAL:
                break
            proxy = item[0]
            fp = fingerprint(proxy)
            region = classify_proxy(str(proxy.get("name", "")))
            us = region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fp))
            # While below floor, still respect US share soft cap on the growing list.
            if us:
                max_us_floor = max(1, int((total_now + 1) * MAX_US_SHARE + 0.999))
                cur_us = sum(
                    1 for reg, rows in final_by_region.items() for row in rows
                    if reg == "🇺🇸 美国" or is_us_node(row[0], real_ok.get(fingerprint(row[0])))
                )
                if cur_us >= max_us_floor:
                    continue
            final_by_region[region].append(item)
            selected_fps.add(fp)
            total_now += 1
            added += 1
        if added:
            print(f"节点数下限 {MIN_FINAL}: 回填 {added} 个（优先亚洲/真实探测/Hy2·Reality）")

    # Trim to MAX_FINAL if over (drop US/low-tier/worst score first).
    flat2: list[tuple] = []
    for region, rows in final_by_region.items():
        for row in rows:
            flat2.append((region, row))
    if len(flat2) > MAX_FINAL:
        def _trim_key(pair):
            region, row = pair
            proxy = row[0]
            fp = fingerprint(proxy)
            us = 1 if (region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fp))) else 0
            real = 0 if row[4] else 1
            pref = 0 if row[3] else 1
            # keep best: non-US, real, preferred, better score — sort ascending then keep[:MAX]
            return (us, real, pref, row[5] if len(row) > 5 else 9, row[1])
        flat2.sort(key=_trim_key)
        flat2 = flat2[:MAX_FINAL]
        final_by_region = defaultdict(list)
        for region, row in flat2:
            final_by_region[region].append(row)
        print(f"节点数上限 {MAX_FINAL}: 裁剪后 {len(flat2)}")

    # ---- 命名与安全隔离 ----
    # 1) 不再附加美西 Runner 测得的延迟标签——该延迟不代表国内真实路径，只会误导用户；
    #    最终测速/优选完全由本地客户端的 url-test（gstatic generate_204）动态完成。
    # 2) skip-cert-verify: true 的节点：名称打 [Insecure] 标签 + 独立分组隔离，
    #    不与合规节点无差别混同，也不进入自动选择/故障转移/地区分组。
    def _base_name(p: dict) -> str:
        base = re.sub(r"\s+\d+ms$", "", str(p.get("name", "node"))).strip()
        return base or "node"

    seen_names: dict[str, int] = {}
    final_proxies: list[dict] = []      # 合规节点
    insecure_proxies: list[dict] = []   # 高风险节点（跳过证书校验）
    for region in list(REGION_RULES.keys()) + ["🌐 其他"]:
        selected = final_by_region.get(region, [])
        for row in selected:
            proxy = row[0]
            np = dict(proxy)
            insecure = _truthy(np.get("skip-cert-verify"))
            full = _base_name(np) + (INSECURE_TAG if insecure else "")
            if full in seen_names:
                seen_names[full] += 1
                full = f"{full}#{seen_names[full]}"
            else:
                seen_names[full] = 1
            np["name"] = full
            (insecure_proxies if insecure else final_proxies).append(np)
        if selected:
            print(f"{region}: 最终保留 {len(selected)}")
    if insecure_proxies:
        print(f"安全隔离: {len(insecure_proxies)} 个 skip-cert-verify 节点已标记{INSECURE_TAG}并独立分组")
    total_final = len(final_proxies) + len(insecure_proxies)
    if total_final < MIN_FINAL:
        print(f"警告: 最终 {total_final} < 下限 {MIN_FINAL}（候选池不足）")

    print(f"\n最终精简节点数: {total_final}（合规 {len(final_proxies)}，高风险隔离 {len(insecure_proxies)}）")
    # 自动选择/故障转移仅包含合规节点；url-test 由客户端本地动态测速
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
        region_names = [p["name"] for p in final_proxies if classify_proxy(p.get("name", "")) == region]
        region_names = list(dict.fromkeys(region_names))
        if region_names:
            groups.append({"name": region, "type": "url-test", "proxies": region_names,
                           "url": PROBE_URL, "interval": URLTEST_INTERVAL})
    # 高风险节点独立池：仅供手动选择，不参与任何自动测速/故障转移
    insecure_names = [p["name"] for p in insecure_proxies]
    if insecure_names:
        groups.append({"name": INSECURE_GROUP, "type": "select", "proxies": insecure_names})
        groups[0]["proxies"].append(INSECURE_GROUP)
    # a select group referencing an empty region group would break the config
    present = {g["name"] for g in groups}
    groups[0]["proxies"] = [n for n in groups[0]["proxies"] if n in present or n == "DIRECT"]

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": final_proxies + insecure_proxies,
        "proxy-groups": groups,
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }

    # ---- 8. persist ----
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    # 多格式输出 + 健康报告（同一份最终节点列表的不同封装）
    write_outputs(final_proxies + insecure_proxies)
    save_json(SURVIVAL_FILE, survival)
    save_json(BAD_SOURCES_FILE, bad_sources)
    save_json(SOURCE_STATS_FILE, {"date": _today(), "sources": per_src, "history": history})
    sm.save_json(sm.SOURCES_FILE, sources)
    sm.save_json(sm.CANDIDATES_FILE, cands)
    sm.save_json(hp.BLOCKLIST_FILE, blocklist.data)
    # 源评分（单调递增/衰减，独立文件，向后兼容）
    try:
        scores = sm.update_source_scores(sources, per_src, history)
        sm.save_json(SOURCE_SCORES_FILE, scores)
    except Exception as e:  # 评分失败不应影响主产出
        print(f"警告: 源评分更新失败（不影响输出）: {type(e).__name__}: {e}")

    print(f"\n✅ 已生成: {OUTPUT_FILE}")
    summary_info = {
        "final": total_final, "compliant": len(final_proxies), "insecure": len(insecure_proxies),
        "tcp": len(tcp_lat), "real": len(real_ok),
        "probe_mode": ("disabled (client-side testing)" if not real_probe_enabled()
                       else ("mihomo" if bin_path else "tcp-only")),
        "https": sum(1 for r in real_ok.values() if r.get("https_ok")),
        "n_official": len(sources["official"]), "n_cands": len(cands["candidates"]),
        "discovery": disc, "cand_rep": cand_rep, "off_rep": off_rep,
        "pre_reasons": dict(pre_reasons), "probe_reasons": dict(probe_reasons),
        "auto_added": len(blocklist.added_this_run), "expired": expired,
        "diversity_dropped": diversity_dropped,
        "flags": "; ".join(f"{u.split('/')[3] if '//' in u else u}: {','.join(f)}" for u, f in src_flags.items()),
        "per_src": per_src,
        "final_proxies": final_proxies + insecure_proxies,
        "probed_total": len(probe),
    }
    write_stats_md(summary_info)
    write_github_summary(summary_info)


if __name__ == "__main__":
    main()
