"""拨测样本选择（select_probe_sample）与历史稳定性加成的回归测试。

覆盖 2026-10 质量回归的四项修订：
1. 陈旧 survival 状态整体关闭历史稳定优先（防已死旧节点霸占拨测预算）；
2. 新节点保底拨测配额（PROBE_FRESH_QUOTA）；
3. 渠道节点保底拨测配额（CHANNEL_PROBE_QUOTA，修复「收集了却永不入选」）；
4. UDP 协议强制入样 + 候选源/区域配额语义。
另保留 survival / history_bonus 的既有测试。
"""

import filter_clash as fc

TODAY = "2026-10-14"
OFFICIAL = "http://official.example/sub"


def _proxy(ptype="ss", name="n", lat=100.0, server="s.example.com", **extra):
    return {"name": name, "type": ptype, "server": server, "port": 443, **extra}


def _run(tcp_lat, unique, prov, official, cand_urls=(), survival=None,
         today=TODAY, source_keys=None):
    return fc.select_probe_sample(
        tcp_lat, unique, prov, set(official), list(cand_urls),
        survival or {}, today, source_keys,
    )


# ---------------------------------------------------------------- 陈旧状态


def test_stale_state_disables_history_priority():
    """survival 陈旧（无今日记录）时整体忽略历史稳定优先，排序交由层级/延迟。

    回归根因：survival.json 停更后，数百个 streak>=3 的陈旧记录（节点多已死亡）
    继续霸占拨测预算前排，新节点无拨测机会，输出质量逐轮下滑。
    """
    old = [f"old{i}" for i in range(3)]   # 高延迟旧节点，历史 streak=10
    new = [f"new{i}" for i in range(3)]   # 低延迟新节点，无历史记录
    tcp_lat, unique, prov = {}, {}, {}
    for fp in old:
        unique[fp] = _proxy("hysteria2", "香港 old", lat=900.0, server=fp)
        tcp_lat[fp] = 900.0
        prov[fp] = {OFFICIAL}
    for fp in new:
        unique[fp] = _proxy("hysteria2", "香港 new", lat=50.0, server=fp)
        tcp_lat[fp] = 50.0
        prov[fp] = {OFFICIAL}
    official = old + new
    fresh = {fp: {"streak": 10, "seen_days": 10, "last_seen": TODAY} for fp in old}
    stale = {fp: {"streak": 10, "seen_days": 10, "last_seen": "2026-10-13"} for fp in old}

    # 状态新鲜：历史 streak 优先，旧稳定节点占据样本前部
    s_fresh = _run(tcp_lat, unique, prov, official, survival=fresh)
    assert set(s_fresh[:3]) == set(old)
    # 状态陈旧（昨日）：忽略历史，低延迟新节点反超
    s_stale = _run(tcp_lat, unique, prov, official, survival=stale)
    assert set(s_stale[:3]) == set(new)
    # 状态缺失/为空：同样视为陈旧，不迷信历史
    s_empty = _run(tcp_lat, unique, prov, official, survival={})
    assert set(s_empty[:3]) == set(new)


# ---------------------------------------------------------------- 新节点保底


def _build_full_reserves():
    """构造恰好填满 8 个区域保留配额（合计 1250 >= 980）的旧节点 + 20 个同区域新节点。"""
    counts = {"香港": 220, "日本": 180, "新加坡": 160, "台湾": 110,
              "韩国": 100, "美国": 150, "英国": 30, "其他": 300}
    tcp_lat, unique, prov, survival = {}, {}, {}, {}
    i = 0
    for region, n in counts.items():
        for _ in range(n):
            fp = f"old{i}"
            unique[fp] = _proxy("ss", f"{region}-{i}", lat=float(i), server=fp)
            tcp_lat[fp] = float(i)
            prov[fp] = {OFFICIAL}
            survival[fp] = {"streak": 10, "seen_days": 10, "last_seen": TODAY}
            i += 1
    new = []
    for j in range(20):
        fp = f"new{j}"
        unique[fp] = _proxy("ss", f"其他-new-{j}", lat=float(10000 + j), server=fp)
        tcp_lat[fp] = float(10000 + j)
        prov[fp] = {OFFICIAL}
        new.append(fp)
    return tcp_lat, unique, prov, list(unique), new


def test_fresh_quota_guarantees_new_nodes(monkeypatch):
    """区域保留已占满 980 拨测预算时，新节点仍凭保底配额获得拨测机会。

    构造：1250 个 streak=10 的旧节点恰好填满 8 个区域保留配额（状态新鲜、
    历史优先开启），20 个无历史记录的新节点同区垫底。
    """
    tcp_lat, unique, prov, official, new = _build_full_reserves()
    # _build_full_reserves 内旧节点均登记今日 survival（状态新鲜）
    survival = {fp: rec for fp, rec in
                ((fp, {"streak": 10, "seen_days": 10, "last_seen": TODAY})
                 for fp in official if fp not in new)}
    sample = _run(tcp_lat, unique, prov, official, survival=survival)
    # 区域保留 1250 个旧节点全入选，新节点保底配额再补 20 个（20 <= 250）
    assert len(sample) == 1250 + len(new)
    assert all(fp in sample for fp in new)  # 保底配额生效

    # 反证：关闭保底配额后，新节点被 980 预算完全挤出（拨测预算被旧节点霸占）
    monkeypatch.setattr(fc, "PROBE_FRESH_QUOTA", 0)
    sample_no_quota = _run(tcp_lat, unique, prov, official, survival=survival)
    assert not any(fp in sample_no_quota for fp in new)


# ---------------------------------------------------------------- 渠道节点


def _channel_case(n_channel=5):
    tcp_lat, unique, prov, survival = {}, {}, {}, {}
    for i in range(3):
        fp = f"off{i}"
        unique[fp] = _proxy("hysteria2", f"香港-{i}", lat=float(i), server=fp)
        tcp_lat[fp] = float(i)
        prov[fp] = {OFFICIAL}
        survival[fp] = {"streak": 1, "seen_days": 1, "last_seen": TODAY}
    channel = []
    for j in range(n_channel):
        fp = f"ch{j}"
        unique[fp] = _proxy("ss", f"ch-{j}", lat=float(100 + j), server=fp)
        tcp_lat[fp] = float(100 + j)
        prov[fp] = {fc.CHANNEL_NODES_KEY}
        survival[fp] = {"streak": 1, "seen_days": 1, "last_seen": TODAY}
        channel.append(fp)
    return tcp_lat, unique, prov, [f"off{i}" for i in range(3)], channel


def test_channel_quota():
    """渠道节点（Telegram/网页分享链接）获得保底拨测配额。

    修复前它们既非正式源也非候选源 URL，样本循环永远选不到——评分时全被
    cand_only 闸门丢弃（收集了却永不入选）。
    """
    tcp_lat, unique, prov, official, channel = _channel_case(5)
    keys = [OFFICIAL, fc.CHANNEL_NODES_KEY]
    survival = {fp: {"streak": 1, "seen_days": 1, "last_seen": TODAY}
                for fp in tcp_lat}  # 全部有今日记录：隔离新节点保底配额干扰

    # source_keys 不含渠道键（或为 None）：渠道节点永不入样（旧缺陷复现）
    s_without = _run(tcp_lat, unique, prov, official, survival=survival,
                     source_keys=[OFFICIAL])
    assert not any(fp in s_without for fp in channel)
    s_none = _run(tcp_lat, unique, prov, official, survival=survival, source_keys=None)
    assert not any(fp in s_none for fp in channel)

    # source_keys 含渠道键：全部 5 个渠道节点入样
    s_with = _run(tcp_lat, unique, prov, official, survival=survival, source_keys=keys)
    assert all(fp in s_with for fp in channel)


def test_channel_quota_capped():
    """渠道入样数受 CHANNEL_PROBE_QUOTA 上限约束。"""
    tcp_lat, unique, prov, official, channel = _channel_case(100)
    survival = {fp: {"streak": 1, "seen_days": 1, "last_seen": TODAY}
                for fp in tcp_lat}
    sample = _run(tcp_lat, unique, prov, official, survival=survival,
                  source_keys=[fc.CHANNEL_NODES_KEY])
    n_in = sum(1 for fp in channel if fp in sample)
    assert n_in == fc.CHANNEL_PROBE_QUOTA


# ---------------------------------------------------------------- UDP 强制入样


def test_udp_forced_into_sample(monkeypatch):
    """UDP 协议（tuic 等）跳过 TCP 检查，必须强制进入拨测样本。

    否则在 980 个拨测预算内，它们会因排序靠后被通用填充循环挤出，
    死或活永远无法被死活闸门验证。构造：980 个同层级（tier 1）但延迟
    更低的 anytls 节点占据填充序列，tuic 延迟最高、排序垫底。
    """
    tcp_lat, unique, prov, survival = {}, {}, {}, {}
    n_pre = fc.PROBE_LIMIT_OFFICIAL  # 980 个排序靠前的 anytls 占满填充预算
    for i in range(n_pre):
        fp = f"anytls{i}"
        unique[fp] = _proxy("anytls", f"其他-{i}", lat=float(i), server=fp)
        tcp_lat[fp] = float(i)
        prov[fp] = {OFFICIAL}
        survival[fp] = {"streak": 1, "seen_days": 1, "last_seen": TODAY}
    udp = []
    for j in range(5):
        fp = f"tuic{j}"
        unique[fp] = _proxy("tuic", f"其他-tuic-{j}", lat=9000.0 + j, server=fp)
        tcp_lat[fp] = 9000.0 + j
        prov[fp] = {OFFICIAL}
        survival[fp] = {"streak": 1, "seen_days": 1, "last_seen": TODAY}
        udp.append(fp)

    sample = _run(tcp_lat, unique, prov, list(unique), survival=survival)
    assert all(fp in sample for fp in udp)

    # 反证：没有 UDP 强制逻辑时，tuic 排序在 980 个 anytls 之后，被预算挤出
    monkeypatch.setattr(fc, "is_udp_protocol", lambda p: False)
    sample_no_force = _run(tcp_lat, unique, prov, list(unique), survival=survival)
    assert not any(fp in sample_no_force for fp in udp)


# ---------------------------------------------------------------- 候选源配额


def test_candidate_per_source_quota():
    """每个候选源最多 PROBE_PER_CANDIDATE 个节点进入拨测样本。"""
    tcp_lat, unique, prov, survival = {}, {}, {}, {}
    for i in range(3):
        fp = f"off{i}"
        unique[fp] = _proxy("hysteria2", f"香港-{i}", lat=float(i), server=fp)
        tcp_lat[fp] = float(i)
        prov[fp] = {OFFICIAL}
        survival[fp] = {"streak": 1, "seen_days": 1, "last_seen": TODAY}
    cand1, cand2 = "http://cand1.example/sub", "http://cand2.example/sub"
    c1 = []
    for i in range(30):  # 超出单源配额，按延迟取前 PROBE_PER_CANDIDATE 个
        fp = f"c1-{i}"
        unique[fp] = _proxy("ss", f"c1-{i}", lat=float(200 + i), server=fp)
        tcp_lat[fp] = float(200 + i)
        prov[fp] = {cand1}
        survival[fp] = {"streak": 1, "seen_days": 1, "last_seen": TODAY}
        c1.append(fp)
    c2 = []
    for i in range(5):
        fp = f"c2-{i}"
        unique[fp] = _proxy("ss", f"c2-{i}", lat=float(500 + i), server=fp)
        tcp_lat[fp] = float(500 + i)
        prov[fp] = {cand2}
        survival[fp] = {"streak": 1, "seen_days": 1, "last_seen": TODAY}
        c2.append(fp)

    sample = _run(tcp_lat, unique, prov, [f"off{i}" for i in range(3)],
                  cand_urls=[cand1, cand2], survival=survival)
    quota = fc.PROBE_PER_CANDIDATE
    assert sum(1 for fp in c1 if fp in sample) == quota      # 30 -> 20
    assert all(fp in sample for fp in c2)                   # 5 < 20 全收
    # 配额内按延迟优先：c1 前 20 个（低延迟）入选，其余落选
    assert all(fp in sample for fp in c1[:quota])
    assert not any(fp in sample for fp in c1[quota:])


# ---------------------------------------------------------------- 区域保留


def test_region_reserve_preferred_first():
    """区域保留内优先协议（hy2/reality）先占 PROBE_PREFERRED_PER_REGION 名额，
    超额的优先协议排在本区非优先节点之后（rest + pref[pref_n:]）。
    """
    tcp_lat, unique, prov, survival = {}, {}, {}, {}
    hy2, ss = [], []
    for i in range(150):
        fp = f"hy2-{i}"
        unique[fp] = _proxy("hysteria2", f"香港-{i}", lat=float(i), server=fp)
        tcp_lat[fp] = float(i)
        prov[fp] = {OFFICIAL}
        survival[fp] = {"streak": 1, "seen_days": 1, "last_seen": TODAY}
        hy2.append(fp)
    for j in range(10):
        fp = f"ss-{j}"
        unique[fp] = _proxy("ss", f"香港-ss-{j}", lat=float(1000 + j), server=fp)
        tcp_lat[fp] = float(1000 + j)
        prov[fp] = {OFFICIAL}
        survival[fp] = {"streak": 1, "seen_days": 1, "last_seen": TODAY}
        ss.append(fp)

    sample = _run(tcp_lat, unique, prov, hy2 + ss, survival=survival)
    assert len(sample) == 160
    pref_n = fc.PROBE_PREFERRED_PER_REGION["🇭🇰 香港"]  # 140
    # 前 pref_n 个是优先协议，随后是本区全部非优先节点，最后才是超额的优先协议
    assert sample[:pref_n] == hy2[:pref_n]
    assert sample[pref_n:pref_n + 10] == ss
    assert sample[pref_n + 10:] == hy2[pref_n:]


# ---------------------------------------------------------------- survival/history


def test_history_bonus_empty_is_zero():
    assert fc.history_bonus("nope", {}) == 0.0
    assert fc.history_bonus("x", {"x": {}}) == 0.0


def test_history_bonus_full_pass_strongest():
    """全部通过的加成应强于部分通过；从不通过无加成。"""
    full = fc.history_bonus("a", {"a": {"real_hist": [1, 1, 1, 1]}})
    half = fc.history_bonus("b", {"b": {"real_hist": [1, 0, 1, 0]}})
    never = fc.history_bonus("c", {"c": {"real_hist": [0, 0, 0]}})
    assert full < half < never == 0.0
    assert full == -fc.HISTORY_PASS_RATE_BONUS


def test_update_survival_records_real_hist():
    """real_hist 应逐次追加并受窗口长度限制。"""
    survival = {"fp1": {"streak": 1, "last_seen": "2000-01-01", "seen_days": 1}}
    out = fc.update_survival({"fp1"}, survival, real_ok_fps={"fp1"})
    assert out["fp1"]["real_hist"] == [1]
    # 新节点若本轮不在 real_ok 中，首次记录为 0；在则记录为 1
    out = fc.update_survival({"fp1", "fp2"}, out, real_ok_fps=set())
    assert out["fp2"]["real_hist"] == [0]
    out = fc.update_survival({"fp1", "fp3"}, out, real_ok_fps={"fp3"})
    assert out["fp3"]["real_hist"] == [1]
    # 窗口裁剪
    survival2 = {"fp": {"streak": 1, "last_seen": "2000-01-01", "seen_days": 1,
                        "real_hist": [1] * fc.SURVIVAL_PASS_WINDOW}}
    out2 = fc.update_survival({"fp"}, survival2, real_ok_fps={"fp"})
    assert len(out2["fp"]["real_hist"]) == fc.SURVIVAL_PASS_WINDOW


def test_update_survival_without_real_ok_keeps_compat():
    """不传 real_ok_fps（疑似禁用拨测）时不得写入 real_hist，保持旧行为。"""
    survival = {}
    out = fc.update_survival({"fp"}, survival)
    assert "real_hist" not in out["fp"]


def test_survival_streak_force_probe_constant():
    assert fc.SURVIVAL_STREAK_FORCE_PROBE >= 1


def test_survival_state_fresh():
    """状态新鲜度判定：有今日记录才新鲜；空/陈旧/昨日均视为陈旧。"""
    today = fc._today()
    yesterday = "2000-01-01"
    assert fc.survival_state_fresh({}, today) is False
    assert fc.survival_state_fresh(None, today) is False
    assert fc.survival_state_fresh({"a": {"last_seen": today}}, today) is True
    assert fc.survival_state_fresh(
        {"a": {"last_seen": yesterday}, "b": {"last_seen": today}}, today) is True
    assert fc.survival_state_fresh({"a": {"last_seen": yesterday}}, today) is False
    # 缺字段/异常值不得抛异常
    assert fc.survival_state_fresh({"a": {}}, today) is False
    assert fc.survival_state_fresh({"a": {"last_seen": None}}, today) is False
