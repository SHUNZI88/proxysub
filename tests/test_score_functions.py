"""评分函数回归测试。

背景：2026-10-13 daily 工作流崩溃于 `score.protocol_penalty` 的
NameError（PROTOCOL_BONUS_TLS_OK 未定义）——filter_clash.py 拆分为四模块时，
protocol_penalty 移入 score.py，但 PROTOCOL_* 常量组与 ASIA_SCORE_BONUS
漏进导入清单；该函数又无任何测试覆盖， Tests 全绿而 daily 一跑即崩。

本文件两条防线：
1. 直接调用每个评分函数（含全部协议分支）——存在性检查不够，必须真调用；
2. filter_clash 主流程评分循环（filter_clash.py:387-407 同款调用序列）冒烟。
"""

import filter_clash as fc
import score


# ---------- 1. protocol_penalty：全分支（本次事故的直接回归） ----------

def test_protocol_penalty_all_branches():
    import config as cm
    cases = [
        ({"type": "hysteria2"}, cm.PROTOCOL_BONUS_HY2),
        ({"type": "hy2"}, cm.PROTOCOL_BONUS_HY2),
        ({"type": "vless", "reality-opts": {"public-key": "k", "short-id": "s"}},
         cm.PROTOCOL_BONUS_REALITY),
        ({"type": "trojan"}, cm.PROTOCOL_BONUS_TROJAN),
        ({"type": "anytls"}, cm.PROTOCOL_BONUS_TLS_OK),
        ({"type": "tuic"}, cm.PROTOCOL_BONUS_TLS_OK),
        ({"type": "hysteria"}, cm.PROTOCOL_BONUS_TLS_OK),
        ({"type": "vless"}, cm.PROTOCOL_BONUS_TLS_OK),
        ({"type": "vmess"}, cm.PROTOCOL_PENALTY_VMESS),
        ({"type": "ss"}, cm.PROTOCOL_PENALTY_SS),
        ({"type": "ssr"}, cm.PROTOCOL_PENALTY_SS),
        ({"type": "http"}, cm.PROTOCOL_PENALTY_HTTP_SOCKS),
        ({"type": "socks5"}, cm.PROTOCOL_PENALTY_HTTP_SOCKS),
        ({"type": "mystery"}, cm.PROTOCOL_PENALTY_OTHER_LOW),
        ({}, cm.PROTOCOL_PENALTY_OTHER_LOW),
    ]
    for proxy, expected in cases:
        got = score.protocol_penalty(proxy)
        assert got == expected, f"{proxy.get('type')!r}: {got} != {expected}"
        # 经 filter_clash 重导出的同名函数也必须一致
        assert fc.protocol_penalty(proxy) == expected


def test_protocol_penalty_bonus_ordering():
    """协议分层方向：hy2 < reality < trojan < tls_ok < vmess < ss < other。"""
    vals = [
        score.protocol_penalty({"type": "hysteria2"}),
        score.protocol_penalty({"type": "vless", "reality-opts": {"public-key": "k"}}),
        score.protocol_penalty({"type": "trojan"}),
        score.protocol_penalty({"type": "vless"}),
        score.protocol_penalty({"type": "vmess"}),
        score.protocol_penalty({"type": "ss"}),
        score.protocol_penalty({"type": "weird"}),
    ]
    assert vals == sorted(vals), f"协议惩罚应单调递增: {vals}"


# ---------- 2. 评分循环冒烟（复刻 filter_clash.py:387-407 调用序列） ----------

def test_scoring_loop_call_sequence_smoke():
    """主流程评分循环用到的每个函数都必须可调用且返回数值。"""
    proxy = {
        "name": "🇭🇰 HK · Vless",
        "type": "vless",
        "server": "hk.example.com",
        "port": 443,
        "servername": "www.microsoft.com",
        "uuid": "3b1d6e2c-9a4f-4c8b-8d7e-1f2a3b4c5d6e",
    }
    probe_result = {"ok": True, "https_ok": True, "cf_blocked": False, "loc": "HK",
                    "latency_ms": 300}
    survival = {"fp1": {"streak": 3, "seen_days": 5, "real_hist": [1, 1, 0]}}

    numeric_values = [
        score.protocol_penalty(proxy),
        score.china_feature_bonus(proxy),
        score.us_china_penalty(proxy, probe_result),
        score.us_china_penalty(proxy, None),
        score.survival_bonus_ms("fp1", survival),
        score.history_bonus("fp1", survival),
        score.protocol_tier(proxy),
    ]
    for v in numeric_values:
        assert isinstance(v, (int, float)), v
    # 布尔/字符串返回值另行断言
    assert isinstance(score.is_preferred(proxy), bool)
    assert isinstance(score.is_us_node(proxy, probe_result), bool)
    assert isinstance(score.classify_proxy(proxy["name"]), str)


# ---------- 3. 其余评分函数行为抽查 ----------

def test_china_feature_bonus_components():
    import config as cm
    # 白名单 SNI + 友好端口
    p = {"type": "vless", "servername": "www.microsoft.com", "port": 443}
    assert score.china_feature_bonus(p) == cm.SNI_BONUS + cm.PORT_BONUS
    # 空 proxy 不炸
    assert score.china_feature_bonus({}) == 0.0
    # 坏 port 不炸
    assert score.china_feature_bonus({"port": "abc"}) == 0.0


def test_us_china_penalty_direction():
    import config as cm
    us = {"name": "🇺🇸 US · Los Angeles", "type": "vmess"}
    asia = {"name": "🇭🇰 HK", "type": "vmess"}
    pen_us = score.us_china_penalty(us, None)
    pen_asia = score.us_china_penalty(asia, None)
    # 美国被惩罚（正值），亚洲获加成（负值）
    assert pen_us > 0
    assert pen_asia < 0
    assert pen_us == cm.US_REGION_DELAY_PENALTY + cm.US_EGRESS_PENALTY_SS_VMESS
    assert pen_asia == cm.ASIA_SCORE_BONUS


def test_us_china_penalty_probe_loc_marks_us():
    """节点名不含美国，但拨测 loc=US → 仍按美国惩罚。"""
    p = {"name": "Unknown Node", "type": "trojan"}
    assert score.us_china_penalty(p, {"loc": "US"}) > 0
    assert score.us_china_penalty(p, {"loc": "HK"}) == 0.0


def test_us_china_penalty_protocol_tiers():
    """P1-4 简化后行为基线：出口惩罚按协议分层，区域项与出口项叠加。

    美国区域名节点（区域项 +120）经主机名线索判 US 后，出口惩罚按协议分三档；
    非美国区域名 + loc=US 时只拿出口惩罚（无区域项）。
    """
    import config as cm
    us = {"name": "🇺🇸 US", "server": "us.example.com", "type": "vmess"}
    hy2 = dict(us, type="hysteria2")
    reality = {**us, "type": "vless", "reality-opts": {"public-key": "x" * 43}}
    ss = dict(us, type="ss")
    http_ = dict(us, type="http")
    trojan = dict(us, type="trojan")
    base = cm.US_REGION_DELAY_PENALTY
    assert score.us_china_penalty(hy2, None) == base + cm.US_EGRESS_PENALTY_HY2_REALITY
    assert score.us_china_penalty(reality, None) == base + cm.US_EGRESS_PENALTY_HY2_REALITY
    assert score.us_china_penalty(ss, None) == base + cm.US_EGRESS_PENALTY_SS_VMESS
    assert score.us_china_penalty(http_, None) == base + cm.US_EGRESS_PENALTY_SS_VMESS
    assert score.us_china_penalty(trojan, None) == base + cm.US_EGRESS_PENALTY_MID
    # 非美国区域名 + 拨测 loc=US：仅出口惩罚（trojan → 居中档）
    anon = {"name": "Unknown", "type": "trojan"}
    assert score.us_china_penalty(anon, {"loc": "US"}) == cm.US_EGRESS_PENALTY_MID


def test_survival_bonus_ms_empty_and_populated():
    assert score.survival_bonus_ms("nope", {}) == 0.0
    v = score.survival_bonus_ms("fp", {"fp": {"streak": 5, "seen_days": 10}})
    assert v < 0  # 负分 = 排更前


def test_survival_bonus_ms_clamped():
    """streak/seen_days 超过 MAX_SURVIVAL_DAYS 时截断，防历史数据无限加权。"""
    import config as cm
    v = score.survival_bonus_ms("fp", {"fp": {"streak": 9999, "seen_days": 9999}})
    expect = -cm.SURVIVAL_WEIGHT * cm.MAX_SURVIVAL_DAYS - cm.SEEN_DAYS_WEIGHT * cm.MAX_SURVIVAL_DAYS
    assert v == expect


def test_protocol_tier_branches():
    assert score.protocol_tier({"type": "hysteria2"}) == 0
    assert score.protocol_tier({"type": "vless", "reality-opts": {"public-key": "k"}}) == 0
    assert score.protocol_tier({"type": "trojan"}) == 1
    assert score.protocol_tier({"type": "vmess", "tls": True}) == 2
    assert score.protocol_tier({"type": "vmess"}) == 3
    assert score.protocol_tier({"type": "ss"}) == 3
    assert score.protocol_tier({"type": "http"}) == 3


def test_is_preferred_branches():
    assert score.is_preferred({"type": "hysteria2"}) is True
    assert score.is_preferred({"type": "vless", "reality-opts": {"public-key": "k"}}) is True
    assert score.is_preferred({"type": "vless"}) is False
    assert score.is_preferred({"type": "vmess"}) is False


def test_update_survival_new_and_decay():
    survival = score.update_survival({"a", "b"}, {})
    assert survival["a"]["streak"] == 1
    assert survival["a"]["seen_days"] == 1
    # 缺失超过 2 天的旧节点 streak 归零
    survival = {"old": {"streak": 9, "last_seen": "2020-01-01", "seen_days": 9}}
    out = score.update_survival(set(), survival)
    assert out["old"]["streak"] == 0


def test_update_survival_real_hist_window():
    """real_hist 滑动窗口不超过 SURVIVAL_PASS_WINDOW。"""
    import config as cm
    survival = {"a": {"streak": 1, "last_seen": None, "seen_days": 1,
                      "real_hist": [1] * (cm.SURVIVAL_PASS_WINDOW - 1)}}
    out = score.update_survival({"a"}, survival, real_ok_fps={"a"})
    assert len(out["a"]["real_hist"]) == cm.SURVIVAL_PASS_WINDOW


# ---------- prune_survival：僵尸记录清理（判据 + 高价值豁免） ----------

def test_prune_survival_removes_interrupted_short_lived():
    """已中断 + 短寿 + 无通过史 = 僵尸，须剔除。

    真实现象（2026-10-15）：survival.json 7285 条中 5005 条属此类——
    last_seen 停在 3+ 天前、streak 归零、seen_days≤2、无 real_hist。
    隐患：seen_days 终身累计不重置，僵尸 fp 若"诈尸"会白得陈旧长寿加成。
    """
    today = "2026-10-15"
    sv = {
        # 僵尸：10-10 出现 2 天后消失，streak=0
        "zombie": {"streak": 0, "last_seen": "2026-10-10", "seen_days": 2},
        # 僵尸：seen_days=1
        "zombie2": {"streak": 0, "last_seen": "2026-10-12", "seen_days": 1},
        # 活跃：今日出现
        "active": {"streak": 1, "last_seen": today, "seen_days": 1},
    }
    out = score.prune_survival(sv, today=today)
    assert "zombie" not in out and "zombie2" not in out
    assert "active" in out


def test_prune_survival_keeps_high_value():
    """高价值豁免：长寿、有真实通过史、连续存活达标者一律保留。"""
    today = "2026-10-15"
    sv = {
        # 长寿（seen_days≥3）——虽已中断仍保留
        "longlived": {"streak": 0, "last_seen": "2026-10-09", "seen_days": 5},
        # 有真实拨测通过史——保留（滚动窗口需延续）
        "passed": {"streak": 0, "last_seen": "2026-10-10", "seen_days": 1,
                   "real_hist": [1, 0, 1]},
        # 连续存活达标（streak≥3）——保留
        "streaky": {"streak": 4, "last_seen": "2026-10-13", "seen_days": 1},
    }
    out = score.prune_survival(sv, today=today)
    assert set(out) == {"longlived", "passed", "streaky"}


def test_prune_survival_idle_rule_for_long_running():
    """判据 A（长期机制）：last_seen 距今 > max_idle_days 即剔除（不管 seen_days）。"""
    today = "2026-10-15"
    sv = {
        "veryold": {"streak": 0, "last_seen": "2026-09-01", "seen_days": 2},
        "recent": {"streak": 0, "last_seen": "2026-10-13", "seen_days": 2},
    }
    out = score.prune_survival(sv, today=today)
    assert "veryold" not in out, "超期未出现须剔除"
    # recent 虽有 2 天 idle 但未超 14 天，且 streak=0/seen=2 命中判据 B
    assert "recent" not in out


def test_prune_survival_no_op_on_empty_and_keeps_all_when_fresh():
    assert score.prune_survival({}, today="2026-10-15") == {}
    sv = {"a": {"streak": 0, "last_seen": "2026-10-15", "seen_days": 1}}
    # 当日出现：判据 B 要求 last_seen != today，故保留
    assert set(score.prune_survival(sv, today="2026-10-15")) == {"a"}
