"""filter_clash 阶段函数单元测试（P1-1d，配合 main() 拆分）。

拆分后的阶段函数是纯/近纯函数，可脱离 main() 直接单测——这正是拆分的
主要收益。本文件覆盖此前无法触及的分支：

  - static_filter_stage：预过滤原因分类、fake-ip DNS 降级、诱饵回流
  - score_candidates：拨测闸门、惩罚/加成项、陈旧 survival 降级
  - select_final：区域配额、美国占比上限、MIN/MAX_FINAL 回填与裁剪
  - name_and_isolate：重名去重后缀、[Insecure] 隔离
  - build_clash_config：分组结构、空地区组引用修剪
"""

import common
import config
import honeypot as hp
import pytest

import filter_clash as fc

TEST_URL = "https://raw.githubusercontent.com/test/repo/main/sub.yaml"


def _vless(name="HK-01", server="1.2.3.4"):
    return {"name": name, "type": "vless", "server": server, "port": 443,
            "uuid": "11111111-2222-3333-4444-555555555555", "tls": True, "network": "tcp",
            "servername": "www.microsoft.com", "flow": "xtls-rprx-vision",
            "reality-opts": {"public-key": "A" * 43, "short-id": "ab12"},
            "client-fingerprint": "chrome"}


def _hy2(name="JP-02", server="5.6.7.8"):
    return {"name": name, "type": "hysteria2", "server": server, "port": 8443,
            "password": "pw123", "sni": "dl.google.com", "obfs": "salamander",
            "obfs-password": "obf"}


def _trojan(name="SG-03", server="9.9.9.9"):
    return {"name": name, "type": "trojan", "server": server, "port": 443,
            "password": "tp@ss", "sni": "apple.com", "network": "ws",
            "ws-opts": {"path": "/ws", "headers": {"Host": "a.com"}}}


def _http(name="US-09", server="4.4.4.4"):
    return {"name": name, "type": "http", "server": server, "port": 8080}


@pytest.fixture
def dns_ok(monkeypatch):
    """所有主机解析到自身（公网 IP），关闭网段聚集标记。"""
    monkeypatch.setattr(fc.hp, "resolve_hosts", lambda hosts: {h: [h] for h in hosts})
    monkeypatch.setattr(fc.hp, "source_cluster_flags", lambda plist, resolved: [])


# ---------------------------------------------------------------------------
# static_filter_stage
# ---------------------------------------------------------------------------

class TestStaticFilterStage:
    def test_valid_nodes_survive(self, dns_ok):
        per_source = {TEST_URL: [_vless(), _hy2(), _trojan()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        assert len(r.unique) == 3
        assert sum(r.pre_reasons.values()) == 0
        assert r.official_fps == set(r.unique.keys())

    def test_keyword_and_missing_server_rejected_silently(self, dns_ok):
        """关键词/缺 server/port 的节点静默丢弃，不计入 pre_reasons（原行为）。"""
        bad = _vless(name="免费 节点")
        no_server = _vless(); no_server.pop("server")
        no_port = _vless(); no_port.pop("port")
        per_source = {TEST_URL: [bad, no_server, no_port, _vless()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        assert len(r.unique) == 1
        assert sum(r.pre_reasons.values()) == 0

    def test_honeypot_reason_counted(self, dns_ok, monkeypatch):
        monkeypatch.setattr(fc.hp, "static_reject_reason",
                            lambda p: "honeypot:fake_port" if p["server"] == "1.2.3.4" else None)
        per_source = {TEST_URL: [_vless(), _hy2()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        assert r.pre_reasons["honeypot:fake_port"] == 1
        assert len(r.unique) == 1

    def test_network_unsupported_reason(self, dns_ok, monkeypatch):
        monkeypatch.setattr(fc, "normalize_network", lambda p: False)
        per_source = {TEST_URL: [_vless()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        assert r.pre_reasons["network_unsupported"] == 1

    def test_protocol_gate_reason(self, dns_ok, monkeypatch):
        monkeypatch.setattr(fc, "protocol_gate_reason", lambda p: "proto:ss_not_allowed")
        per_source = {TEST_URL: [_vless()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        assert r.pre_reasons["proto:ss_not_allowed"] == 1

    def test_unresolvable_counted(self, monkeypatch):
        monkeypatch.setattr(fc.hp, "resolve_hosts", lambda hosts: {})
        per_source = {TEST_URL: [_vless()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        assert r.pre_reasons["unresolvable"] == 1
        assert not r.unique

    def test_dns_to_reserved_ip_counted(self, dns_ok, monkeypatch):
        monkeypatch.setattr(fc.hp, "resolve_hosts", lambda hosts: {h: ["127.0.0.1"] for h in hosts})
        per_source = {TEST_URL: [_vless()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        assert r.pre_reasons["dns_to_reserved_ip"] == 1

    def test_fake_ip_dns_env_skips_reserved_check(self, monkeypatch):
        """多数域名解析到保留地址时整体降级：保留地址检查被跳过。"""
        monkeypatch.setattr(fc.hp, "resolve_hosts",
                            lambda hosts: {h: ["198.18.0.1"] for h in hosts})
        # 域名主机（非 IP 字面量）才会计入 doms
        dom_node = _vless(server="cdn.example.com")
        per_source = {TEST_URL: [dom_node]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        # 降级后 reserved 检查不生效，节点保留（但 unresolvable 也不会触发）
        assert "dns_to_reserved_ip" not in r.pre_reasons
        assert len(r.unique) == 1

    def test_blocklist_hit_counted_with_key(self, dns_ok):
        bl = hp.Blocklist(None)
        bl.data.setdefault("ips", []).append("1.2.3.4")
        per_source = {TEST_URL: [_vless(), _hy2()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), bl)
        assert any(k.startswith("blocklist:") for k in r.pre_reasons)
        assert len(r.unique) == 1

    def test_bait_fingerprint_dropped_and_counted(self, dns_ok):
        fp = fc.fingerprint(_vless())
        per_source = {TEST_URL: [_vless(), _hy2()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, {fp}, hp.Blocklist(None))
        assert r.pre_reasons["bait_reuse"] == 1
        assert len(r.unique) == 1

    def test_bait_reuse_flags_source(self, dns_ok):
        fp = fc.fingerprint(_vless())
        per_source = {TEST_URL: [_vless(), _hy2()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, {fp}, hp.Blocklist(None))
        assert r.src_flags[TEST_URL] == ["bait_reuse"]

    def test_dedup_keeps_first_and_records_provenance(self, dns_ok):
        same_a, same_b = _vless(), _vless()   # 同服务器同凭证 -> 同指纹
        per_source = {TEST_URL: [same_a], "https://other/x.yaml": [same_b]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        assert len(r.unique) == 1
        assert len(list(r.prov.values())[0]) == 2   # 两个源都记录

    def test_official_fps_only_from_official_sources(self, dns_ok):
        per_source = {TEST_URL: [_vless()], "https://cand/x.yaml": [_hy2()]}
        r = fc.static_filter_stage(per_source, {TEST_URL}, set(), hp.Blocklist(None))
        fp_hy2 = fc.fingerprint(_hy2())
        assert fc.fingerprint(_vless()) in r.official_fps
        assert fp_hy2 not in r.official_fps


# ---------------------------------------------------------------------------
# score_candidates
# ---------------------------------------------------------------------------

def _scored_items(unique):
    """构造 score_candidates 需要的 tcp_lat（全部 TCP 存活）。"""
    return {fp: 50.0 for fp in unique}


def _fresh_survival(streak=5, seen_days=10, hist=(1, 1, 1)):
    """构造一条「今日新鲜」的 survival 记录（存活天数 + 真实通过史）。

    survival_state_fresh 要求 last_seen == 今日，否则历史加成被整体忽略
    （陈旧守卫，见 score_candidates docstring）。
    """
    return {"last_seen": common._today(), "streak": streak,
            "seen_days": seen_days, "real_hist": list(hist)}


class TestScoreCandidates:
    def _run(self, nodes, real_ok=None, bin_path="/fake/mihomo", survival=None,
             tampered=None, official_fps=None, prov=None, off_set=None,
             cn_latency_cap=config.MAX_ACCEPT_LATENCY_MS,
             us_latency_cap=config.MAX_ACCEPT_LATENCY_MS_US,
             score_latency_cap=config.TCP_LATENCY_CAP_IN_SCORE):
        unique = {fc.fingerprint(p): p for p in nodes}
        prov = prov or {fp: {TEST_URL} for fp in unique}
        official_fps = official_fps if official_fps is not None else set(unique)
        return fc.score_candidates(
            _scored_items(unique), unique, prov, official_fps, off_set or {TEST_URL},
            real_ok or {}, tampered or set(), bin_path, survival or {},
            cn_latency_cap, {}, {}, True,
            us_latency_cap, score_latency_cap)

    def test_liveness_gate_drops_unprobed_when_mihomo_present(self):
        """语义翻转（任务#102，2026-10-24）：默认开关关闭——未过拨测节点
        保留进评分、带 NO_REAL_PROBE_PENALTY 沉底；显式打开开关时恢复旧
        死活闸门行为（保留一键回滚能力）。"""
        nodes = [_vless(), _hy2()]
        ok = {fc.fingerprint(_hy2()): {"status": "ok", "latency": 100.0, "https_ok": True}}
        r = self._run(nodes, real_ok=ok)
        assert len(r.scored) == 2  # 未拨测的 vless 不再被丢弃
        # 带惩罚沉底：hy2（已拨测）排前，vless（未拨测）排后
        assert r.scored[0][0]["type"] == "hysteria2"
        assert r.scored[1][0]["type"] == "vless"
        # 开关显式打开 → 旧死活闸门行为
        monkeypatch = __import__("pytest").MonkeyPatch()
        monkeypatch.setattr(fc, "REQUIRE_REAL_PROBE_IN_OUTPUT", True)
        try:
            r2 = self._run(nodes, real_ok=ok)
            assert len(r2.scored) == 1
            assert r2.scored[0][0]["type"] == "hysteria2"
        finally:
            monkeypatch.undo()

    def test_no_gate_without_mihomo(self):
        """无 mihomo 时 TCP 存活节点全部保留（带 NO_REAL_PROBE_PENALTY）。"""
        r = self._run([_vless(), _hy2()], bin_path=None)
        assert len(r.scored) == 2

    def test_tampered_excluded(self):
        nodes = [_vless(), _hy2()]
        fp = fc.fingerprint(_vless())
        r = self._run(nodes, tampered={fp})
        assert all(it[0]["type"] != "vless" for it in r.scored)

    def test_latency_outlier_dropped(self):
        fp = fc.fingerprint(_hy2())
        ok = {fp: {"status": "ok", "latency": 99999.0, "https_ok": True}}
        r = self._run([_hy2()], real_ok=ok)
        assert not r.scored

    def test_open_http_dropped_when_mihomo_present(self):
        fp = fc.fingerprint(_http())
        ok = {fp: {"status": "ok", "latency": 100.0, "https_ok": True}}
        r = self._run([_http()], real_ok=ok)
        assert not r.scored   # tier>=3 的开放代理在纯净路径下被丢弃

    def test_open_http_kept_without_mihomo(self):
        r = self._run([_http()], bin_path=None)
        assert len(r.scored) == 1

    def test_us_node_uses_learned_us_cap(self):
        """美国出口节点用 us_latency_cap（非 CN 上限）；自学习放宽后保留。"""
        node = {"name": "US-01", "type": "vless", "server": "h1.vultr.example.com",
                "port": 443, "uuid": "u1"}
        fp = fc.fingerprint(node)
        ok = {fp: {"status": "ok", "latency": 3000.0, "https_ok": True}}
        # 默认 US 上限 2800ms：3000ms 超界 -> 离群点丢弃
        assert not self._run([node], real_ok=ok).scored
        # 自学习放宽到 5000ms：保留
        r = self._run([node], real_ok=ok, us_latency_cap=5000.0)
        assert len(r.scored) == 1

    def test_score_latency_cap_limits_contribution(self):
        """score_latency_cap 限制 TCP 延迟（美西 RTT，≠国内路径）的排序贡献。

        同构非美国节点延迟 100 vs 99999，cn 上限抬高避免离群丢弃，
        score_latency_cap=500：两节点 score 之差应恰为 min() 之差 400。
        """
        base = {"name": "HK-01", "type": "vless", "server": "1.2.3.4",
                "port": 443, "uuid": "u-base"}
        fp = fc.fingerprint(base)
        ok_low = {fp: {"status": "ok", "latency": 100.0, "https_ok": True}}
        ok_hi = {fp: {"status": "ok", "latency": 99999.0, "https_ok": True}}
        s_low = self._run([base], real_ok=ok_low, cn_latency_cap=100000.0,
                          score_latency_cap=500.0).scored[0][1]
        s_hi = self._run([base], real_ok=ok_hi, cn_latency_cap=100000.0,
                         score_latency_cap=500.0).scored[0][1]
        assert abs((s_hi - s_low) - 400.0) < 1e-6

    def test_candidate_only_must_pass_probe(self):
        """语义翻转（任务#102，2026-10-24）：候选源未过拨测节点不再直接
        剔除——NO_REAL_PROBE_PENALTY + CANDIDATE_ONLY_PENALTY 双重软惩罚
        沉底，中国实测才是生死证。"""
        nodes = [_vless()]
        r = self._run(nodes, official_fps=set(), real_ok={})
        assert len(r.scored) == 1
        # 惩罚确实在评分里生效（与正式源已拨测对照拉开距离）
        r_off_probed = self._run([_vless()], official_fps={fc.fingerprint(_vless())},
                                 real_ok={fc.fingerprint(_vless()): {
                                     "status": "ok", "latency": 100.0, "https_ok": True}})
        assert r.scored[0][1] > r_off_probed.scored[0][1]

    def test_https_gate_drops_cf_blocked_https_fail(self, monkeypatch):
        # 注意 patch 目标：score_candidates 引用的是 fc 命名空间的裸名
        # （filter_clash re-export），patch common 上的同名常量无效。
        monkeypatch.setattr(fc, "REQUIRE_HTTPS_OK_IN_OUTPUT", True)
        fp = fc.fingerprint(_vless())
        ok = {fp: {"status": "ok", "latency": 100.0, "https_ok": False}}
        r = self._run([_vless()], real_ok=ok)
        assert not r.scored

    def test_stale_survival_ignores_history_bonus(self):
        """survival 无今日记录时历史加成不参与（陈旧守卫）。"""
        stale = {fc.fingerprint(_vless()): {"date": "2020-01-01", "streak": 99, "seen_days": 99}}
        r_stale = self._run([_vless()], bin_path=None, survival=stale)
        r_none = self._run([_vless()], bin_path=None, survival={})
        assert r_stale.scored[0][1] == r_none.scored[0][1]   # 分数不受陈旧历史影响

    def test_survival_updated_with_real_ok_when_probing(self):
        fp = fc.fingerprint(_vless())
        ok = {fp: {"status": "ok", "latency": 100.0, "https_ok": True}}
        r = self._run([_vless()], real_ok=ok, survival={})
        assert fp in r.survival
        assert r.survival[fp].get("real_hist") is not None or "streak" in r.survival[fp]

    def test_multi_source_bonus_applied(self):
        """同一节点来自 2+ 正式源时获得多源加成（分数更低）。"""
        other = "https://other/x.yaml"
        fp = fc.fingerprint(_vless())
        off_both = {TEST_URL, other}
        r_multi = self._run([_vless()], bin_path=None,
                            prov={fp: {TEST_URL, other}}, off_set=off_both)
        r_single = self._run([_vless()], bin_path=None)
        assert r_multi.scored[0][1] < r_single.scored[0][1]
        # multi=2 → 加成 = MULTI_SOURCE_BONUS * min(multi-1, 3) = 一档
        assert (r_single.scored[0][1] - r_multi.scored[0][1]
                == config.MULTI_SOURCE_BONUS)

    def test_diversity_cap_drops_excess_credentials(self):
        """同一凭证超过 MAX_PER_CREDENTIAL 时多余节点被丢弃。"""
        nodes = [_vless(server=f"10.0.0.{i}") for i in range(1, config.MAX_PER_CREDENTIAL + 3)]
        r = self._run(nodes, bin_path=None)
        kept_cred = sum(1 for it in r.scored if it[0].get("uuid"))
        assert kept_cred == config.MAX_PER_CREDENTIAL
        assert r.diversity_dropped == len(nodes) - config.MAX_PER_CREDENTIAL

    def test_preferred_bonus_scaling(self):
        """hy2 优先协议的 survival 历史加成 ×1.5。

        1.5x 只放大 bonus（survival/history/cn_stability），不碰 penalty——
        因此用「同一节点有无新鲜历史记录」的分数差来隔离验证，避免与
        protocol_penalty / china_feature_bonus 的协议间静态差混淆。
        """
        fp = fc.fingerprint(_hy2())
        rec = _fresh_survival()
        raw = (fc.survival_bonus_ms(fp, {fp: rec})
               + fc.history_bonus(fp, {fp: rec}))
        assert raw < 0  # 记录有实质加成
        r_off = self._run([_hy2()], bin_path=None, survival={})
        r_on = self._run([_hy2()], bin_path=None, survival={fp: rec})
        # raw 为负（加成降分）：优先协议把历史加成放大 1.5 倍
        assert r_on.scored[0][1] - r_off.scored[0][1] == pytest.approx(1.5 * raw)

    def test_non_preferred_bonus_not_scaled(self):
        """非优先协议（无 Reality 的 vless）历史加成不放大（×1.0）。"""
        plain = _vless()
        plain.pop("reality-opts")
        plain.pop("flow")
        assert not fc.is_preferred(plain)
        fp = fc.fingerprint(plain)
        rec = _fresh_survival()
        raw = (fc.survival_bonus_ms(fp, {fp: rec})
               + fc.history_bonus(fp, {fp: rec}))
        r_off = self._run([plain], bin_path=None, survival={})
        r_on = self._run([plain], bin_path=None, survival={fp: rec})
        assert r_on.scored[0][1] - r_off.scored[0][1] == pytest.approx(raw)


# ---------------------------------------------------------------------------
# select_final
# ---------------------------------------------------------------------------

def _item(node, score=100.0, display=100.0):
    """构造 scored 元组：(proxy, score, display, preferred, real, tier)。"""
    return (node, score, display, fc.is_preferred(node), True, fc.protocol_tier(node))


class TestSelectFinal:
    def test_region_quota_respected(self):
        """无回填压力时各区域严格等于配额（回填让位配额的场景另测）。

        每区配额 +5 个富余节点：选中总量 245 ≥ MIN_FINAL(150)，既不下限
        回填也不超 MAX_FINAL(300)，配额严格生效。
        """
        quotas = config.REGION_QUOTAS
        plan = [("HK", "🇭🇰 香港", _vless, 11), ("JP", "🇯🇵 日本", _hy2, 12),
                ("SG", "🇸🇬 新加坡", _trojan, 13), ("TW", "🇹🇼 台湾", _vless, 14),
                ("KR", "🇰🇷 韩国", _hy2, 15), ("US", "🇺🇸 美国", _vless, 16),
                ("UK", "🇬🇧 英国", _trojan, 17), ("ZZ", "🌐 其他", _vless, 18)]
        scored = []
        for prefix, region, factory, octet in plan:
            n = quotas.get(region, config.MAX_OTHER) + 5
            for i in range(n):
                scored.append(_item(factory(name=f"{prefix}-{i:03d}",
                                            server=f"{octet}.0.{i % 250}.1")))
        out = fc.select_final(scored, {})
        for region, quota in quotas.items():
            assert len(out.get(region, [])) == quota, region
        assert len(out.get("🌐 其他", [])) == config.MAX_OTHER
        assert sum(len(v) for v in out.values()) == sum(quotas.values()) + config.MAX_OTHER

    def test_unknown_region_uses_max_other(self):
        """未知地区走 MAX_OTHER 上限（构造已越过 MIN_FINAL，排除回填干扰）。"""
        scored = []
        for i in range(config.MAX_OTHER + 5):
            scored.append(_item(_vless(name=f"ZZ-{i:03d}", server=f"18.0.{i % 250}.1")))
        for i in range(config.REGION_QUOTAS["🇭🇰 香港"] + 5):
            scored.append(_item(_hy2(name=f"HK-{i:03d}", server=f"11.0.{i % 250}.1")))
        for i in range(config.REGION_QUOTAS["🇯🇵 日本"] + 5):
            scored.append(_item(_hy2(name=f"JP-{i:03d}", server=f"12.0.{i % 250}.1")))
        for i in range(config.REGION_QUOTAS["🇸🇬 新加坡"] + 5):
            scored.append(_item(_hy2(name=f"SG-{i:03d}", server=f"13.0.{i % 250}.1")))
        out = fc.select_final(scored, {})
        assert len(out.get("🌐 其他", [])) == config.MAX_OTHER
        # 选中总量 60+40+35+30=165 ≥ MIN_FINAL：无回填、无裁剪
        assert sum(len(v) for v in out.values()) == config.MAX_OTHER + 40 + 35 + 30

    def test_min_final_backfill_from_pool(self):
        """低于 MIN_FINAL 时从未选中的池回填。"""
        scored = [_item(_vless(name=f"HK-{i:02d}", server=f"1.1.1.{i}")) for i in range(5)]
        out = fc.select_final(scored, {})
        # 池全部入选（5 < MIN_FINAL 但无更多节点），不应崩溃
        assert sum(len(v) for v in out.values()) == 5

    def test_backfill_prioritizes_total_over_quota(self):
        """低于 MIN_FINAL 时下限回填优先于区域配额（保总数，配额让位）。"""
        n = config.REGION_QUOTAS["🇭🇰 香港"] + 5
        scored = [_item(_vless(name=f"HK-{i:03d}", server=f"11.0.{i % 250}.1"))
                  for i in range(n)]
        out = fc.select_final(scored, {})
        # 香港配额 40，但总量 45 < MIN_FINAL → 富余 5 个全部回填，允许超过配额
        assert len(out["🇭🇰 香港"]) == n

    def test_max_final_trim(self, monkeypatch):
        """超过 MAX_FINAL 时裁剪到上限，保留分数最优者。

        生产配额下各区域选中量上限 245 < MAX_FINAL(300)，该分支只在配额
        上调后才可达——此处下调 fc.MAX_FINAL 专门 exercise 裁剪逻辑。
        """
        monkeypatch.setattr(fc, "MAX_FINAL", 100)
        scored = [_item(_vless(name=f"HK-{i:03d}", server=f"11.0.{i % 250}.1"),
                        score=float(i)) for i in range(45)]
        scored += [_item(_hy2(name=f"JP-{i:03d}", server=f"12.0.{i % 250}.1"),
                         score=float(100 + i)) for i in range(40)]
        scored += [_item(_hy2(name=f"SG-{i:03d}", server=f"13.0.{i % 250}.1"),
                         score=float(200 + i)) for i in range(35)]
        out = fc.select_final(scored, {})
        flat = [row for rows in out.values() for row in rows]
        assert len(flat) == 100
        # 配额选中 HK40+JP35+SG30=105，裁剪丢最差 5 个（SG 最高分 225-229）
        kept = sorted(row[1] for row in flat)
        assert kept == sorted([float(i) for i in range(40)]
                              + [float(100 + i) for i in range(35)]
                              + [float(200 + i) for i in range(25)])

    def test_us_share_cap(self):
        """美国节点占比不超过 MAX_US_SHARE。"""
        nodes = []
        # 充足的非美节点越过 MIN_FINAL，美国节点数受配额+占比双重限制
        for i in range(config.MIN_FINAL + 30):
            nodes.append(_item(_hy2(name=f"JP-{i:03d}", server=f"5.5.5.{i % 250}")))
        for i in range(30):
            nodes.append(_item(_vless(name=f"US-{i:02d}", server=f"3.3.3.{i}")))
        out = fc.select_final(nodes, {})
        flat = [row for rows in out.values() for row in rows]
        n_us = sum(1 for row in flat if fc.classify_proxy(row[0]["name"]) == "🇺🇸 美国")
        assert n_us <= max(1, int(len(flat) * config.MAX_US_SHARE + 0.999))
        assert n_us < 30   # 占比上限实际压过了美国节点数

    def test_preferred_real_fills_before_low_tier(self):
        """同一区域内优先+真实节点先于低档位节点入选。"""
        hi = _hy2(name="JP-01", server="5.6.7.8")     # tier 0 preferred
        lo = _trojan(name="SG-01", server="9.9.9.9")  # tier 1
        scored = [_item(lo, score=1.0), _item(hi, score=999.0)]
        out = fc.select_final(scored, {})
        jp = [row[0]["name"] for row in out.get("🇯🇵 日本", [])]
        sg = [row[0]["name"] for row in out.get("🇸🇬 新加坡", [])]
        assert "JP-01" in jp and "SG-01" in sg


# ---------------------------------------------------------------------------
# name_and_isolate
# ---------------------------------------------------------------------------

class TestNameAndIsolate:
    def test_insecure_tagged_and_separated(self):
        node = _trojan()
        node["skip-cert-verify"] = True
        out = fc.name_and_isolate({"🇸🇬 新加坡": [_item(node)]})
        assert len(out.insecure_proxies) == 1
        assert fc.INSECURE_TAG in out.insecure_proxies[0]["name"]
        assert out.final_proxies == []

    def test_duplicate_names_get_suffix(self):
        a, b, c = _vless(name="HK-01", server="1.1.1.1"), _vless(name="HK-01", server="2.2.2.2"), _vless(name="HK-01", server="3.3.3.3")
        out = fc.name_and_isolate({"🇭🇰 香港": [_item(a), _item(b), _item(c)]})
        names = [p["name"] for p in out.final_proxies]
        assert names == ["HK-01", "HK-01#2", "HK-01#3"]

    def test_latency_suffix_stripped_from_name(self):
        node = _vless(name="HK-01 120ms")
        out = fc.name_and_isolate({"🇭🇰 香港": [_item(node)]})
        assert out.final_proxies[0]["name"] == "HK-01"

    def test_empty_name_fallback(self):
        node = _vless(name="   ")
        out = fc.name_and_isolate({"🇭🇰 香港": [_item(node)]})
        assert out.final_proxies[0]["name"] == "node"

    def test_final_name_by_fp_mapping(self):
        node = _vless()
        out = fc.name_and_isolate({"🇭🇰 香港": [_item(node)]})
        assert out.final_name_by_fp[fc.fingerprint(node)] == "HK-01"

    def test_empty_region_dict(self):
        out = fc.name_and_isolate({})
        assert out.total_final == 0 and out.final_proxies == []


# ---------------------------------------------------------------------------
# build_clash_config
# ---------------------------------------------------------------------------

class TestBuildClashConfig:
    def test_core_groups_present(self):
        cfg = fc.build_clash_config([_vless()], [])
        names = {g["name"] for g in cfg["proxy-groups"]}
        assert {"🚀 节点选择", "♻️ 自动选择", "🔯 故障转移", "🇭🇰 香港"} <= names

    def test_auto_and_fallback_only_compliant(self):
        ins = _trojan(); ins["skip-cert-verify"] = True
        cfg = fc.build_clash_config([_vless()], [dict(ins, name="SG-03[Insecure]")])
        auto = next(g for g in cfg["proxy-groups"] if g["name"] == "♻️ 自动选择")
        assert auto["proxies"] == ["HK-01"]

    def test_insecure_group_is_select_only(self):
        ins = dict(_trojan(), name="SG-03[Insecure]")
        cfg = fc.build_clash_config([_vless()], [ins])
        grp = next(g for g in cfg["proxy-groups"] if g["name"] == fc.INSECURE_GROUP)
        assert grp["type"] == "select"
        assert grp["proxies"] == ["SG-03[Insecure]"]
        # 顶层 select 引用 Insecure 组
        top = next(g for g in cfg["proxy-groups"] if g["name"] == "🚀 节点选择")
        assert fc.INSECURE_GROUP in top["proxies"]

    def test_empty_region_group_not_referenced(self):
        """没有节点的地区组不应出现在顶层 select（否则客户端加载失败）。"""
        cfg = fc.build_clash_config([_vless()], [])
        top = next(g for g in cfg["proxy-groups"] if g["name"] == "🚀 节点选择")
        present = {g["name"] for g in cfg["proxy-groups"]}
        for ref in top["proxies"]:
            assert ref == "DIRECT" or ref in present

    def test_no_proxies_still_valid(self):
        cfg = fc.build_clash_config([], [])
        assert cfg["proxies"] == []
        assert any(g["name"] == "♻️ 自动选择" for g in cfg["proxy-groups"])

    def test_proxies_concatenated_compliant_first(self):
        ins = dict(_trojan(), name="SG-03[Insecure]")
        cfg = fc.build_clash_config([_vless()], [ins])
        assert [p["name"] for p in cfg["proxies"]] == ["HK-01", "SG-03[Insecure]"]
