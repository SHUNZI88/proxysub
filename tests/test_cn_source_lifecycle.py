"""cn 源级生命周期（cn_source_lifecycle，2026-10-20）专项测试。

沙箱 verification_report.json 的 by_source 统计经 evolution 折回
source_scores.json 的 cn_* 维度后，驱动**独立于 CI 侧评分**的源级决策层。
本文件覆盖四层 + 熔断：

  A. 数据层：evolution.cn_source_stats 提取口径（只取含 cn_tested 的条目）/
     cn_fetch_tilt 四档倾斜（None/0.5/1.0/1.5）、非对称样本门槛、陈旧守卫；
  B. 淘汰层：sources_manager.update_official 的 cn streak 判低、连续轮数
     淘汰、三重保底（manual 豁免 / 单轮上限 MAX_CN_DEMOTE_PER_RUN / 保底
     MIN_OFFICIAL）、无实证清零、淘汰清零 streak；
  C. 晋升层：evaluate_candidates 的 cn 实证优先排序（Wilson 下界降序）、
     cn_stats=None/空时与改造前排序完全一致；
  D. 拨测层：select_probe_sample 的单源基础上限 PROBE_SOURCE_SAMPLE_CAP
     （仅对有新鲜实证的源生效）与候选源配额倾斜；无实证不干预；
  E. 熔断层：config.CN_LIFECYCLE_ENABLED=False 时 main() 不构造 cn_stats，
     三个消费点全部退化为改造前行为。

全部走 mock：无网络、不读写真实状态文件（load_json 已 patch）。
"""

from __future__ import annotations

import datetime as dt

import config
import evolution
import filter_clash as fc
import sources_manager as sm
from test_main_pipeline import pipeline  # 复用 main() 全流程 fixture（熔断测试）

TODAY = "2026-10-14"
NOW = dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------------------
# 辅助构造
# ---------------------------------------------------------------------------

def _cn(tested: int, passed: int, hours_ago: float = 1.0) -> dict:
    """一条源级 cn 实证记录（cn_last 默认 1 小时前，视为新鲜）。"""
    last = (NOW - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"cn_tested": tested, "cn_passed": passed,
            "cn_pass_rate": (passed / tested) if tested else 0.0,
            "cn_last": last}


def _ok_run(**kw) -> dict:
    """一轮健康的 per-source 运行记录（不误触任何 CI 侧淘汰判据）。

    usable/unique_new 满足候选晋升下限（MIN_CANDIDATE_USABLE=5 /
    MIN_CANDIDATE_UNIQUE=4），unique_new 可经 kw 覆盖。
    """
    r = {"ok": True, "count": 30, "alive": 20, "unique_alive": 6, "usable": 10,
         "unique_new": 6, "real_ok": 3, "probed": 20, "tamper": 0,
         "cf_blocked": 0, "flags": []}
    r.update(kw)
    return r


def _src(entries, **kw) -> dict:
    s = {"official": entries, "removed": [], "max_official": 30, "deny_repos": []}
    s.update(kw)
    return s


def _entry(url: str, origin: str = "discovered") -> dict:
    return {"url": url, "origin": origin, "added": "2026-10-01"}


def _proxy(ptype="trojan", name="n", lat=100.0, server="s.example.com", **extra):
    return {"name": name, "type": ptype, "server": server, "port": 443, **extra}


def _survival_rec() -> dict:
    return {"streak": 1, "seen_days": 1, "last_seen": TODAY}


# ===========================================================================
# A. 数据层：cn_source_stats / cn_fetch_tilt
# ===========================================================================

class TestCnSourceStats:
    def test_extracts_only_cn_entries(self):
        scores = {
            "http://a/sub": {"score": 100, "cn_tested": 30, "cn_passed": 3,
                             "cn_pass_rate": 0.1, "cn_last": "t"},
            "http://b/sub": {"score": 80},                      # 无 cn 维度
            "owner/repo": {"score": 60, "cn_tested": 5},         # 历史镜像键也提取
        }
        out = evolution.cn_source_stats(scores)
        assert set(out) == {"http://a/sub", "owner/repo"}
        assert out["http://a/sub"] == {"cn_tested": 30, "cn_passed": 3,
                                       "cn_pass_rate": 0.1, "cn_last": "t"}

    def test_empty_and_none_safe(self):
        assert evolution.cn_source_stats({}) == {}
        assert evolution.cn_source_stats(None) == {}


class TestCnFetchTilt:
    def test_none_when_no_evidence(self):
        assert evolution.cn_fetch_tilt("http://a/sub", {}) is None
        assert evolution.cn_fetch_tilt(None, {"http://a/sub": _cn(30, 0)}) is None
        # 样本不足 CN_MIN_SAMPLE_HIGH=10：不干预（正向判据从宽但不下探到噪声区）
        assert evolution.cn_fetch_tilt("http://a/sub", {"http://a/sub": _cn(2, 2)}) is None

    def test_low_yield_halves(self):
        # 0/30：Wilson 下界恒 0 < 5%，且 n>=CN_MIN_SAMPLE=20
        stats = {"http://a/sub": _cn(30, 0)}
        assert evolution.cn_fetch_tilt("http://a/sub", stats) == config.CN_TILT_LOW
        # 1/25：裸通过率 4%，下界 ~0.7% < 5%（真实数据 Au1rxx 型低产源）
        assert evolution.cn_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _cn(25, 1)}) == config.CN_TILT_LOW

    def test_neutral_one_for_middling(self):
        # 10/30：点估计 33% 但 Wilson 下界 ~19% < 30% → 中性（防小样本虚高）
        assert evolution.cn_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _cn(30, 10)}) == 1.0
        # 10/20：点估计 50%，Wilson 下界 29.93% 压线低于 30% → 仍中性
        # （点估计会把它捧成高产源，下界不会——防小样本虚高的核心案例）
        assert evolution.cn_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _cn(20, 10)}) == 1.0

    def test_high_yield_one_and_half(self):
        # 7/11：点估计 63.6%，下界 ~35% >= 30%（真实数据 ovmvo 型高产源）
        assert evolution.cn_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _cn(11, 7)}) == config.CN_TILT_HIGH
        # 11/11：下界 ~74%
        assert evolution.cn_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _cn(11, 11)}) == config.CN_TILT_HIGH

    def test_asymmetric_demotion_threshold_stricter(self):
        # 1/15：裸率 6.7%、下界 ~1.2%（看着低），但 n=15 < CN_MIN_SAMPLE=20 →
        # 不判低产（淘汰要严：误杀不可逆）；下界也未达高产线 → 中性
        assert evolution.cn_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _cn(15, 1)}) == 1.0

    def test_stale_data_returns_none(self):
        stats = {"http://a/sub": _cn(30, 0, hours_ago=72)}
        assert evolution.cn_fetch_tilt("http://a/sub", stats,
                                       max_age_s=config.CN_DECISION_MAX_AGE_S) is None
        # max_age_s=None 时调用方自控新鲜度，本函数不做年龄筛选
        assert evolution.cn_fetch_tilt("http://a/sub", stats) == config.CN_TILT_LOW

    def test_missing_cn_last_with_max_age_returns_none(self):
        rec = _cn(30, 0)
        rec.pop("cn_last")
        assert evolution.cn_fetch_tilt("http://a/sub", {"http://a/sub": rec},
                                       max_age_s=config.CN_DECISION_MAX_AGE_S) is None

    def test_unparsable_cn_last_returns_none(self):
        rec = _cn(30, 0)
        rec["cn_last"] = "not-a-time"
        assert evolution.cn_fetch_tilt("http://a/sub", {"http://a/sub": rec},
                                       max_age_s=config.CN_DECISION_MAX_AGE_S) is None


# ===========================================================================
# B. 淘汰层：update_official 的 cn 决策
# ===========================================================================

class TestUpdateOfficialCnDemote:
    """cn 淘汰判据、streak、三重保底。CI 侧判据全部保持健康（并联不干扰）。

    注意：淘汰要过 MIN_OFFICIAL=6 保底（keep_n - MIN_OFFICIAL = room），
    因此「预期发生淘汰」的用例必须配够 7 个以上 official 源。
    """

    @staticmethod
    def _with_floor(target_url: str, origin: str = "discovered") -> tuple[dict, dict]:
        """目标源 + 6 个健康陪衬源（凑过保底线，使 room=1 可汰 1 个）。"""
        entries = [_entry(target_url, origin)]
        entries += [_entry(f"http://filler{i}/sub") for i in range(6)]
        run = {e["url"]: _ok_run() for e in entries}
        return _src(entries), run

    def test_zero_pass_source_demoted_after_streak(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources, run = self._with_floor("http://zero/sub")
        hist: dict = {}
        cn = {"http://zero/sub": _cn(20, 0)}
        # 第一轮：判低但 streak=1 < CN_DEMOTE_STREAK=2 → 只观察
        rep = sm.update_official(sources, hist, run, cn)
        assert rep["demoted"] == {}
        assert hist["http://zero/sub"]["cn_low_streak"] == 1
        # 第二轮：streak=2 → 淘汰
        rep = sm.update_official(sources, hist, run, cn)
        assert rep["demoted"] == {"http://zero/sub": "cn_low_pass_rate:0/20"}
        assert "http://zero/sub" not in [e["url"] for e in sources["official"]]
        assert sources["removed"][0]["reason"] == "cn_low_pass_rate:0/20"

    def test_single_low_run_not_demoted(self, monkeypatch):
        """单轮判低不汰（streak 保护）；紧接着实证中断即清零。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources, run = self._with_floor("http://zero/sub")
        hist: dict = {}
        cn = {"http://zero/sub": _cn(20, 0)}
        rep = sm.update_official(sources, hist, run, cn)
        assert rep["demoted"] == {}
        assert hist["http://zero/sub"]["cn_low_streak"] == 1
        # 第二轮该源无实证（cn_stats 非空但不含它）→ streak 清零，不累积成误杀
        rep = sm.update_official(sources, hist, run, {"http://other/sub": _cn(20, 0)})
        assert rep["demoted"] == {}
        assert hist["http://zero/sub"]["cn_low_streak"] == 0

    def test_borderline_chengaopan_not_low(self, monkeypatch):
        """真实数据回归：4/27 裸通过率 14.8%，但 Wilson 下界 ~5.9% > 5% → 不判低。

        判据用下界（保守侧）的意义：裸率会误杀这类"看着差其实区间横跨门槛"
        的源；下界要求"连最悲观的估计都低于 5%"才淘汰。
        """
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://cgp/sub")])
        hist: dict = {}
        cn = {"http://cgp/sub": _cn(27, 4)}
        for _ in range(4):  # 远超 streak 要求
            rep = sm.update_official(sources, hist, {"http://cgp/sub": _ok_run()}, cn)
        assert rep["demoted"] == {}
        assert hist["http://cgp/sub"]["cn_low_streak"] == 0

    def test_manual_source_exempt(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://zero/sub", origin="manual")])
        hist: dict = {}
        cn = {"http://zero/sub": _cn(20, 0)}
        for _ in range(4):
            rep = sm.update_official(sources, hist, {"http://zero/sub": _ok_run()}, cn)
        assert rep["demoted"] == {}
        assert len(sources["official"]) == 1

    def test_demote_capped_at_three_worst_first(self, monkeypatch):
        """4 个低产源同轮达标，但单轮上限 3：Wilson 下界最劣的 3 个先汰。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        lows = [("http://l0/sub", 0, 25), ("http://l1/sub", 1, 25),
                ("http://l2/sub", 2, 25), ("http://l3/sub", 3, 25)]
        entries = [_entry(u) for u, _, _ in lows]
        entries += [_entry(f"http://h{i}/sub") for i in range(5)]  # 保底数量外 healthy
        sources = _src(entries)
        hist: dict = {}
        run = {u: _ok_run() for u, _, _ in lows}
        run.update({f"http://h{i}/sub": _ok_run() for i in range(5)})
        cn = {u: _cn(t, p) for u, p, t in lows}
        cn.update({f"http://h{i}/sub": _cn(25, 20) for i in range(5)})
        for _ in range(config.CN_DEMOTE_STREAK):
            rep = sm.update_official(sources, hist, run, cn)
        # 下界升序：0/25(0.0) < 1/25(~0.007) < 2/25(~0.022) < 3/25(~0.042)
        assert set(rep["demoted"]) == {"http://l0/sub", "http://l1/sub", "http://l2/sub"}
        assert rep["demoted"]["http://l0/sub"] == "cn_low_pass_rate:0/25"
        # 最劣 3 个出局后 official 剩 6（= MIN_OFFICIAL），第 4 劣留下继续观察
        assert "http://l3/sub" in [e["url"] for e in sources["official"]]
        assert len(sources["official"]) == 6

    def test_min_official_floor_blocks_all_demotion(self, monkeypatch):
        """official 已贴保底线 MIN_OFFICIAL=6：本轮一个都不汰（防淘光无源可抓）。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        entries = [_entry(f"http://z{i}/sub") for i in range(6)]
        sources = _src(entries)
        hist: dict = {}
        run = {f"http://z{i}/sub": _ok_run() for i in range(6)}
        cn = {f"http://z{i}/sub": _cn(20, 0) for i in range(6)}
        for _ in range(config.CN_DEMOTE_STREAK + 1):
            rep = sm.update_official(sources, hist, run, cn)
        assert rep["demoted"] == {}
        assert len(sources["official"]) == 6

    def test_no_evidence_clears_streak(self, monkeypatch):
        """实证中断（本轮无该源记录）→ streak 清零：波动不会累积成误杀。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://zero/sub")])
        hist: dict = {}
        sm.update_official(sources, hist, {"http://zero/sub": _ok_run()},
                           {"http://zero/sub": _cn(20, 0)})
        assert hist["http://zero/sub"]["cn_low_streak"] == 1
        # 第二轮换源实证缺失 → 清零
        sm.update_official(sources, hist, {"http://zero/sub": _ok_run()},
                           {"http://other/sub": _cn(20, 0)})
        assert hist["http://zero/sub"]["cn_low_streak"] == 0
        assert "cn_low_last" not in hist["http://zero/sub"]
        # 清零后再判低也要重新攒满 streak
        rep = sm.update_official(sources, hist, {"http://zero/sub": _ok_run()},
                                 {"http://zero/sub": _cn(20, 0)})
        assert rep["demoted"] == {}

    def test_small_sample_not_low(self, monkeypatch):
        """n=10 < CN_MIN_SAMPLE=20：只观察不淘汰（护小源实证）。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://small/sub")])
        hist: dict = {}
        cn = {"http://small/sub": _cn(10, 0)}
        for _ in range(5):
            rep = sm.update_official(sources, hist, {"http://small/sub": _ok_run()}, cn)
        assert rep["demoted"] == {}
        assert hist["http://small/sub"]["cn_low_streak"] == 0

    def test_stale_evidence_not_low(self, monkeypatch):
        """cn_last 超过 CN_DECISION_MAX_AGE_S=48h：视为无实证（容忍沙箱漏跑一轮）。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://old/sub")])
        hist: dict = {}
        cn = {"http://old/sub": _cn(20, 0, hours_ago=72)}
        for _ in range(4):
            rep = sm.update_official(sources, hist, {"http://old/sub": _ok_run()}, cn)
        assert rep["demoted"] == {}
        assert hist["http://old/sub"]["cn_low_streak"] == 0

    def test_demote_clears_streak_for_reentry(self, monkeypatch):
        """淘汰即清零 streak：30 天冷却回迁的源不会被旧 streak 瞬杀。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources, run = self._with_floor("http://zero/sub")
        hist: dict = {}
        cn = {"http://zero/sub": _cn(20, 0)}
        for _ in range(2):
            sm.update_official(sources, hist, run, cn)
        assert hist["http://zero/sub"].get("cn_low_streak", 0) == 0
        assert "cn_low_last" not in hist["http://zero/sub"]

    def test_no_cn_stats_leaves_hist_untouched(self, monkeypatch):
        """cn_stats=None：stats_hist 不新增任何键（降级 = 改造前逐字节一致）。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://x/sub")])
        hist: dict = {}
        sm.update_official(sources, hist, {"http://x/sub": _ok_run()})
        sm.update_official(sources, hist, {"http://x/sub": _ok_run()}, None)
        assert "cn_low_streak" not in hist["http://x/sub"]
        assert "cn_low_last" not in hist["http://x/sub"]
        assert len(sources["official"]) == 1

    def test_ci_reason_preempts_cn_candidate(self, monkeypatch):
        """CI 侧已判淘汰（诱饵转载）时不重复计入 cn 候选（reason 非空即跳过）。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://bait/sub")])
        hist: dict = {}
        cn = {"http://bait/sub": _cn(20, 0)}
        rep = sm.update_official(sources, hist,
                                 {"http://bait/sub": _ok_run(flags=["bait_reuse:x"])}, cn)
        assert rep["demoted"] == {"http://bait/sub": "redistributes_bait"}
        # 源已出局，下一轮无 official 条目自然无淘汰
        rep = sm.update_official(sources, hist,
                                 {"http://bait/sub": _ok_run(flags=["bait_reuse:x"])}, cn)
        assert rep["demoted"] == {}


# ===========================================================================
# B2. 有效性守卫：零独有淘汰不误汰有实证高效率源（2026-10-21 任务#93）
# ===========================================================================

class TestZeroUniqueValidityGuard:
    """零独有（proxy 指标）淘汰的有效性守卫。

    事故锚点：blog.ermao.net cn 通过率 12.3%（16/130，全池第二高）因
    zero_unique_contribution:16runs 被汰——用独有性代理指标淘汰了有效源。
    守卫：有充足且新鲜 cn 实效实证（Wilson 下界 >= CN_LOW_CI_HIGH）的源
    豁免零独有淘汰；无实证时守卫 inert（改造前行为），无效源仍由
    zero_real_ok / fail_streak / cn_low 通道淘汰。
    """

    @staticmethod
    def _zero_unique_run() -> dict:
        return _ok_run(unique_alive=0)

    def test_effective_source_guarded_from_zero_unique(self, monkeypatch):
        """有实效实证 + 零独有 streak 达标 ⇒ 不淘汰，记入 rep["guarded"]。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://ermao/sub")])
        hist: dict = {}
        cn = {"http://ermao/sub": _cn(130, 16)}   # 事故数据：12.3%，下界 ~7.6% > 5%
        rep = None
        for _ in range(sm.OFFICIAL_ZERO_UNIQUE_DEMOTE + 2):
            rep = sm.update_official(sources, hist,
                                     {"http://ermao/sub": self._zero_unique_run()}, cn)
        assert rep["demoted"] == {}
        assert "http://ermao/sub" in [e["url"] for e in sources["official"]]
        g = rep["guarded"]["http://ermao/sub"]
        assert g["guard"] == "zero_unique_guarded_by_cn_evidence"
        assert g["cn_tested"] == 130 and g["cn_passed"] == 16
        assert g["wilson_ci_low"] >= config.CN_LOW_CI_HIGH
        assert g["zero_unique_streak"] >= sm.OFFICIAL_ZERO_UNIQUE_DEMOTE

    def test_no_evidence_zero_unique_still_demotes(self, monkeypatch):
        """无实证（cn_stats=None）+ 零独有 streak 达标 ⇒ 照汰（守卫 inert）。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://dup/sub")])
        hist: dict = {}
        rep = None
        for _ in range(sm.OFFICIAL_ZERO_UNIQUE_DEMOTE):
            rep = sm.update_official(sources, hist,
                                     {"http://dup/sub": self._zero_unique_run()})
        assert rep["demoted"] == {
            "http://dup/sub": f"zero_unique_contribution:{sm.OFFICIAL_ZERO_UNIQUE_DEMOTE}runs"}

    def test_low_evidence_zero_unique_still_demotes(self, monkeypatch):
        """cn 低产实证（0/20 下界 0）+ 零独有 ⇒ 照汰（无效源不漏网）。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://dead/sub")])
        hist: dict = {}
        cn = {"http://dead/sub": _cn(20, 0)}
        rep = None
        for _ in range(sm.OFFICIAL_ZERO_UNIQUE_DEMOTE):
            rep = sm.update_official(sources, hist,
                                     {"http://dead/sub": self._zero_unique_run()}, cn)
        assert rep["demoted"] == {
            "http://dead/sub": f"zero_unique_contribution:{sm.OFFICIAL_ZERO_UNIQUE_DEMOTE}runs"}

    def test_small_sample_evidence_does_not_guard(self, monkeypatch):
        """样本不足（10 < CN_MIN_SAMPLE=20）+ 零独有 ⇒ 照汰（无实证不放行）。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://small/sub")])
        hist: dict = {}
        cn = {"http://small/sub": _cn(10, 5)}      # 50% 通过但样本不足
        rep = None
        for _ in range(sm.OFFICIAL_ZERO_UNIQUE_DEMOTE):
            rep = sm.update_official(sources, hist,
                                     {"http://small/sub": self._zero_unique_run()}, cn)
        assert rep["demoted"] == {
            "http://small/sub": f"zero_unique_contribution:{sm.OFFICIAL_ZERO_UNIQUE_DEMOTE}runs"}

    def test_stale_evidence_does_not_guard(self, monkeypatch):
        """实证陈旧（72h > 48h）+ 零独有 ⇒ 照汰。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = _src([_entry("http://old/sub")])
        hist: dict = {}
        cn = {"http://old/sub": _cn(30, 12, hours_ago=72)}
        rep = None
        for _ in range(sm.OFFICIAL_ZERO_UNIQUE_DEMOTE):
            rep = sm.update_official(sources, hist,
                                     {"http://old/sub": self._zero_unique_run()}, cn)
        assert rep["demoted"] == {
            "http://old/sub": f"zero_unique_contribution:{sm.OFFICIAL_ZERO_UNIQUE_DEMOTE}runs"}

    def test_cn_effective_evidence_boundary(self):
        """_cn_effective_evidence 判据边界：下界横跨门槛时按保守侧处理。"""
        # 4/27 下界 ~5.9% > 5% ⇒ 有实效（与 test_borderline_chengaopan_not_low 同数据）
        ok, lo, t, p = sm._cn_effective_evidence("u", {"u": _cn(27, 4)})
        assert ok is True and lo >= config.CN_LOW_CI_HIGH and (t, p) == (27, 4)
        # 无记录 / 样本不足 / 陈旧 ⇒ 无实效
        assert sm._cn_effective_evidence("u", {})[0] is False
        assert sm._cn_effective_evidence("u", {"u": _cn(10, 5)})[0] is False
        assert sm._cn_effective_evidence("u", {"u": _cn(30, 12, hours_ago=72)})[0] is False


# ===========================================================================
# C. 晋升层：evaluate_candidates 的 cn 优先排序
# ===========================================================================

def _cand(**kw) -> dict:
    c = {"repo": "o/r", "required_runs": 1, "runs": 0, "good_streak": 0,
         "fail_streak": 0, "history": [], "first_seen": "2026-10-13"}
    c.update(kw)
    return c


def _ready_cands(specs: dict[str, tuple[int, dict | None]]) -> tuple[dict, dict, dict]:
    """specs: url -> (unique_new, cn_entry or None)。返回 (cands, run, cn)。

    注意 unique_new 必须 >= MIN_CANDIDATE_UNIQUE(4) 候选才 ready；
    排序用的"独有贡献"即 history 累计（单轮时等于本轮的 unique_new）。
    """
    cands = {"candidates": {u: _cand() for u in specs}, "rejected": {}}
    run = {u: _ok_run(unique_new=n) for u, (n, _) in specs.items()}
    cn = {u: e for u, (_, e) in specs.items() if e}
    return cands, run, cn


class TestEvaluateCandidatesCnPriority:
    def test_none_cn_stats_matches_legacy_order(self):
        """cn_stats=None：排序键恒为 (1, 0.0, -uniq)，与改造前完全一致。"""
        cands, run, _ = _ready_cands({"u0": (6, None), "u1": (4, None), "u2": (5, None)})
        rep = sm.evaluate_candidates(cands, run, {"official": []}, None)
        assert rep["promoted"] == ["u0", "u2"]

    def test_cn_evidence_beats_higher_unique(self):
        """有正向实证的低贡献候选压过无实证的高贡献候选。"""
        cands, run, cn = _ready_cands({"u0": (10, None), "u1": (4, _cn(11, 11))})
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn)
        assert rep["promoted"] == ["u1", "u0"]

    def test_wilson_lower_bound_prefers_larger_sample(self):
        """同点估计（70%）样本大者下界更高：14/20 压过 7/10。"""
        cands, run, cn = _ready_cands({"u0": (5, _cn(10, 7)), "u1": (5, _cn(20, 14))})
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn)
        assert rep["promoted"][0] == "u1"

    def test_small_sample_gets_no_priority(self):
        """2/2 满分但 n=2 < CN_MIN_SAMPLE_HIGH=10：不享受实证优先。"""
        cands, run, cn = _ready_cands({"u0": (4, _cn(2, 2)), "u1": (5, None)})
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn)
        assert rep["promoted"][0] == "u1"

    def test_zero_pass_evidence_not_prioritized(self):
        """0/20 有实证但零通过：不进优先组（passed>=1 才优先）。"""
        cands, run, cn = _ready_cands({"u0": (4, _cn(20, 0)), "u1": (5, None)})
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn)
        assert rep["promoted"][0] == "u1"

    def test_promotion_still_capped(self):
        """cn 优先只改顺序不改名额：MAX_PROMOTIONS_PER_RUN=2 仍生效。"""
        specs = {"u0": (10, None), "u1": (4, _cn(11, 11)), "u2": (8, None)}
        cands, run, cn = _ready_cands(specs)
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn)
        assert rep["promoted"] == ["u1", "u0"]
        assert "u2" in cands["candidates"]


# ===========================================================================
# D. 拨测层：select_probe_sample 的 cn 配额倾斜
# ===========================================================================

def _run_sample(tcp_lat, unique, prov, official, cand_urls=(), survival=None,
                today=TODAY, source_keys=None, cn_stats=None):
    return fc.select_probe_sample(
        tcp_lat, unique, prov, set(official), list(cand_urls),
        survival or {}, today, source_keys, cn_stats,
    )


def _official_nodes(prefix: str, n: int, url: str, lat0: float = 100.0):
    """n 个 TCP 官方节点（同区"其他"、非 UDP、有今日 survival 记录）。"""
    tcp_lat, unique, prov, survival = {}, {}, {}, {}
    fps = []
    for i in range(n):
        fp = f"{prefix}-{i}"
        unique[fp] = _proxy("trojan", f"n{prefix}-{i}", lat=lat0 + i, server=fp)
        tcp_lat[fp] = lat0 + i
        prov[fp] = {url}
        survival[fp] = _survival_rec()
        fps.append(fp)
    return fps, tcp_lat, unique, prov, survival


class TestSelectProbeCnTilt:
    def test_low_yield_source_capped_at_half_base(self):
        """低产源（0/30）单源上限 = 240*0.5 = 120：300 个节点只放行 120。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("low", 300, "http://low/sub")
        cn = {"http://low/sub": _cn(30, 0)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 120

    def test_no_evidence_source_not_capped(self):
        """无实证源不受基础上限：300 个节点全进（改造前行为）。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("free", 300, "http://free/sub")
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, cn_stats=None)
        assert sum(1 for fp in fps if fp in sample) == 300
        # cn_stats 非空但不含该源：同样不干预
        sample2 = _run_sample(tcp_lat, unique, prov, fps, survival=survival,
                              cn_stats={"http://other/sub": _cn(30, 0)})
        assert sum(1 for fp in fps if fp in sample2) == 300

    def test_high_yield_source_gets_wider_cap(self):
        """高产源（30/30）上限 = 240*1.5 = 360：400 个节点放行 360。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("hi", 400, "http://hi/sub")
        cn = {"http://hi/sub": _cn(30, 30)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 360

    def test_stale_evidence_does_not_cap(self):
        """证据陈旧（72h > 48h 决策窗）：视为无实证，不设上限。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("old", 300, "http://old/sub")
        cn = {"http://old/sub": _cn(30, 0, hours_ago=72)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 300

    def test_neutral_evidence_caps_at_base(self):
        """中性实证（10/30，tilt=1.0）：上限 = 240*1.0 = 240（防单源霸榜）。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("mid", 300, "http://mid/sub")
        cn = {"http://mid/sub": _cn(30, 10)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 240

    def test_candidate_quota_halved_for_low_yield(self):
        """低产候选源试用配额 20*0.5=10：30 个节点只试 10 个。"""
        tcp_lat, unique, prov, survival = {}, {}, {}, {}
        cand = "http://cand-low/sub"
        fps = []
        for i in range(30):
            fp = f"cl-{i}"
            unique[fp] = _proxy("ss", f"cl-{i}", lat=float(200 + i), server=fp)
            tcp_lat[fp] = float(200 + i)
            prov[fp] = {cand}
            survival[fp] = _survival_rec()
            fps.append(fp)
        cn = {cand: _cn(30, 0)}
        sample = _run_sample(tcp_lat, unique, prov, [], cand_urls=[cand],
                             survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 10

    def test_candidate_quota_scaled_up_for_high_yield(self):
        """高产候选源（7/11）试用配额 20*1.5=30：30 个节点全试。"""
        tcp_lat, unique, prov, survival = {}, {}, {}, {}
        cand = "http://cand-hi/sub"
        fps = []
        for i in range(30):
            fp = f"ch-{i}"
            unique[fp] = _proxy("ss", f"ch-{i}", lat=float(200 + i), server=fp)
            tcp_lat[fp] = float(200 + i)
            prov[fp] = {cand}
            survival[fp] = _survival_rec()
            fps.append(fp)
        cn = {cand: _cn(11, 7)}
        sample = _run_sample(tcp_lat, unique, prov, [], cand_urls=[cand],
                             survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 30

    def test_candidate_quota_neutral_and_none(self):
        """中性实证配额=20（原额）；cn_stats=None 亦为 20（改造前行为）。"""
        tcp_lat, unique, prov, survival = {}, {}, {}, {}
        cand = "http://cand-mid/sub"
        fps = []
        for i in range(30):
            fp = f"cm-{i}"
            unique[fp] = _proxy("ss", f"cm-{i}", lat=float(200 + i), server=fp)
            tcp_lat[fp] = float(200 + i)
            prov[fp] = {cand}
            survival[fp] = _survival_rec()
            fps.append(fp)
        for cn in ({cand: _cn(30, 10)}, None):
            sample = _run_sample(tcp_lat, unique, prov, [], cand_urls=[cand],
                                 survival=survival, cn_stats=cn)
            assert sum(1 for fp in fps if fp in sample) == 20


# ===========================================================================
# E. 熔断层：CN_LIFECYCLE_ENABLED=False 时 main() 不构造 cn_stats
# ===========================================================================

class TestCircuitBreaker:
    """经 main() 全流程验证熔断：三个消费点收到的 cn_stats 必须为空。"""

    @staticmethod
    def _patch_main(monkeypatch, scores_cn: dict, seen: dict):
        monkeypatch.setattr(fc, "load_evolution_inputs",
                            lambda root, sources=None: ({}, {}, scores_cn))

        def _eval(cands, run, sources, cn_stats=None):
            seen["eval"] = cn_stats
            return {"promoted": [], "rejected": {}}

        def _upd(sources, hist, run, cn_stats=None):
            seen["upd"] = cn_stats
            return {"demoted": {}}

        def _probe(*a, **k):
            seen["probe"] = k.get("cn_stats", a[7] if len(a) > 7 else None)
            return _orig_probe(*a, **k)

        _orig_probe = fc.real_probe_stage
        monkeypatch.setattr(fc.sm, "evaluate_candidates", _eval)
        monkeypatch.setattr(fc.sm, "update_official", _upd)
        monkeypatch.setattr(fc, "real_probe_stage", _probe)

    def test_breaker_on_passes_cn_stats(self, pipeline, monkeypatch):
        scores_cn = {"http://low.example/sub": _cn(30, 0)}
        seen: dict = {}
        self._patch_main(monkeypatch, scores_cn, seen)
        monkeypatch.setattr(fc, "CN_LIFECYCLE_ENABLED", True)
        fc.main()
        assert seen["eval"] == scores_cn
        assert seen["upd"] == scores_cn
        assert seen["probe"] == scores_cn

    def test_breaker_off_passes_empty(self, pipeline, monkeypatch):
        scores_cn = {"http://low.example/sub": _cn(30, 0)}
        seen: dict = {}
        self._patch_main(monkeypatch, scores_cn, seen)
        monkeypatch.setattr(fc, "CN_LIFECYCLE_ENABLED", False)
        fc.main()
        assert seen["eval"] == {}
        assert seen["upd"] == {}
        assert seen["probe"] == {}
