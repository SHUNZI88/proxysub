"""cn 源级生命周期（cn_source_lifecycle，2026-10-20）专项测试。

沙箱 verification_report.json 的 by_source 统计经 evolution 折回
source_scores.json 的 cn_*/ai_* 维度后，驱动**独立于 CI 侧评分**的源级决策层。
本文件覆盖四层 + 熔断：

  A. 数据层：evolution.cn_source_stats 提取口径（只取含 cn_tested 的条目）/
     cn_fetch_tilt 四档倾斜（None/0.5/1.0/1.5）、非对称样本门槛、陈旧守卫；
  B. 淘汰层：sources_manager.update_official 的 cn streak 判低、连续轮数
     淘汰、三重保底（manual 豁免 / 单轮上限 MAX_CN_DEMOTE_PER_RUN / 保底
     MIN_OFFICIAL）、无实证清零、淘汰清零 streak；
  C. 晋升层：evaluate_candidates 的 cn/AI 实证优先排序（Wilson 下界降序）、
     cn_stats=None/空时与改造前排序完全一致；
  D. 拨测层：select_probe_sample 的单源基础上限 PROBE_SOURCE_SAMPLE_CAP
     （仅对有新鲜实证的源生效）、候选源配额倾斜、cn×AI 复合封顶；
  E. 熔断层：config.CN_LIFECYCLE_ENABLED / AI_LIFECYCLE_ENABLED=False 时
     main() 不构造对应 stats，各消费点全部退化为改造前行为。

2026-10-21 任务#94 起追加 AI 源级生命周期（F 区，插在 D/E 之间）：
报告 by_source 的 `{ai_tested, ai_reachable, ai_api}` 口径（任务#92）折回
source_scores 的 ai_* 字段 → ai_source_stats / ai_fetch_tilt /
evaluate_candidates AI 优先晋升 / select_probe_sample 复合倾斜
（相乘封顶 PROBE_TILT_MAX=2.0）。AI 维度非对称：**无低产档**——
AI 不可达≠节点死亡，低产 down-tilt 由 cn 通道负责。

全部走 mock：无网络、不读写真实状态文件（load_json 已 patch）。
"""

from __future__ import annotations

import datetime as dt
import json

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

    def test_zero_yield_frozen(self):
        """任务#110（2026-10-28）：零产源降冻结档 0.1——Wilson 下界 < 1%。
        实证：10+ 个源各测 50-311 个节点 0 通过，旧 0.5 档仍给一半配额。"""
        assert evolution.cn_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _cn(30, 0)}) == config.CN_TILT_FROZEN
        # 1/25：下界 0.71% < 1% → 仍冻结（tomjiu 7/507 下界 0.67% 同档）
        assert evolution.cn_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _cn(25, 1)}) == config.CN_TILT_FROZEN

    def test_low_yield_halves(self):
        # 2/25：下界 2.22% ∈ [1%, 3%) → 低产档（冻结与中性之间的过渡带）
        assert evolution.cn_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _cn(25, 2)}) == config.CN_TILT_LOW

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
        assert evolution.cn_fetch_tilt("http://a/sub", stats) == config.CN_TILT_FROZEN

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
        """4 个零通过源同轮达标，但单轮上限 3：Wilson 下界最劣的 3 个先汰。

        任务#105（2026-10-24）后淘汰需「绝对通过数 = 0」——原用例的
        1/25、2/25、3/25 低产非零源不再淘汰（由 cn_source_bonus 倾斜减配额），
        故数据改为全零通过，验证单轮上限与最劣优先逻辑不变。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        lows = [("http://l0/sub", 0, 25), ("http://l1/sub", 0, 25),
                ("http://l2/sub", 0, 25), ("http://l3/sub", 0, 25)]
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
        # 同为 0/25 下界并列，任取 3 个最劣出局
        assert len(rep["demoted"]) == 3
        assert all(v == "cn_low_pass_rate:0/25" for v in rep["demoted"].values())
        # 最劣 3 个出局后 official 剩 6（= MIN_OFFICIAL），第 4 劣留下继续观察
        assert len(sources["official"]) == 6

    def test_low_but_nonzero_pass_never_demoted(self, monkeypatch):
        """判据收紧（任务#105）：低产但绝对通过数非零的源不淘汰——
        VPN-Links 8/302 被汰是旧 5% 下界的误杀（绝对通过数是 Au1rxx 两倍）。
        非零低产由 cn_source_bonus 按源级通过率自动倾斜减配额。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        entries = [_entry("http://low/sub")] + [_entry(f"http://h{i}/sub") for i in range(5)]
        sources = _src(entries)
        hist: dict = {}
        run = {"http://low/sub": _ok_run(),
               **{f"http://h{i}/sub": _ok_run() for i in range(5)}}
        cn = {"http://low/sub": _cn(302, 8),  # 8/302：下界 ~1.5% < 3%，但非零
              **{f"http://h{i}/sub": _cn(25, 20) for i in range(5)}}
        for _ in range(config.CN_DEMOTE_STREAK + 2):
            rep = sm.update_official(sources, hist, run, cn)
        assert rep["demoted"] == {}
        assert "http://low/sub" in [e["url"] for e in sources["official"]]

    def test_manual_source_cn_demoted_same_rule(self, monkeypatch):
        """手工源取消 cn 豁免（任务#105）：origin=manual 只豁免发现流程，
        不豁免质量判据——绝对零通过的源不论来历同判。"""
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        e = _entry("http://manual0/sub")
        e["origin"] = "manual"
        entries = [e] + [_entry(f"http://h{i}/sub") for i in range(8)]  # 共 9，留淘汰空间
        sources = _src(entries)
        hist: dict = {}
        run = {"http://manual0/sub": _ok_run(),
               **{f"http://h{i}/sub": _ok_run() for i in range(8)}}
        cn = {"http://manual0/sub": _cn(30, 0),  # 0/30 绝对零通过
              **{f"http://h{i}/sub": _cn(25, 20) for i in range(8)}}
        for _ in range(config.CN_DEMOTE_STREAK):
            rep = sm.update_official(sources, hist, run, cn)
        assert "http://manual0/sub" in rep["demoted"]

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
                today=TODAY, source_keys=None, cn_stats=None, ai_stats=None):
    return fc.select_probe_sample(
        tcp_lat, unique, prov, set(official), list(cand_urls),
        survival or {}, today, source_keys, cn_stats, ai_stats,
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
        """低产源（3/40，下界 2.6%）单源上限 = 240*0.5 = 120：300 个节点只放行 120。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("low", 300, "http://low/sub")
        cn = {"http://low/sub": _cn(40, 3)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 120

    def test_zero_yield_source_frozen_quota(self):
        """任务#110：零产源（0/30）冻结档上限 = 240*0.1 = 24——留回评配额
        防「复活误杀」，但把拨测预算让给高产源。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("fro", 300, "http://fro/sub")
        cn = {"http://fro/sub": _cn(30, 0)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 24

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
        """低产候选源（3/40）试用配额 20*0.5=10：30 个节点只试 10 个。"""
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
        cn = {cand: _cn(40, 3)}
        sample = _run_sample(tcp_lat, unique, prov, [], cand_urls=[cand],
                             survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 10

    def test_candidate_quota_frozen_for_zero_yield(self):
        """任务#110：零产候选源试用配额 20*0.1=2（保底 1）。"""
        tcp_lat, unique, prov, survival = {}, {}, {}, {}
        cand = "http://cand-fro/sub"
        fps = []
        for i in range(30):
            fp = f"cf-{i}"
            unique[fp] = _proxy("ss", f"cf-{i}", lat=float(200 + i), server=fp)
            tcp_lat[fp] = float(200 + i)
            prov[fp] = {cand}
            survival[fp] = _survival_rec()
            fps.append(fp)
        cn = {cand: _cn(30, 0)}
        sample = _run_sample(tcp_lat, unique, prov, [], cand_urls=[cand],
                             survival=survival, cn_stats=cn)
        assert sum(1 for fp in fps if fp in sample) == 2

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
# F. AI 源级生命周期（2026-10-21 任务#94）
# ===========================================================================
#
# 数据链：cn_probe 报告 by_source[*].{ai_tested,ai_reachable,ai_api}（任务#92）
# → evolution.update_source_scores_ai 折回 source_scores 的 ai_* 字段
# → ai_source_stats / ai_fetch_tilt / evaluate_candidates AI 优先晋升
# → select_probe_sample 复合倾斜（相乘封顶 PROBE_TILT_MAX=2.0）。
# AI 维度对 cn 的三处刻意非对称：
#   ① 只在 ai_tested>0 时写（无证据不抹零）；
#   ② 样本门槛 AI_MIN_SAMPLE=6（AI 证据只覆盖通过节点，非对称低门槛）；
#   ③ **无低产档**：AI 不可达≠节点死亡，低产 down-tilt 由 cn 通道负责。

def _ai(tested: int, api: int, reachable: int | None = None,
        hours_ago: float = 1.0) -> dict:
    """一条源级 AI 实证记录（ai_last 默认 1 小时前，视为新鲜）。"""
    last = (NOW - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"ai_tested": tested,
            "ai_reachable": api if reachable is None else reachable,
            "ai_api": api,
            "ai_api_rate": (api / tested) if tested else 0.0,
            "ai_last": last}


def _ai_report(by_source_ai: dict, stale: bool = False) -> dict:
    """最小化报告：counts.by_source 每行带 AI 证据口径（任务#92 的字段名）。

    stale=True 时 generated_at 置 2020 年——超过 VERIFICATION_MAX_AGE_S=24h，
    所有写函数必须原样跳过（陈旧守卫）。
    """
    return {
        "round_id": "20261021T0702Z",
        "generated_at": ("2020-01-01T00:00:00Z" if stale else
                         dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
        "counts": {"by_source": by_source_ai},
    }


def _ready_cands_ai(specs: dict[str, tuple[int, dict | None, dict | None]]
                    ) -> tuple[dict, dict, dict, dict]:
    """specs: url -> (unique_new, cn_entry or None, ai_entry or None)。

    返回 (cands, run, cn, ai)；unique_new 必须 >= MIN_CANDIDATE_UNIQUE(4)
    候选才 ready（同 _ready_cands 口径）。
    """
    cands = {"candidates": {u: _cand() for u in specs}, "rejected": {}}
    run = {u: _ok_run(unique_new=n) for u, (n, _, _) in specs.items()}
    cn = {u: e for u, (_, e, _) in specs.items() if e}
    ai = {u: e for u, (_, _, e) in specs.items() if e}
    return cands, run, cn, ai


class TestAiSourceStats:
    def test_extracts_only_ai_entries(self):
        scores = {
            "http://a/sub": {"score": 100, "ai_tested": 12, "ai_api": 6,
                             "ai_reachable": 9, "ai_api_rate": 0.5, "ai_last": "t"},
            "http://b/sub": {"score": 80},                      # 无 AI 维度
            "owner/repo": {"score": 60, "ai_tested": 5},        # 历史镜像键也提取
        }
        out = evolution.ai_source_stats(scores)
        assert set(out) == {"http://a/sub", "owner/repo"}
        assert out["http://a/sub"] == {"ai_tested": 12, "ai_reachable": 9,
                                       "ai_api": 6, "ai_api_rate": 0.5,
                                       "ai_last": "t"}

    def test_empty_and_none_safe(self):
        assert evolution.ai_source_stats({}) == {}
        assert evolution.ai_source_stats(None) == {}


class TestUpdateSourceScoresAi:
    def test_writes_ai_fields(self, tmp_path):
        out = str(tmp_path / "source_scores.json")
        with open(out, "w") as f:
            json.dump({"owner/repo": {"score": 100.0, "runs": 5}}, f)
        report = _ai_report({"owner/repo": {"tested": 20, "passed": 10,
                                            "ai_tested": 12, "ai_reachable": 9,
                                            "ai_api": 6}})
        res = evolution.update_source_scores_ai(report, out)
        e = res["owner/repo"]
        assert e["ai_tested"] == 12 and e["ai_reachable"] == 9 and e["ai_api"] == 6
        assert e["ai_api_rate"] == 0.5
        assert "ai_last" in e
        assert e["score"] == 100.0 and e["runs"] == 5   # 不动既有 CI 评分字段

    def test_no_ai_evidence_does_not_erase(self, tmp_path):
        """ai_tested=0：不写也不抹——上一轮实证不得被无证据轮清零（差异①）。

        场景：该源本轮无通过节点/证据预算跳过尾部 → by_source 无 AI 口径；
        若按 cn 口径无条件覆写，一个空轮就把高产源打回无知状态。
        """
        out = str(tmp_path / "source_scores.json")
        prev = {"ai_tested": 12, "ai_api": 6, "ai_api_rate": 0.5, "ai_last": "t0"}
        with open(out, "w") as f:
            json.dump({"owner/repo": dict(prev)}, f)
        report = _ai_report({"owner/repo": {"tested": 20, "passed": 0,
                                            "ai_tested": 0, "ai_reachable": 0,
                                            "ai_api": 0}})
        res = evolution.update_source_scores_ai(report, out)
        assert res["owner/repo"] == dict(prev)

    def test_stale_report_skipped(self, tmp_path):
        out = str(tmp_path / "source_scores.json")
        with open(out, "w") as f:
            json.dump({"owner/repo": {"score": 100.0}}, f)
        report = _ai_report({"owner/repo": {"ai_tested": 12, "ai_api": 6}}, stale=True)
        res = evolution.update_source_scores_ai(report, out)
        assert "ai_tested" not in res["owner/repo"]

    def test_unknown_pseudo_key_skipped(self, tmp_path):
        """carryover 无源伪键 "?" 不写（同 cn 维度口径）。"""
        out = str(tmp_path / "source_scores.json")
        with open(out, "w") as f:
            json.dump({}, f)
        report = _ai_report({"?": {"ai_tested": 8, "ai_reachable": 8, "ai_api": 8},
                             "good/repo": {"ai_tested": 8, "ai_reachable": 8,
                                           "ai_api": 4}})
        res = evolution.update_source_scores_ai(report, out)
        assert "?" not in res
        assert res["good/repo"]["ai_api"] == 4

    def test_url_by_src_mapping(self, tmp_path):
        """url_by_src 提供时写 URL 主键（与 update_source_scores_cn 同口径）。"""
        out = str(tmp_path / "source_scores.json")
        with open(out, "w") as f:
            json.dump({"http://real/sub": {"score": 50.0}}, f)
        report = _ai_report({"owner/repo": {"ai_tested": 10, "ai_reachable": 8,
                                            "ai_api": 8}})
        res = evolution.update_source_scores_ai(report, out,
                                                {"owner/repo": "http://real/sub"})
        assert res["http://real/sub"]["ai_tested"] == 10
        assert "owner/repo" not in res


class TestAiFetchTilt:
    def test_none_when_no_evidence(self):
        assert evolution.ai_fetch_tilt("http://a/sub", {}) is None
        assert evolution.ai_fetch_tilt(None, {"http://a/sub": _ai(12, 6)}) is None
        # 样本不足 AI_MIN_SAMPLE=6：不干预（非对称低门槛，但不下探到噪声区）
        assert evolution.ai_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _ai(5, 5)}) is None

    def test_high_yield_one_and_half(self):
        # 6/6：点估计 100%，Wilson 下界 61% >= 40%
        assert evolution.ai_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _ai(6, 6)}) == config.AI_TILT_HIGH
        # 8/10：点估计 80%，下界 49% >= 40%
        assert evolution.ai_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _ai(10, 8)}) == config.AI_TILT_HIGH

    def test_neutral_one_for_middling(self):
        # 3/6：点估计 50%，下界 18.8% < 40% → 中性
        assert evolution.ai_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _ai(6, 3)}) == 1.0
        # 6/12：点估计 50% 且样本更大，下界 25.4% 仍 < 40% → 中性
        # （防小样本虚高的镜像案例：同 cn 维度 10/20 压线）
        assert evolution.ai_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _ai(12, 6)}) == 1.0

    def test_no_low_tilt_for_zero_api(self):
        """AI 非对称设计：0/6 零 API 可达也只中性 1.0，**无低产档**减半。

        AI 不可达≠节点死亡（仍是可用代理）；对低 AI 源减配会饿死通用
        节点供给，低产 down-tilt 由 cn 通道（cn_low/zero_real_ok）负责。
        """
        assert evolution.ai_fetch_tilt("http://a/sub",
                                       {"http://a/sub": _ai(6, 0)}) == 1.0

    def test_stale_data_returns_none(self):
        stats = {"http://a/sub": _ai(6, 6, hours_ago=72)}
        assert evolution.ai_fetch_tilt("http://a/sub", stats,
                                       max_age_s=config.CN_DECISION_MAX_AGE_S) is None
        # max_age_s=None 时调用方自控新鲜度，本函数不做年龄筛选
        assert evolution.ai_fetch_tilt("http://a/sub", stats) == config.AI_TILT_HIGH

    def test_missing_ai_last_with_max_age_returns_none(self):
        rec = _ai(12, 6)
        rec.pop("ai_last")
        assert evolution.ai_fetch_tilt("http://a/sub", {"http://a/sub": rec},
                                       max_age_s=config.CN_DECISION_MAX_AGE_S) is None

    def test_unparsable_ai_last_returns_none(self):
        rec = _ai(12, 6)
        rec["ai_last"] = "not-a-time"
        assert evolution.ai_fetch_tilt("http://a/sub", {"http://a/sub": rec},
                                       max_age_s=config.CN_DECISION_MAX_AGE_S) is None


class TestEvaluateCandidatesAiPriority:
    """AI 实证优先于 cn 实证（任务#94）：用户核心诉求是可用于 AI 连接的节点。

    排序键：(ai_tier, -ai_lo, cn_tier, -cn_lo, -uniq)——
    有正向 AI 实证（ai_tested>=AI_MIN_SAMPLE 且 ai_api>=1）排最前，
    组内 Wilson 下界降序；无实证者退化到 cn 口径。
    """

    def test_none_ai_stats_matches_cn_only_order(self):
        """ai_stats=None：AI 前缀恒为 (1, 0.0)，排序即 cn 口径（改造前一致）。"""
        cands, run, cn = _ready_cands({"u0": (10, None), "u1": (4, _cn(11, 11))})
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn, None)
        assert rep["promoted"] == ["u1", "u0"]

    def test_ai_evidence_beats_cn_evidence(self):
        """同待晋升：有 AI 实证者压过有 cn 实证者（AI 排最前）。"""
        cands, run, cn, ai = _ready_cands_ai({
            "u0": (10, _cn(11, 11), None),      # cn 下界 ~74%，贡献 10
            "u1": (4, None, _ai(6, 6)),          # AI 下界 ~61%，贡献 4
        })
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn, ai)
        assert rep["promoted"] == ["u1", "u0"]

    def test_wilson_lower_bound_prefers_larger_ai_sample(self):
        """同点估计（80%）样本大者下界更高：12/15（~55%）压过 8/10（~49%）。"""
        cands, run, cn, ai = _ready_cands_ai({
            "u0": (5, None, _ai(10, 8)),
            "u1": (5, None, _ai(15, 12)),
        })
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn, ai)
        assert rep["promoted"][0] == "u1"

    def test_small_sample_gets_no_ai_priority(self):
        """5/5 满分但 n=5 < AI_MIN_SAMPLE=6：不享受 AI 实证优先。"""
        cands, run, cn, ai = _ready_cands_ai({
            "u0": (4, None, _ai(5, 5)),
            "u1": (5, None, None),
        })
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn, ai)
        assert rep["promoted"][0] == "u1"

    def test_zero_api_evidence_not_prioritized(self):
        """0/6 有实证但零 API 可达：不进 AI 优先组（ai_api>=1 才优先）。"""
        cands, run, cn, ai = _ready_cands_ai({
            "u0": (4, None, _ai(6, 0)),
            "u1": (5, None, None),
        })
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn, ai)
        assert rep["promoted"][0] == "u1"

    def test_ai_priority_does_not_bypass_cn_demote_side(self):
        """AI 只影响晋升排序，不动淘汰侧：update_official 不接 ai_stats。"""
        import inspect
        sig = inspect.signature(sm.update_official)
        assert "ai_stats" not in sig.parameters

    def test_promotion_still_capped(self):
        """AI 优先只改顺序不改名额：MAX_PROMOTIONS_PER_RUN=2 仍生效。"""
        cands, run, cn, ai = _ready_cands_ai({
            "u0": (10, None, None),
            "u1": (4, None, _ai(6, 6)),
            "u2": (8, None, _ai(10, 8)),
        })
        rep = sm.evaluate_candidates(cands, run, {"official": []}, cn, ai)
        assert rep["promoted"] == ["u1", "u2"]   # 两个 AI 实证者占满名额
        assert "u0" in cands["candidates"]


class TestSelectProbeAiTilt:
    """拨测层：cn×AI 复合倾斜（相乘封顶 PROBE_TILT_MAX=2.0）。

    复合语义：两侧皆无实证 → None 不干预；单侧有实证 → 另一侧按 1.0
    中性参与；双侧实证 → 相乘后封顶 2.0（防单一源霸占拨测预算）。
    """

    def test_ai_high_yield_only_widens_cap(self):
        """AI 高产实证（cn 无实证）：上限 = 240*1.5 = 360（_src_cap 守卫必须
        两侧联判——首版只查 cn_stats 会在此场景把复合结果悄悄短路）。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("aihi", 400, "http://aihi/sub")
        ai = {"http://aihi/sub": _ai(6, 6)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, ai_stats=ai)
        assert sum(1 for fp in fps if fp in sample) == 360

    def test_ai_low_yield_does_not_down_tilt(self):
        """AI 零可达（0/6）：只按中性封基础顶 240，**不**按 cn 低产档砍半。

        对照 cn 低产（0/30 → 120）：AI 无低产档，不可达≠节点死亡。
        """
        fps, tcp_lat, unique, prov, survival = _official_nodes("ailow", 300, "http://ailow/sub")
        ai = {"http://ailow/sub": _ai(6, 0)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, ai_stats=ai)
        assert sum(1 for fp in fps if fp in sample) == 240

    def test_composite_capped_at_max(self):
        """双侧高产（cn 1.5 × AI 1.5 = 2.25）：封顶 PROBE_TILT_MAX=2.0 → 480。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("both", 600, "http://both/sub")
        cn = {"http://both/sub": _cn(30, 30)}
        ai = {"http://both/sub": _ai(6, 6)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival,
                             cn_stats=cn, ai_stats=ai)
        assert sum(1 for fp in fps if fp in sample) == 480

    def test_ai_stale_does_not_cap(self):
        """AI 证据陈旧（72h > 48h 决策窗）且 cn 无实证：两侧皆无实证不干预。"""
        fps, tcp_lat, unique, prov, survival = _official_nodes("aiold", 300, "http://aiold/sub")
        ai = {"http://aiold/sub": _ai(6, 6, hours_ago=72)}
        sample = _run_sample(tcp_lat, unique, prov, fps, survival=survival, ai_stats=ai)
        assert sum(1 for fp in fps if fp in sample) == 300

    def test_candidate_quota_scaled_by_ai(self):
        """高产候选源 AI 实证：试用配额 20*1.5=30，30 个节点全试。"""
        tcp_lat, unique, prov, survival = {}, {}, {}, {}
        cand = "http://cand-aihi/sub"
        fps = []
        for i in range(30):
            fp = f"cah-{i}"
            unique[fp] = _proxy("ss", fp, lat=float(200 + i), server=fp)
            tcp_lat[fp] = float(200 + i)
            prov[fp] = {cand}
            survival[fp] = _survival_rec()
            fps.append(fp)
        ai = {cand: _ai(6, 6)}
        sample = _run_sample(tcp_lat, unique, prov, [], cand_urls=[cand],
                             survival=survival, ai_stats=ai)
        assert sum(1 for fp in fps if fp in sample) == 30

    def test_candidate_quota_not_reduced_for_low_ai(self):
        """低 AI 候选源不减配：20*1.0=20（cn 亦无实证时只封基础顶）。"""
        tcp_lat, unique, prov, survival = {}, {}, {}, {}
        cand = "http://cand-ailow/sub"
        fps = []
        for i in range(30):
            fp = f"cal-{i}"
            unique[fp] = _proxy("ss", fp, lat=float(200 + i), server=fp)
            tcp_lat[fp] = float(200 + i)
            prov[fp] = {cand}
            survival[fp] = _survival_rec()
            fps.append(fp)
        ai = {cand: _ai(6, 0)}
        sample = _run_sample(tcp_lat, unique, prov, [], cand_urls=[cand],
                             survival=survival, ai_stats=ai)
        assert sum(1 for fp in fps if fp in sample) == 20


# ===========================================================================
# E. 熔断层：CN/AI_LIFECYCLE_ENABLED=False 时 main() 不构造对应 stats
# ===========================================================================

class TestCircuitBreaker:
    """经 main() 全流程验证熔断：各消费点收到的 stats 必须为空。

    cn 与 AI 两个维度**独立熔断**（共用一份 source_scores，消费点不同）：
    cn 三个消费点（晋升/淘汰/拨测），AI 两个（晋升/拨测）。
    """

    @staticmethod
    def _patch_main(monkeypatch, scores: dict, seen: dict):
        monkeypatch.setattr(fc, "load_evolution_inputs",
                            lambda root, sources=None: ({}, {}, scores))

        def _eval(cands, run, sources, cn_stats=None, ai_stats=None):
            seen["eval"] = cn_stats
            seen["eval_ai"] = ai_stats
            return {"promoted": [], "rejected": {}}

        def _upd(sources, hist, run, cn_stats=None):
            seen["upd"] = cn_stats
            return {"demoted": {}}

        def _probe(*a, **k):
            seen["probe"] = k.get("cn_stats", a[7] if len(a) > 7 else None)
            seen["probe_ai"] = k.get("ai_stats", a[8] if len(a) > 8 else None)
            return _orig_probe(*a, **k)

        _orig_probe = fc.real_probe_stage
        monkeypatch.setattr(fc.sm, "evaluate_candidates", _eval)
        monkeypatch.setattr(fc.sm, "update_official", _upd)
        monkeypatch.setattr(fc, "real_probe_stage", _probe)

    def test_breaker_on_passes_both_stats(self, pipeline, monkeypatch):
        """双熔断开启：cn/AI 两维度各自提取后送达消费点（互不串味）。"""
        scores = {"http://cn.example/sub": _cn(30, 0),
                  "http://ai.example/sub": _ai(6, 6)}
        seen: dict = {}
        self._patch_main(monkeypatch, scores, seen)
        monkeypatch.setattr(fc, "CN_LIFECYCLE_ENABLED", True)
        monkeypatch.setattr(fc, "AI_LIFECYCLE_ENABLED", True)
        fc.main()
        assert seen["eval"] == evolution.cn_source_stats(scores)
        assert seen["eval_ai"] == evolution.ai_source_stats(scores)
        assert seen["upd"] == evolution.cn_source_stats(scores)
        assert seen["probe"] == evolution.cn_source_stats(scores)
        assert seen["probe_ai"] == evolution.ai_source_stats(scores)

    def test_breaker_off_passes_empty(self, pipeline, monkeypatch):
        """双熔断关闭：两个维度全部退化为改造前行为（空 stats）。"""
        scores = {"http://cn.example/sub": _cn(30, 0),
                  "http://ai.example/sub": _ai(6, 6)}
        seen: dict = {}
        self._patch_main(monkeypatch, scores, seen)
        monkeypatch.setattr(fc, "CN_LIFECYCLE_ENABLED", False)
        monkeypatch.setattr(fc, "AI_LIFECYCLE_ENABLED", False)
        fc.main()
        assert seen["eval"] == {}
        assert seen["eval_ai"] == {}
        assert seen["upd"] == {}
        assert seen["probe"] == {}
        assert seen["probe_ai"] == {}

    def test_ai_breaker_off_only(self, pipeline, monkeypatch):
        """CN 开 / AI 关：cn_stats 照常送达，ai_stats 必须为空（独立熔断）。"""
        scores = {"http://cn.example/sub": _cn(30, 0),
                  "http://ai.example/sub": _ai(6, 6)}
        seen: dict = {}
        self._patch_main(monkeypatch, scores, seen)
        monkeypatch.setattr(fc, "CN_LIFECYCLE_ENABLED", True)
        monkeypatch.setattr(fc, "AI_LIFECYCLE_ENABLED", False)
        fc.main()
        assert seen["eval"] == evolution.cn_source_stats(scores)
        assert seen["upd"] == evolution.cn_source_stats(scores)
        assert seen["probe"] == evolution.cn_source_stats(scores)
        assert seen["eval_ai"] == {}
        assert seen["probe_ai"] == {}
