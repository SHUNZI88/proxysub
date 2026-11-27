"""CI 候选池取样（pool_sample）回归测试（任务#140，2026-11-20）。

背景：14 个源的本机产出率实测差两个数量级（v2rayfree 9/15、mfuu 6/15、
flying dashie 0/110）。均匀抽样等于把绝大部分拨测名额浪费在几乎不出节点的
源上。取样必须同时满足三件事：

1. 预算倾斜：产出率高的源拿更多名额；
2. 保留探索：新源/零产源仍有保底，否则永远没有历史、自我实现地淘汰；
3. 探索成本随证据递减：已测 60+ 且 0 通过的源只留探针名额。
"""

import collections

from scripts import cn_probe


def _pool(src_sizes):
    pool, i = [], 0
    for src, n in src_sizes.items():
        for _ in range(n):
            pool.append({"src": src, "fp": f"{src}-{i}"})
            i += 1
    return pool


def test_small_budget_gives_floor_to_every_source():
    pool = _pool({"a": 500, "b": 500, "c": 500})
    got = cn_probe.pool_sample(pool, 60, {}, round_id="r1", min_per=20)
    cnt = collections.Counter(x["src"] for x in got)
    assert len(got) == 60
    assert all(cnt[s] >= 20 for s in "abc")


def test_high_yield_source_dominates_budget():
    pool = _pool({"junk": 800, "gold": 40})
    yields = {"junk": {"tested": 300, "passed": 0},
              "gold": {"tested": 20, "passed": 8}}
    got = cn_probe.pool_sample(pool, 100, yields, round_id="r1", min_per=20)
    cnt = collections.Counter(x["src"] for x in got)
    assert cnt["gold"] == 40              # 小池子全取
    assert cnt["junk"] < 60               # 不再占大头


def test_zero_yield_source_floor_shrinks_after_enough_evidence():
    pool = _pool({"dead": 500})
    yields = {"dead": {"tested": 200, "passed": 0}}
    got = cn_probe.pool_sample(pool, 100, yields, round_id="r1", min_per=20)
    # 2026-11-21 15:40：判据换成推特后，24 源有 20 源被旧 gstatic 口径的
    # 「零产出」钉死在 10 个名额，2278 候选只取样 1203——用户「资源枯竭」的
    # 真正机制。现放宽为 30% 上限（35 个/100），仍低于正常源 45%，惩罚保留
    # 但不再饿死；判死门槛从 tested>=60 提到 >=150。
    assert 20 <= len(got) <= 40, "零产源仍收缩（<正常 45%），但必须留足可复活名额"
    # 证据不足（tested<150）时不该被判定为零产源，应拿满正常保底
    got2 = cn_probe.pool_sample(_pool({"fresh": 500}),
                               100, {"fresh": {"tested": 80, "passed": 0}},
                               round_id="r1", min_per=20)
    assert len(got2) >= 20, "证据不足时不得提前判死"


def test_no_source_exceeds_cap():
    pool = _pool({"big": 5000, "small": 10})
    got = cn_probe.pool_sample(pool, 200, {"big": {"tested": 10, "passed": 5}},
                               round_id="r1", min_per=20)
    cnt = collections.Counter(x["src"] for x in got)
    assert cnt["big"] <= int(200 * 0.45) + 1


def test_different_round_rotates_sample():
    pool = _pool({"a": 300})
    a = {x["fp"] for x in cn_probe.pool_sample(pool, 50, {}, round_id="r1")}
    b = {x["fp"] for x in cn_probe.pool_sample(pool, 50, {}, round_id="r2")}
    assert a != b
    assert len(a & b) < 50          # 不同轮次应当换一批（池子会被逐步覆盖）


def test_empty_pool_and_zero_limit():
    assert cn_probe.pool_sample([], 100, {}) == []
    assert cn_probe.pool_sample(_pool({"a": 10}), 0, {}) == []


def test_canon_src_merges_short_and_full_name():
    """短名（本机自抓）与 owner/repo（CI 池）必须归一到同一把尺子。"""
    assert cn_probe.canon_src("ermaozi") == "ermaozi"
    assert cn_probe.canon_src("ermaozi/get_subscribe") == "ermaozi"
    assert cn_probe.canon_src("https://tt.vg/freeclash") == "tt.vg"
    assert cn_probe.canon_src("tt.vg") == "tt.vg"
    assert cn_probe.canon_src(None) == "?"


def test_pool_sample_groups_short_and_full_name_together():
    """同一源的短名/全名节点应归入同一组，共享上限，不被拆成两份。"""
    pool = [
        {"src": "ermaozi", "fp": "a1"}, {"src": "ermaozi", "fp": "a2"},
        {"src": "ermaozi/get_subscribe", "fp": "b1"},
        {"src": "gold", "fp": "g1"},
    ]
    got = cn_probe.pool_sample(pool, 100, {}, round_id="r1", min_per=20)
    assert len(got) == 4  # 全取；分组不因双键名重复计数名额
    srcs = {cn_probe.canon_src(n["src"]) for n in got}
    assert srcs == {"ermaozi", "gold"}


def test_zero_yield_source_not_permanently_starved():
    """已证零产出源必须保留可复活的探索面（2026-11-21 15:40 放宽到 30 个/100）。

    原契约「<=20」是在旧 gstatic 判据下定的；换成推特判据后 20/24 源沦为
    「零产出」，若继续按 <=20 收敛，等于把 80% 货源变相删除。
    """
    pool = _pool({"dead": 500})
    yields = {"dead": {"tested": 200, "passed": 0}}
    got = cn_probe.pool_sample(pool, 100, yields, round_id="r1", min_per=20)
    assert len(got) >= 20, "零产源仍需保留有意义的探索名额（不能再钉在 10 个）"
    assert len(got) <= 40, "惩罚仍需体现：上限低于正常源的 45%"


def test_dead_src_from_ledger_gets_probe_floor_only():
    """source_ledger 判死的源只留探针名额（2026-11-27）。

    实证：14 个源连续 6 个合格轮 0 通过（累计 tested 209~543），此前仍按
    30 个保底，14×30=420 名额/轮，实测中约占半轮拨测预算。dead_srcs 让
    它们只拿 DEAD_SRC_FLOOR 个探针，预算转给有产出的源。
    """
    pool = _pool({"dead": 500, "g1": 500, "g2": 500, "g3": 500})
    yields = {"dead": {"tested": 543, "passed": 0},
              "g1": {"tested": 100, "passed": 10},
              "g2": {"tested": 100, "passed": 10},
              "g3": {"tested": 100, "passed": 10}}
    got = cn_probe.pool_sample(pool, 300, yields, round_id="r1", min_per=20,
                               dead_srcs={"dead"})
    cnt = collections.Counter(x["src"] for x in got)
    plain = collections.Counter(x["src"] for x in cn_probe.pool_sample(
        pool, 300, yields, round_id="r1", min_per=20))
    assert cnt["dead"] == cn_probe.DEAD_SRC_FLOOR
    assert plain["dead"] == 30, "对照组：未限流时零产源仍拿 30 保底"
    good = ("g1", "g2", "g3")
    assert sum(cnt[g] for g in good) > sum(plain[g] for g in good), \
        "省下的名额必须转给有产出的源"
    assert sum(cnt[g] for g in good) == 300 - cn_probe.DEAD_SRC_FLOOR


def test_dead_src_pool_smaller_than_floor_takes_all():
    pool = _pool({"dead": 3})
    got = cn_probe.pool_sample(pool, 100, {}, round_id="r1", min_per=20,
                               dead_srcs={"dead"})
    assert len(got) == 3


def test_dead_src_exits_dead_set_after_one_pass():
    """最近 6 轮只要有 1 次通过，就不再是 dead 源，恢复 30 保底。

    上游 source_retire_candidates 的重算逻辑保证这一点；这里锁定 pool_sample
    在 dead_srcs 不含该源时不得再限流（否则复活后仍被钉死）。
    """
    pool = _pool({"revived": 500})
    yields = {"revived": {"tested": 543, "passed": 1}}
    got = cn_probe.pool_sample(pool, 100, yields, round_id="r1", min_per=20,
                               dead_srcs=set())
    assert len(got) >= 20
