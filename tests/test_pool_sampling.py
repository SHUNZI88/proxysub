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
    assert 0 < len(got) <= 5, "已证零产出只应留探针名额（探索不归零）"


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
