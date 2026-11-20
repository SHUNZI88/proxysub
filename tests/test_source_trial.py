"""scripts/source_trial.py 的判定与候选筛选（任务#139）。

背景：源准入曾只看节点数量与 TCP 存活率，结果 anaer/Sub（边际 1039、TCP 52.5%）
目标站 0/12 也差点被当成优质源。判据必须只有目标站可达率。
"""
import json

from scripts import source_trial as st


def test_judge_rejects_when_tunnel_only():
    """隧道通但目标站不通（0/8）必须拒绝——这是 21 个候选里最常见的形态。"""
    assert st.judge_verdict(8, 0, 0.25, 2, 5) == "reject"


def test_judge_promotes_at_threshold():
    assert st.judge_verdict(8, 2, 0.25, 2, 5) == "promote"


def test_judge_insufficient_sample_not_promoted():
    """1/1 = 100% 是噪声：实测该源 TCP 只筛出 1 个活节点，源已基本全死。"""
    assert st.judge_verdict(1, 1, 0.25, 2, 5) == "insufficient"


def test_judge_requires_absolute_count():
    """可达率高但可用数不够，补不上供给。"""
    assert st.judge_verdict(5, 1, 0.2, 2, 5) == "reject"


def test_candidate_urls_skips_official_and_tested(tmp_path, monkeypatch):
    pool = {"pool": [
        {"repo": "a/one", "url": "https://x/a/one/clash.yaml"},
        {"repo": "b/two", "url": "https://x/b/two/clash.yaml"},
        {"repo": "c/three", "url": "https://x/c/three/clash.yaml"},
    ]}
    f = tmp_path / "pool.json"
    f.write_text(json.dumps(pool), encoding="utf-8")
    monkeypatch.setattr(st, "POOL_FILE", str(f))
    ledger = {"tested": {"https://x/b/two/clash.yaml": {"verdict": "reject"}}}
    sources = {"official": [{"url": "https://x/c/three/clash.yaml"}]}
    got = st.candidate_urls(ledger, sources)
    assert [r for r, _ in got] == ["a/one"]
