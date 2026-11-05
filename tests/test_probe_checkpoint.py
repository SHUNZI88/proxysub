"""断点续跑检查点（任务#120）回归测试。

锁定的承诺：
  * 签名只由测试集节点名集合决定——同一批节点才复用，换批即作废；
  * 逐节点落盘，被休眠打断的轮次重启后能接着跑，而不是从零开始；
  * 过期 / 损坏 / 签名不符一律当作「没有检查点」，绝不拿旧结论充新证据；
  * 成功发布后由 clear() 清理，避免下一轮误用。

这些用例能在非 POSIX 环境跑（cn_probe 已把 fcntl 降级为可选依赖），
否则本模块的改动只能在线上沙箱验证——那等于没有本地验证。
"""

import json
import os

import pytest

from scripts import cn_probe


def _mk(workdir, sig="2:abc", round_id="R1", *, now=1000.0, ttl=2700, flush=0.0):
    return cn_probe.ProbeCheckpoint(
        str(workdir), sig, round_id, ttl_s=ttl, flush_s=flush, now=now)


# ------------------------------------------------------------------ 签名
def test_signature_order_independent():
    a = cn_probe.checkpoint_signature(["n1", "n2", "n3"])
    b = cn_probe.checkpoint_signature(["n3", "n1", "n2"])
    assert a == b


def test_signature_changes_with_set():
    a = cn_probe.checkpoint_signature(["n1", "n2"])
    b = cn_probe.checkpoint_signature(["n1", "n3"])
    c = cn_probe.checkpoint_signature(["n1", "n2", "n3"])
    assert a != b
    assert a != c
    # 测试集规模也进签名：同前缀不同数量不得被视为同一批
    assert a.startswith("2:") and c.startswith("3:")


def test_signature_separator_prevents_collision():
    """节点名拼接必须有分隔符，否则 ['ab','c'] 与 ['a','bc'] 会撞成同一签名。"""
    assert (cn_probe.checkpoint_signature(["ab", "c"])
            != cn_probe.checkpoint_signature(["a", "bc"]))


# ------------------------------------------------------------------ 复用
def test_roundtrip_delay_and_real(tmp_path):
    ck = _mk(tmp_path)
    ck.mark_delay("n1", {"ok": True, "latency_ms": 120})
    ck.mark_delay("n2", {"ok": False, "latency_ms": None})
    ck.mark_real("n1", {"ok": True, "latency_ms": 120,
                        "real_traffic": {"ok": True, "bps": 300000}})

    fresh = _mk(tmp_path, now=1010.0)
    delay_done, real_done, results = fresh.load()
    assert delay_done == {"n1", "n2"}
    assert real_done == {"n1"}          # 只有带 real_traffic 的才算终筛完毕
    assert results["n2"]["ok"] is False
    assert results["n1"]["real_traffic"]["bps"] == 300000


def test_resume_only_probes_remaining_nodes(tmp_path):
    """核心场景：初筛全部完成、终筛做了一半被杀 → 重启应只补另一半。"""
    ck = _mk(tmp_path)
    for name in ("n1", "n2", "n3"):
        ck.mark_delay(name, {"ok": True, "latency_ms": 100})
    ck.mark_real("n1", {"ok": True, "real_traffic": {"ok": True}})

    resumed = _mk(tmp_path, now=1100.0)
    delay_done, real_done, _ = resumed.load()
    todo_delay = [n for n in ("n1", "n2", "n3") if n not in delay_done]
    todo_real = [n for n in ("n1", "n2", "n3") if n not in real_done]
    assert todo_delay == []
    assert todo_real == ["n2", "n3"]


def test_signature_mismatch_discards(tmp_path):
    _mk(tmp_path).mark_delay("n1", {"ok": True, "latency_ms": 1})
    other = _mk(tmp_path, sig="9:ffff")       # 测试集变了
    assert other.load() == (set(), set(), {})


def test_ttl_expiry_discards(tmp_path):
    ck = _mk(tmp_path, now=1000.0, ttl=600)
    ck.mark_delay("n1", {"ok": True, "latency_ms": 1})
    # 过期 1 秒
    assert _mk(tmp_path, now=1601.0, ttl=600).load() == (set(), set(), {})
    # 恰好在有效期内（边界内仍复用）
    delay_done, _, _ = _mk(tmp_path, now=1599.0, ttl=600).load()
    assert delay_done == {"n1"}


def test_corrupt_file_is_ignored(tmp_path):
    path = tmp_path / cn_probe.CHECKPOINT_FILE
    path.write_text('{"signature": "2:abc", "results": ', encoding="utf-8")
    assert _mk(tmp_path).load() == (set(), set(), {})


def test_missing_file_is_empty(tmp_path):
    assert _mk(tmp_path).load() == (set(), set(), {})


# ------------------------------------------------------------------ 落盘
def test_flush_is_atomic_and_valid_json(tmp_path):
    ck = _mk(tmp_path)
    ck.mark_delay("n1", {"ok": True, "latency_ms": 1})
    ck.flush(force=True)
    payload = json.loads((tmp_path / cn_probe.CHECKPOINT_FILE).read_text(
        encoding="utf-8"))
    assert payload["signature"] == "2:abc"
    assert payload["round_id"] == "R1"
    assert payload["results"]["n1"]["latency_ms"] == 1
    # 临时文件不得残留（否则下次可能读到半截文件）
    assert not os.path.exists(str(tmp_path / (cn_probe.CHECKPOINT_FILE + ".tmp")))


def test_flush_throttled_without_force(tmp_path):
    ck = _mk(tmp_path, flush=15.0)
    ck.mark_delay("n1", {"ok": True, "latency_ms": 1})   # 首次落盘
    path = tmp_path / cn_probe.CHECKPOINT_FILE
    first = path.read_text(encoding="utf-8")
    ck.mark_delay("n2", {"ok": True, "latency_ms": 2})   # 节流窗口内：不写
    assert path.read_text(encoding="utf-8") == first
    ck.flush(force=True)                                  # 强制写：补齐
    assert "n2" in path.read_text(encoding="utf-8")


def test_clear_removes_checkpoint(tmp_path):
    ck = _mk(tmp_path)
    ck.mark_delay("n1", {"ok": True, "latency_ms": 1})
    assert os.path.exists(str(tmp_path / cn_probe.CHECKPOINT_FILE))
    ck.clear()
    assert not os.path.exists(str(tmp_path / cn_probe.CHECKPOINT_FILE))
    assert ck.results == {}
    # 清理后必须读不到任何结论（防「发布后又被下一轮误用」）
    assert _mk(tmp_path).load() == (set(), set(), {})


def test_write_failure_is_not_fatal(tmp_path, monkeypatch):
    """检查点写失败不得中断整轮：最坏退化为「重跑」，与修复前一致。"""
    ck = _mk(tmp_path)

    def boom(*_a, **_kw):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    ck.mark_delay("n1", {"ok": True, "latency_ms": 1})   # 不应抛异常
    assert ck.results["n1"]["ok"] is True


@pytest.mark.parametrize("name", ["带中文", "a b", "#2"])
def test_odd_names_do_not_collide(tmp_path, name):
    sig = cn_probe.checkpoint_signature([name, "other"])
    ck = _mk(tmp_path, sig=sig)
    ck.mark_delay(name, {"ok": True, "latency_ms": 7})
    assert _mk(tmp_path, sig=sig).load()[0] == {name}
