"""safe_io 原子化 JSON 读写回归测试。

验证：
- 正常读写往返；
- 损坏（截断）文件不会导致崩溃，自动备份为 .corrupt 并返回默认值；
- 并发写入不会产生损坏文件（filelock + 临时文件 + os.replace）。
"""

import json
import threading

import pytest

from safe_io import load_json, save_json


def test_roundtrip(tmp_path):
    p = tmp_path / "data.json"
    data = {"official": [{"url": "https://example.com/sub"}], "n": 1}
    save_json(str(p), data)
    assert load_json(str(p), {}) == data


def test_missing_file_returns_default(tmp_path):
    p = tmp_path / "missing.json"
    assert load_json(str(p), {"d": 1}) == {"d": 1}


def test_truncated_file_returns_default_and_backs_up(tmp_path):
    """模拟写入中断：文件内容被截断 -> 不崩溃，返回默认值，损坏文件备份。"""
    p = tmp_path / "broken.json"
    p.write_text('{"official": [{"url": "https://ex', encoding="utf-8")  # 截断
    default = {"official": []}
    assert load_json(str(p), default) == default
    assert (tmp_path / "broken.json.corrupt").exists()
    # 损坏文件被移走后，后续写入恢复正常
    save_json(str(p), {"ok": True})
    assert load_json(str(p), {}) == {"ok": True}


def test_empty_file_returns_default(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    assert load_json(str(p), {"d": 2}) == {"d": 2}


def test_concurrent_writes_no_corruption(tmp_path):
    """多线程并发写同一文件：最终文件必须始终是合法 JSON。"""
    p = tmp_path / "conc.json"
    save_json(str(p), {"v": 0})
    errors = []
    barrier = threading.Barrier(8)

    def worker(i):
        barrier.wait()
        for n in range(25):
            try:
                save_json(str(p), {"v": i * 1000 + n, "pad": list(range(50))})
            except Exception as e:  # pragma: no cover
                errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # 最终状态必须是完整可解析的 JSON
    with open(p, encoding="utf-8") as f:
        final = json.load(f)
    assert "v" in final
    # 每次写入都是原子替换，期间读取也不会看到半截 JSON
    assert isinstance(load_json(str(p), None), dict)


def test_write_failure_leaves_old_file_intact(tmp_path):
    """写入不可序列化对象失败时，旧文件必须保持完好（不留半截文件）。"""
    p = tmp_path / "keep.json"
    save_json(str(p), {"good": 1})

    class Bad:
        def __init__(self):
            self.self_ref = self  # 无法 JSON 序列化

    with pytest.raises(Exception):
        save_json(str(p), {"bad": Bad()})
    # 旧内容完好
    assert load_json(str(p), {}) == {"good": 1}
    # 不残留临时文件
    leftovers = [f for f in tmp_path.iterdir() if f.name.startswith(".tmp-")]
    assert leftovers == []
