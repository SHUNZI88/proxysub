"""handoff 模块测试：CI → 沙箱交接文档构建/救援集选择/落盘。"""

import json

import config
import handoff


def _proxy(name="n", type_="hysteria2", server="a.example", **extra):
    p = {"name": name, "type": type_, "server": server, "port": 443}
    p.update(extra)
    return p


def test_round_stamp_format():
    import datetime

    rid, now = handoff.round_stamp(datetime.datetime(2026, 10, 14, 0, 17, 42,
                                                     tzinfo=datetime.timezone.utc))
    assert rid == "20261014T0017Z"
    assert now == "2026-10-14T00:17:42Z"


def test_build_pending_doc_union_and_names():
    unique = {
        "fp1": _proxy(name="HK-01", server="a.example"),
        "fp2": _proxy(name="JP-02", server="b.example"),
        "fp3": _proxy(name="US-03", server="c.example"),
    }
    doc = handoff.build_pending_doc(
        round_id="R1", generated_at="2026-10-14T00:17:42Z",
        sample_fps=["fp1", "fp2"],
        final_names={"fp2": "🇯🇵 日本 02 [Insecure]"},
        unique=unique, real_ok={"fp1": {"status": "ok"}},
    )
    # 样本 ∪ 最终输出，去重且保序
    assert [n["fp"] for n in doc["nodes"]] == ["fp1", "fp2"]
    assert doc["counts"]["nodes"] == 2
    assert doc["counts"]["final"] == 1
    assert doc["counts"]["us_ok"] == 1
    # 入选节点用最终发布名（含 Insecure 标签），未入选用原始名
    by_fp = {n["fp"]: n for n in doc["nodes"]}
    assert by_fp["fp2"]["name"] == "🇯🇵 日本 02 [Insecure]"
    assert by_fp["fp2"]["final"] is True
    assert by_fp["fp1"]["name"] == "HK-01"
    assert by_fp["fp1"]["final"] is False
    assert by_fp["fp1"]["us_ok"] is True
    assert by_fp["fp2"]["us_ok"] is False
    # proxies 为 clash 原生条目（完整参数）
    assert by_fp["fp1"]["proxy"]["server"] == "a.example"
    assert doc["generator"] == config.HANDOFF_GENERATOR
    assert doc["counts"]["by_protocol"] == {"hysteria2": 2}


def test_build_pending_doc_final_only_when_sample_empty():
    """PROXYSUB_DISABLE_PROBE=1 时样本为空：待测集=最终输出（仍可验证）。"""
    unique = {"fp1": _proxy()}
    doc = handoff.build_pending_doc(
        round_id="R", generated_at="T", sample_fps=[],
        final_names={"fp1": "HK-01"}, unique=unique, real_ok={},
    )
    assert [n["fp"] for n in doc["nodes"]] == ["fp1"]
    assert doc["counts"]["final"] == 1


def test_build_pending_doc_skips_unknown_fp():
    doc = handoff.build_pending_doc(
        round_id="R", generated_at="T", sample_fps=["ghost"],
        final_names={}, unique={}, real_ok={},
    )
    assert doc["nodes"] == []


def test_select_rescue_ordering_and_quota():
    # fp_t1: tier1 非偏好低延迟；fp_t0: tier0 偏好（hy2）应最前；
    # fp_udp: tier0 但 UDP 中性延迟 9999，同档内排后；fp_tamper: 排除。
    unique = {
        "fp_t1": _proxy(type_="vless"),
        "fp_t0": _proxy(type_="hysteria2"),
        "fp_udp": _proxy(type_="tuic"),
        "fp_tamper": _proxy(type_="vless"),
    }
    tcp_lat = {"fp_t1": 50.0, "fp_t0": 200.0, "fp_udp": 9999.0, "fp_tamper": 10.0}

    def is_preferred(p):  # hy2/reality 类偏好
        return p["type"] == "hysteria2"

    def protocol_tier(p):
        return {"hysteria2": 0, "tuic": 0, "vless": 1}[p["type"]]

    picked = handoff.select_rescue(
        tcp_lat=tcp_lat, unique=unique, tampered={"fp_tamper"},
        excluded=set(), is_preferred=is_preferred, protocol_tier=protocol_tier,
    )
    assert picked == ["fp_t0", "fp_udp", "fp_t1"]

    # excluded 中的节点不入救援集
    picked2 = handoff.select_rescue(
        tcp_lat=tcp_lat, unique=unique, tampered=set(), excluded={"fp_t0"},
        is_preferred=is_preferred, protocol_tier=protocol_tier,
    )
    assert "fp_t0" not in picked2

    # 配额上限
    many = {f"fp{i}": _proxy(server=f"s{i}") for i in range(10)}
    lat = {f"fp{i}": float(i) for i in range(10)}
    picked3 = handoff.select_rescue(
        tcp_lat=lat, unique=many, tampered=set(), excluded=set(), quota=3,
        is_preferred=is_preferred, protocol_tier=protocol_tier,
    )
    assert len(picked3) == 3


def test_build_rescue_doc():
    unique = {"fp1": _proxy(name="SG-01", server="x.example")}
    doc = handoff.build_rescue_doc(
        round_id="R", generated_at="T", rescue_fps=["fp1"], unique=unique,
    )
    assert doc["counts"]["nodes"] == 1
    node = doc["nodes"][0]
    assert node["name"] == "SG-01"
    assert node["final"] is False
    assert node["us_ok"] is False  # 未入样本 = 未经美国拨测


def test_write_handoff_docs(tmp_path):
    pending = {"round_id": "R", "generated_at": "T", "nodes": [{"fp": "a"}]}
    rescue = {"round_id": "R", "generated_at": "T", "nodes": []}
    stat = handoff.write_handoff_docs(str(tmp_path), pending, rescue)
    assert stat == {config.PENDING_PROBE_FILE: 1, config.PENDING_RESCUE_FILE: 0}
    for fname in (config.PENDING_PROBE_FILE, config.PENDING_RESCUE_FILE):
        with open(tmp_path / fname, encoding="utf-8") as f:
            json.load(f)  # 必须是合法 JSON


def test_module_reexport():
    import filter_clash as fc

    for name in ("build_pending_doc", "build_rescue_doc", "select_rescue",
                 "write_handoff_docs", "round_stamp"):
        assert hasattr(fc, name), name
