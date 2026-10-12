"""两阶段探测与历史稳定性加成的回归测试。"""

import filter_clash as fc


def test_light_http_probe_udp_exempt():
    """UDP 协议（hy2/tuic）在轻量阶段直接放行，交由完整拨测验证。"""
    assert fc.light_http_probe({"type": "hysteria2", "server": "x", "port": 1}) is True
    assert fc.light_http_probe({"type": "tuic", "server": "x", "port": 1}) is True


def test_light_http_probe_invalid_fields():
    """缺少 server/port 必须返回 False，不能抛异常。"""
    assert fc.light_http_probe({"type": "vless"}) is False
    assert fc.light_http_probe({"type": "vless", "server": "1.2.3.4"}) is False
    assert fc.light_http_probe({"type": "vless", "server": "1.2.3.4", "port": "abc"}) is False


def test_light_probe_constants_sane():
    """轻量阶段应比完整拨测更高并发、更短超时。"""
    assert fc.LIGHT_PROBE_CONCURRENCY > fc.PROBE_CONCURRENCY
    assert fc.LIGHT_PROBE_TIMEOUT < fc.PROBE_TIMEOUT


def test_history_bonus_empty_is_zero():
    assert fc.history_bonus("nope", {}) == 0.0
    assert fc.history_bonus("x", {"x": {}}) == 0.0


def test_history_bonus_full_pass_strongest():
    """全部通过的加成应强于部分通过；从不通过无加成。"""
    full = fc.history_bonus("a", {"a": {"real_hist": [1, 1, 1, 1]}})
    half = fc.history_bonus("b", {"b": {"real_hist": [1, 0, 1, 0]}})
    never = fc.history_bonus("c", {"c": {"real_hist": [0, 0, 0]}})
    assert full < half < never == 0.0
    assert full == -fc.HISTORY_PASS_RATE_BONUS


def test_update_survival_records_real_hist():
    """real_hist 应逐次追加并受窗口长度限制。"""
    survival = {"fp1": {"streak": 1, "last_seen": "2000-01-01", "seen_days": 1}}
    out = fc.update_survival({"fp1"}, survival, real_ok_fps={"fp1"})
    assert out["fp1"]["real_hist"] == [1]
    # 新节点若本轮不在 real_ok 中，首次记录为 0；在则记录为 1
    out = fc.update_survival({"fp1", "fp2"}, out, real_ok_fps=set())
    assert out["fp2"]["real_hist"] == [0]
    out = fc.update_survival({"fp1", "fp3"}, out, real_ok_fps={"fp3"})
    assert out["fp3"]["real_hist"] == [1]
    # 窗口裁剪
    survival2 = {"fp": {"streak": 1, "last_seen": "2000-01-01", "seen_days": 1,
                        "real_hist": [1] * fc.SURVIVAL_PASS_WINDOW}}
    out2 = fc.update_survival({"fp"}, survival2, real_ok_fps={"fp"})
    assert len(out2["fp"]["real_hist"]) == fc.SURVIVAL_PASS_WINDOW


def test_update_survival_without_real_ok_keeps_compat():
    """不传 real_ok_fps（疑似禁用拨测）时不得写入 real_hist，保持旧行为。"""
    survival = {}
    out = fc.update_survival({"fp"}, survival)
    assert "real_hist" not in out["fp"]


def test_survival_streak_force_probe_constant():
    assert fc.SURVIVAL_STREAK_FORCE_PROBE >= 1
