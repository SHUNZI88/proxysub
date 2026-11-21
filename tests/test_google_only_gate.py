"""回归测试：用户原始设计判据「能连 Google 即通过」（GOOGLE_ONLY_GATE）。

背景（2026-11-20）：用户明确重申项目设计——
  GitHub Actions 抓源+初选 → 本地实测 → 能连通 Google（generate_204）即通过。
任务#132 后我陆续叠加三站直测/吞吐/延迟/熔断，把能连 Google 的 104 个节点
砍到 6 个并熔断拒发。本测试锁定总开关契约，防止设计判据再次被改丢。
"""
import re
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_google_only_gate_defaults_on():
    """总开关默认开启 = 默认遵循用户原始设计判据。"""
    import config
    assert getattr(config, "GOOGLE_ONLY_GATE", False) is True, (
        "GOOGLE_ONLY_GATE 必须默认 True（用户的原始设计：能连 Google 即通过）")


def test_probe_url_is_google_generate_204():
    """实测尺子必须是 Google 的 generate_204。"""
    import config
    assert "gstatic.com/generate_204" in config.PROBE_URL, (
        f"本地实测尺子应是 Google generate_204，实为 {config.PROBE_URL}")


def test_all_downstream_gates_are_gated_by_switch():
    """所有后加闸门（吞吐/集中度/熔断/延迟/终筛）都必须受总开关控制。

    用源码断言——这些短路嵌在主流程里，无法用纯函数单测覆盖；
    静态检查确保每个闸门点都带 GOOGLE_ONLY_GATE 条件，漏一个就会
    重新出现「能连 Google 却被砍」的回归。
    """
    src = _read(os.path.join(ROOT, "scripts", "cn_probe.py"))
    # 每个闸门短路点都应引用总开关（至少 5 处：终筛/延迟/吞吐/集中度/熔断）
    hits = len(re.findall(r"GOOGLE_ONLY_GATE", src))
    assert hits >= 5, f"闸门短路点不足，仅找到 {hits} 处 GOOGLE_ONLY_GATE 引用"

    # 关键闸门各自必须被短路（允许跨行，用 DOTALL 分段匹配）
    assert re.search(r"_thin\s*=[\s\S]{0,120}GOOGLE_ONLY_GATE[\s\S]{0,120}select_thin_nodes", src), \
        "吞吐闸门未受控"
    assert re.search(r"if verified and not getattr\(config, \"GOOGLE_ONLY_GATE\"", src), \
        "集中度限额未受控"
    assert re.search(r"not getattr\(config, \"GOOGLE_ONLY_GATE\"[\s\S]{0,120}verified and _prev_n", src), \
        "质量熔断未受控"
    assert re.search(r"_google_only\s*=[\s\S]{0,60}GOOGLE_ONLY_GATE", src) and \
        re.search(r"if _google_only and delay_passed", src), "三站终筛未受控"
    assert re.search(r"_slow\s*=\s*\[\] if getattr\(config, \"GOOGLE_ONLY_GATE\"", src), \
        "延迟降级未受控"


def test_switch_off_restores_strict_behavior_contract():
    """关闭开关后，闸门函数本身行为不变（可回退性）。"""
    import config
    from scripts import cn_probe

    nodes = [{"name": "slow", "probe_name": "p_slow"}]
    results = {"p_slow": {"kbps": 21}}
    old = config.GOOGLE_ONLY_GATE
    try:
        config.GOOGLE_ONLY_GATE = True
        # 闸门纯函数本身不受开关影响（开关只控制主流程是否调用它）
        assert [n["name"] for n in cn_probe.select_thin_nodes(nodes, results, 64)] == ["slow"]
    finally:
        config.GOOGLE_ONLY_GATE = old


def test_twitter_probe_criterion_contract():
    """2026-11-20 用户决策：本地实测判据从 gstatic/CF 改为推特。

    手机 FlClash 实测「本地通过 32 个里 20+ 超时」，实证 gstatic 全通过的
    23 个里 12 个推特不达标——gstatic 离国内路径近、延迟天然偏低。
    锁定：GENERATE_204 读推特端点 + 稳定性采样恢复为多次多数通过。
    """
    import config
    from scripts import cn_probe

    url = getattr(config, "TWITTER_PROBE_URL", "")
    assert url and ("twitter" in url.lower() or "x.com" in url.lower()), \
        "主判据必须是推特端点"
    assert cn_probe.GENERATE_204 == url
    # 稳定性采样不能是 1/1（等于不采样，单次碰巧成功混入＝用户端超时根因）
    assert getattr(config, "SERIAL_LATENCY_SAMPLES", 1) >= 3
    assert getattr(config, "SERIAL_LATENCY_MIN_PASS", 1) >= 2
    assert getattr(config, "SERIAL_LATENCY_RECHECK", False) is True


def test_client_grade_verify_contract():
    """客户端同款终验契约（2026-11-21，用户「手机大量超时」的根治层）。

    背景：初筛 16 并发 + delay_test 5s→8s 重试 →「8 秒内碰巧返回一次」算通；
    手机 url-test 低并发短超时，两者不同构。实证发布 12 个里稳定仅 3 个。
    锁定：终验必须开着、低并发、有延迟上限，端点仍是推特主判据。

    2026-11-21 15:40 修正契约：终验**不做严格淘汰**，只淘汰 3 轮全死的，
    并按稳定度排序。原契约（全轮通过才留）已被数据推翻：
      14:05 轮 19 候选 → 全通过仅 8（砍 58%）；14:19 发布；15:44 实测
      只剩 3 稳定 / 2 已死——严格筛选并不能预测一小时后的存活。
    免费节点寿命是小时级，广撒网 + 排序 ＞ 精选少数。
    """
    import config
    from scripts import cn_probe

    assert getattr(config, "CLIENT_GRADE_ENABLED", False) is True
    assert config.CLIENT_GRADE_ROUNDS >= 3
    assert config.CLIENT_GRADE_CONCURRENCY <= 6, "并发必须贴近单机手机，不能自家抬高 RTT"
    assert config.CLIENT_GRADE_MIN_PASS_ROUNDS <= 2, \
        "终验不得做严格淘汰（>=3 会把可用节点砍掉一半，重蹈任务#132 覆辙）"
    assert getattr(config, "CLIENT_GRADE_SORT_BY_STABILITY", False) is True, \
        "既然放宽淘汰，就必须按稳定度排序，把 3/3 的排前面"
    assert 1000 <= config.CLIENT_GRADE_LATENCY_CAP_MS <= 4500, \
        "延迟上限只做极端慢粗筛；实证延迟与稳定性不相关，不可压得过紧"
    assert bool(getattr(config, "GOOGLE_ONLY_GATE", False)) is True
    assert cn_probe.GENERATE_204 == config.TWITTER_PROBE_URL


def test_main_calls_client_grade_verify_before_publish():
    """主流程必须在发布前调用终验（防止以后被删掉或挪到发布之后）。"""
    import inspect
    from scripts import cn_probe
    src = inspect.getsource(cn_probe.main)
    assert "client_grade_verify(" in src
    # 调用点必须在 write_verified_outputs 之前
    assert src.index("client_grade_verify(") < src.index("write_verified_outputs(")


def test_quick_health_uses_main_probe_url():
    """健康抽查的端点必须与发布判据一致（2026-11-21）。

    原先 quick_health 硬编码 gstatic，与推特主判据不一致：
    「gstatic 通、推特不通」的节点被判健康 → 腐烂名单一路用到 stale-h(10h)。
    同时锁定健康线（6 个里 ≥4 可用），旧线 ≤sample//3 太松。
    """
    import inspect
    from scripts import local_round

    src = inspect.getsource(local_round.quick_health)
    assert "www.gstatic.com" not in src, "健康抽查不得硬编码 gstatic，须用主判据端点"
    assert "cn_probe.GENERATE_204" in src
    assert "need_ok" in src
