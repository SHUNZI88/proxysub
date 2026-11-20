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
