"""模块结构冒烟测试：拆分后无循环依赖、关键符号经 filter_clash 可见。"""

import importlib

import filter_clash as fc


def test_submodules_importable():
    for mod in ("common", "probe", "score", "output"):
        m = importlib.import_module(mod)
        assert m.__name__ == mod


def test_common_is_leaf_no_cycle():
    # common 不反向 import probe/score/output（架构叶子）
    import common

    for dep in ("probe", "score", "output"):
        assert dep not in vars(common), f"common 不应依赖 {dep}"


def test_reexport_surface():
    for name in (
        "fingerprint", "protocol_gate_reason", "parse_subscription_text", "fetch_all_sources",
        "select_probe_sample", "mihomo_probe", "tcp_probe",
        "survival_state_fresh", "update_survival", "history_bonus",
        "is_preferred", "classify_proxy",
        "proxy_to_share_link", "proxy_to_singbox", "write_outputs", "write_stats_md",
    ):
        assert hasattr(fc, name), name


def test_main_still_callable():
    assert callable(fc.main)
