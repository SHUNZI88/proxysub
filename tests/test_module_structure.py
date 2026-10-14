"""模块结构冒烟测试：拆分后无循环依赖、关键符号经 filter_clash 可见。"""

import importlib

import filter_clash as fc


def test_submodules_importable():
    for mod in ("common", "probe", "score", "output", "handoff"):
        m = importlib.import_module(mod)
        assert m.__name__ == mod


def test_common_is_leaf_no_cycle():
    # common 不反向 import probe/score/output（架构叶子）
    import common

    for dep in ("probe", "score", "output"):
        assert dep not in vars(common), f"common 不应依赖 {dep}"


# P1-3 起 filter_clash 改用显式 import 暴露这些名字（原 _reexport 动态注入）。
# 名字清单保持不变——`import filter_clash as fc` 的既有调用方不受影响。
def test_import_surface():
    for name in (
        "fingerprint", "protocol_gate_reason", "parse_subscription_text", "fetch_all_sources",
        "select_probe_sample", "mihomo_probe", "tcp_probe",
        "survival_state_fresh", "update_survival", "history_bonus",
        "is_preferred", "classify_proxy",
        "proxy_to_share_link", "proxy_to_singbox", "write_outputs", "write_stats_md",
    ):
        assert hasattr(fc, name), name


def test_reexport_hack_removed():
    """P1-3：动态符号注入已废弃，不得回退。

    _reexport() 会在运行时把子模块公开符号静默注入本命名空间，静态分析
    不可见（pyflakes 无法校验漏 import，正是 2026-10-13 NameError 事故根因）。
    用 AST 检查「定义 + 调用」两层，避免把文档字符串里的历史说明误判为回退。
    """
    import ast
    import pathlib

    assert not hasattr(fc, "_reexport")
    tree = ast.parse(pathlib.Path(fc.__file__).read_text(encoding="utf-8"))
    defined = [n.name for n in tree.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    called = [n.func.id for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    assert "_reexport" not in defined and "_reexport" not in called


def test_main_still_callable():
    assert callable(fc.main)
