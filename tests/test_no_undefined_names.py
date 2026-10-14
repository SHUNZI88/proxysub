"""静态门禁：核心模块不得含「未定义名字」（pyflakes UndefinedName）。

背景：2026-10-13 daily 工作流崩于 score.protocol_penalty 的 NameError
（PROTOCOL_BONUS_TLS_OK 未定义）——filter_clash.py 拆分为四模块时漏导入
整个 PROTOCOL_* 常量组。符号「存在性」冒烟查不出「函数存在但内部引用
未定义」这类问题，故用 pyflakes 对每个模块做全量 AST 检查。

filter_clash.py 自 P1-3 起纳入检查范围：其原 _reexport() 在运行时把子
模块符号动态注入本模块命名空间，静态分析必然大面积误报；改为按来源模块的
显式 import 后，依赖面对 pyflakes 完全可见——漏 import 在 CI 即失败，
不再等到运行期 NameError（正是 2026-10-13 事故的根因）。
"""

import ast
from pathlib import Path

import pytest

from pyflakes import checker as pyflakes_checker
from pyflakes.messages import UndefinedName

ROOT = Path(__file__).resolve().parent.parent

CHECKED_MODULES = [
    "filter_clash.py",
    "common.py",
    "score.py",
    "probe.py",
    "output.py",
    "channels.py",
    "sources_manager.py",
    "anti_crawl.py",
    "safe_io.py",
    "honeypot.py",
]


@pytest.mark.parametrize("mod", CHECKED_MODULES)
def test_no_undefined_names(mod):
    path = ROOT / mod
    assert path.exists(), f"{mod} 不存在（模块被删除/改名时请同步本清单）"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=mod)
    warnings = pyflakes_checker.Checker(tree, mod).messages
    undefined = [m for m in warnings if isinstance(m, UndefinedName)]
    assert not undefined, (
        f"{mod} 引用了未定义的名字（典型场景：拆模块后漏 import 常量）:\n"
        + "\n".join(f"  L{m.lineno}: {m.message}" for m in undefined)
    )
