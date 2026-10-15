"""scripts/dashboard.py 运行态面板测试：解析容错、渲染内容、注入防护。

Dashboard 是产品化-观测件的落点：只读 probe_history.jsonl 产出单文件 HTML。
测试覆盖坏行/空文件降级、单轮与多轮渲染、SVG 几何、聚合正确性与
HTML 转义（源名等动态文本绝不可原样入页）。
"""
import json
import os

import pytest

from scripts import dashboard

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ROUND_A = {
    "ts": "2026-10-13T18:18:21Z", "round": "20261013T1804Z",
    "tested": 1193, "passed": 59, "pass_rate": 0.0495,
    "by_origin": {"pending": 51, "rescue": 0, "carryover": 8},
    "top_sources": [],
}
ROUND_B = {
    "ts": "2026-10-14T17:11:43Z", "round": "20261014T1533Z",
    "tested": 1182, "passed": 46, "pass_rate": 0.0389,
    "by_origin": {"pending": 45, "rescue": 1, "carryover": 0},
    "top_sources": [
        {"src": "blog.ermao.net/sub/clash/ermao.net", "passed": 16, "tested": 136},
        {"src": "VPN-Subcription-Links/ClashX-V2Ray-TopFreeProxy", "passed": 9, "tested": 136},
        {"src": "<script>alert(1)</script>", "passed": 3, "tested": 30},
    ],
}


def _write_jsonl(path, rounds, extra_lines=()):
    lines = [json.dumps(r, ensure_ascii=False) for r in rounds]
    lines.extend(extra_lines)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def two_rounds(tmp_path):
    return _write_jsonl(tmp_path / "probe_history.jsonl", [ROUND_A, ROUND_B])


# ---------------------------------------------------------------- 解析
def test_load_rounds_parses_valid_lines(two_rounds):
    rounds = dashboard.load_rounds(two_rounds)
    assert len(rounds) == 2
    assert rounds[0]["tested"] == 1193
    # pass_rate 由 tested/passed 重算（不信任原字段），与渲染口径一致
    assert rounds[0]["pass_rate"] == pytest.approx(59 / 1193)
    # by_origin 缺键补 0
    assert rounds[0]["by_origin"] == {"pending": 51, "rescue": 0, "carryover": 8}


def test_load_rounds_skips_bad_lines(tmp_path):
    p = _write_jsonl(tmp_path / "h.jsonl", [ROUND_A], extra_lines=[
        "not json at all",                       # 非法 JSON
        "[]",                                    # 非对象
        json.dumps({"ts": "x", "tested": "abc"}),  # tested 不可转 int
        json.dumps({"ts": "x", "tested": -5, "passed": 1}),  # 负数
        "   ",                                   # 空行
    ])
    rounds = dashboard.load_rounds(p)
    assert len(rounds) == 1
    assert rounds[0]["round"] == "20261013T1804Z"


def test_load_rounds_missing_file(tmp_path):
    assert dashboard.load_rounds(tmp_path / "nope.jsonl") == []


def test_load_rounds_top_sources_tolerates_junk(tmp_path):
    junk = ["not a dict", {"src": 42, "passed": 1, "tested": 1},
            {"src": "skip/repo", "passed": "x", "tested": 1}]
    valid = [{"src": f"ok{i}/repo", "passed": i, "tested": 10 + i} for i in range(1, 6)]
    r = dict(ROUND_A, top_sources=junk + valid + [{"src": "sixth/repo", "passed": 1, "tested": 1}])
    p = _write_jsonl(tmp_path / "h.jsonl", [r])
    top = dashboard.load_rounds(p)[0]["top_sources"]
    # 垃圾条目跳过；过滤后截断到前 5 个有效源（sixth 被截）
    assert [t["src"] for t in top] == [f"ok{i}/repo" for i in range(1, 6)]


def test_load_rounds_top_sources_string_numbers(tmp_path):
    r = dict(ROUND_A, top_sources=[{"src": "ok/repo", "passed": "7", "tested": 8}])
    p = _write_jsonl(tmp_path / "h.jsonl", [r])
    top = dashboard.load_rounds(p)[0]["top_sources"]
    assert top[0]["passed"] == 7  # 字符串数字可转


# ---------------------------------------------------------------- 渲染：空数据
def test_render_empty_rounds_degrades():
    page = dashboard.render_html([])
    assert "暂无数据" in page
    assert "probe_history.jsonl" in page
    assert "scripts/dashboard.py" in page
    assert "<svg" not in page


# ---------------------------------------------------------------- 渲染：单轮
def test_render_single_round(tmp_path):
    p = _write_jsonl(tmp_path / "h.jsonl", [ROUND_B])
    page = dashboard.render_html(dashboard.load_rounds(p))
    assert "<svg" in page
    assert "polyline" in page            # 单点仍出折线元素
    assert "新测通过" in page and "救回" in page and "结转" in page  # 图例
    assert "首轮" in page                # KPI 无上轮对比
    assert "blog.ermao.net" in page      # 最新轮源明细
    assert "VPN-Subcription-Links" in page
    assert "累计贡献前 10 源" in page     # 累计表 caption


# ---------------------------------------------------------------- 渲染：多轮
def test_render_two_rounds_kpis_and_geometry(two_rounds):
    rounds = dashboard.load_rounds(two_rounds)
    page = dashboard.render_html(rounds)
    # KPI：最新轮通过率 3.9%，较上轮 4.95% 下降（绿）
    assert "3.9%" in page
    assert "↓" in page and 'class="down"' in page
    assert "1182" in page and "2,375" in page  # 最新轮测试量 / 累计 tested
    # 折线点数 == 轮数
    assert page.count("<circle") == 2
    assert 'points="' in page
    # 堆叠条两行且最新在上（只看 bar-label 区域，避开趋势图横轴标注）
    labels = [page[i:i + 200] for i in range(len(page)) if page.startswith('class="bar-label"', i)]
    assert len(labels) == 2
    assert "10-14T17" in labels[0] and "10-13T18" in labels[1]
    # 累计聚合：ermao 16/136、VPN 9/136
    assert "累计通过" in page


def test_render_escapes_injection_in_source_name(tmp_path):
    r = dict(ROUND_B)
    p = _write_jsonl(tmp_path / "h.jsonl", [r])
    page = dashboard.render_html(dashboard.load_rounds(p))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_render_escapes_ts_and_round(tmp_path):
    r = dict(ROUND_A, ts='"><img src=x>', round="r1")
    p = _write_jsonl(tmp_path / "h.jsonl", [r])
    page = dashboard.render_html(dashboard.load_rounds(p))
    assert "<img src=x>" not in page
    assert "&lt;img src=x&gt;" in page


# ---------------------------------------------------------------- 聚合口径
def test_sources_table_aggregates_across_rounds(two_rounds):
    rounds = dashboard.load_rounds(two_rounds)
    table = dashboard.sources_table(rounds)
    # B 轮三个源均入累计表；A 轮无 top_sources
    assert "blog.ermao.net" in table
    assert "&lt;script&gt;" in table  # 注入名在表格中同样被转义
    # 累计行含最近出现时间
    assert "2026-10-14T17" in table


def test_sources_table_empty_rounds_placeholder(tmp_path):
    p = _write_jsonl(tmp_path / "h.jsonl", [dict(ROUND_A, top_sources=[])])
    table = dashboard.sources_table(dashboard.load_rounds(p))
    assert "最新轮无 top_sources 记录" in table
    assert "历史累计无数据" in table


# ---------------------------------------------------------------- CLI 端到端
def test_main_writes_html_file(tmp_path, capsys):
    src = _write_jsonl(tmp_path / "in.jsonl", [ROUND_A, ROUND_B])
    out = tmp_path / "out.html"
    rc = dashboard.main([str(src), "-o", str(out)])
    assert rc == 0
    assert out.is_file()
    page = out.read_text(encoding="utf-8")
    assert page.startswith("<!DOCTYPE html>")
    assert "3.9%" in page
    assert "2 轮" in capsys.readouterr().out


def test_main_missing_input_degrades(tmp_path, capsys):
    out = tmp_path / "out.html"
    rc = dashboard.main([str(tmp_path / "nope.jsonl"), "-o", str(out)])
    assert rc == 0
    assert "暂无数据" in out.read_text(encoding="utf-8")
    assert "降级页" in capsys.readouterr().out


# ---------------------------------------------------------------- 真实仓库集成
def test_real_repo_history_renders():
    """对仓库真实 probe_history.jsonl 生成页面：契约在变，渲染必须不炸。"""
    path = os.path.join(REPO_ROOT, dashboard.config.PROBE_HISTORY_FILE)
    if not os.path.isfile(path):
        pytest.skip("仓库中暂无 probe_history.jsonl")
    rounds = dashboard.load_rounds(path)
    assert rounds, "真实历史至少一轮"
    page = dashboard.render_html(rounds)
    assert "<svg" in page and "</html>" in page
    assert page.count("<circle") == len(rounds)
