#!/usr/bin/env python3
"""proxysub 运行态 Dashboard：把 probe_history.jsonl 渲染为单文件 HTML。

用法:
    python3 scripts/dashboard.py [输入.jsonl] [-o 输出.html]

默认输入为仓库根的 probe_history.jsonl（config.PROBE_HISTORY_FILE），
默认输出 dashboard.html。

设计意图（产品化-观测面板）:
  - 订阅者与维护者一眼看清运行态：每轮拨测量、通过率趋势、通过构成
    （新测 pending / 救回 rescue / 结转 carryover）、源的累计贡献；
  - 单文件、零外部依赖、无 JavaScript——断网/NoScript 环境可读，
    也便于随滚动 Release 分发（固定资产名，链接永久有效）；
  - 隐私纪律：只含聚合统计，绝不包含节点内容与订阅地址。

输入契约（evolution.append_probe_history 每轮写一行）:
    {"ts", "round", "tested", "passed", "pass_rate", "by_origin", "top_sources"}
解析容错：坏行/缺字段跳过，空文件输出降级页——Dashboard 永不因
数据问题崩溃（它是观测件，不是关键路径）。
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import config  # noqa: E402

# by_origin 三类构成的固定展示顺序与配色（与 evolution 计数键一致）
_ORIGINS = [("pending", "新测通过", "#2563eb"),
            ("rescue", "救回", "#16a34a"),
            ("carryover", "结转", "#d97706")]

# 趋势图布局常量（viewBox 坐标系）
_VB_W, _VB_H = 720, 220
_PAD_L, _PAD_R, _PAD_T, _PAD_B = 46, 14, 14, 30


# ---------------------------------------------------------------- 数据加载
def _norm_round(obj: object) -> dict | None:
    """把一行 jsonl 规范化为渲染用 dict；结构不符返回 None（跳过）。"""
    if not isinstance(obj, dict):
        return None
    try:
        tested = int(obj.get("tested") or 0)
        passed = int(obj.get("passed") or 0)
    except (TypeError, ValueError):
        return None
    if tested < 0 or passed < 0:
        return None
    by_origin = obj.get("by_origin")
    origins = {}
    if isinstance(by_origin, dict):
        for key, _label, _color in _ORIGINS:
            try:
                origins[key] = int(by_origin.get(key) or 0)
            except (TypeError, ValueError):
                origins[key] = 0
    top = []
    raw_top = obj.get("top_sources")
    if isinstance(raw_top, list):
        for item in raw_top:
            if len(top) >= 5:  # 过滤后仍保留前 5 个有效源（与写入端 top5 语义一致）
                break
            if isinstance(item, dict) and isinstance(item.get("src"), str):
                try:
                    top.append({"src": item["src"],
                                "passed": int(item.get("passed") or 0),
                                "tested": int(item.get("tested") or 0)})
                except (TypeError, ValueError):
                    continue
    rate = passed / tested if tested else 0.0
    return {
        "ts": str(obj.get("ts") or ""),
        "round": str(obj.get("round") or ""),
        "tested": tested,
        "passed": passed,
        "pass_rate": rate,
        "by_origin": origins,
        "top_sources": top,
    }


def load_rounds(path: str | Path) -> list[dict]:
    """读取 jsonl；坏行/空值跳过。文件不存在返回空列表。"""
    p = Path(path)
    if not p.is_file():
        return []
    rounds = []
    for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            print(f"警告: {p.name}:{lineno} 不是合法 JSON，已跳过", file=sys.stderr)
            continue
        norm = _norm_round(obj)
        if norm is None:
            print(f"警告: {p.name}:{lineno} 字段结构不符，已跳过", file=sys.stderr)
            continue
        rounds.append(norm)
    return rounds


# ---------------------------------------------------------------- SVG 趋势图
def _fmt_pct(rate: float) -> str:
    return f"{rate * 100:.1f}%"


def trend_svg(rounds: list[dict]) -> str:
    """pass_rate 折线图（SVG polyline + 圆点 + hover title）。

    横轴等距取轮次（不按真实时间比例：轮次间隔不均时等距更易读），
    纵轴 0..max(5%, 峰值*1.15)，网格三条。
    """
    n = len(rounds)
    plot_w = _VB_W - _PAD_L - _PAD_R
    plot_h = _VB_H - _PAD_T - _PAD_B
    peak = max(r["pass_rate"] for r in rounds)
    y_max = max(0.05, peak * 1.15)

    def x(i: int) -> float:
        return _PAD_L + (plot_w * i / (n - 1) if n > 1 else plot_w / 2)

    def y(rate: float) -> float:
        return _PAD_T + plot_h * (1 - rate / y_max)

    parts = [f'<svg viewBox="0 0 {_VB_W} {_VB_H}" role="img" '
             f'aria-label="每轮通过率趋势" class="trend">']
    # 横向网格与 y 轴刻度（0 / 中 / 顶）
    for frac in (0.0, 0.5, 1.0):
        gy = _PAD_T + plot_h * frac
        val = y_max * (1 - frac)
        parts.append(f'<line x1="{_PAD_L}" y1="{gy:.1f}" x2="{_VB_W - _PAD_R}" '
                     f'y2="{gy:.1f}" class="grid"/>')
        parts.append(f'<text x="{_PAD_L - 6}" y="{gy + 4:.1f}" '
                     f'class="axis">{_fmt_pct(val)}</text>')
    # 数据点与折线
    pts = " ".join(f"{x(i):.1f},{y(r['pass_rate']):.1f}"
                   for i, r in enumerate(rounds))
    parts.append(f'<polyline points="{pts}" class="line"/>')
    for i, r in enumerate(rounds):
        cx, cy = x(i), y(r["pass_rate"])
        title = (f"{r['ts'] or r['round']}｜通过率 {_fmt_pct(r['pass_rate'])}"
                 f"（{r['passed']}/{r['tested']}）")
        parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="3.5" class="dot">'
                     f"<title>{html.escape(title)}</title></circle>")
    # 横轴首末时间标注（中文习惯展示 UTC）
    first, last = rounds[0], rounds[-1]
    parts.append(f'<text x="{_PAD_L}" y="{_VB_H - 8}" class="axis">'
                 f"{html.escape((first['ts'] or first['round'])[:16])}</text>")
    anchor_end = f'<text x="{_VB_W - _PAD_R}" y="{_VB_H - 8}" text-anchor="end" class="axis">'
    parts.append(anchor_end + html.escape((last["ts"] or last["round"])[:16]) + "</text>")
    parts.append("</svg>")
    return "".join(parts)


# ---------------------------------------------------------------- 通过构成（堆叠条）
def origin_bars(rounds: list[dict]) -> str:
    """每轮一条水平堆叠条：按 tested 归一，展示 pending/rescue/carryover 构成。"""
    rows = []
    for r in reversed(rounds):  # 最新在上
        total = r["tested"] or 1
        segs = []
        for key, label, color in _ORIGINS:
            v = r["by_origin"].get(key, 0)
            if v <= 0:
                continue
            w = v / total * 100
            tip = f"{label} {v} / 通过 {r['passed']}"
            segs.append(
                f'<span class="seg" style="width:{w:.2f}%;background:{color}" '
                f'title="{html.escape(tip)}"></span>')
        rows.append(
            f'<div class="bar-row">'
            f'<span class="bar-label" title="{html.escape(r["ts"] or r["round"])}">'
            f"{html.escape((r['ts'] or r['round'])[5:16])}</span>"
            f'<span class="bar">{"".join(segs)}</span>'
            f'<span class="bar-num">{r["passed"]}/{r["tested"]}</span>'
            f"</div>")
    return "".join(rows)


# ---------------------------------------------------------------- 源贡献表
def sources_table(rounds: list[dict]) -> str:
    """两段：最新轮 top_sources 明细 + 全历史累计贡献（按累计 passed 降序）。"""
    latest = rounds[-1]
    latest_rows = []
    for item in latest["top_sources"]:
        rate = item["passed"] / item["tested"] if item["tested"] else 0.0
        latest_rows.append(
            f"<tr><td class='src'>{html.escape(item['src'])}</td>"
            f"<td>{item['passed']}</td><td>{item['tested']}</td>"
            f"<td>{_fmt_pct(rate)}</td></tr>")
    if not latest_rows:
        latest_rows.append("<tr><td colspan='4' class='empty'>最新轮无 top_sources 记录</td></tr>")

    agg: dict[str, dict] = {}
    for r in rounds:
        for item in r["top_sources"]:
            acc = agg.setdefault(item["src"], {"passed": 0, "tested": 0, "last": ""})
            acc["passed"] += item["passed"]
            acc["tested"] += item["tested"]
            if r["ts"] > acc["last"]:
                acc["last"] = r["ts"]
    agg_rows = []
    for src, acc in sorted(agg.items(), key=lambda kv: -kv[1]["passed"])[:10]:
        rate = acc["passed"] / acc["tested"] if acc["tested"] else 0.0
        agg_rows.append(
            f"<tr><td class='src'>{html.escape(src)}</td>"
            f"<td>{acc['passed']}</td><td>{acc['tested']}</td>"
            f"<td>{_fmt_pct(rate)}</td>"
            f"<td class='muted'>{html.escape(acc['last'][:16])}</td></tr>")
    if not agg_rows:
        agg_rows.append("<tr><td colspan='5' class='empty'>历史累计无数据</td></tr>")
    return (f"<table><caption>最新轮（{html.escape(latest['round'] or latest['ts'])}）"
            f"贡献前 5 源</caption><thead><tr><th>源</th><th>通过</th>"
            f"<th>测试</th><th>通过率</th></tr></thead>"
            f"<tbody>{''.join(latest_rows)}</tbody></table>"
            f"<table><caption>全历史累计贡献前 10 源（跨轮聚合 top_sources）</caption>"
            f"<thead><tr><th>源</th><th>累计通过</th><th>累计测试</th>"
            f"<th>通过率</th><th>最近出现</th></tr></thead>"
            f"<tbody>{''.join(agg_rows)}</tbody></table>")


# ---------------------------------------------------------------- KPI 卡
def kpi_cards(rounds: list[dict]) -> str:
    latest, prev = rounds[-1], (rounds[-2] if len(rounds) > 1 else None)

    def delta(cur: float, old: float | None, fmt) -> str:
        if old is None:
            return '<span class="muted">首轮</span>'
        d = cur - old
        if abs(d) < 1e-9:
            return '<span class="muted">→ 持平</span>'
        arrow = "↑" if d > 0 else "↓"
        cls = "up" if d > 0 else "down"
        return f'<span class="{cls}">{arrow} {fmt(abs(d))}</span>'

    rate_d = delta(latest["pass_rate"], prev["pass_rate"] if prev else None,
                   lambda v: _fmt_pct(v))
    pass_d = delta(float(latest["passed"]), float(prev["passed"]) if prev else None,
                   lambda v: f"{v:.0f}")
    tot_t = sum(r["tested"] for r in rounds)
    tot_p = sum(r["passed"] for r in rounds)
    cards = [
        ("最新轮通过率", _fmt_pct(latest["pass_rate"]), rate_d),
        ("最新轮通过数", f"{latest['passed']}<span class='unit'> / {latest['tested']} 测</span>", pass_d),
        ("累计测试", f"{tot_t:,}", f"共 {len(rounds)} 轮"),
        ("累计通过", f"{tot_p:,}", f"总通过率 {_fmt_pct(tot_p / tot_t if tot_t else 0)}"),
    ]
    return "".join(
        f'<div class="card"><div class="card-label">{html.escape(label)}</div>'
        f'<div class="card-value">{value}</div>'
        f'<div class="card-delta">{d}</div></div>'
        for label, value, d in cards)


# ---------------------------------------------------------------- 页面组装
_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
       margin: 0; background: #f6f7f9; color: #1f2430; line-height: 1.55; }
.wrap { max-width: 860px; margin: 0 auto; padding: 24px 16px 48px; }
header h1 { font-size: 20px; margin: 0 0 4px; }
header p { margin: 0 0 20px; color: #6b7280; font-size: 13px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
         gap: 12px; margin-bottom: 20px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 14px 16px; }
.card-label { font-size: 12px; color: #6b7280; }
.card-value { font-size: 24px; font-weight: 650; margin: 2px 0; }
.card-value .unit { font-size: 13px; font-weight: 400; color: #6b7280; }
.card-delta { font-size: 12px; }
.up { color: #dc2626; } .down { color: #16a34a; } .muted { color: #9ca3af; }
section { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px;
          padding: 16px 18px; margin-bottom: 16px; }
section h2 { font-size: 15px; margin: 0 0 12px; }
.trend { width: 100%; height: auto; }
.trend .grid { stroke: #e5e7eb; stroke-width: 1; stroke-dasharray: 3 3; }
.trend .line { fill: none; stroke: #2563eb; stroke-width: 2; }
.trend .dot { fill: #2563eb; }
.trend .axis { fill: #9ca3af; font-size: 10px; }
.bar-row { display: flex; align-items: center; gap: 8px; margin: 5px 0; font-size: 12px; }
.bar-label { width: 96px; color: #6b7280; font-variant-numeric: tabular-nums;
             white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bar { flex: 1; display: flex; height: 14px; background: #f3f4f6;
       border-radius: 4px; overflow: hidden; }
.seg { height: 100%; }
.bar-num { width: 64px; text-align: right; color: #6b7280;
           font-variant-numeric: tabular-nums; }
.legend { display: flex; gap: 14px; font-size: 12px; color: #6b7280; margin-top: 10px; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px;
            margin-right: 5px; vertical-align: -1px; }
table { width: 100%; border-collapse: collapse; font-size: 12.5px; margin: 4px 0 14px; }
caption { text-align: left; font-size: 12px; color: #6b7280; padding: 4px 0 8px; }
th { text-align: left; font-weight: 600; color: #6b7280; border-bottom: 1px solid #e5e7eb;
     padding: 6px 8px 6px 0; white-space: nowrap; }
td { border-bottom: 1px solid #f3f4f6; padding: 6px 8px 6px 0;
     font-variant-numeric: tabular-nums; }
td.src { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11.5px;
         word-break: break-all; }
td.empty, td.muted { color: #9ca3af; }
footer { color: #9ca3af; font-size: 12px; margin-top: 8px; }
footer code { background: #f3f4f6; border-radius: 4px; padding: 1px 5px; }
@media (prefers-color-scheme: dark) {
  body { background: #111318; color: #e5e7eb; }
  .card, section { background: #1a1d24; border-color: #2a2e37; }
  .trend .grid { stroke: #2a2e37; }
  .bar { background: #242832; }
  th { border-color: #2a2e37; } td { border-color: #22262e; }
  footer code { background: #242832; }
}
"""


def render_html(rounds: list[dict], generated_at: str | None = None) -> str:
    """组装完整 HTML。rounds 为空时输出降级页（说明数据来源与生成方式）。"""
    gen = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if not rounds:
        return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>proxysub 运行态</title><style>{_CSS}</style></head>
<body><div class="wrap">
<header><h1>proxysub 运行态观测</h1>
<p>生成时间 {html.escape(gen)}</p></header>
<section><h2>暂无数据</h2>
<p>未在 <code>probe_history.jsonl</code> 读到有效轮次。该文件由每轮 CI 拨测后
追加一行（evolution.append_probe_history）；首次运行过滤脚本后即有数据。</p>
</section>
<footer>由 <code>scripts/dashboard.py</code> 生成 · 仅含聚合统计，不含节点与订阅地址</footer>
</div></body></html>"""

    latest = rounds[-1]
    first, last = rounds[0]["ts"] or rounds[0]["round"], latest["ts"] or latest["round"]
    legend = "".join(
        f'<span><i style="background:{c}"></i>{html.escape(label)}</span>'
        for _k, label, c in _ORIGINS)
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>proxysub 运行态 · 最新轮 {html.escape(latest["round"] or latest["ts"])}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<header><h1>proxysub 运行态观测</h1>
<p>生成时间 {html.escape(gen)} · 数据范围 {html.escape(first)} → {html.escape(last)}
（共 {len(rounds)} 轮）</p></header>

<section><h2>关键指标</h2><div class="cards">{kpi_cards(rounds)}</div></section>

<section><h2>每轮通过率趋势</h2>{trend_svg(rounds)}
<p class="muted" style="font-size:12px">横轴等距取轮次；纵轴为通过节点数 / 测试节点数。
悬停数据点可看该轮明细。</p></section>

<section><h2>通过构成（按轮次，占测试量比例）</h2>{origin_bars(rounds)}
<div class="legend">{legend}</div></section>

<section><h2>源贡献</h2>{sources_table(rounds)}</section>

<footer>由 <code>scripts/dashboard.py</code> 从 <code>probe_history.jsonl</code> 生成 ·
仅含聚合统计，不含节点内容与订阅地址 · 配色遵循「涨红跌绿」</footer>
</div></body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="把 probe_history.jsonl 渲染为单文件 HTML 运行态面板")
    parser.add_argument("input", nargs="?", default=str(REPO_ROOT / config.PROBE_HISTORY_FILE),
                        help="输入 jsonl（默认: 仓库根的 probe_history.jsonl）")
    parser.add_argument("-o", "--output", default="dashboard.html",
                        help="输出 HTML 路径（默认: dashboard.html）")
    args = parser.parse_args(argv)
    rounds = load_rounds(args.input)
    out = Path(args.output)
    out.write_text(render_html(rounds), encoding="utf-8")
    if rounds:
        latest = rounds[-1]
        print(f"已生成 {out}（{len(rounds)} 轮，最新轮 {latest['round'] or latest['ts']}，"
              f"通过率 {_fmt_pct(latest['pass_rate'])}）")
    else:
        print(f"已生成 {out}（无有效数据，降级页）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
