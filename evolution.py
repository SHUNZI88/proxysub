"""Phase 2 进化引擎（CI 侧读取 verification_report.json 反哺迭代）。

四个闭环，全部带护栏（详见沙箱实测接力方案设计稿 §5.4）：
  1. 节点级：per-fp 中国通过史（cn_history.json）——寿命/稳定性加成复用；
  2. 源级：每订阅源中国通过率 -> source_scores.json 的 cn 维度（配额/排序倾斜）；
  3. 门槛级：静态硬门槛参数自学习（learned_thresholds.json + threshold_history.json
     审计：样本≥30 才动、幅度减半渐进、有界区间、逐条留痕、可回滚）；
  4. 审计：probe_history.jsonl 每轮一行（可 grep、随 CI 进 git）。

所有写操作均带陈旧守卫：报告 age > VERIFICATION_MAX_AGE_S 时跳过（不信任
过时数据），与 survival_state_fresh 守卫同源思路——状态停更即不信历史。
"""
from __future__ import annotations

import datetime
import json
import os

import config


# ------------------------------------------------------------------ 护栏常量
THRESHOLD_MIN_SAMPLES = 30          # 样本 < 30 不动门槛
THRESHOLD_STEP_FRACTION = 0.5       # 幅度减半渐进（防过冲）
# 自学习参数注册表：name -> (默认/下界/上界/方向)
#  direction: "loosen_if_low_pass"  通过率偏低时放宽（让更多节点进候选）
#             "tighten_if_high_pass" 通过率健康且分布收紧时收紧（提质）
# 注册表即「声明即可学」：新增参数只需在此登记 + 在消费点用
#   learned_params.get(name, config.XXX) 取值，learn_thresholds 通用逻辑自动覆盖
#   （所有延迟类上限共用 p90 收紧 / 低通过率放宽规则，见 learn_thresholds）。
LEARNED_PARAMS = {
    "CN_LATENCY_CAP_MS": {
        "default": 4500.0,
        "min": 2500.0,
        "max": 6000.0,
        "direction": "tighten_if_high_pass",
    },
    # 美国命名/美国出口节点的更严格延迟上限（config.MAX_ACCEPT_LATENCY_MS_US 的同形自学习版）
    "US_LATENCY_CAP_MS": {
        "default": 2800.0,
        "min": 1800.0,
        "max": 4500.0,
        "direction": "tighten_if_high_pass",
    },
    # 排序中 TCP 延迟（美西 Runner RTT，≠国内路径）的贡献上限
    # （config.TCP_LATENCY_CAP_IN_SCORE 的同形自学习版）
    "SCORE_LATENCY_CAP_MS": {
        "default": 600.0,
        "min": 400.0,
        "max": 1200.0,
        "direction": "tighten_if_high_pass",
    },
}


# ------------------------------------------------------------------ 通用工具
def _load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path: str, data) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def _report_age_s(report: dict) -> float:
    """报告生成时刻到现在的秒数（陈旧守卫用）。"""
    gen = report.get("generated_at")
    if not gen:
        return 1e9
    try:
        dt = datetime.datetime.fromisoformat(str(gen).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return 1e9
    return (datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds()


# ------------------------------------------------------------------ 2.1 节点级通过史
def update_cn_history(report: dict, path: str = config.CN_HISTORY_FILE) -> dict:
    """把报告内 per-fp 中国结果合并进 cn_history.json。

    返回更新后的历史字典。守卫：报告陈旧则原样返回（不覆盖好历史）。
    cn_ok 决定 streak/fails 增减；cn_runs/cn_pass 累计寿命统计。
    """
    if _report_age_s(report) > config.VERIFICATION_MAX_AGE_S:
        return _load_json(path, {})
    hist = _load_json(path, {})
    for n in report.get("nodes", []):
        fp = n.get("fp")
        cn = n.get("cn") or {}
        ok = bool(cn.get("ok"))
        rec = hist.get(fp, {"cn_ok": None, "cn_streak": 0, "cn_fails": 0,
                           "cn_runs": 0, "cn_pass": 0})
        rec["cn_runs"] = rec.get("cn_runs", 0) + 1
        if ok:
            rec["cn_ok"] = True
            rec["cn_streak"] = rec.get("cn_streak", 0) + 1
            rec["cn_fails"] = 0
            rec["cn_pass"] = rec.get("cn_pass", 0) + 1
            if cn.get("latency_ms") is not None:
                rec["cn_latency_ms"] = cn["latency_ms"]
            if cn.get("exit_loc"):
                rec["cn_egress"] = cn["exit_loc"]
        else:
            rec["cn_ok"] = False
            rec["cn_fails"] = rec.get("cn_fails", 0) + 1
            rec["cn_streak"] = 0
        rec["cn_last"] = report.get("generated_at")
        hist[fp] = rec
    hist = prune_cn_history(hist)
    _save_json(path, hist)
    return hist


def prune_cn_history(hist: dict, *, max_age_s: int | None = None) -> dict:
    """清理「已陈旧且从未通过」的 cn_history 记录（控制体积 + 无评分损失）。

    为什么安全（与 survival 的 prune 不同，此处不涉评分信号，纯体积）：
    `cn_stability_bonus_ms` 有**双重失效判据**——`cn_last` 超过
    `VERIFICATION_MAX_AGE_S`（12h）即整条归零；且失败惩罚 `-fails×8` 在
    max_bonus（80ms=10 次失败）处封顶，失败次数再多也不再改变评分。

    实测（2026-10-15）：cn_history.json 2654 条中 1331 条为「已陈旧(>12h) 且
    cn_pass=0」，占 202KB 随每轮 CI 提交进 git，却对评分**零贡献**（陈旧归零）。
    注意 cn_history 只用于评分加成（不用于"跳过已测节点"），故删除不造成
    重复测试——这是与「黑名单记忆」的关键区别。

    保留规则（宁留勿删）：
      1. `cn_pass > 0`（曾有中国通过史，正/负加成均有参考价值）——一律保留；
      2. `cn_last` 在 `max_age_s` 内（仍参与评分）——保留；
      3. `cn_last` 缺失/不可解析——归为陈旧，剔除（本就永不生效）。
    其余（陈旧 + 从未通过）判为僵尸，剔除。
    """
    if not hist:
        return hist
    age_s = max_age_s if max_age_s is not None else config.VERIFICATION_MAX_AGE_S
    now = datetime.datetime.now(datetime.timezone.utc)
    out: dict = {}
    for fp, rec in hist.items():
        if int(rec.get("cn_pass", 0)) > 0:
            out[fp] = rec           # 规则 1：有通过史
            continue
        last = rec.get("cn_last")
        fresh = False
        if last:
            try:
                dt = datetime.datetime.fromisoformat(str(last).replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                fresh = (now - dt).total_seconds() <= age_s
            except Exception:
                fresh = False
        if fresh:
            out[fp] = rec           # 规则 2：仍在评分窗口内
            continue
        # 其余（陈旧 + 从未通过）剔除
    if len(out) != len(hist):
        print(f"中国通过史清理: {len(hist)} -> {len(out)}"
              f"（剔除 {len(hist) - len(out)} 条陈旧且从未通过的记录）")
    return out


def cn_stability_bonus_ms(fp: str, hist: dict, *, max_bonus: float = 80.0) -> float:
    """中国稳定性的评分加成（ms 等价，与 survival_bonus 同向）。

    连续通过（cn_streak）给正加成，连续失败（cn_fails）给惩罚；
    cn_last 陈旧则归零（不信历史）。返回 [−max_bonus, +max_bonus]。
    """
    rec = hist.get(fp)
    if not rec:
        return 0.0
    last = rec.get("cn_last")
    if last:
        dt = None
        try:
            dt = datetime.datetime.fromisoformat(str(last).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            dt = None
        if dt and (datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds() > config.VERIFICATION_MAX_AGE_S:
            return 0.0
    streak = rec.get("cn_streak", 0)
    fails = rec.get("cn_fails", 0)
    if rec.get("cn_ok") and streak > 0:
        return min(max_bonus, streak * 8.0)
    if fails > 0:
        return -min(max_bonus, fails * 8.0)
    return 0.0


# ------------------------------------------------------------------ 2.2 源级通过率
def update_source_scores_cn(report: dict, path: str = config.SOURCE_SCORES_FILE,
                            url_by_src: dict | None = None) -> dict:
    """把报告 by_source 的中国通过率折回 source_scores.json 的 cn 维度。

    键口径（关键修复）：报告的 `by_source` 键是 `owner/repo`（`common.src_key`
    产出），而 `source_scores.json` 的主键是**完整订阅 URL**（由
    `sources_manager.update_source_scores` 以 url 为键写入）。若直接把 owner/repo
    当键写，会新增一批"影子源"条目，使主键 URL 永远拿不到 cn 维度——实测 79 源
    仅 27 个有 cn 维度，头部的 Au1rxx/yy1588133（score=100）恰是 cn 盲区。

    故新增 `url_by_src`（`src_key(url) -> url` 映射）：传入时 cn 写入正确的 URL
    键；未传时退回旧行为（镜像键）以兼容既有调用与测试。

    只写 cn_* 三个字段、**不重建整个条目**——避免抹掉主键上已有的
    score/runs/role（反向亦然：`update_source_scores` 已改为保留 cn_* 字段）。
    守卫：报告陈旧则跳过（不污染源评分）；"? " 伪源不写入并清理历史残留。
    """
    if _report_age_s(report) > config.VERIFICATION_MAX_AGE_S:
        return _load_json(path, {})
    scores = _load_json(path, {})
    by_source = report.get("counts", {}).get("by_source", {})
    # 无源伪键 "?" 不写入；并清理历史残留（修复前报告曾写入该键，
    # 它不代表任何真实源，留着会污染 source_scores 的 cn 维度）。
    scores.pop("?", None)
    for src, c in by_source.items():
        if not src or src == "?":
            continue
        key = (url_by_src or {}).get(src, src)
        tested = c.get("tested", 0)
        passed = c.get("passed", 0)
        entry = scores.get(key, {})
        entry["cn_tested"] = tested
        entry["cn_passed"] = passed
        entry["cn_pass_rate"] = round(passed / tested, 4) if tested else 0.0
        entry["cn_last"] = report.get("generated_at")
        scores[key] = entry
    _save_json(path, scores)
    return scores


def cn_source_bonus(src: str | None, scores: dict, *, max_bonus: float = 60.0) -> float:
    """源级中国通过率加成（ms 等价）：高通过率源排更前 / 拿更多配额。

    通过率 < 5% 给惩罚，>= 30% 给正加成，中间线性；缺数据返回 0。
    """
    if not src:
        return 0.0
    rate = (scores.get(src) or {}).get("cn_pass_rate")
    if rate is None:
        return 0.0
    if rate < 0.05:
        return -max_bonus
    return min(max_bonus, max_bonus * (rate - 0.05) / 0.25)


# ------------------------------------------------------------------ 2.3 门槛自学习
def learn_thresholds(report: dict, out_path: str = config.LEARNED_THRESHOLDS_FILE,
                     hist_path: str = config.THRESHOLD_HISTORY_FILE) -> dict:
    """静态门槛自学习（带护栏），返回当前生效参数表。

    每个参数：样本≥30 才动；目标值取数据分布点 + 方向修正；幅度 = 幅度减半
    渐进（不超过旧值与新目标差的一半）；夹在 [min, max] 区间内；每次变更写
    threshold_history.json（旧值/新值/样本/理由）。无变更则不写审计。
    """
    learned = _load_json(out_path, {})
    history = _load_json(hist_path, [])
    if _report_age_s(report) > config.VERIFICATION_MAX_AGE_S:
        return {k: learned.get(k, v["default"]) for k, v in LEARNED_PARAMS.items()}

    counts = report.get("counts", {})
    tested = counts.get("tested", 0)
    passed = counts.get("passed", 0)
    pass_rate = (passed / tested) if tested else 0.0
    # 用 passed 节点的延迟分布定位 China 真实延迟水位
    lats = [n["cn"].get("latency_ms") for n in report.get("nodes", [])
            if n.get("cn", {}).get("ok") and n["cn"].get("latency_ms") is not None]
    lats.sort()
    p90 = lats[int(len(lats) * 0.9) - 1] if len(lats) >= 10 else (max(lats) if lats else None)

    for name, spec in LEARNED_PARAMS.items():
        cur = float(learned.get(name, spec["default"]))
        target = cur
        reason = ""
        if tested >= THRESHOLD_MIN_SAMPLES:
            # 延迟类上限通用规则：通过率健康且 p90 水位低于当前 cap -> 收紧提质；
            # 通过率偏低 -> 放宽，给更多节点候选机会。CN/US/SCORE 三类上限同构复用。
            if spec["direction"] == "tighten_if_high_pass" and pass_rate >= 0.10 and p90:
                if p90 < cur and p90 >= spec["min"]:
                    target = p90
                    reason = (f"pass_rate={pass_rate:.2%} 健康、p90延迟 {p90:.0f}ms "
                              f"< 当前 {cur:.0f}ms -> 收紧提质")
            elif spec["direction"] == "loosen_if_low_pass" and pass_rate < 0.08:
                target = min(spec["max"], cur * 1.1)
                reason = f"pass_rate={pass_rate:.2%} 偏低 -> 放宽"
            # 夹区间
            target = max(spec["min"], min(spec["max"], target))
            # 幅度减半渐进：至多走一半到目标
            step = (target - cur) * THRESHOLD_STEP_FRACTION
            new_val = round(cur + step, 1)
            new_val = max(spec["min"], min(spec["max"], new_val))
            if new_val != cur and reason:
                history.append({
                    "param": name, "old": cur, "new": new_val,
                    "samples": tested, "passed": passed,
                    "at": report.get("generated_at"), "reason": reason,
                })
                learned[name] = new_val
                cur = new_val
        learned.setdefault(name, spec["default"])

    _save_json(out_path, learned)
    if history:
        _save_json(hist_path, history[-200:])  # 保留最近 200 条审计
    return {k: learned.get(k, v["default"]) for k, v in LEARNED_PARAMS.items()}


# ------------------------------------------------------------------ 2.4 审计行
def append_probe_history(report: dict, path: str = config.PROBE_HISTORY_FILE) -> dict:
    """每轮写一行 jsonl（待测/通过/分源通过率），返回本行；CI 提交进 git。

    守卫：报告陈旧则跳过（不记过期轮次）。小、单行、可 grep。
    """
    if _report_age_s(report) > config.VERIFICATION_MAX_AGE_S:
        return {}
    counts = report.get("counts", {})
    tested = counts.get("tested", 0)
    passed = counts.get("passed", 0)
    by_source = counts.get("by_source", {})
    top = sorted(((s, c["passed"], c["tested"]) for s, c in by_source.items()),
                 key=lambda x: (-x[1], -x[2]))[:5]
    line = {
        "ts": report.get("generated_at"),
        "round": report.get("tested_round") or report.get("round_id"),
        "tested": tested, "passed": passed,
        "pass_rate": round(passed / tested, 4) if tested else 0.0,
        "by_origin": counts.get("passed_by_origin", {}),
        "top_sources": [{"src": s, "passed": p, "tested": t} for s, p, t in top],
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(line, ensure_ascii=False) + "\n")
    return line


# ------------------------------------------------------------------ 编排
def run_evolution(report: dict, repo_root: str = ".",
                  url_by_src: dict | None = None) -> dict:
    """CI 侧一次性编排 4 个闭环；返回各产物摘要（供 main 打印/提交）。

    `url_by_src`（src_key(url) -> url）：供源级 cn 维度写入正确的主键 URL，
    见 update_source_scores_cn 的键口径说明。
    """
    def _p(name):
        return os.path.join(repo_root, name)
    cn_hist = update_cn_history(report, _p(config.CN_HISTORY_FILE))
    src = update_source_scores_cn(report, _p(config.SOURCE_SCORES_FILE), url_by_src)
    params = learn_thresholds(report, _p(config.LEARNED_THRESHOLDS_FILE),
                              _p(config.THRESHOLD_HISTORY_FILE))
    line = append_probe_history(report, _p(config.PROBE_HISTORY_FILE))
    return {
        "cn_history_nodes": len(cn_hist),
        "source_scores_with_cn": sum(1 for v in src.values() if "cn_pass_rate" in v),
        "learned": params,
        "probe_history_line": line,
    }
