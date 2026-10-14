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

import common


# ------------------------------------------------------------------ 护栏常量
THRESHOLD_MIN_SAMPLES = 30          # 样本 < 30 不动门槛
THRESHOLD_STEP_FRACTION = 0.5       # 幅度减半渐进（防过冲）
# 自学习参数注册表：name -> (默认/下界/上界/方向)
#  direction: "loosen_if_low_pass"  通过率偏低时放宽（让更多节点进候选）
#             "tighten_if_high_pass" 通过率健康且分布收紧时收紧（提质）
LEARNED_PARAMS = {
    "CN_LATENCY_CAP_MS": {
        "default": 4500.0,
        "min": 2500.0,
        "max": 6000.0,
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
def update_cn_history(report: dict, path: str = common.CN_HISTORY_FILE) -> dict:
    """把报告内 per-fp 中国结果合并进 cn_history.json。

    返回更新后的历史字典。守卫：报告陈旧则原样返回（不覆盖好历史）。
    cn_ok 决定 streak/fails 增减；cn_runs/cn_pass 累计寿命统计。
    """
    if _report_age_s(report) > common.VERIFICATION_MAX_AGE_S:
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
    _save_json(path, hist)
    return hist


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
        if dt and (datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds() > common.VERIFICATION_MAX_AGE_S:
            return 0.0
    streak = rec.get("cn_streak", 0)
    fails = rec.get("cn_fails", 0)
    if rec.get("cn_ok") and streak > 0:
        return min(max_bonus, streak * 8.0)
    if fails > 0:
        return -min(max_bonus, fails * 8.0)
    return 0.0


# ------------------------------------------------------------------ 2.2 源级通过率
def update_source_scores_cn(report: dict, path: str = common.SOURCE_SCORES_FILE) -> dict:
    """把报告 by_source 的中国通过率折回 source_scores.json 的 cn 维度。

    返回更新后的评分字典。守卫：报告陈旧则跳过（不污染源评分）。
    """
    if _report_age_s(report) > common.VERIFICATION_MAX_AGE_S:
        return _load_json(path, {})
    scores = _load_json(path, {})
    by_source = report.get("counts", {}).get("by_source", {})
    # 无源伪键 "?" 不写入；并清理历史残留（修复前报告曾写入该键，
    # 它不代表任何真实源，留着会污染 source_scores 的 cn 维度）。
    scores.pop("?", None)
    for src, c in by_source.items():
        if not src or src == "?":
            continue
        tested = c.get("tested", 0)
        passed = c.get("passed", 0)
        entry = scores.get(src, {})
        entry["cn_tested"] = tested
        entry["cn_passed"] = passed
        entry["cn_pass_rate"] = round(passed / tested, 4) if tested else 0.0
        entry["cn_last"] = report.get("generated_at")
        scores[src] = entry
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
def learn_thresholds(report: dict, out_path: str = common.LEARNED_THRESHOLDS_FILE,
                     hist_path: str = common.THRESHOLD_HISTORY_FILE) -> dict:
    """静态门槛自学习（带护栏），返回当前生效参数表。

    每个参数：样本≥30 才动；目标值取数据分布点 + 方向修正；幅度 = 幅度减半
    渐进（不超过旧值与新目标差的一半）；夹在 [min, max] 区间内；每次变更写
    threshold_history.json（旧值/新值/样本/理由）。无变更则不写审计。
    """
    learned = _load_json(out_path, {})
    history = _load_json(hist_path, [])
    if _report_age_s(report) > common.VERIFICATION_MAX_AGE_S:
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
            if name == "CN_LATENCY_CAP_MS":
                # 通过率健康且延迟水位明显低于当前 cap -> 收紧提质
                if spec["direction"] == "tighten_if_high_pass" and pass_rate >= 0.10 and p90:
                    if p90 < cur and p90 >= spec["min"]:
                        target = p90
                        reason = (f"pass_rate={pass_rate:.2%} 健康、p90延迟 {p90:.0f}ms "
                                  f"< 当前 {cur:.0f}ms -> 收紧提质")
                # 通过率偏低 -> 放宽，给更多节点候选机会
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
def append_probe_history(report: dict, path: str = common.PROBE_HISTORY_FILE) -> dict:
    """每轮写一行 jsonl（待测/通过/分源通过率），返回本行；CI 提交进 git。

    守卫：报告陈旧则跳过（不记过期轮次）。小、单行、可 grep。
    """
    if _report_age_s(report) > common.VERIFICATION_MAX_AGE_S:
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
def run_evolution(report: dict, repo_root: str = ".") -> dict:
    """CI 侧一次性编排 4 个闭环；返回各产物摘要（供 main 打印/提交）。"""
    def _p(name):
        return os.path.join(repo_root, name)
    cn_hist = update_cn_history(report, _p(common.CN_HISTORY_FILE))
    src = update_source_scores_cn(report, _p(common.SOURCE_SCORES_FILE))
    params = learn_thresholds(report, _p(common.LEARNED_THRESHOLDS_FILE),
                              _p(common.THRESHOLD_HISTORY_FILE))
    line = append_probe_history(report, _p(common.PROBE_HISTORY_FILE))
    return {
        "cn_history_nodes": len(cn_hist),
        "source_scores_with_cn": sum(1 for v in src.values() if "cn_pass_rate" in v),
        "learned": params,
        "probe_history_line": line,
    }
