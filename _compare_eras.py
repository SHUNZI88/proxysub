"""同尺对比：11-05 家宽最初几轮（E批）vs 11-07 现在批（N批）。

背景：用户质疑"最初几轮遍布广质量高，后面越优化越差"。
要回答的核心问题不是"哪个方案好"，而是：**同一把尺子下，早期那批节点今天还剩多少可用**。
把"尺子变化造成的观感差异"与"免费节点真实衰减"分开量化。

口径（写死在代码里，可复现）
- E批（早期）：11-05 家宽时代通过过的全部节点。来源 = git 快照 e78a9d3 的
  cn_history.json（11-05 23:23 北京，含当天全部 CN 通过记录）中 cn_pass>=1
  且 cn_last 落在 2026-11-05 当天（UTC）。11-05 当天几轮 carryover 高度重叠，
  这 58 个即"最初几轮"的节点池并集。
- N批（现在）：当前 verification_report.json 的 published_nodes（36 个）。

同一把尺子（与项目 #128/#129 修正后一致）
1. 稳定性：delay_once（cf-204）单次探测 ×5，成功次数与中位延迟；
2. 真实用途：target_test 直打 chatgpt/claude/youtube，任一 2xx/3xx 记命中；
3. 串行：单实例单节点逐一切换（避免 #127 的并发抬高 RTT / #133 的选组竞态）。

提前止损：若前 3 次 delay 全失败，判 dead，跳过剩余采样与站点直测（省时，
对"已死"的判定不产生偏差——3 次 3s 超时已足以排除偶发抖动）。
"""
import json
import os
import statistics
import subprocess
import socket
import sys
import time

import yaml

ROOT = r"D:\我的助手\2026-11-05-13-36-19\proxysub"
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import cn_probe  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

WORK = cn_probe.default_workdir()
LIB_PATH = os.path.join(WORK, "node_library.json")
REP_PATH = os.path.join(WORK, "verification_report.json")
SNAPSHOT_SHA = "e78a9d3"          # 11-05 23:23 北京，含当天全部 CN 通过记录
SAMPLES = 5
MIN_PASS = 4
EARLY_DAY = "2026-11-05"


def epoch(s):
    if not s:
        return None
    try:
        import datetime
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def load_inputs():
    lib = json.load(open(LIB_PATH, encoding="utf-8"))["nodes"]
    raw = subprocess.run(["git", "show", f"{SNAPSHOT_SHA}:cn_history.json"],
                         capture_output=True, text=True, encoding="utf-8",
                         cwd=ROOT).stdout
    snap = json.loads(raw)
    early_fps = []
    for fp, v in snap.items():
        if v.get("cn_pass", 0) < 1:
            continue
        t = epoch(v.get("cn_last"))
        if t and t.strftime("%Y-%m-%d") == EARLY_DAY:
            early_fps.append(fp)
    rep = json.load(open(REP_PATH, encoding="utf-8"))
    now_fps = [n["fp"] for n in rep.get("published_nodes", [])]
    # 去重保序
    seen = set()
    early_fps = [x for x in early_fps if not (x in seen or seen.add(x))]
    seen = set()
    now_fps = [x for x in now_fps if not (x in seen or seen.add(x))]
    return lib, snap, early_fps, now_fps


def build_queue(fps, prefix, lib, snap):
    q = []
    for i, fp in enumerate(fps):
        e = lib.get(fp)
        if not e:
            continue
        p = dict(e["proxy"])
        p["name"] = f"{prefix}{i:03d}"
        meta = snap.get(fp, {})
        q.append({
            "name": p["name"], "fp": fp, "proxy": p,
            "orig": e["proxy"].get("name"),
            "type": e["proxy"].get("type"),
            "egress": meta.get("cn_egress"),
            "early_pass": meta.get("cn_pass"),
            "early_last": meta.get("cn_last"),
        })
    return q


def main():
    lib, snap, early_fps, now_fps = load_inputs()
    E = build_queue(early_fps, "e", lib, snap)
    N = build_queue(now_fps, "n", lib, snap)
    early_set = {x["fp"] for x in E}
    overlap = len(early_set & {x["fp"] for x in N})
    print(f"[load] E批={len(E)}  N批={len(N)}  交集(早期且现在仍在发)={overlap}", flush=True)

    allp = [x["proxy"] for x in E + N]
    names = [p["name"] for p in allp]
    mixed, api = free_port(), free_port()
    workdir = os.path.join(WORK, "era_dir")
    os.makedirs(workdir, exist_ok=True)
    cfg = {
        "mixed-port": mixed, "allow-lan": False, "mode": "rule",
        "log-level": "warning", "external-controller": f"127.0.0.1:{api}",
        "proxies": allp,
        "proxy-groups": [{"name": "PROBE", "type": "select",
                          "proxies": names + ["DIRECT"]}],
        "rules": ["MATCH,PROBE"],
    }
    cfg_path = os.path.join(workdir, "cfg.yaml")
    yaml.dump(cfg, open(cfg_path, "w", encoding="utf-8"), allow_unicode=True)
    exe = cn_probe.ensure_mihomo(WORK)
    if not exe:
        print("[fatal] mihomo 不可用", flush=True)
        return 3
    log = open(os.path.join(workdir, "mihomo.log"), "w", encoding="utf-8")
    proc = subprocess.Popen([exe, "-d", workdir, "-f", cfg_path],
                            stdout=log, stderr=subprocess.STDOUT)
    results = {"meta": {"early": len(E), "now": len(N), "overlap": overlap,
                        "samples": SAMPLES, "min_pass": MIN_PASS,
                        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")},
               "nodes": []}
    out_path = os.path.join(ROOT, "_compare_eras_result.json")

    def run_batch(batch, items):
        for idx, it in enumerate(items, 1):
            row = {k: it[k] for k in ("name", "fp", "orig", "type", "egress",
                                      "early_pass", "early_last")}
            row["batch"] = batch
            lats, ok_cnt, done = [], 0, 0
            for s in range(SAMPLES):
                r = cn_probe.delay_once(api, it["name"])
                done += 1
                if r.get("ok"):
                    ok_cnt += 1
                    lats.append(r["latency_ms"])
                elif s >= 2 and ok_cnt == 0:
                    break                      # 前3次全失败 -> 早停
            row["samples_done"] = done
            row["ok_count"] = ok_cnt
            row["stable"] = ok_cnt >= min(MIN_PASS, done)
            row["median_ms"] = int(statistics.median(lats)) if lats else None
            if ok_cnt >= 1:
                tt = cn_probe.target_test(api, mixed, it["name"])
                t = tt.get("targets", {}) or {}
                row["chatgpt"] = t.get("chatgpt")
                row["claude"] = t.get("claude")
                row["youtube"] = t.get("youtube")
                row["target_ok"] = tt.get("ok")
                row["ai_ok"] = tt.get("ai_ok")
            else:
                row["chatgpt"] = row["claude"] = row["youtube"] = None
                row["target_ok"] = False
                row["ai_ok"] = False
            results["nodes"].append(row)
            json.dump(results, open(out_path, "w", encoding="utf-8"),
                      ensure_ascii=False, indent=1)
            mark = "OK " if row["target_ok"] else "   "
            print(f"[{batch} {idx}/{len(items)}] {mark}{it['orig'][:38]:<38} "
                  f"ok={ok_cnt}/{done} med={row['median_ms']} "
                  f"gpt={row['chatgpt']} yt={row['youtube']}", flush=True)

    try:
        if not cn_probe.wait_controller(api, timeout=40):
            print("[fatal] mihomo 控制器未就绪", flush=True)
            return 4
        run_batch("E", E)
        run_batch("N", N)
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        log.close()

    # 汇总
    def summarize(batch):
        rows = [r for r in results["nodes"] if r["batch"] == batch]
        n = len(rows)
        if not n:
            return {}
        return {
            "n": n,
            "stable_4of5": sum(1 for r in rows if r["stable"]),
            "any_ok": sum(1 for r in rows if r["ok_count"] >= 1),
            "chatgpt_ok": sum(1 for r in rows if r["chatgpt"] and 200 <= r["chatgpt"] < 400),
            "target_ok": sum(1 for r in rows if r["target_ok"]),
            "ai_ok": sum(1 for r in rows if r["ai_ok"]),
            "median_ms_ok": int(statistics.median([r["median_ms"] for r in rows
                                                   if r["median_ms"]])) if any(r["median_ms"] for r in rows) else None,
        }

    results["summary"] = {"E": summarize("E"), "N": summarize("N")}
    json.dump(results, open(out_path, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("SUMMARY", json.dumps(results["summary"], ensure_ascii=False), flush=True)
    print("SAVED", out_path, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
