#!/usr/bin/env python3
"""候选源试用：把「源准入」从节点数量改成目标站实测（任务#139）。

## 为什么需要这个脚本

2026-11-20 一次性实测了 21 个候选源，结论刺眼：

    源                        边际新增   TCP存活   目标站可达
    anaer/Sub                   1039     52.5%     0/12
    happygithub007/nodelist      267     65.0%     0/12
    10ium/filembad               142     35.9%     0/8
    10ium/speeds                  58     40.0%     0/8
    10ium/persian                 41     32.4%     0/8
    proco2024/a                   62     64.9%     0/8
    proco2024/b                   42     45.5%     0/8
    FlyingDashie/auto            173     54.3%     7/12   ← 可用
    bily1258-design/beimi        557     50.0%     4/12   ← 可用

TCP 存活率与「能不能上网」几乎没有相关性（65% 存活的那个 0 可用，54% 的那个
7/12 可用）。命中率约 2/21 ≈ 10%。

**推论：增量供应只能靠「批量筛 + 每源实测」。** 每次只看 2~3 个源，期望产出
不到 0.3 个，永远补不上；而每一轮正式拨测只有 1500 个名额，让未验证的源进来
就是拿预算赌运气。

## 用法

    python scripts/source_trial.py                # 验 6 个未验过的候选
    python scripts/source_trial.py --limit 12     # 验 12 个
    python scripts/source_trial.py --dry-run      # 只报告，不改 sources.json

达标的源（可达率 >= --min-rate 且可用 >= --min-alive）直接追加进
sources.json 的 official；全部结果记入 source_trial.json 台账，已验过的源
不会被重复烧预算。

判据只有一条：**经 mihomo 实测，chatgpt.com 有 HTTP 响应**（含 403——那说明
TLS 与 HTTP 往返完成，只是被站点策略拒绝；None 才是真的不通）。
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
import common  # noqa: E402
import config  # noqa: E402
from scripts import cn_probe  # noqa: E402

LEDGER = os.path.join(REPO_ROOT, "source_trial.json")
SOURCES = os.path.join(REPO_ROOT, "sources.json")
SCAN_CACHE = os.path.join(os.path.dirname(REPO_ROOT), "_source_scan.json")

TCP_SAMPLE = 90          # 每源先取多少个做 TCP 筛
PER_SRC = 12             # TCP 通过后实测几个（样本越多，25% 这类边缘值越不可信）
BATCH_NODES = 40         # 一批塞多少个节点进 mihomo
TCP_TIMEOUT = 4.0
PROBE_TIMEOUT = 6

# 候选池来源：candidate_pool.json（由扫描脚本的真实抓取结果固化）。
# 教训（2026-11-20）：一度在代码里手写了 40 个「业界常见源」，实测时前三个
# 全部失效——barry-far/V2ray-Configs 已被 GitHub 以 ToS 封禁、
# yebekhe/TelegramV2rayCollector 与 Epodonios/v2ray-configs 均 404。
# 仓库名必须来自**真实抓取成功的记录**，不能凭印象写。
POOL_FILE = os.path.join(REPO_ROOT, "candidate_pool.json")


def load_ledger() -> dict:
    try:
        with open(LEDGER, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        d = {}
    d.setdefault("tested", {})
    return d


def save_ledger(d: dict) -> None:
    tmp = LEDGER + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.replace(tmp, LEDGER)


def load_sources() -> dict:
    with open(SOURCES, encoding="utf-8") as f:
        return json.load(f)


def save_sources(d: dict) -> None:
    tmp = SOURCES + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SOURCES)


def official_urls(sources: dict) -> set[str]:
    return {i.get("url") if isinstance(i, dict) else i for i in (sources.get("official") or [])}


def candidate_urls(ledger: dict, sources: dict) -> list[tuple[str, str]]:
    """返回 [(repo, url)]，跳过已在 official 的、以及台账里已验过的。

    候选来自 candidate_pool.json——那是扫描脚本**真实抓取成功**的记录。
    曾经手写仓库名，实测前三个全部失效（ToS 封禁 / 404），白白浪费一轮。
    """
    tried = ledger.get("tested") or {}
    known = official_urls(sources)
    try:
        with open(POOL_FILE, encoding="utf-8") as f:
            pool = json.load(f).get("pool") or []
    except Exception:
        pool = []
    out: list[tuple[str, str]] = []
    seen_repo: set[str] = set()
    for row in pool:
        repo, url = row.get("repo"), row.get("url")
        if not repo or not url or repo in seen_repo:
            continue
        if any(u and repo in str(u) for u in known):
            continue
        if url in known or url in tried:
            continue
        seen_repo.add(repo)
        out.append((repo, url))
    return out


def fetch_text(url: str, timeout: int = 30) -> str | None:
    for chan in cn_probe.source_mirrors(url):
        try:
            req = urllib.request.Request(chan, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception:
            continue
    return None


def parse_proxies(txt: str | None) -> list[dict]:
    if not txt:
        return []
    try:
        raw = common.parse_subscription_text(txt)
    except Exception:
        return []
    out = []
    for p in raw:
        if not isinstance(p, dict) or not p.get("server"):
            continue
        if common.protocol_gate_reason(p):
            continue
        out.append(dict(p))
    return out


def _c24(h: str) -> str:
    p = str(h).split(".")
    return ".".join(p[:3]) if len(p) == 4 and all(x.isdigit() for x in p) else ""


def tcp_alive(p: dict) -> bool:
    try:
        s = socket.create_connection((str(p.get("server")).strip(), int(p.get("port") or 0)),
                                     timeout=TCP_TIMEOUT)
        s.close()
        return True
    except Exception:
        return False


def pick_samples(nodes: list[dict], n_scan: int = TCP_SAMPLE, n_keep: int = PER_SRC) -> list[dict]:
    """等距取样（源头部常是最旧的）→ TCP 筛 → 同 /24 限 2 → 取前 n_keep。"""
    if not nodes:
        return []
    step = max(1, len(nodes) // n_scan)
    pool = nodes[::step][:n_scan]
    with ThreadPoolExecutor(max_workers=32) as ex:
        flags = list(ex.map(tcp_alive, pool))
    alive = [p for p, f in zip(pool, flags) if f]
    net_c, out = Counter(), []
    for p in alive:
        k = _c24(p.get("server"))
        if k and net_c[k] >= 2:
            continue
        if k:
            net_c[k] += 1
        out.append(p)
        if len(out) >= n_keep:
            break
    return out


def run_batch(mihomo: str, workdir: str, items: list[tuple[str, dict]]) -> dict[str, dict]:
    """一批节点塞进一个 mihomo，逐节点切组测 baidu + chatgpt。"""
    if not items:
        return {}
    mixed_port, api_port = cn_probe.free_port(7897), cn_probe.free_port(9097)
    proxies = [dict(p, name=f"T{i:03d}") for i, (_, p) in enumerate(items)]
    cfg = {
        "mixed-port": mixed_port, "allow-lan": False, "mode": "rule",
        "log-level": "silent", "external-controller": f"127.0.0.1:{api_port}",
        "proxies": proxies,
        "proxy-groups": [{"name": "PROBE", "type": "select",
                          "proxies": [p["name"] for p in proxies] + ["DIRECT"]}],
        "rules": ["MATCH,PROBE"],
    }
    cfg_path = os.path.join(workdir, "_trial_cfg.yaml")
    dropped = cn_probe.prune_invalid_cfg(mihomo, workdir, cfg, cfg_path)
    if dropped:
        print(f"    配置预检剔除 {len(dropped)} 个非法节点", flush=True)
    keep = {p["name"] for p in (cfg.get("proxies") or [])}
    proxy_url = f"http://127.0.0.1:{mixed_port}"
    logf = open(os.path.join(workdir, "_trial_mihomo.log"), "w", encoding="utf-8")
    proc = subprocess.Popen([mihomo, "-d", workdir, "-f", cfg_path],
                            stdout=logf, stderr=subprocess.STDOUT)
    res: dict[str, dict] = {}
    try:
        for _ in range(40):
            time.sleep(0.5)
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{api_port}/version", timeout=1)
                break
            except Exception:
                continue
        lat_cap = int(getattr(config, "TARGET_LATENCY_MAX_MS", 1500))
        for p in proxies:
            if p["name"] not in keep:
                continue
            if not cn_probe.api_put(api_port, "/proxies/PROBE", {"name": p["name"]}):
                res[p["name"]] = {"baidu": None, "chatgpt": None, "latency": None}
                continue
            # 必须与正式轮次同一把尺子（任务#139 修正）：
            # 正式轮次是「TCP → delay < TARGET_LATENCY_MAX_MS → 目标直测」。
            # 这里若跳过延迟闸门，就会把一批在正式轮次里连初筛都过不去的节点
            # 判为可用——实测教训：FlyingDashie 单测 7/12 可用，但当轮正式拨测
            # 该源 97 个节点 0 通过，因为它全部倒在 delay 初筛。
            dl = cn_probe.delay_once(api_port, p["name"], timeout_ms=lat_cap)
            lat = dl.get("latency_ms") if dl.get("ok") else None
            if lat is None or lat > lat_cap:
                res[p["name"]] = {"baidu": None, "chatgpt": None, "latency": lat,
                                  "fail": "latency"}
                continue
            res[p["name"]] = {
                "latency": lat,
                "baidu": cn_probe._http_status_via_proxy("http://www.baidu.com", proxy_url,
                                                         PROBE_TIMEOUT),
                "chatgpt": cn_probe._http_status_via_proxy("https://chatgpt.com/", proxy_url,
                                                           PROBE_TIMEOUT),
            }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except Exception:
            proc.kill()
        logf.close()
    return res


def judge_verdict(n: int, ok: int, min_rate: float, min_alive: int,
                  min_samples: int) -> str:
    """单个候选源的判定（纯函数）。返回 promote / reject / insufficient。

    三条线缺一不可：
      - 样本充足：1/1 命中按比率是 100%，实际是「源已基本全死」；
      - 可达率：TCP 存活率无预测力（65% 存活的那个 0 可用），只有目标站算数；
      - 绝对数量：可达率再高，只有 1 个可用也补不上供给。
    """
    if n < min_samples:
        return "insufficient"
    rate = ok / max(n, 1)
    if rate >= min_rate and ok >= min_alive:
        return "promote"
    return "reject"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="候选源试用：目标站实测后决定是否转正")
    ap.add_argument("--limit", type=int, default=6, help="本轮验几个源（默认 6）")
    ap.add_argument("--min-rate", type=float, default=0.25, help="达标可达率（默认 0.25）")
    ap.add_argument("--min-alive", type=int, default=3,
                    help="至少几个可用（默认 3）——2/8 这种边缘值已被实证误收过一次")
    ap.add_argument("--min-samples", type=int, default=5,
                    help="实测样本不足此数不判（默认 5）——1/1 的 100%% 是噪声，不是信号")
    ap.add_argument("--dry-run", action="store_true", help="只报告，不改 sources.json")
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--log", default=None,
                    help="追加日志文件（计划任务不保存 stdout，本机排障全靠它）")
    args = ap.parse_args(argv)

    workdir = args.workdir or cn_probe.default_workdir()
    os.makedirs(workdir, exist_ok=True)
    log_fh = None
    if args.log:
        try:
            log_fh = open(args.log, "a", encoding="utf-8")
        except OSError:
            log_fh = None
    import builtins
    _print = builtins.print

    def print(*a, **kw):  # noqa: A001 - 本脚本自用，重定向到日志
        _print(*a, **kw)
        if log_fh:
            kw.pop("flush", None)
            _print(*a, file=log_fh, **kw)
            log_fh.flush()
    print(f"\n===== {datetime.datetime.now().isoformat(timespec='seconds')} 源试用开始 =====")
    ledger = load_ledger()
    sources = load_sources()
    cands = candidate_urls(ledger, sources)
    if not cands:
        print("没有未验过的候选源了；重跑扫描脚本刷新 candidate_pool.json")
        return 0
    todo = cands[:max(1, args.limit)]
    print(f"候选源 {len(cands)} 个，本轮验 {len(todo)} 个")

    print("\n[1/3] 抓取并 TCP 筛 ...")
    batches: list[tuple[str, list[dict]]] = []
    for repo, url in todo:
        txt = fetch_text(url)
        nodes = parse_proxies(txt)
        samples = pick_samples(nodes)
        print(f"  {repo:40} 解析 {len(nodes):4d}  样本 {len(samples):2d}")
        if samples:
            batches.append((repo, samples))
        ledger.setdefault("tested", {})[url] = {
            "repo": repo, "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            "parsed": len(nodes), "samples": len(samples), "verdict": "pending",
        }
    if not batches:
        print("本轮没有可测样本"); save_ledger(ledger); return 0

    mihomo = cn_probe.ensure_mihomo(workdir)
    if not mihomo:
        print("mihomo 不可用，中止"); return 3

    print("\n[2/3] 目标站实测 ...")
    agg: dict[str, dict] = {}
    # 分批，避免单份配置过大导致加载慢或单点失败
    flat = [(repo, p) for repo, ps in batches for p in ps]
    for i in range(0, len(flat), BATCH_NODES):
        chunk = flat[i:i + BATCH_NODES]
        print(f"  批次 {i // BATCH_NODES + 1}：{len(chunk)} 个节点", flush=True)
        res = run_batch(mihomo, workdir, chunk)
        for j, (repo, _p) in enumerate(chunk):
            r = res.get(f"T{j:03d}")
            a = agg.setdefault(repo, {"n": 0, "tunnel": 0, "ok": 0, "lat_ok": 0})
            a["n"] += 1
            if not r:
                continue
            if r.get("latency"):
                a["lat_ok"] += 1
            if r.get("baidu"):
                a["tunnel"] += 1
            if r.get("chatgpt"):
                a["ok"] += 1

    print("\n[3/3] 判定 ...")
    print(f"{'源':40} {'实测':>4} {'延迟达标':>8} {'隧道':>4} {'可用':>4} {'可达率':>7}")
    print("-" * 74)
    promoted = []
    for repo, a in sorted(agg.items(), key=lambda kv: -kv[1]["ok"]):
        rate = a["ok"] / max(a["n"], 1)
        print(f"{repo:40} {a['n']:4d} {a['lat_ok']:8d} {a['tunnel']:4d} {a['ok']:4d} "
              f"{rate * 100:6.1f}%")
        url = next(u for r, u in todo if r == repo)
        verdict = judge_verdict(a["n"], a["ok"], args.min_rate,
                                args.min_alive, args.min_samples)
        if verdict == "insufficient":
            verdict = "reject"
            print(f"    （{repo} 仅 {a['n']} 个样本 < {args.min_samples}，不足以判定）")
        ledger["tested"][url].update({"samples": a["n"], "lat_ok": a["lat_ok"],
                                      "tunnel": a["tunnel"], "ok": a["ok"],
                                      "rate": round(rate, 3), "verdict": verdict})
        if verdict == "promote":
            promoted.append((repo, url, a, rate))

    if promoted and not args.dry_run:
        have = official_urls(sources)
        for repo, url, a, rate in promoted:
            if url in have:
                continue
            sources.setdefault("official", []).append({
                "url": url, "origin": "trial",
                "added": datetime.date.today().isoformat(), "repo": repo,
                "note": (f"任务#139 目标站实测：{a['ok']}/{a['n']} 可达"
                         f"（隧道 {a['tunnel']}/{a['n']}），达标线 {args.min_rate:.0%}"),
            })
        save_sources(sources)
        print(f"\n已转正 {len(promoted)} 个源 → sources.json official"
              f"（现有 {len(sources['official'])} 个）")
    elif promoted:
        print(f"\n[dry-run] 本可转正 {len(promoted)} 个源")
    else:
        print("\n本轮无源达标（命中率本就约 10%，属正常）")

    ledger["last_run"] = datetime.datetime.now().isoformat(timespec="seconds")
    save_ledger(ledger)
    print(f"台账已更新: {LEDGER}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
