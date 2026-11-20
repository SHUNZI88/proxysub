#!/usr/bin/env python3
"""候选池构建（CI 侧执行，任务#140）。

## 为什么必须放在 CI 上

「抓源」与「实测」是两个**观测环境不同**的动作，不能混在一台机器上做：

  * CI runner 在海外，GitHub raw / 各订阅源都是一等公民，抓到的是**完整、
    最新的原始订阅**；抓取失败只可能意味着源真的坏了。
  * 本机在家宽，raw.githubusercontent 十次里失败两三次（实测同一 URL 3 次
    只有 1 次 200）；为绕开它还加了 jsDelivr 兜底。此时「这个源没内容」和
    「这个源我这边连不上」不可区分——源评估被网络噪声污染，越评越窄。

所以职责切开：

    本脚本（CI）：抓全部源 → 解析 → 协议闸门 → 物理去重 → 输出 pool.json
    本地实测      ：只下载 pool.json，做「从我这里能不能用」的判断

本地只在拿不到 pool（CI 挂了 / 首次运行）时降级自抓，并显式打警告。

## 输出

  pool.json       {"generated_at", "vantage":"ci", "sources":{url:{count,err}},
                   "nodes":[{fp,name,proxy,src}]}
  pool_stats.json 逐源统计（供 dashboard / 人工核对）
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)

import common  # noqa: E402

UA = {"User-Agent": "curl/8"}


def mirrors(url: str) -> list[str]:
    """GitHub raw 的备用通道。CI 上原站通常就够，兜底只为抗单点抖动。"""
    m = url.split("raw.githubusercontent.com/")
    if len(m) != 2:
        return [url]
    parts = m[1].split("/")
    if len(parts) < 4:
        return [url]
    owner, repo, branch = parts[0], parts[1], parts[2]
    path = "/".join(parts[3:])
    return [
        url,
        f"https://gcore.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}",
        f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}",
    ]


def fetch_text(url: str, timeout: int = 25) -> tuple[str | None, str | None]:
    last = None
    for ch in mirrors(url):
        try:
            req = urllib.request.Request(ch, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                txt = r.read().decode("utf-8", "ignore")
            if txt.strip():
                return txt, None
            last = "empty body"
        except Exception as e:      # noqa: BLE001
            last = f"{type(e).__name__}: {e}"
    return None, last


def src_tag(url: str, index: int) -> str:
    """源标识：github 用 owner/repo，其它用域名，保证跨轮稳定可比。"""
    if "githubusercontent.com/" in url:
        rest = url.split("githubusercontent.com/")[1].split("/")
        if len(rest) >= 2:
            return f"{rest[0]}/{rest[1]}"
    host = url.split("://")[-1].split("/")[0]
    return host or f"src{index}"


def fp_of(proxy: dict) -> str:
    blob = json.dumps(proxy, sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default=os.path.join(ROOT, "sources.json"))
    ap.add_argument("--out", default=os.path.join(ROOT, "pool.json"))
    ap.add_argument("--stats", default=os.path.join(ROOT, "pool_stats.json"))
    ap.add_argument("--per-source", type=int, default=1500,
                    help="单源最多保留多少条（0=不限）；只防个别源体积失控")
    ap.add_argument("--max-pool", type=int, default=8000)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--budget", type=int, default=180,
                    help="总抓取预算秒数（CI 60 分钟上限里很宽裕）")
    args = ap.parse_args()

    data = json.load(open(args.sources, encoding="utf-8"))
    urls: list[str] = []
    for item in (data.get("official") or []) + (data.get("candidate") or []):
        u = item.get("url") if isinstance(item, dict) else item
        if u and u not in urls:
            urls.append(u)
    if not urls:
        print("sources.json 里没有可用源", file=sys.stderr)
        return 2
    print(f"抓取 {len(urls)} 个源…")

    t0 = time.time()
    results: dict[str, dict] = {}
    ex = cf.ThreadPoolExecutor(max_workers=args.workers)
    futs = {ex.submit(fetch_text, u): u for u in urls}
    try:
        for fut in cf.as_completed(futs, timeout=args.budget):
            url = futs[fut]
            try:
                txt, err = fut.result()
            except Exception as e:      # noqa: BLE001
                txt, err = None, str(e)
            results[url] = {"text": txt, "err": err}
    except cf.TimeoutError:
        print(f"抓取超预算 {args.budget}s，已完成的源先入库")
    finally:
        for f in futs:
            f.cancel()
        ex.shutdown(wait=False)

    seen_fp: set[str] = set()
    seen_hp: set[str] = set()
    nodes: list[dict] = []
    stats: dict[str, dict] = {}
    gate_hist: dict[str, int] = {}
    for i, url in enumerate(urls):
        tag = src_tag(url, i)
        r = results.get(url) or {}
        txt, err = r.get("text"), r.get("err")
        if not txt:
            stats[tag] = {"url": url, "ok": False, "error": err, "count": 0,
                          "kept": 0, "gated": 0, "dup": 0}
            print(f"  失败 {tag}: {err}")
            continue
        proxies = common.parse_subscription_text(txt)
        kept = gated = dup = 0
        local: list[dict] = []
        # 去重只做**源内**（任务#140）：跨源去重会让「先处理的源」赢者通吃，
        # 后处理的源全变成 dup=0 保留，于是它的实测产出率恒为 0，被预算
        # 淘汰——而它其实只是被别的源抢先登记了。跨源重复留到本机取样时按
        # 物理入口去掉（那里才知道该保留哪个源的身份）。
        seen_fp.clear()
        seen_hp.clear()
        for p in proxies:
            reason = common.protocol_gate_reason(p)
            if reason:
                gated += 1
                key = reason.split(":")[0]
                gate_hist[key] = gate_hist.get(key, 0) + 1
                continue
            server = str(p.get("server") or "").strip().lower()
            if not server:
                gated += 1
                continue
            hp = f"{server}:{p.get('port')}"
            fp = fp_of(p)
            if hp in seen_hp or fp in seen_fp:
                dup += 1
                continue
            seen_hp.add(hp)
            seen_fp.add(fp)
            local.append({"fp": fp, "name": str(p.get("name") or "node"),
                          "proxy": p, "src": tag})
            kept += 1
            if args.per_source and kept >= args.per_source:
                break
        nodes.extend(local)
        stats[tag] = {"url": url, "ok": True, "error": None,
                      "count": len(proxies), "kept": kept, "gated": gated,
                      "dup": dup}
        print(f"  {tag}: 解析 {len(proxies)} → 保留 {kept}"
              f"（协议闸门 {gated}，去重 {dup}）")

    if args.max_pool and len(nodes) > args.max_pool:
        # 均匀抽稀而不是截断：截断会让排在前面的源独占池子
        step = len(nodes) / float(args.max_pool)
        nodes = [nodes[int(i * step)] for i in range(args.max_pool)]
        print(f"池子超过上限，均匀抽稀至 {len(nodes)}")

    doc = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "vantage": "ci",
        "sources": {k: {kk: vv for kk, vv in v.items() if kk != "text"}
                    for k, v in stats.items()},
        "gate_hist": gate_hist,
        "nodes": nodes,
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)
    with open(args.stats, "w", encoding="utf-8") as f:
        json.dump({"generated_at": doc["generated_at"], "sources": doc["sources"],
                   "gate_hist": gate_hist},
                  f, ensure_ascii=False, indent=1)

    ok = sum(1 for s in stats.values() if s["ok"])
    print(f"\n协议闸门拒绝原因: {dict(sorted(gate_hist.items(), key=lambda x: -x[1]))}")
    print(f"完成：{len(nodes)} 个候选 / {ok}/{len(urls)} 个源有产出，"
          f"耗时 {int(time.time() - t0)}s → {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
