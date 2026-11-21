"""客户端同款验证：对给定订阅做低并发多轮延迟测试。

目的：复现手机 FlClash url-test 的真实手感，判断「本地判据通过」与
「客户端超时」的差距到底来自判据太松，还是免费节点本身已死。

方法：
  - 4 并发（不争抢本机 CPU/带宽，贴近手机单机场景）
  - 5s 超时（FlClash 默认量级）
  - 3 轮分散采样（轮间 20s），记录每轮每节点延迟
  - 判据端点与主判据一致（api.twitter.com/robots.txt）

用法：python _diag_client_now.py <订阅yaml> [--url URL] [--rounds N] [--concurrency N]
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml

MIHOMO = r"C:\Users\shunz\AppData\Local\proxysub\mihomo.exe"
DEFAULT_URL = "https://api.twitter.com/robots.txt"
PROXY_PORT = 17890
API_PORT = 17891


def pick_free_port(base):
    import socket
    for p in range(base, base + 60):
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", p))
            s.close()
            return p
        except OSError:
            s.close()
    raise RuntimeError("no free port")


def build_cfg(proxies):
    return {
        "mixed-port": PROXY_PORT,
        "allow-lan": False,
        "mode": "global",
        "log-level": "silent",
        "external-controller": f"127.0.0.1:{API_PORT}",
        "proxies": proxies,
    }


def start(proxies, workdir):
    cfg_path = os.path.join(workdir, "cfg.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(build_cfg(proxies), f, allow_unicode=True, sort_keys=False)
    proc = subprocess.Popen(
        [MIHOMO, "-d", workdir, "-f", cfg_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        time.sleep(0.5)
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{API_PORT}/version", timeout=2) as r:
                if r.status == 200:
                    return proc
        except Exception:
            continue
    proc.kill()
    raise RuntimeError("mihomo 启动失败")


def delay(name, url, timeout_ms):
    q = urllib.parse.urlencode({"url": url, "timeout": timeout_ms})
    path = f"/proxies/{urllib.parse.quote(name, safe='')}/delay?{q}"
    try:
        with urllib.request.urlopen(
                f"http://127.0.0.1:{API_PORT}{path}",
                timeout=timeout_ms / 1000 + 3) as r:
            body = json.loads(r.read().decode("utf-8", "replace"))
        d = body.get("delay")
        return int(d) if isinstance(d, (int, float)) and d > 0 else None
    except Exception:
        return None


def main():
    if len(sys.argv) < 2:
        print("用法: python _diag_client_now.py <订阅yaml> [--url URL] [--rounds N] [--concurrency N]")
        return 2
    sub_path = sys.argv[1]
    url = DEFAULT_URL
    rounds = 3
    conc = 4
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--url":
            url = args[i + 1]; i += 2
        elif args[i] == "--rounds":
            rounds = int(args[i + 1]); i += 2
        elif args[i] == "--concurrency":
            conc = int(args[i + 1]); i += 2
        else:
            i += 1

    with open(sub_path, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    proxies = [p for p in (cfg.get("proxies") or []) if isinstance(p, dict) and p.get("server")]
    names = [str(p.get("name") or f"n{k}") for k, p in enumerate(proxies)]
    # 去重名称，mihomo 要求唯一
    seen = {}
    uniq = []
    for p, n in zip(proxies, names):
        if n in seen:
            seen[n] += 1
            n = f"{n} #{seen[n]}"
            p = dict(p); p["name"] = n
        else:
            seen[n] = 0
        uniq.append(p)
    names = [str(p["name"]) for p in uniq]

    print(f"节点数: {len(uniq)}  端点: {url}  轮次: {rounds}  并发: {conc}")
    workdir = tempfile.mkdtemp(prefix="diag_now_")
    proc = start(uniq, workdir)
    try:
        results = {n: [] for n in names}
        for rd in range(1, rounds + 1):
            t0 = time.time()
            with ThreadPoolExecutor(max_workers=conc) as ex:
                futs = {ex.submit(delay, n, url, 5000): n for n in names}
                for fu in futs:
                    n = futs[fu]
                    results[n].append(fu.result())
            okc = sum(1 for n in names if results[n][-1] is not None)
            print(f"  第{rd}轮: 通过 {okc}/{len(names)}  耗时 {time.time()-t0:.0f}s")
            if rd < rounds:
                time.sleep(20)
    finally:
        proc.kill()

    print("\n=== 逐节点结果（每轮延迟ms，None=超时）===")
    stable, flaky, dead = [], [], []
    for n in names:
        vals = results[n]
        passed = sum(1 for v in vals if v is not None)
        med = None
        good = sorted(v for v in vals if v is not None)
        if good:
            med = good[len(good) // 2]
        tag = "稳定" if passed == rounds else ("波动" if passed else "全超时")
        if passed == rounds:
            stable.append(n)
        elif passed:
            flaky.append(n)
        else:
            dead.append(n)
        print(f"  [{tag}] {passed}/{rounds}  中位{med}ms  {n[:44]}  {vals}")

    print(f"\n=== 汇总 共{len(names)} ===")
    print(f"  稳定(全轮通过): {len(stable)}")
    print(f"  波动(部分通过): {len(flaky)}")
    print(f"  全超时(已死)  : {len(dead)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
