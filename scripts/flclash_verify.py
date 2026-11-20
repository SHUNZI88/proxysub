#!/usr/bin/env python3
"""用本机 mihomo/FlClash 内核对已发布主资产做独立交叉验证。

动机（2026-11-20）：用户质疑「一屏意大利节点是不是真的有效」。仅靠 cn_probe
自己的拨测结论自证不够——必须用**另一个内核、另一条真实代理链路**复测：
每个节点逐个切入独立实例，实测出口国家/ASN 与 chatgpt / claude / youtube 的
真实 HTTP 响应。脚本不碰 FlClash GUI 正在使用的 profile 和端口。

用法：
    python scripts/flclash_verify.py                    # 从 release 取最新主资产
    python scripts/flclash_verify.py --local main.yaml  # 用本地 yaml
    python scripts/flclash_verify.py --json report.json # 指定报告输出

依赖：workdir 下的 mihomo.exe（可用 MIHOMO_BIN 覆盖）、PyYAML。
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import config  # noqa: E402
import yaml  # noqa: E402

try:
    from scripts import gh_compat  # noqa: E402
except ImportError:
    import gh_compat  # noqa: E402

TARGETS = {
    "chatgpt": "https://chatgpt.com/",
    "claude": "https://claude.ai/",
    "youtube": "https://www.youtube.com/",
}
GEO_URL = "https://ipwho.is/"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _mihomo_bin() -> str | None:
    env = os.environ.get("MIHOMO_BIN")
    if env and os.path.isfile(env):
        return env
    workdir = getattr(config, "WORKDIR", "") or os.path.join(
        os.environ.get("LOCALAPPDATA", tempfile.gettempdir()), "proxysub")
    exe = "mihomo.exe" if sys.platform == "win32" else "mihomo"
    local = os.path.join(workdir, exe)
    if os.path.isfile(local):
        return local
    return shutil.which(exe)


def _latest_main_asset() -> str:
    """从 sub release 找最新发布的 *_c.yaml 主资产。"""
    errs: list[str] = []
    assets = gh_compat.release_assets("sub")
    cands = [a for a in assets if str(a.get("name", "")).endswith("_c.yaml")
             and not str(a.get("name", "")).endswith(".staging")]
    if not cands:
        raise RuntimeError("sub release 里没有 *_c.yaml 主资产：" + " | ".join(errs))
    cands.sort(key=lambda a: a.get("updated_at") or "", reverse=True)
    return cands[0]["name"]


def _fetch_asset(name: str, dest: str) -> None:
    errs: list[str] = []
    if not gh_compat.download_asset("sub", name, dest, timeout=90, errs=errs):
        raise RuntimeError("下载主资产失败：" + " | ".join(errs))


def _http(opener, url: str, timeout: int) -> dict:
    t = time.time()
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with opener.open(req, timeout=timeout) as r:
            body = r.read(4096)
            return {"ok": True, "status": r.status,
                    "ms": int((time.time() - t) * 1000),
                    "snippet": body[:60].decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        return {"ok": True, "status": e.code, "ms": int((time.time() - t) * 1000)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "err": f"{type(e).__name__}: {str(e)[:100]}",
                "ms": int((time.time() - t) * 1000)}


def _wait_api(api: str, proc: subprocess.Popen, seconds: float = 15) -> bool:
    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    until = time.time() + seconds
    while time.time() < until:
        if proc.poll() is not None:
            return False
        try:
            direct.open(api + "/version", timeout=1).read()
            return True
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
    return False


def verify(nodes: list[dict], timeout: int = 9) -> list[dict]:
    binpath = _mihomo_bin()
    if not binpath:
        raise RuntimeError("找不到 mihomo 可执行文件（设 MIHOMO_BIN 或放一份到 workdir）")
    tmp = tempfile.mkdtemp(prefix="ps_flclash_verify_")
    mixed, ctl = _free_port(), _free_port()
    api = f"http://127.0.0.1:{ctl}"
    names = [p["name"] for p in nodes]
    cfg = {
        "mixed-port": mixed,
        "external-controller": f"127.0.0.1:{ctl}",
        "mode": "rule",
        "allow-lan": False,
        "log-level": "warning",
        "proxies": nodes,
        "proxy-groups": [{"name": "VERIFY", "type": "select", "proxies": names}],
        "rules": ["MATCH,VERIFY"],
    }
    cfg_path = os.path.join(tmp, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, allow_unicode=True, sort_keys=False)

    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    proxy = urllib.request.build_opener(urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{mixed}", "https": f"http://127.0.0.1:{mixed}"}))
    proc = subprocess.Popen([binpath, "-d", tmp, "-f", cfg_path, "-ext-ctl", f"127.0.0.1:{ctl}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results: list[dict] = []
    try:
        if not _wait_api(api, proc):
            raise RuntimeError("内核未能启动，检查 mihomo 日志：" + tmp)
        for idx, node in enumerate(nodes, 1):
            rec = {"name": node["name"], "type": node.get("type"),
                   "server": node.get("server"), "port": node.get("port")}
            try:
                req = urllib.request.Request(
                    api + "/proxies/VERIFY", method="PUT",
                    data=json.dumps({"name": node["name"]}).encode("utf-8"),
                    headers={"Content-Type": "application/json"})
                direct.open(req, timeout=8).read()
                time.sleep(0.2)

                try:
                    with proxy.open(GEO_URL, timeout=timeout) as r:
                        geo = json.loads(r.read().decode("utf-8", "replace"))
                    rec.update(exit_ip=geo.get("ip"), exit_country=geo.get("country"),
                               exit_city=geo.get("city"),
                               exit_asn=(geo.get("connection") or {}).get("asn"))
                except Exception as e:  # noqa: BLE001
                    rec["exit_err"] = f"{type(e).__name__}: {str(e)[:80]}"

                for key, url in TARGETS.items():
                    rec[key] = _http(proxy, url, timeout)
            except Exception as e:  # noqa: BLE001
                rec["fatal"] = f"{type(e).__name__}: {e}"
            results.append(rec)
            sites = "/".join("1" if rec.get(k, {}).get("status", 0) and
                             rec[k]["status"] < 500 else "0" for k in TARGETS)
            print(f"[{idx:02d}/{len(nodes)}] {node['name'][:40]:40s} "
                  f"exit={str(rec.get('exit_country', '-')):10s} sites={sites}", flush=True)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                proc.kill()
            except Exception:
                pass
        shutil.rmtree(tmp, ignore_errors=True)
    return results


def summarize(results: list[dict]) -> dict:
    ok = [r for r in results if all(
        r.get(k, {}).get("ok") and r[k].get("status", 0) < 500 for k in TARGETS)]
    return {
        "tested": len(results),
        "all_targets_ok": len(ok),
        "exit_countries": dict(collections.Counter(
            r.get("exit_country") or "?" for r in results).most_common()),
        "exit_asns": {str(k): v for k, v in collections.Counter(
            r.get("exit_asn") or "?" for r in results).most_common()},
        "per_target": {k: sum(1 for r in results if r.get(k, {}).get("status", 0)
                              and r[k]["status"] < 500) for k in TARGETS},
        "nodes": results,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--local", help="本地 clash yaml（不指定则从 release 取最新主资产）")
    ap.add_argument("--json", help="报告输出路径（默认 print 摘要）")
    ap.add_argument("--timeout", type=int, default=9, help="单次 HTTP 超时秒数")
    args = ap.parse_args()

    raw = args.local
    if not raw:
        name = _latest_main_asset()
        raw = os.path.join(tempfile.gettempdir(), "ps_verify_" + name)
        print("取主资产:", name)
        _fetch_asset(name, raw)
    with open(raw, encoding="utf-8") as f:
        proxies = yaml.safe_load(f).get("proxies") or []
    if not proxies:
        raise RuntimeError("主资产里没有 proxies")
    print("逐节点交叉验证", len(proxies), "个（独立内核实例，不触碰 FlClash GUI）")
    report = summarize(verify(proxies, timeout=args.timeout))
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(text)
        print("报告已写入", args.json)
    else:
        for k in ("tested", "all_targets_ok", "exit_countries", "exit_asns", "per_target"):
            print(f"{k}: {report[k]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
