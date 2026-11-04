"""对照实验（任务#119）：沙箱测量环境健康度验证。

问题：本轮 310 个候选只有 16 个能握手（5.2%），历史也有 20 个源零产出。
需要区分两种可能：
  A. 源/节点真的普遍失效（供给问题）
  B. 沙箱测量环境本身退化（出口被限、DNS 故障、mihomo 异常）

方法：取用户本地实测判定 alive 的节点配置（客观事实：它们在用户家宽能用），
在沙箱里用与正式流程完全相同的 mihomo + delay_test + real_traffic_test 测量。
若这些「已知可用」的节点在沙箱大量失败 → 环境退化（B）；
若大部分通过 → 沙箱环境正常，本轮的低通过率是真实供给问题（A）。
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "scripts"))

import yaml  # noqa: E402

import cn_probe  # noqa: E402

WORK = "/tmp/cn_probe"
CHECK = os.path.join(WORK, "user_alive_check.yaml")


def load_check_nodes():
    with open(CHECK, encoding="utf-8") as f:
        d = yaml.safe_load(f)
    plist = d.get("proxies", d) if isinstance(d, dict) else d
    return [dict(x) for x in plist]


def main() -> int:
    nodes = load_check_nodes()
    mihomo = cn_probe.ensure_mihomo(WORK)
    if not mihomo:
        print("mihomo 不可用")
        return 3
    mixed_port, api_port = cn_probe.free_port(7897), cn_probe.free_port(9097)
    names = []
    for i, p in enumerate(nodes):
        nm = f"chk{i}"
        names.append((nm, p["name"], p.get("type")))
        p["name"] = nm
    cfg = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{api_port}",
        "proxies": nodes,
        "proxy-groups": [{"name": "PROBE", "type": "select",
                          "proxies": [n[0] for n in names] + ["DIRECT"]}],
        "rules": ["MATCH,PROBE"],
    }
    cfg_path = os.path.join(WORK, "chk_config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)
    logf = os.path.join(WORK, "chk_mihomo.log")
    with open(logf, "w", encoding="utf-8") as ml:
        proc = subprocess.Popen([mihomo, "-d", WORK, "-f", cfg_path],
                                stdout=ml, stderr=subprocess.STDOUT)
    try:
        if not cn_probe.wait_controller(api_port):
            print("控制器未就绪，日志尾部:")
            with open(logf, encoding="utf-8") as f:
                print("".join(list(f)[-20:]))
            return 3
        print(f"对照集 {len(nodes)} 个（用户实测 alive 的节点），沙箱同流程测量：\n")
        print(f"{'延迟':>7}{'字节':>10}{'KB/s':>8}{'ok':>6}  节点")
        ok_cnt = 0
        for nm, real_name, typ in names:
            d = cn_probe.delay_test(api_port, nm)
            lat = d.get("latency_ms")
            rt = {}
            if d.get("ok"):
                rt = cn_probe.real_traffic_test(api_port, mixed_port, nm)
                if rt.get("ok"):
                    ok_cnt += 1
            bps = (rt.get("bps") or 0) / 1024
            print(f"{(lat if lat else '-'):>7}{rt.get('bytes', 0):>10}{bps:>8.0f}"
                  f"{str(rt.get('ok')):>6}  [{typ}] {real_name[:42]}")
        print(f"\n沙箱通过 {ok_cnt}/{len(nodes)}"
              f"（这些节点在用户家宽实测为 alive）")
        print("判定："
              + ("环境退化——已知可用节点在沙箱大量失败，测量链路有问题"
                 if ok_cnt <= len(nodes) / 3 else
                 "环境正常——沙箱能测出用户实测可用的节点，"
                 "本轮低通过率是真实供给问题"))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except Exception:
            proc.kill()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
