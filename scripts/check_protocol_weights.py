#!/usr/bin/env python3
"""协议权重化门槛检查（docs/protocol_weights_todo.md 配套工具）。

用途：任何 AI 会话或人工，一条命令判定「协议维度是否已积累足够证据，
可以评估实施分层权重」。

判定门槛（见 config.py）：
  某协议 累计 tested >= PROTOCOL_WEIGHT_MIN_CUM_SAMPLE（50）
          且 rounds  >= PROTOCOL_WEIGHT_MIN_ROUNDS（5）

退出码：0=至少一个协议达标（应提示用户）；1=均未达标（继续观察）。

用法：
  python3 scripts/check_protocol_weights.py [--path protocol_history.json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import config  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default=os.path.join(
        REPO_ROOT, config.PROTOCOL_HISTORY_FILE))
    args = ap.parse_args()

    if not os.path.exists(args.path):
        print(f"未找到 {args.path}——尚无协议历史（将随每轮 CI 自动生成）。")
        return 1

    with open(args.path, encoding="utf-8") as f:
        hist = json.load(f)

    need_n = config.PROTOCOL_WEIGHT_MIN_CUM_SAMPLE
    need_r = config.PROTOCOL_WEIGHT_MIN_ROUNDS
    print(f"门槛：累计 tested ≥ {need_n} 且 rounds ≥ {need_r}\n")
    print(f"{'协议':12}{'rounds':>8}{'tested':>8}{'passed':>8}{'通过率':>9}  状态")

    ready = []
    for proto, v in sorted(hist.items(), key=lambda x: -x[1].get("tested", 0)):
        n, r = v.get("tested", 0), v.get("rounds", 0)
        p = v.get("passed", 0)
        rate = f"{p / n * 100:6.1f}%" if n else "   n/a"
        ok = n >= need_n and r >= need_r
        if ok:
            ready.append(proto)
        print(f"{proto:12}{r:>8}{n:>8}{p:>8}{rate:>9}  {'✅ 达标' if ok else '⏳ 观察中'}")

    print()
    if ready:
        print(f"🎯 已达标：{', '.join(ready)}——**应提示用户可评估「协议分层权重」**。")
        print("   评估要点见 docs/protocol_weights_todo.md 第五节。")
        return 0
    print("均未达标——继续积累跨轮证据（无需人工干预，每轮 CI 自动累加）。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
