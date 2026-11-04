#!/usr/bin/env python3
"""构建/更新「用户实测验证常驻池」（任务#119）。

背景：user_probe.json 只存了「节点名 + alive/dead + 时间戳」，没有完整代理
配置。于是用户验证过能用的节点一旦滑出最近两轮订阅，配置就永久丢失，保活
逻辑只能作用于恰好还在候选池里的少数节点——这是「可用节点越来越少」的
结构性断点。

本脚本把用户实测结论与完整配置绑定，产出 user_verified_pool.json：
  * 配置来源：仓库历史订阅快照（git）、release 资产、节点库、待测文档；
  * alive 精确按节点名匹配入库，dead 不入库并从旧池移除；
  * 匹配不上的 alive 记入 unrecoverable，如实留痕，绝不编造配置。

用户每次给出新的本地实测反馈后重跑一次即可（幂等，可反复执行）。
"""
from __future__ import annotations

import argparse
import datetime
import glob
import json
import os
import subprocess
import sys

import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import common  # noqa: E402
import config  # noqa: E402

HIST_FILES = ("clean_clash.yaml", "clean_proxies_only.yaml")


def _scan(obj, index: dict, source: str) -> None:
    """递归收集任何长得像代理配置的 dict，按原始 name 建索引（首次出现优先）。"""
    if isinstance(obj, dict):
        if obj.get("name") and obj.get("type") and (
                obj.get("server") or obj.get("servername")):
            index.setdefault(str(obj["name"]), (dict(obj), source))
        for v in obj.values():
            _scan(v, index, source)
    elif isinstance(obj, list):
        for v in obj:
            _scan(v, index, source)


def _load(path: str, index: dict) -> None:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f) if path.endswith(".json") else yaml.safe_load(f)
        _scan(data, index, os.path.basename(path))
    except Exception:
        pass


def collect_sources(extra_dirs: list[str], workdir: str) -> dict:
    index: dict = {}
    # 1) git 历史订阅快照：git log 倒序，先出现的是较新版本
    try:
        commits = subprocess.run(
            ["git", "log", "--format=%H", "--", *HIST_FILES],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        ).stdout.split()
        for commit in commits:
            for fname in HIST_FILES:
                r = subprocess.run(
                    ["git", "show", f"{commit}:{fname}"],
                    cwd=REPO_ROOT, capture_output=True, text=True, timeout=20,
                )
                if r.returncode == 0 and r.stdout.strip():
                    try:
                        _scan(yaml.safe_load(r.stdout), index, f"git:{commit[:8]}")
                    except Exception:
                        pass
    except Exception as e:
        print(f"警告: git 历史扫描失败: {type(e).__name__}: {e}", file=sys.stderr)
    # 2) 本地/release 资产
    for d in [workdir, *extra_dirs]:
        for path in glob.glob(os.path.join(d, "*")):
            if os.path.splitext(path)[1].lower() in (".yaml", ".yml", ".json"):
                _load(path, index)
    return index


def main() -> int:
    ap = argparse.ArgumentParser(description="构建用户实测验证常驻池")
    ap.add_argument("--workdir", default="/tmp/cn_probe")
    ap.add_argument("--extra-dir", action="append", default=[])
    ap.add_argument("--out", default=os.path.join(REPO_ROOT,
                                                  config.USER_POOL_FILE))
    args = ap.parse_args()

    with open(os.path.join(REPO_ROOT, config.USER_PROBE_FILE),
              encoding="utf-8") as f:
        probe = (json.load(f) or {}).get("nodes") or {}
    alives = {k: v for k, v in probe.items()
              if str((v or {}).get("result", "")).lower() == "alive"}
    deads = {k for k, v in probe.items()
             if str((v or {}).get("result", "")).lower() == "dead"}

    index = collect_sources(args.extra_dir, args.workdir)
    print(f"配置来源: {len(index)} 个唯一节点名")

    pool: dict = {"nodes": {}}
    if os.path.exists(args.out):
        try:
            with open(args.out, encoding="utf-8") as f:
                pool = json.load(f) or {"nodes": {}}
        except Exception:
            pass
    nodes = pool.setdefault("nodes", {})
    # dead 硬否决：从旧池移除
    for fp, rec in list(nodes.items()):
        if rec.get("name") in deads:
            nodes.pop(fp)

    added, kept = 0, 0
    missing = []
    for name, item in alives.items():
        hit = index.get(name)
        if not hit:
            missing.append(name)
            continue
        proxy, source = hit
        fp = common.fingerprint(proxy)
        if fp in nodes:
            kept += 1
            continue
        nodes[fp] = {
            "name": name,
            "proxy": proxy,
            "verdict": "alive",
            "ts": int((item or {}).get("ts") or 0),
            "recovered_from": source,
        }
        added += 1

    pool["_说明"] = ("用户本地实测判定 alive 且已找回完整配置的节点常驻池。"
                     "由 scripts/build_user_pool.py 生成/更新；cn_probe 每轮无条件"
                     "并入主资产，沙箱复测结果不否决（视角不等价）。")
    pool["updated_at"] = datetime.datetime.now(
        datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    pool["unrecoverable"] = sorted(missing)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(pool, f, ensure_ascii=False, indent=1)
    print(f"常驻池: 新增 {added} / 保留 {kept} / 无法恢复 {len(missing)}，"
          f"共 {len(nodes)} 个 → {args.out}")
    for name in sorted(missing):
        print(f"  [配置缺失] {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
