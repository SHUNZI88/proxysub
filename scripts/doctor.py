#!/usr/bin/env python3
"""proxysub 自检：配置正确性与本地环境的一条命令体检。

用法:
    python3 scripts/doctor.py [--repo-root PATH] [--quiet]

退出码: 0 = 通过（可含警告）；1 = 存在错误；2 = 用法错误。

设计意图（产品化-上手助手）:
  - fork 后首次运行前本地自检，把配置错误挡在 CI 之外；
  - 提 Issue 前自检，输出可贴进 bug 表单（见 .github/ISSUE_TEMPLATE），
    减少「环境-配置」类问题的来回确认成本。

检查分三级: ERROR（退出码 1）/ WARN（仅提示）/ OK。
所有检查只读不写——自检绝不允许产生副作用。
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

import config  # noqa: E402

OK, WARN, ERROR = "ok", "warn", "error"
_SYMBOL = {OK: "✅", WARN: "⚠️", ERROR: "❌"}

# JSON 配置/状态文件（config.py 单一事实来源，P1-2 后文件名不再散落硬编码）
_JSON_FILES = [
    "channels.json",
    "sources.json",
    "anti_crawl.json",
    "candidate_sources.json",
    config.SOURCE_SCORES_FILE,
    config.SOURCE_STATS_FILE,
    config.BAD_SOURCES_FILE,
    config.SURVIVAL_FILE,
]


@dataclass
class Check:
    level: str
    name: str
    detail: str = ""


# ---------------------------------------------------------------- 依赖
def _floor_tuple(spec: str) -> tuple[int, ...] | None:
    """从 'requests>=2.32,<3' 取下限版本元组；解析不了返回 None。"""
    m = re.match(r"^[A-Za-z0-9_.\-]+>=([0-9][0-9A-Za-z.\-_]*)", spec.strip())
    if not m:
        return None
    return tuple(int(p) for p in re.findall(r"\d+", m.group(1)))


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", v)[:3])


def _check_deps(root: Path) -> list[Check]:
    """requests / yaml 可导入且满足 requirements.txt 下限。"""
    reqs = root / "requirements.txt"
    floors: dict[str, tuple[int, ...]] = {}
    if reqs.exists():
        for line in reqs.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = re.split(r"[<>=!~]", line, 1)[0].strip()
            floor = _floor_tuple(line)
            if floor:
                floors[name.lower()] = floor
    out = []
    for dist, module in (("requests", "requests"), ("pyyaml", "yaml")):
        try:
            __import__(module)
        except ImportError as e:
            out.append(Check(ERROR, f"依赖 {dist}", f"无法导入：{e}"))
            continue
        try:
            have = importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            out.append(Check(WARN, f"依赖 {dist}", "已可导入但无分发元数据，跳过版本校验"))
            continue
        floor = floors.get(dist)
        if floor and _version_tuple(have) < floor:
            out.append(Check(ERROR, f"依赖 {dist}",
                             f"已装 {have}，低于 requirements.txt 下限 {'.'.join(map(str, floor))}"))
        else:
            out.append(Check(OK, f"依赖 {dist}", f"{have}（下限 {'.'.join(map(str, floor)) if floor else '未声明'}）"))
    return out


# ---------------------------------------------------------------- JSON 配置
def _load_json_file(root: Path, name: str) -> tuple[dict | list | None, Check | None]:
    """读取 JSON 配置文件；返回 (数据, 错误检查项)。文件缺失返回 (None, None)。"""
    path = root / name
    if not path.exists():
        return None, None
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return None, Check(ERROR, f"配置文件 {name}",
                           f"无法解析（{e}）。safe_io 运行时会自愈并备份为 {name}.corrupt，"
                           "但请人工确认根因（截断写入/手工编辑失误）")


def _check_json_configs(root: Path) -> list[Check]:
    out = []
    seen = set()
    for name in _JSON_FILES:
        if name in seen:
            continue
        seen.add(name)
        _, err = _load_json_file(root, name)
        if err:
            out.append(err)
        elif (root / name).exists():
            out.append(Check(OK, f"配置文件 {name}", "可解析"))
    return out


# ---------------------------------------------------------------- channels
def _check_channels(root: Path) -> list[Check]:
    data, err = _load_json_file(root, "channels.json")
    if err:
        return [err]
    if data is None:
        return [Check(WARN, "多渠道配置", "channels.json 缺失：源发现仅靠 GitHub 搜索")]
    if not isinstance(data, dict):
        return [Check(ERROR, "多渠道配置", "channels.json 顶层应为对象")]
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return [Check(ERROR, "多渠道配置", f"enabled 应为布尔值，当前为 {enabled!r}")]
    if not enabled:
        return [Check(OK, "多渠道配置", "已关闭（enabled=false）")]
    lists = {}
    for key in ("telegram", "web", "static_sources"):
        v = data.get(key)
        if v is None:
            lists[key] = []
        elif isinstance(v, list):
            lists[key] = v
        else:
            return [Check(ERROR, "多渠道配置", f"{key} 应为数组，当前为 {type(v).__name__}")]
    for key, v in lists.items():
        bad = [i for i, e in enumerate(v) if not isinstance(e, (str, dict))]
        if bad:
            return [Check(ERROR, "多渠道配置",
                          f"{key} 第 {bad[0]} 项既非字符串也非对象，格式见 README「多渠道搜集配置」")]
    if not any(lists.values()):
        return [Check(WARN, "多渠道配置",
                      "enabled=true 但 telegram/web/static_sources 均为空：实际仅 GitHub 搜索贡献新源")]
    total = sum(len(v) for v in lists.values())
    return [Check(OK, "多渠道配置", f"已开启，共 {total} 个渠道条目")]


# ---------------------------------------------------------------- sources
def _check_sources(root: Path) -> list[Check]:
    data, err = _load_json_file(root, "sources.json")
    if err:
        return [err]
    if data is None:
        return [Check(WARN, "正式源列表", "sources.json 缺失：首次运行将重建默认值")]
    if not isinstance(data, dict):
        return [Check(ERROR, "正式源列表", "sources.json 顶层应为对象")]
    for key in ("official", "removed", "deny_repos"):
        if key in data and not isinstance(data[key], list):
            return [Check(ERROR, "正式源列表", f"{key} 应为数组，当前为 {type(data[key]).__name__}")]
    official = data.get("official") or []
    bad = [i for i, e in enumerate(official)
           if not isinstance(e, dict) or not str(e.get("url") or "").startswith(("http://", "https://"))]
    if bad:
        return [Check(ERROR, "正式源列表",
                      f"official 第 {bad[0]} 项缺少合法 url（需 http(s) 开头）")]
    if not official:
        return [Check(WARN, "正式源列表",
                      "official 为空：节点完全依赖自动发现，建议按 README「手动控制」加一条手工源保底")]
    return [Check(OK, "正式源列表", f"{len(official)} 条正式源")]


# ---------------------------------------------------------------- anti_crawl
def _check_anti_crawl(root: Path) -> list[Check]:
    data, err = _load_json_file(root, "anti_crawl.json")
    if err:
        return [err]
    if data is None:
        return [Check(WARN, "反爬配置", "anti_crawl.json 缺失：反爬默认关闭")]
    if not isinstance(data, dict):
        return [Check(ERROR, "反爬配置", "anti_crawl.json 顶层应为对象")]
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return [Check(ERROR, "反爬配置", f"enabled 应为布尔值，当前为 {enabled!r}")]
    if not enabled:
        return [Check(WARN, "反爬配置",
                      "已关闭：固定名 raw 地址即真实内容（见 README「反爬与防搜索」）")]
    names = data.get("asset_names")
    if not isinstance(names, dict) or not names:
        return [Check(ERROR, "反爬配置",
                      "enabled=true 但 asset_names 为空：固定名已改写为诱饵，"
                      "而滚动 Release 未配置资产名——订阅者无处可订。"
                      "首次运行 filter_clash 会自动生成；若手工开启请先跑一次或按 README 配置 PROXYSUB_ASSET_NAMES")]
    out = [Check(OK, "反爬配置", f"已开启，Release 资产名 {len(names)} 个")]
    if data.get("publish_release") is False:
        days = data.get("rotate_days", "?")
        out.append(Check(WARN, "反爬配置",
                         f"publish_release=false：轮换文件名模式，链接约 {days} 天失效，"
                         "订阅者需定期更新地址（永久地址模式见 README）"))
    return out


# ---------------------------------------------------------------- 工作流
def _check_workflows(root: Path) -> list[Check]:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return [Check(ERROR, "工作流", ".github/workflows 缺失：产品引擎（定时抓取/发布）不在")]
    out = []
    files = sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))
    if not files:
        return [Check(ERROR, "工作流", ".github/workflows 下没有任何工作流文件")]
    for f in files:
        try:
            yaml.safe_load(f.read_text(encoding="utf-8"))
            out.append(Check(OK, f"工作流 {f.name}", "YAML 可解析"))
        except yaml.YAMLError as e:
            out.append(Check(ERROR, f"工作流 {f.name}", f"YAML 解析失败：{e}"))
    return out


# ---------------------------------------------------------------- mihomo
def _check_mihomo() -> list[Check]:
    env_bin = os.environ.get("MIHOMO_BIN")
    if env_bin:
        if os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
            return [Check(OK, "mihomo 二进制", f"MIHOMO_BIN 指向可执行文件 {env_bin}")]
        return [Check(WARN, "mihomo 二进制", f"MIHOMO_BIN 指向的 {env_bin} 不是可执行文件")]
    found = shutil.which("mihomo")
    if found:
        return [Check(OK, "mihomo 二进制", f"PATH 中发现 {found}")]
    return [Check(WARN, "mihomo 二进制",
                  "未发现 mihomo：CI 会自动下载安装；本地运行真实拨测（PROXYSUB_DISABLE_PROBE 未设）需要它")]


# ---------------------------------------------------------------- 损坏备份
def _check_corrupt_backups(root: Path) -> list[Check]:
    backups = sorted(p.name for p in root.glob("*.corrupt"))
    if not backups:
        return [Check(OK, "损坏备份", "无 .corrupt 文件")]
    return [Check(WARN, "损坏备份",
                  f"存在 {len(backups)} 个自愈备份：{', '.join(backups[:5])}"
                  "——safe_io 已从损坏中恢复，建议关注根因（磁盘满/并发写）")]


def run_checks(root: Path) -> list[Check]:
    """执行全部自检（只读）。root 为仓库根目录。"""
    root = Path(root)
    return [
        *_check_deps(root),
        *_check_json_configs(root),
        *_check_channels(root),
        *_check_sources(root),
        *_check_anti_crawl(root),
        *_check_workflows(root),
        *_check_mihomo(),
        *_check_corrupt_backups(root),
    ]


def _report(checks: list[Check], quiet: bool) -> None:
    width = max(len(c.name) for c in checks) if checks else 0
    for c in checks:
        if quiet and c.level == OK:
            continue
        line = f"{_SYMBOL[c.level]} {c.name:<{width}}  {c.detail}".rstrip()
        print(line)
    n_err = sum(1 for c in checks if c.level == ERROR)
    n_warn = sum(1 for c in checks if c.level == WARN)
    n_ok = sum(1 for c in checks if c.level == OK)
    print(f"\n小结: {n_ok} 通过 / {n_warn} 警告 / {n_err} 错误")
    if n_err:
        print("存在错误项——修复后再运行 filter_clash 或提交 Issue（可附上本输出）。")
    elif n_warn:
        print("仅有警告——可按提示决定是否处理，不阻塞运行。")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="proxysub 配置与环境自检（只读）")
    parser.add_argument("--repo-root", default=str(REPO_ROOT),
                        help="仓库根目录（默认: 本脚本所在仓库）")
    parser.add_argument("--quiet", action="store_true", help="只输出警告与错误")
    args = parser.parse_args(argv)
    root = Path(args.repo_root).resolve()
    if not root.is_dir():
        print(f"❌ 仓库根目录不存在: {root}", file=sys.stderr)
        return 2
    checks = run_checks(root)
    _report(checks, args.quiet)
    return 1 if any(c.level == ERROR for c in checks) else 0


if __name__ == "__main__":
    sys.exit(main())
