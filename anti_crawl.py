#!/usr/bin/env python3
"""proxysub 反爬与防搜索模块（anti-crawl）。

威胁模型：public 仓库的订阅文件通过 raw.githubusercontent.com 对任何人可读，
且会被「按固定路径扫描」的爬虫 / 聚合站 / 搜索引擎收录。本模块提供一层
「诱饵分流 + 永久地址 + 回流检测」，显著提高爬虫成本：

  1. 诱饵分流（decoy）：开启后，固定名订阅文件（clean_clash.yaml 等）改写为
     **诱饵内容**——大量形态合法但必定不可用的诱饵节点（名称带 [BAIT] 标记，
     服务器指向保留域 .invalid，任何客户端都无法连通）。
  2. 永久订阅地址（rolling release，默认）：真实输出发布到仓库的滚动
     GitHub Release（tag 可配，默认 `sub`），资产名为首次生成的随机字符串
     （p_<hex>_c.yaml 等，之后永久不变）。订阅地址形如
     https://github.com/<repo>/releases/download/<tag>/p_<hex>_c.yaml
     —— **一次复制，永久有效**；按固定路径扫描 raw 的爬虫永远只会扫到诱饵。
     （注意：必须用具体 tag 而非 `releases/latest`——latest 标记会被仓库内
     其他较新创建的 release 抢走，导致地址漂移失效。）
  3. 诱饵回流检测（bait feedback）：若某个订阅源收录了我们生成的诱饵节点
     （指纹比对），该源会被自动标记 bait_reuse —— 候选源直接拒绝、
     正式源自动淘汰。爬虫转载诱饵即自我暴露。
  4. robots.txt：生成 Disallow: / 声明，劝阻合规爬虫。
  5. 真实订阅地址只写入 GitHub Actions Step Summary（仅仓库所有者可见），
     不进入任何公开文件（README / stats.md 均不含）。

备选模式（publish_release=false）：真实输出写轮换文件名
（clean_clash.<token>.yaml，每 rotate_days 天更换，过期自动删除）——链接会
定期失效，适合「分享出去的链接应过期」的场景；默认不启用。

效果边界（如实说明，详见 README「反爬与防搜索」）：
  - public 仓库无法从根本上避免被 GitHub 站内搜索 / 代码索引 / 外部搜索引擎收录；
  - 永久地址的随机资产名记录在公开的 anti_crawl.json 中，可防御大众爬虫，
    无法防御针对性人工分析（也可用环境变量 PROXYSUB_ASSET_NAMES 指定资产名、
    使其完全不落仓库）；要彻底隐藏只有转 private 仓库（代价见 README）。

默认关闭：anti_crawl.json 的 "enabled": false 时本模块完全不改变原有行为
（不写诱饵、不发布、不删文件），也可用环境变量 PROXYSUB_ANTI_CRAWL=0 强制关闭。

依赖分层：本模块可 import output（filter_clash 已同时依赖它们，
不构成循环）；不 import probe / score / sources_manager。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import uuid
from datetime import date
from typing import Any, Callable

import yaml

from safe_io import load_json, save_json  # 原子化读写，防止 JSON 截断损坏

CONFIG_FILE = "anti_crawl.json"
ROBOTS_FILE = "robots.txt"
PUBLISH_DIR = ".publish"               # 真实输出的本地暂存目录（由工作流发布为 Release 资产）

# 固定名文件 = 诱饵；真实输出 = Release 资产（见 asset_name）
OUTPUT_BASENAMES = (
    "clean_clash.yaml",
    "clean_proxies_only.yaml",
    "clean_singbox.json",
    "clean_v2ray.txt",
)
# 资产名后缀：随机 token + 区分格式的后缀 + 原扩展名（p_<hex>_c.yaml 等）
_ASSET_SUFFIX = {
    "clean_clash.yaml": "_c",
    "clean_proxies_only.yaml": "_p",
    "clean_singbox.json": "_s",
    "clean_v2ray.txt": "_v",
}

BAIT_TAG = "[BAIT]"
DEFAULT_BAIT_HOST = "bait.invalid"   # RFC 2606 保留域：任何客户端都无法连通
DEFAULT_ROTATE_DAYS = 3
DEFAULT_DECOY_COUNT = 60
DEFAULT_RELEASE_TAG = "sub"
BAIT_HISTORY_KEEP = 3                # 保留最近 N 轮诱饵节点指纹用于回流检测


# ====================== 配置 ======================

def default_config() -> dict:
    return {
        "_doc": (
            "反爬与防搜索配置（默认关闭）。enabled=true 后：固定名订阅文件改写为诱饵内容，"
            "真实输出发布到滚动 GitHub Release（资产名为随机字符串、永久不变，publish_release=true，"
            "默认）；publish_release=false 则退回轮换文件名模式（链接定期失效）。"
            "token_seed/token/current_outputs/stale_outputs/bait_nodes/bait_history/asset_names "
            "由程序自动维护，请勿手工编辑；PROXYSUB_ANTI_CRAWL=0 可临时强制关闭；"
            "PROXYSUB_ASSET_NAMES 可指定 Release 资产名（JSON，指定后不写入本文件）。"
            "效果边界见 README「反爬与防搜索」。"
        ),
        "enabled": False,
        "publish_release": True,      # True: 滚动 Release 永久地址（默认）；False: 轮换文件名
        "release_tag": DEFAULT_RELEASE_TAG,
        "rotate_days": DEFAULT_ROTATE_DAYS,
        "decoy_count": DEFAULT_DECOY_COUNT,
        "bait_host": DEFAULT_BAIT_HOST,
        "token_seed": "",
        "asset_token": "",
        "token": "",
        "rotated_at": "",
        "output_mode": "",            # "release" | "rotate"，由程序维护
        "current_outputs": [],
        "stale_outputs": [],
        "asset_names": {},
        "bait_nodes": [],
        "bait_history": [],
    }


def load_config() -> dict:
    cfg = load_json(CONFIG_FILE, None)
    base = default_config()
    if not isinstance(cfg, dict):
        return base
    base.update({k: v for k, v in cfg.items() if k in base})
    # 类型兜底：损坏/手误的字段回退到默认值，绝不让流水线崩溃
    base["enabled"] = bool(base.get("enabled"))
    base["publish_release"] = bool(base.get("publish_release", True))
    base["release_tag"] = str(base.get("release_tag") or DEFAULT_RELEASE_TAG)
    for k, lo, hi, dflt in (("rotate_days", 1, 30, DEFAULT_ROTATE_DAYS),
                            ("decoy_count", 5, 500, DEFAULT_DECOY_COUNT)):
        try:
            base[k] = max(lo, min(hi, int(base.get(k, dflt))))
        except (TypeError, ValueError):
            base[k] = dflt
    base["bait_host"] = str(base.get("bait_host") or DEFAULT_BAIT_HOST).strip().lower().rstrip(".")
    for k in ("current_outputs", "stale_outputs", "bait_nodes", "bait_history"):
        if not isinstance(base.get(k), list):
            base[k] = []
    if not isinstance(base.get("asset_names"), dict):
        base["asset_names"] = {}
    return base


def save_config(cfg: dict) -> None:
    save_json(CONFIG_FILE, cfg)


def is_enabled(cfg: dict | None = None) -> bool:
    """配置开启且未被环境变量击杀。PROXYSUB_ANTI_CRAWL=0 可临时强制关闭。"""
    if os.environ.get("PROXYSUB_ANTI_CRAWL", "1") == "0":
        return False
    cfg = cfg if cfg is not None else load_config()
    return bool(cfg.get("enabled"))


def publish_mode(cfg: dict) -> bool:
    """True=滚动 Release 永久地址模式；False=轮换文件名模式。"""
    return bool(cfg.get("publish_release", True))


# ====================== 轮换 token 与文件名（rotate 模式） ======================

def epoch_of(day: date, rotate_days: int) -> int:
    return day.toordinal() // max(1, int(rotate_days))


def rotate_token(cfg: dict, today: date | None = None) -> str:
    """确定性派生轮换 token：同一周期内稳定，跨周期必变（seed + epoch 的哈希）。"""
    today = today or date.today()
    seed = str(cfg.get("token_seed") or "unseeded")
    epoch = epoch_of(today, int(cfg.get("rotate_days", DEFAULT_ROTATE_DAYS) or DEFAULT_ROTATE_DAYS))
    return hashlib.sha256(f"proxysub-bait:{seed}:{epoch}".encode()).hexdigest()[:10]


def rotated_name(basename: str, token: str) -> str:
    """clean_clash.yaml -> clean_clash.<token>.yaml（保留扩展名，客户端按 URL 识别格式）。"""
    root, ext = os.path.splitext(basename)
    return f"{root}.{token}{ext}"


def make_namer(cfg: dict) -> Callable[[str], str]:
    """返回 basename -> 当前真实输出文件名 的映射函数（rotate 模式，供 output 层使用）。"""
    token = str(cfg.get("token") or "")
    return lambda base: rotated_name(base, token) if token else base


# ====================== Release 永久地址（release 模式，默认） ======================

def safe_asset_name(name) -> str:
    """资产名安全校验（安全评估 F4 / CWE-22）：必须是纯 basename。

    Release 资产名会进入 ``.publish/<name>`` 写入路径与永久订阅 URL；
    环境变量 PROXYSUB_ASSET_NAMES 与 anti_crawl.json 持久化值若含
    ``../``、绝对路径或目录分隔符，可导致写出/删除落到 .publish 之外。
    此处强制 basename 形态，非法值抛 ValueError（调用方按配置错误处理）。
    """
    name = str(name or "").strip()
    if (not name
            or name != os.path.basename(name)
            or ".." in name
            or "/" in name
            or "\\" in name
            or name.startswith(".")
            or "\x00" in name):
        raise ValueError(f"invalid asset name: {name!r}")
    return name


def asset_name(cfg: dict, basename: str) -> str:
    """Release 资产名：首次生成为随机字符串，之后永久不变。

    优先使用环境变量 PROXYSUB_ASSET_NAMES（JSON dict，指定后不写入公开配置，
    资产名即可完全不落仓库）；否则生成 p_<hex><后缀><扩展名> 并持久化。
    两条路径的返回值都经 safe_asset_name 校验（F4）。
    """
    env = os.environ.get("PROXYSUB_ASSET_NAMES")
    if env:
        try:
            override = json.loads(env)
            if isinstance(override, dict) and basename in override:
                return safe_asset_name(override[basename])
        except ValueError:
            raise  # 资产名非法是配置错误，必须显式失败而非静默回退
        except Exception:
            pass
    names = cfg.setdefault("asset_names", {})
    if basename not in names or not names[basename]:
        if not cfg.get("asset_token"):
            cfg["asset_token"] = secrets.token_hex(5)
        ext = os.path.splitext(basename)[1]
        names[basename] = f"p_{cfg['asset_token']}{_ASSET_SUFFIX.get(basename, '')}{ext}"
    return safe_asset_name(names[basename])


def publish_paths(cfg: dict) -> dict[str, str]:
    """basename -> .publish/<资产名>（工作流随后上传为 Release 资产）。"""
    return {b: os.path.join(PUBLISH_DIR, asset_name(cfg, b)) for b in OUTPUT_BASENAMES}


def release_urls(cfg: dict, repo: str | None = None) -> list[str]:
    """永久订阅地址：https://github.com/<repo>/releases/download/<tag>/<资产名>。

    注意：必须用具体 release_tag（默认 `sub`）而非 `releases/latest`。
    GitHub 的 latest 标记归属最新创建的 release——仓库内任何较新创建的
    release（如 status dashboard）都会把它抢走，使 `latest/download` 路径
    404。具体 tag 路径不依赖 latest 标记，永久稳定。
    """
    repo = repo or os.environ.get("GITHUB_REPOSITORY") or "OWNER/REPO"
    tag = str(cfg.get("release_tag") or DEFAULT_RELEASE_TAG)
    return [f"https://github.com/{repo}/releases/download/{tag}/{asset_name(cfg, b)}"
            for b in OUTPUT_BASENAMES]


# ====================== 诱饵节点与诱饵订阅 ======================

def _rand_public_key() -> str:
    """43 字符 base64url（X25519 公钥形态，满足 X25519_PUBLIC_KEY_RE）。"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def gen_decoy_nodes(n: int, token: str, cfg: dict) -> list[dict]:
    """生成 n 个形态合法但必定不可用的诱饵节点（混合 vless-reality / trojan / hysteria2）。"""
    host = str(cfg.get("bait_host") or DEFAULT_BAIT_HOST).strip().lower().rstrip(".") or DEFAULT_BAIT_HOST
    nodes: list[dict] = []
    for i in range(max(0, int(n))):
        name = f"{BAIT_TAG}{token}-{i:03d}"
        sub = secrets.token_hex(6)
        kind = i % 3
        if kind == 0:  # VLESS + Reality（当前最主流的优质协议形态）
            nodes.append({
                "name": name,
                "type": "vless",
                "server": f"{sub}.{host}",
                "port": 443,
                "uuid": str(uuid.uuid4()),
                "network": "tcp",
                "tls": True,
                "flow": "xtls-rprx-vision",
                "servername": f"{secrets.token_hex(6)}.{host}",
                "client-fingerprint": "chrome",
                "reality-opts": {
                    "public-key": _rand_public_key(),
                    "short-id": secrets.token_hex(4),
                },
            })
        elif kind == 1:  # Trojan
            nodes.append({
                "name": name,
                "type": "trojan",
                "server": f"{sub}.{host}",
                "port": 443,
                "password": secrets.token_urlsafe(24),
                "sni": f"{secrets.token_hex(6)}.{host}",
                "network": "tcp",
                "client-fingerprint": "chrome",
            })
        else:  # Hysteria2
            nodes.append({
                "name": name,
                "type": "hysteria2",
                "server": f"{sub}.{host}",
                "port": 443,
                "password": secrets.token_urlsafe(24),
                "sni": f"{secrets.token_hex(6)}.{host}",
            })
    return nodes


def build_decoy_config(nodes: list[dict]) -> dict:
    """与真实输出同构的 Clash 配置（proxies + proxy-groups + rules）。"""
    names = [p["name"] for p in nodes]
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": nodes,
        "proxy-groups": [
            {"name": "🚀 节点选择", "type": "select",
             "proxies": (["♻️ 自动选择", "DIRECT"] + names)[:200]},
            {"name": "♻️ 自动选择", "type": "url-test", "proxies": names,
             "url": "http://www.gstatic.com/generate_204", "interval": 150, "tolerance": 50},
        ],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }


def write_decoy_outputs(cfg: dict) -> dict:
    """把诱饵内容写入 4 个固定名文件（与真实输出完全同构，仅节点不可用）。

    多格式转换复用 output 层的 proxy_to_singbox / proxy_to_share_link，
    保证诱饵文件的形态与真实输出一致（base64 / json / yaml 均可被正常解析）。
    """
    import output  # 延迟导入：避免模块加载期拉起整条依赖链（测试可单独 import 本模块）

    token = str(cfg.get("token") or "notoken")
    nodes = cfg.get("bait_nodes") or gen_decoy_nodes(
        int(cfg.get("decoy_count", DEFAULT_DECOY_COUNT)), token, cfg)
    cfg["bait_nodes"] = nodes

    stat = {"proxies_only": 0, "singbox": 0, "links": 0, "total": len(nodes)}

    with open("clean_clash.yaml", "w", encoding="utf-8") as f:
        yaml.dump(build_decoy_config(nodes), f, allow_unicode=True, sort_keys=False)

    with open("clean_proxies_only.yaml", "w", encoding="utf-8") as f:
        yaml.dump({"proxies": nodes}, f, allow_unicode=True, sort_keys=False)
    stat["proxies_only"] = len(nodes)

    outbounds = []
    for p in nodes:
        ob = output.proxy_to_singbox(p)
        if ob:
            outbounds.append(ob)
    outbounds.append({"type": "direct", "tag": "direct"})
    with open("clean_singbox.json", "w", encoding="utf-8") as f:
        json.dump({"outbounds": outbounds}, f, ensure_ascii=False, indent=2)
    stat["singbox"] = len(outbounds) - 1

    links = []
    for p in nodes:
        link = output.proxy_to_share_link(p)
        if link:
            links.append(link)
    payload = base64.b64encode("\n".join(links).encode("utf-8")).decode("ascii")
    with open("clean_v2ray.txt", "w", encoding="utf-8") as f:
        f.write(payload + "\n")
    stat["links"] = len(links)
    return stat


# ====================== 每轮推进 ======================

def begin_run(cfg: dict | None = None, today: date | None = None) -> dict:
    """每轮更新开始时调用：按需轮换诱饵 / 推进输出模式 / 清理过期文件 / 写配置。

    未启用时原样返回（不落盘、不产生任何文件变化）。
    """
    cfg = cfg if cfg is not None else load_config()
    if not is_enabled(cfg):
        return cfg
    today = today or date.today()

    if not cfg.get("token_seed"):
        cfg["token_seed"] = secrets.token_hex(16)  # 首次启用：随机种子（之后保持不变）

    prev_token = cfg.get("token")
    prev_mode = cfg.get("output_mode")
    prev_outputs = [p for p in cfg.get("current_outputs", []) if p]
    mode = "release" if publish_mode(cfg) else "rotate"
    token = rotate_token(cfg, today)

    # 诱饵按周期轮换（两种模式都做：外部流传的旧诱饵指纹仍保留 BAIT_HISTORY_KEEP 轮）
    if token != prev_token:
        nodes = gen_decoy_nodes(int(cfg.get("decoy_count", DEFAULT_DECOY_COUNT)), token, cfg)
        cfg["bait_nodes"] = nodes
        history = [h for h in cfg.get("bait_history", []) if isinstance(h, dict)]
        cfg["bait_history"] = history[-(BAIT_HISTORY_KEEP - 1):] + [{"token": token, "nodes": nodes}]
        cfg["token"] = token
        cfg["rotated_at"] = today.isoformat()

    # 输出文件名推进
    stale: list[str] = []
    if prev_mode and prev_mode != mode:
        # 模式切换：清理旧模式的输出文件（如 rotate -> release 时删掉轮换文件）
        stale = prev_outputs
    elif mode == "rotate" and token != prev_token:
        stale = prev_outputs
    cfg["stale_outputs"] = stale
    cfg["output_mode"] = mode
    if mode == "release":
        # 永久地址：资产名首次生成后不变，无需删旧文件
        cfg["current_outputs"] = list(publish_paths(cfg).values())
    elif token != prev_token:
        cfg["current_outputs"] = [rotated_name(b, token) for b in OUTPUT_BASENAMES]

    # 删除过期输出文件（模式切换残留 / 上一轮换周期的真实输出）
    # F4 加固：只删两类合法位置的文件——.publish/ 内（release 模式资产）
    # 或仓库根级纯 basename（rotate 模式轮换名 clean_clash.<token>.yaml）。
    # stale_outputs 来自持久化配置，若被注入 ../ 或绝对路径，防止 os.remove
    # 落到这些位置之外。
    _pub = os.path.realpath(PUBLISH_DIR)
    _root = os.path.realpath(os.getcwd())
    for f in cfg.get("stale_outputs", []):
        try:
            fs = str(f)
            real = os.path.realpath(fs)
            parent = os.path.dirname(real)
            if parent not in (_pub, _root):
                continue
            if os.path.exists(fs):
                os.remove(fs)
        except OSError:
            pass

    save_config(cfg)
    return cfg


def bait_fingerprints(cfg: dict, fingerprint_fn: Callable[[dict], str]) -> set[str]:
    """最近若干轮全部诱饵节点的指纹集合（供主流程比对源内节点）。"""
    fps: set[str] = set()
    for h in cfg.get("bait_history", []):
        for p in h.get("nodes", []) if isinstance(h, dict) else []:
            try:
                fps.add(fingerprint_fn(p))
            except Exception:
                continue
    return fps


# ====================== robots.txt ======================

ROBOTS_TEMPLATE = """# proxysub anti-crawl
# 本仓库内容为个人自用的节点聚合，请勿抓取、索引或镜像。
User-agent: *
Disallow: /
"""


def robots_text() -> str:
    return ROBOTS_TEMPLATE


def write_robots(directory: str = ".") -> str:
    path = os.path.join(directory, ROBOTS_FILE)
    with open(path, "w", encoding="utf-8") as f:
        f.write(robots_text())
    return path


# ====================== Step Summary ======================

def summary_lines(cfg: dict) -> list[str]:
    """GitHub Actions Step Summary 用（仅仓库所有者可见，真实地址只出现在这里）。"""
    lines = [
        "## 反爬状态（真实地址仅本页可见，请勿外传）",
        "",
    ]
    if publish_mode(cfg):
        lines.append(
            f"- 模式：诱饵分流 + 滚动 Release 永久地址（tag `{cfg.get('release_tag', DEFAULT_RELEASE_TAG)}`，"
            f"固定名 raw 文件为诱饵内容 {len(cfg.get('bait_nodes', []))} 个）")
        lines.append("- **永久订阅地址（一次复制，永久有效，不会变）**：")
        lines += [f"  - `{u}`" for u in release_urls(cfg)]
    else:
        lines.append(
            f"- 模式：诱饵分流 + 文件名轮换（每 {cfg.get('rotate_days', DEFAULT_ROTATE_DAYS)} 天，"
            f"当前 token `{cfg.get('token', '')}`，过期链接自动失效）")
        lines.append("- 当前订阅地址：")
        lines += [f"  - `{u}`" for u in real_output_urls(cfg)]
    if cfg.get("stale_outputs"):
        lines.append(f"- 已过期的旧地址（已删除）：{', '.join(cfg['stale_outputs'])}")
    return lines


def real_output_urls(cfg: dict, repo: str | None = None) -> list[str]:
    """rotate 模式下的当前真实输出 raw 地址。"""
    repo = repo or os.environ.get("GITHUB_REPOSITORY") or "OWNER/REPO"
    return [f"https://raw.githubusercontent.com/{repo}/main/{p}"
            for p in cfg.get("current_outputs", []) if p]


__all__: list[Any] = [
    "CONFIG_FILE", "ROBOTS_FILE", "PUBLISH_DIR", "OUTPUT_BASENAMES", "BAIT_TAG",
    "default_config", "load_config", "save_config", "is_enabled", "publish_mode",
    "rotate_token", "rotated_name", "make_namer", "real_output_urls", "epoch_of",
    "asset_name", "publish_paths", "release_urls",
    "gen_decoy_nodes", "build_decoy_config", "write_decoy_outputs",
    "begin_run", "bait_fingerprints", "robots_text", "write_robots", "summary_lines",
]
