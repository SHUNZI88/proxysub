#!/usr/bin/env python3
"""多渠道订阅源 / 节点搜集（Telegram 频道 · 网页 · 手工静态源）。

设计要点
--------
- **与 sources_manager / common 解耦**：本模块仅依赖 ``safe_io`` + ``requests`` +
  标准库，因此 ``sources_manager`` 可安全 ``import channels`` 而不会产生循环依赖
  （``common`` 是架构叶子，也不反向依赖本模块）。
- 搜集到的「订阅源 URL」与 GitHub 自动发现走**同一套**候选 → 试用期 → 淘汰流程
  （由 ``sources_manager`` 负责晋升/降级），因此天然继承蜜罐检测、配额、上限等防护。
- 搜集到的「原始节点分享链接」(vmess/vless/trojan/ss) 写入 ``collected_nodes.txt``，
  主流程会将其 ingest 后经过同样的静态门槛与死活闸门清洗，最终只保留白名单协议且
  通过拨测的节点。
- 所有外部抓取均带超时与限流，失败时跳过并记入报告，**绝不影响主流程**。

配置见 ``channels.json``（默认空列表，由用户按渠道填充）。
"""

from __future__ import annotations

import os
import re
import time
from datetime import date, timedelta
from typing import Any, Callable

import requests

from safe_io import load_json
from net_safety import safe_http_get


CHANNELS_FILE = "channels.json"
COLLECTED_NODES_FILE = "collected_nodes.txt"

# ---- knobs ----
CHANNEL_MAX_NEW = 10               # 所有渠道每轮新增候选源上限
CHANNEL_MAX_PER_SOURCE = 3         # 单个频道 / 网页每轮最多取几个候选 URL
CHANNEL_FETCH_TIMEOUT = 25
CHANNEL_SCAN_ANCHORS = 300         # 每页最多扫描的 <a href> / 文本 URL 数
CHANNEL_MIN_NODES = 20             # 候选源需解析出至少这么多节点（与 GitHub 路径一致）
TELEGRAM_SLEEP = 3.0               # Telegram 限流（t.me/s 易被限流）
WEB_SLEEP = 1.5
CHANNEL_PROBATION_RUNS = 3         # 渠道候选源试用期（与正常候选一致）
MAX_COLLECTED_NODES = 5000         # collected_nodes.txt 保留上限（行）

# ---- URL 提取 / 归一化 ----
# 抓取页面里的全部 http(s) URL（含 href 与裸文本），再做订阅源判定。
URL_RE = re.compile(r'https?://[^\s"\'<>)\]]+', re.I)
# 原始节点分享链接：vmess/vless/trojan/ss
NODE_LINK_RE = re.compile(r'(?:vmess|vless|trojan|ss)://[^\s"\']+', re.I)
# github.com/<owner>/<repo>/(blob|raw)/<branch>/<path> → raw.githubusercontent.com
GITHUB_RE = re.compile(r'https?://github\.com/([^/]+)/([^/]+)/(?:blob|raw)/([^/]+)/(.+)', re.I)
YAML_EXT_RE = re.compile(r'\.(ya?ml|txt|json)$', re.I)
# 订阅端点常含的路径 / 主机关键字（含糊其辞的 token 式短链可能漏判，由 fetch 校验兜底）
SUB_PATH_RE = re.compile(
    r'(clash|mihomo|meta|subscribe|sub|v2ray|proxy|proxies|node|nodes|list|api|raw|feed|subscription)',
    re.I,
)

UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    )
}


def _today() -> str:
    return date.today().isoformat()


def _norm_url(url: str) -> str | None:
    """归一化：github blob/raw → raw.githubusercontent、去尾部标点与 #fragment。

    同时去除中英文尾部标点（Telegram / 网页消息常带全角句号「。」或括号）。
    """
    url = url.strip().rstrip(".,;。，；、）)")
    if not url.startswith("http"):
        return None
    m = GITHUB_RE.match(url)
    if m:
        owner, repo, branch, path = m.groups()
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
    if "#" in url:
        url = url.split("#", 1)[0]
    return url or None


def _looks_like_sub(url: str) -> bool:
    """启发式：是否为「订阅源」而非普通网页 / 图片 / 社交帖。"""
    if GITHUB_RE.search(url):
        return YAML_EXT_RE.search(url) is not None
    if YAML_EXT_RE.search(url) and SUB_PATH_RE.search(url):
        return True
    return SUB_PATH_RE.search(url) is not None


def _repo_of(url: str) -> str | None:
    m = re.match(r"https://raw\.githubusercontent\.com/([^/]+/[^/]+)/", url)
    return m.group(1).lower() if m else None


def _recently_removed(sources: dict, url: str) -> bool:
    cutoff = (date.today() - timedelta(days=30)).isoformat()
    return any(
        r.get("url") == url and r.get("date", "") >= cutoff
        for r in sources.get("removed", [])
    )


def _denied(deny: set, url: str) -> bool:
    repo = _repo_of(url)
    return bool(repo and repo in deny)


def load_channels() -> dict:
    data = load_json(CHANNELS_FILE, None)
    if not isinstance(data, dict):
        data = {}
    data.setdefault("enabled", True)
    data.setdefault("telegram", [])
    data.setdefault("web", [])
    data.setdefault("static_sources", [])
    return data


def _make_candidate(channel: str, kind: str) -> dict:
    return {
        "channel": f"{kind}:{channel}",
        "origin": f"channel_{kind}",
        "added": _today(),
        "first_seen": _today(),
        "runs": 0,
        "good_streak": 0,
        "fail_streak": 0,
        "history": [],
        "required_runs": CHANNEL_PROBATION_RUNS,
    }


def _validate_candidate(url: str, parse_fn: Callable[[str], list[dict]]) -> tuple[bool, str]:
    """抓取并以 parse_fn 校验节点数是否达标；返回 (ok, 原因)。"""
    try:
        r = safe_http_get(url, timeout=CHANNEL_FETCH_TIMEOUT, headers=UA)
    except Exception as e:
        return False, f"fetch:{e}"
    if r.status_code != 200:
        return False, f"http{r.status_code}"
    charset = r.encoding
    if not charset or charset.lower() in ("iso-8859-1", "latin-1", "latin1"):
        charset = r.apparent_encoding or "utf-8"
    try:
        text = r.content.decode(charset, errors="ignore")
    except Exception:
        text = r.text
    try:
        n = len(parse_fn(text))
    except Exception:
        n = 0
    if n < CHANNEL_MIN_NODES:
        return False, f"nodes={n}"
    return True, ""


def _append_node_links(links: set[str]) -> int:
    """将原始节点分享链接去重合并进 collected_nodes.txt（原子写），返回新增行数。"""
    existing: list[str] = []
    if os.path.exists(COLLECTED_NODES_FILE):
        try:
            with open(COLLECTED_NODES_FILE, encoding="utf-8") as f:
                existing = [l.strip() for l in f if l.strip()]
        except Exception:
            existing = []
    merged = list(dict.fromkeys(existing + list(links)))
    added = len(merged) - len(existing)
    if len(merged) > MAX_COLLECTED_NODES:
        merged = merged[-MAX_COLLECTED_NODES:]
    tmp = COLLECTED_NODES_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(merged) + "\n")
    os.replace(tmp, COLLECTED_NODES_FILE)
    return added


def _extract_sub_and_nodes(html: str) -> tuple[set[str], set[str]]:
    """从页面文本提取订阅源 URL 集合与原始节点链接集合。"""
    subs: set[str] = set()
    nodes: set[str] = set()
    for raw in URL_RE.findall(html)[:CHANNEL_SCAN_ANCHORS]:
        nu = _norm_url(raw)
        if nu and _looks_like_sub(nu):
            subs.add(nu)
    for m in NODE_LINK_RE.findall(html):
        nodes.add(m.strip())
    return subs, nodes


def discover_telegram(
    sources: dict, cands: dict, parse_fn: Callable[[str], list[dict]],
    known: set, deny: set, log: Callable[[str], None], budget: dict,
) -> dict:
    """抓取配置的 Telegram 频道公开消息（t.me/s/<频道>），提取订阅源与节点链接。"""
    rep = {"channels_scanned": 0, "urls_found": 0, "added": [], "rejected": {}, "errors": [], "nodes": 0}
    cfg = load_channels()
    for ch in cfg.get("telegram", []):
        if budget["left"] <= 0:
            break
        ch = ch.strip().lstrip("@")
        if not ch:
            continue
        rep["channels_scanned"] += 1
        url = f"https://t.me/s/{ch}"
        try:
            r = safe_http_get(url, timeout=CHANNEL_FETCH_TIMEOUT, headers=UA)
        except Exception as e:
            rep["errors"].append(f"{ch}: {e}")
            time.sleep(TELEGRAM_SLEEP)
            continue
        if r.status_code != 200 or "tgme_widget_message" not in r.text:
            rep["errors"].append(f"{ch}: http{r.status_code}/no_messages")
            time.sleep(TELEGRAM_SLEEP)
            continue
        subs, nodes = _extract_sub_and_nodes(r.text)
        rep["urls_found"] += len(subs)
        if nodes:
            rep["nodes"] += _append_node_links(nodes)
        picked = 0
        for u in sorted(subs):
            if budget["left"] <= 0 or picked >= CHANNEL_MAX_PER_SOURCE:
                break
            if u in known or _recently_removed(sources, u) or _denied(deny, u):
                continue
            ok, why = _validate_candidate(u, parse_fn)
            if not ok:
                rep["rejected"][u] = why
                continue
            cands["candidates"][u] = _make_candidate(ch, "telegram")
            known.add(u)
            budget["left"] -= 1
            picked += 1
            rep["added"].append(u)
            log(f"[Telegram@{ch}] 发现候选源: {u}")
        time.sleep(TELEGRAM_SLEEP)
    return rep


def discover_web(
    sources: dict, cands: dict, parse_fn: Callable[[str], list[dict]],
    known: set, deny: set, log: Callable[[str], None], budget: dict,
) -> dict:
    """抓取配置的网页，提取订阅源 URL 与节点链接（博客 / 聚合页 / 论坛帖等）。"""
    rep = {"pages_scanned": 0, "urls_found": 0, "added": [], "rejected": {}, "errors": [], "nodes": 0}
    cfg = load_channels()
    for page in cfg.get("web", []):
        if budget["left"] <= 0:
            break
        page = page.strip()
        if not page.startswith("http"):
            continue
        rep["pages_scanned"] += 1
        try:
            r = safe_http_get(page, timeout=CHANNEL_FETCH_TIMEOUT, headers=UA)
        except Exception as e:
            rep["errors"].append(f"{page}: {e}")
            time.sleep(WEB_SLEEP)
            continue
        if r.status_code != 200:
            rep["errors"].append(f"{page}: http{r.status_code}")
            time.sleep(WEB_SLEEP)
            continue
        charset = r.encoding
        if not charset or charset.lower() in ("iso-8859-1", "latin-1", "latin1"):
            charset = r.apparent_encoding or "utf-8"
        try:
            html = r.content.decode(charset, errors="ignore")
        except Exception:
            html = r.text
        subs, nodes = _extract_sub_and_nodes(html)
        rep["urls_found"] += len(subs)
        if nodes:
            rep["nodes"] += _append_node_links(nodes)
        picked = 0
        for u in sorted(subs):
            if budget["left"] <= 0 or picked >= CHANNEL_MAX_PER_SOURCE:
                break
            if u in known or _recently_removed(sources, u) or _denied(deny, u):
                continue
            ok, why = _validate_candidate(u, parse_fn)
            if not ok:
                rep["rejected"][u] = why
                continue
            cands["candidates"][u] = _make_candidate(page, "web")
            known.add(u)
            budget["left"] -= 1
            picked += 1
            rep["added"].append(u)
            log(f"[Web] 发现候选源: {u}")
        time.sleep(WEB_SLEEP)
    return rep


def discover_channels(
    sources: dict, cands: dict, parse_fn: Callable[[str], list[dict]],
    log: Callable[[str], None] = print,
) -> dict:
    """多渠道搜集总入口：静态源（直接转正）→ Telegram → 网页。

    返回报告 dict，并就地修改 ``sources``（静态源转正）与 ``cands``（新增候选）。
    """
    report = {"telegram": {}, "web": {}, "static_added": [], "static_rejected": {},
              "nodes_collected": 0, "added": []}
    cfg = load_channels()
    if os.environ.get("PROXYSUB_DISCOVERY", "1") == "0" or not cfg.get("enabled", True):
        log("多渠道搜集已关闭 (PROXYSUB_DISCOVERY=0 或 channels.json enabled=false)")
        return report

    known = (
        {s["url"] for s in sources.get("official", []) if s.get("url")}
        | set(cands.get("candidates", {}))
        | set(cands.get("rejected", {}))
    )
    deny = {d.lower() for d in sources.get("deny_repos", [])}
    budget = {"left": CHANNEL_MAX_NEW}

    # 1) 手工静态源：用户从任意渠道搜集到的源可直接粘到 channels.json，等同手工源直接转正
    for u in cfg.get("static_sources", []):
        u = _norm_url(u)
        if not u:
            continue
        if any(s.get("url") == u for s in sources.get("official", [])):
            continue
        if _recently_removed(sources, u) or _denied(deny, u):
            continue
        ok, why = _validate_candidate(u, parse_fn)
        if not ok:
            report["static_rejected"][u] = why
            continue
        sources["official"].append({"url": u, "origin": "static_channel", "added": _today()})
        report["static_added"].append(u)
        report["added"].append(u)
        log(f"[static] 加入正式源: {u}")

    # 2) Telegram 频道
    tg = discover_telegram(sources, cands, parse_fn, known, deny, log, budget)
    report["telegram"] = tg
    report["added"].extend(tg["added"])
    report["nodes_collected"] += tg.get("nodes", 0)

    # 3) 网页
    wb = discover_web(sources, cands, parse_fn, known, deny, log, budget)
    report["web"] = wb
    report["added"].extend(wb["added"])
    report["nodes_collected"] += wb.get("nodes", 0)

    return report
