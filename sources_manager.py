#!/usr/bin/env python3
"""Subscription source lifecycle for proxysub.

official (sources.json)  <-- promote --  candidates (candidate_sources.json)  <-- discover -- GitHub search
        |                                         |
        +-- demote (failures / zero contribution / honeypot / cap) --> removed (cooldown)
"""

from __future__ import annotations

import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote

import requests

import channels  # 多渠道搜集（Telegram / 网页 / 手工静态源）；本模块不反向依赖 sources_manager，无循环
import config  # CN_* 源级中国实测反哺常量（叶子模块，无循环）
from common import wilson_ci  # Wilson 95% 区间（唯一实现，与沙箱侧共用）
from net_safety import safe_http_get  # SSRF 防护抓取（安全评估 F1）
from safe_io import load_json, save_json  # 原子化读写；save_json 亦为测试/调用方接缝（sm.save_json）

SOURCES_FILE = "sources.json"
CANDIDATES_FILE = "candidate_sources.json"
SOURCE_SCORES_FILE = "source_scores.json"

# ---- lifecycle knobs ----
MAX_OFFICIAL = 30
MAX_PROMOTIONS_PER_RUN = 2
PROBATION_RUNS = 3            # consecutive good runs needed (normal reputation)
PROBATION_RUNS_LOW_REP = 5    # low-star / young repos are held longer
PROBATION_MAX_RUNS = 16       # give up on a candidate after this many runs w/o promotion
CANDIDATE_MAX_FAILS = 3
# 活跃候选窗口（2026-10-20 15→20）：实测候选池曾枯竭到仅 2 个（46 个被拒），
# 15 槽窗口大量空转、发现的新源排队等待无意义。窗口即每轮实际拉取+拨测的
# 候选源数，提高到 20 让新发现更快进入试用（每源仅多 1 次 HTTP 拉取；
# 拨测预算 980 + 20/候选源，同步扩容）。
MAX_ACTIVE_CANDIDATES = 20
MIN_CANDIDATE_USABLE = 5      # usable (real-probe ok) nodes per run
MIN_CANDIDATE_UNIQUE = 4      # of which not already offered by official sources
OFFICIAL_FAIL_DEMOTE = 4      # consecutive failed runs (= ~24h at 6h cadence)
OFFICIAL_ZERO_UNIQUE_DEMOTE = 16  # consecutive runs w/o unique alive node (= ~4 days)
OFFICIAL_ZERO_REAL_DEMOTE = 4     # consecutive runs with probes but 0 real-ok (= ~1 day)
REMOVED_COOLDOWN_DAYS = 30

# ---- discovery knobs ----
# 每轮新候选 10→15（2026-10-20）：用户反馈有效节点数长期停在 29，根因之一是
# 输入池窄（官方源仅 11/30、候选池枯竭至 2 个）——免费节点池绝对死亡率 97%
# 的硬现实下，只有扩大源头吞吐才能提高期望产出。配套 DISCOVERY_MAX_REPOS
# 20→25：15 个新候选需要更多仓库树 lookup 才能凑齐（大量仓库树无目标文件
# 或解析不足 CANDIDATE_MIN_NODES，按 looked 计数会提前触顶）。
DISCOVERY_MAX_NEW = 15        # new candidates per run
DISCOVERY_MAX_REPOS = 25      # repo tree lookups per run
DISCOVERY_QUERIES_PER_RUN = 4
DISCOVERY_PUSHED_DAYS = 3
REPO_MIN_AGE_DAYS = 7
REPO_LOW_REP_STARS = 5
REPO_LOW_REP_AGE_DAYS = 60
CANDIDATE_MIN_NODES = 20
MAX_FILE_BYTES = 8 * 1024 * 1024

# 发现查询词（2026-10-20 由 8 扩至 16）：原 8 词聚焦 clash/v2ray 英文站，
# 漏掉中文社区主流命名（clashnode / nodefree / 免费机场 / 节点分享）。GitHub
# 仓库搜索匹配名称/描述/README；「免费机场」等词会命中招商站——由
# repo_reputation 的 SPAM_RE（招商/推广/卖号关键词）拒收，节点内容另有
# CANDIDATE_MIN_NODES + 蜜罐/篡改检测把关。轮换周期不变：每轮 4 词、
# 槽位每 6h 推进，16 词 4 轮（24h）全覆盖。
DISCOVERY_QUERIES = [
    "clash free nodes",
    "free clash subscribe",
    "mihomo free proxies",
    "proxypool clash",
    "免费节点 clash",
    "v2ray free subscription",
    "free vpn subscriptions clash",
    "AutoMergePublicNodes",
    # ---- 2026-10-20 扩容：中文社区主流命名 + 更宽的英文同义 ----
    "clashnode",
    "nodefree",
    "免费机场 clash",
    "免费节点分享",
    "free proxy list",
    "free clash config",
    "v2ray free nodes",
    "merge public nodes",
]
CODE_QUERIES = [
    "proxies filename:list.meta.yml",
    "proxies filename:mihomo.yaml",
    "proxies filename:clash.yaml path:/",
]
TARGET_FILE_RE = re.compile(
    r"(^|/)((clash|mihomo|meta|proxies|nodes?|sub|list\.meta|clash[-_]?meta|speednodes|clash_config)[^/]*\.ya?ml)$",
    re.I,
)
SKIP_PATH_RE = re.compile(r"(^|/)(\.github|docs?|test|tests|example|examples|rules?|ruleset|template|templates)/", re.I)
SPAM_RE = re.compile(
    r"(airdrop|casino|gambl|博彩|赌|贷款|loan|porn|色情|成人|crypto ?wallet|giveaway|"
    r"破解|cracked|keygen|hack ?tool|免费领|返利|推广|加群|代理招商|telegram ?bot ?sell)",
    re.I,
)


def _today() -> str:
    return date.today().isoformat()


# load_json / save_json 统一由 safe_io 提供（原子写入 + 文件锁 + 损坏自愈）。


# ====================== sources.json ======================

def load_sources(fallback_urls: list[str] | None = None) -> dict:
    data = load_json(SOURCES_FILE, None)
    if not isinstance(data, dict) or not isinstance(data.get("official"), list):
        data = {
            "max_official": MAX_OFFICIAL,
            "official": [
                {"url": u, "origin": "manual", "added": _today()} for u in (fallback_urls or [])
            ],
            "removed": [],
            "deny_repos": [],
        }
    data.setdefault("max_official", MAX_OFFICIAL)
    data.setdefault("removed", [])
    data.setdefault("deny_repos", [])
    return data


def official_urls(sources: dict) -> list[str]:
    return [s["url"] for s in sources["official"] if s.get("url")]


def load_candidates() -> dict:
    data = load_json(CANDIDATES_FILE, None)
    if not isinstance(data, dict):
        data = {}
    data.setdefault("candidates", {})
    data.setdefault("rejected", {})
    return data


def active_candidate_urls(cands: dict) -> list[str]:
    items = sorted(cands["candidates"].items(), key=lambda kv: kv[1].get("first_seen", ""))
    return [u for u, _ in items[:MAX_ACTIVE_CANDIDATES]]


def _recently_removed(sources: dict, url: str) -> bool:
    cutoff = (date.today() - timedelta(days=REMOVED_COOLDOWN_DAYS)).isoformat()
    return any(r.get("url") == url and r.get("date", "") >= cutoff for r in sources.get("removed", []))


def _repo_of(url: str) -> str | None:
    m = re.match(r"https://raw\.githubusercontent\.com/([^/]+/[^/]+)/", url)
    return m.group(1).lower() if m else None


def _age_s(ts) -> float:
    """ISO8601 时间戳距今年秒数；缺失/不可解析返回 1e18（视为永不新鲜）。"""
    if not ts:
        return 1e18
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    except Exception:
        return 1e18
    return (datetime.now(timezone.utc) - dt).total_seconds()


def _cn_window(url: str, cn_stats: dict) -> tuple[int, int, bool]:
    """提取源级 cn 实证窗口（tested, passed, 样本充足且新鲜）。

    样本不足（< CN_MIN_SAMPLE）或数据陈旧（> CN_DECISION_MAX_AGE_S）时
    fresh=False——调用方按「无实证」处理：淘汰侧清零 streak（宁可少汰），
    守卫侧不放行（宁可不豁免）。
    """
    cn = (cn_stats or {}).get(url) or {}
    tested = int(cn.get("cn_tested") or 0)
    passed = int(cn.get("cn_passed") or 0)
    fresh = (tested >= config.CN_MIN_SAMPLE
             and _age_s(cn.get("cn_last")) <= config.CN_DECISION_MAX_AGE_S)
    return tested, passed, fresh


def _cn_low_evidence(url: str, cn_stats: dict) -> tuple[bool, float, int, int]:
    """源级低产实证判定（cn 维度，2026-10-20 新增决策层）。

    返回 (判低, wilson 下界, tested, passed)。判 False 的所有情形（样本不足 /
    数据陈旧 / 无 cn 记录）都视为"无实证"——调用方据此**清零** streak（保守
    方向：宁可少汰，不可误汰）。

    判据：cn_tested >= config.CN_MIN_SAMPLE 且 Wilson 95% **下界** <
    config.CN_LOW_CI_HIGH。零通过源天然适用（0/n 下界恒 0）。
    """
    tested, passed, fresh = _cn_window(url, cn_stats)
    if not fresh:
        return False, 0.0, tested, passed
    lo, _ = wilson_ci(passed, tested)
    return lo < config.CN_LOW_CI_HIGH, lo, tested, passed


def _cn_effective_evidence(url: str, cn_stats: dict) -> tuple[bool, float, int, int]:
    """源级「有实效」实证判定（cn 维度，2026-10-21 任务#93 反哺口径）。

    与 `_cn_low_evidence` 共用同一证据窗口，但只认**样本充足且新鲜、
    且 Wilson 下界 >= CN_LOW_CI_HIGH** 为「有实效」：样本不足/陈旧/无记录
    都返回 False（无实证——守卫不放行，无效源仍由 zero_real_ok /
    fail_streak / cn_low 通道淘汰）。

    用途：零独有淘汰（proxy 指标：连续 N 轮无独有存活节点）不得误汰有
    实证高效率的源。2026-10-16 事故：blog.ermao.net cn 通过率 12.3%
    （16/130，全池第二高）因 zero_unique_contribution:16runs 被汰——
    用独有性代理指标淘汰了有效源（其节点与其他聚合源重复，去重后仍在
    池中，但方法学错误真实存在）。用户口径：源的生命周期必须由**节点
    有效性**反哺，而非代理指标。
    """
    tested, passed, fresh = _cn_window(url, cn_stats)
    if not fresh:
        return False, 0.0, tested, passed
    lo, _ = wilson_ci(passed, tested)
    return lo >= config.CN_LOW_CI_HIGH, lo, tested, passed


# ====================== GitHub discovery ======================

class GitHub:
    def __init__(self, token: str | None):
        self.s = requests.Session()
        self.s.headers.update({
            "Accept": "application/vnd.github+json",
            "User-Agent": "proxysub-discovery/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        if token:
            self.s.headers["Authorization"] = f"Bearer {token}"
        self.exhausted = False
        self.calls = 0
        self.errors: list[str] = []

    def get(self, path: str, params: dict | None = None) -> Any:
        """GET with rate-limit awareness; at most 2 attempts."""
        if self.exhausted:
            return None
        for attempt in (1, 2):
            try:
                self.calls += 1
                r = self.s.get(f"https://api.github.com{path}", params=params, timeout=20)
            except Exception as e:
                self.errors.append(f"{path}: {e}")
                time.sleep(2)
                continue
            remaining = r.headers.get("X-RateLimit-Remaining")
            if r.status_code in (403, 429):
                if remaining == "0" or "rate limit" in r.text.lower():
                    self.exhausted = True
                    self.errors.append(f"rate_limited at {path}")
                    return None
                self.errors.append(f"{path}: HTTP {r.status_code}")
                return None
            if r.status_code >= 500 and attempt == 1:
                time.sleep(3)
                continue
            if r.status_code != 200:
                self.errors.append(f"{path}: HTTP {r.status_code}")
                return None
            if remaining is not None and remaining.isdigit() and int(remaining) <= 2:
                self.exhausted = True  # leave headroom; use this response though
            return r.json()
        return None


def repo_reputation(repo: dict) -> tuple[str, str]:
    """Return (verdict, reason) where verdict in ok/low/reject."""
    if repo.get("fork"):
        return "reject", "fork"
    if repo.get("archived") or repo.get("disabled"):
        return "reject", "archived"
    text = " ".join([
        repo.get("full_name") or "", repo.get("description") or "", " ".join(repo.get("topics") or []),
    ])
    if SPAM_RE.search(text):
        return "reject", "spam_keywords"
    try:
        created = datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - created).days
    except Exception:
        age_days = 0
    stars = int(repo.get("stargazers_count") or 0)
    if age_days < REPO_MIN_AGE_DAYS:
        return "reject", f"too_new:{age_days}d"
    if stars == 0 and age_days < REPO_LOW_REP_AGE_DAYS:
        return "reject", "zero_stars_young"
    if stars < REPO_LOW_REP_STARS or age_days < REPO_LOW_REP_AGE_DAYS:
        return "low", f"stars={stars},age={age_days}d"
    return "ok", f"stars={stars},age={age_days}d"


def queries_for_slot(slot: int) -> list[str]:
    """按 6h 槽位轮换查询词（纯函数）：每轮 DISCOVERY_QUERIES_PER_RUN 个。

    全量查询词在 len(DISCOVERY_QUERIES)/PER_RUN 个槽位（6h 节奏下即 24h）
    内覆盖一遍、不重不漏——前提是词表长度是 PER_RUN 的整数倍（16%4==0），
    该不变量由 test_query_rotation_covers_all_queries_in_one_day 锁定。
    """
    return [DISCOVERY_QUERIES[(slot * DISCOVERY_QUERIES_PER_RUN + i)
                              % len(DISCOVERY_QUERIES)]
            for i in range(DISCOVERY_QUERIES_PER_RUN)]


def discover(
    sources: dict,
    cands: dict,
    parse_fn: Callable[[str], list[dict]],
    token: str | None,
    log: Callable[[str], None] = print,
) -> dict:
    """Search GitHub for fresh subscription files; add up to DISCOVERY_MAX_NEW candidates."""
    report = {"searched_repos": 0, "added": [], "rejected": {}, "api_calls": 0, "errors": []}
    if os.environ.get("PROXYSUB_DISCOVERY", "1") == "0":
        log("自动发现已关闭 (PROXYSUB_DISCOVERY=0)")
        return report
    gh = GitHub(token)
    known = set(official_urls(sources)) | set(cands["candidates"]) | set(cands["rejected"])
    known_repos = {_repo_of(u) for u in known if _repo_of(u)}
    deny = {d.lower() for d in sources.get("deny_repos", [])}
    # 排除自己：搜索可能命中本仓库（反爬开启时固定名文件是诱饵，自收录会触发
    # bait_reuse 拒绝而浪费发现名额），直接跳过。
    own = (os.environ.get("GITHUB_REPOSITORY") or "").lower()
    since = (date.today() - timedelta(days=DISCOVERY_PUSHED_DAYS)).isoformat()

    # rotate queries across runs so each run spends few search calls
    slot = int(time.time() // (6 * 3600))
    qs = queries_for_slot(slot)

    repos: dict[str, dict] = {}
    for q in qs:
        data = gh.get("/search/repositories", {
            "q": f"{q} pushed:>={since}", "sort": "updated", "order": "desc", "per_page": 15,
        })
        for item in (data or {}).get("items", []):
            repos.setdefault(item["full_name"].lower(), item)
        time.sleep(2.2)  # search API: 30 req/min authenticated

    # one code-search query per run (may be unavailable to some tokens; ignored on error)
    if token:
        cq = CODE_QUERIES[slot % len(CODE_QUERIES)]
        data = gh.get("/search/code", {"q": cq, "per_page": 20})
        for item in (data or {}).get("items", []):
            repo = item.get("repository") or {}
            full = (repo.get("full_name") or "").lower()
            if full and full not in repos:
                repos[full] = {"_needs_meta": True, "full_name": repo.get("full_name")}

    ranked = sorted(repos.items(), key=lambda kv: -int(kv[1].get("stargazers_count") or 0))
    added = 0
    looked = 0
    for full, repo in ranked:
        if added >= DISCOVERY_MAX_NEW or looked >= DISCOVERY_MAX_REPOS or gh.exhausted:
            break
        if full in known_repos or full in deny or (own and full == own):
            continue
        if repo.get("_needs_meta"):
            repo = gh.get(f"/repos/{repo['full_name']}") or {}
            if not repo:
                continue
        verdict, why = repo_reputation(repo)
        if verdict == "reject":
            report["rejected"][full] = why
            continue
        looked += 1
        branch = repo.get("default_branch") or "main"
        tree = gh.get(f"/repos/{repo['full_name']}/git/trees/{quote(branch)}", {"recursive": "1"})
        if not tree:
            continue
        files = [
            t for t in tree.get("tree", [])
            if t.get("type") == "blob"
            and TARGET_FILE_RE.search(t.get("path", ""))
            and not SKIP_PATH_RE.search(t.get("path", ""))
            and 1024 <= int(t.get("size") or 0) <= MAX_FILE_BYTES
        ]
        files.sort(key=lambda t: (t["path"].count("/"), -int(t.get("size") or 0)))
        for f in files[:2]:
            url = f"https://raw.githubusercontent.com/{repo['full_name']}/{quote(branch)}/{quote(f['path'])}"
            if url in known or _recently_removed(sources, url):
                continue
            try:
                r = safe_http_get(url, timeout=20, headers={"User-Agent": "proxysub-discovery/1.0"})
                n = len(parse_fn(r.text)) if r.status_code == 200 else 0
            except Exception:
                n = 0
            if n < CANDIDATE_MIN_NODES:
                continue
            cands["candidates"][url] = {
                "repo": repo["full_name"],
                "stars": int(repo.get("stargazers_count") or 0),
                "repo_created": repo.get("created_at"),
                "reputation": verdict,
                "reputation_note": why,
                "required_runs": PROBATION_RUNS_LOW_REP if verdict == "low" else PROBATION_RUNS,
                "first_seen": _today(),
                "initial_nodes": n,
                "runs": 0,
                "good_streak": 0,
                "fail_streak": 0,
                "history": [],
            }
            known.add(url)
            report["added"].append(url)
            added += 1
            log(f"发现候选源: {url} ({n} 节点, {why})")
            if added >= DISCOVERY_MAX_NEW:
                break
    report["searched_repos"] = len(repos)
    report["api_calls"] = gh.calls
    report["errors"] = gh.errors[:10]

    # ---- 多渠道搜集（Telegram 频道 / 网页 / 手工静态源）----
    # 与 GitHub 发现共享同一套候选→试用期→淘汰流程；任何异常都不影响主流程。
    try:
        ch = channels.discover_channels(sources, cands, parse_fn, log)
        report["channels"] = ch
        report["added"].extend(ch["added"])
    except Exception as e:  # 多渠道为增强能力，失败绝不应阻断更新
        report["channels_error"] = f"{type(e).__name__}: {e}"
        log(f"多渠道搜集异常（已忽略）: {type(e).__name__}: {e}")

    return report


# ====================== probation / promotion / demotion ======================

def evaluate_candidates(cands: dict, run: dict[str, dict], sources: dict,
                        cn_stats: dict | None = None) -> dict:
    """run[url] = {ok, count, usable, unique_new, tamper, probed, flags}。

    `cn_stats`（可选，2026-10-20）：源级中国实测维度（格式同 update_official）。
    **只影响晋升排序**（ready.sort），不改晋升资格判定：有正向 cn 实证
    （cn_tested >= CN_MIN_SAMPLE_HIGH 且 cn_passed >= 1）的候选优先晋升，
    组内按 Wilson 95% **下界**降序（同点估计下样本大者下界更高、证据更硬，
    防 3/3 这类小样本虚高霸榜）；其余候选退化为按独有贡献降序。
    cn_stats=None / 无实证时键恒为 (1, 0.0, -uniq)，与改造前完全一致。
    """
    rep = {"promoted": [], "rejected": {}}
    ready = []
    for url, c in list(cands["candidates"].items()):
        r = run.get(url)
        if r is None:
            continue  # not active this run
        c["runs"] = int(c.get("runs", 0)) + 1
        good = bool(r.get("ok")) and r.get("usable", 0) >= MIN_CANDIDATE_USABLE \
            and r.get("unique_new", 0) >= MIN_CANDIDATE_UNIQUE
        c["fail_streak"] = 0 if r.get("ok") else int(c.get("fail_streak", 0)) + 1
        c["good_streak"] = int(c.get("good_streak", 0)) + 1 if good else 0
        c["history"] = (c.get("history", []) + [{
            "date": _today(), "count": r.get("count", 0), "usable": r.get("usable", 0),
            "unique_new": r.get("unique_new", 0), "tamper": r.get("tamper", 0),
        }])[-8:]
        reason = None
        # N2：与 update_official 保持一致——probed/tamper 统一 int() 兜底，
        # 避免上游显式传 None 时 max(1, None) / >= 比较抛 TypeError。
        tamper, probed = int(r.get("tamper") or 0), max(1, int(r.get("probed") or 0))
        if r.get("flags"):
            # 转载我们诱饵节点的源（爬虫/聚合站）直接拒绝，与蜜罐结构区分原因
            bait = [f for f in r["flags"] if "bait_reuse" in f]
            reason = ("redistributes_bait:" + ";".join(bait)) if bait \
                else ("honeypot_structure:" + ";".join(r["flags"]))
        elif tamper >= 3 or (tamper >= 1 and tamper / probed >= 0.2):
            reason = f"honeypot_tamper:{tamper}/{probed}"
        elif int(r.get("cf_blocked", 0)) >= 2 and int(r.get("cf_blocked", 0)) / probed >= 0.25:
            reason = f"cf_blocked:{r.get('cf_blocked')}/{probed}"
        elif c["fail_streak"] >= CANDIDATE_MAX_FAILS:
            reason = "fetch_failures"
        elif c["runs"] >= PROBATION_MAX_RUNS:
            reason = "no_stable_contribution"
        if reason:
            cands["rejected"][url] = {"reason": reason, "date": _today(), "repo": c.get("repo")}
            cands["candidates"].pop(url, None)
            rep["rejected"][url] = reason
            continue
        if c["good_streak"] >= int(c.get("required_runs", PROBATION_RUNS)):
            ready.append((url, c))

    def _promo_key(kv) -> tuple:
        url, c = kv
        uniq = sum(h.get("unique_new", 0) for h in c.get("history", []))
        cn = (cn_stats or {}).get(url) or {}
        tested = int(cn.get("cn_tested") or 0)
        passed = int(cn.get("cn_passed") or 0)
        if tested >= config.CN_MIN_SAMPLE_HIGH and passed >= 1:
            lo, _ = wilson_ci(passed, tested)
            return (0, -lo, -uniq)   # 有正向实证：Wilson 下界降序，再按独有贡献
        return (1, 0.0, -uniq)       # 无实证/小样本/零通过：原排序（独有贡献降序）

    ready.sort(key=_promo_key)
    for url, c in ready[:MAX_PROMOTIONS_PER_RUN]:
        sources["official"].append({
            "url": url, "origin": "discovered", "added": _today(), "repo": c.get("repo"),
            "probation_runs": c.get("runs"),
        })
        cands["candidates"].pop(url, None)
        rep["promoted"].append(url)
    # prune rejected older than cooldown so they may be rediscovered later
    cutoff = (date.today() - timedelta(days=REMOVED_COOLDOWN_DAYS)).isoformat()
    for u in [u for u, v in cands["rejected"].items() if v.get("date", "") < cutoff]:
        cands["rejected"].pop(u, None)
    return rep


def update_official(sources: dict, stats_hist: dict, run: dict[str, dict],
                    cn_stats: dict | None = None) -> dict:
    """Update per-source history and demote bad / surplus official sources.

    `cn_stats`（可选，2026-10-20）：`{url: {cn_tested, cn_passed, cn_pass_rate,
    cn_last}}` 源级中国实测维度（沙箱实证，见 evolution.cn_source_stats）。
    **非空**时启用 cn 淘汰决策层（与 CI 侧判据**并联**，任一命中即淘汰）：

      - 判低：cn_tested >= CN_MIN_SAMPLE 且 Wilson 95% 下界 < CN_LOW_CI_HIGH；
      - streak：连续 CN_DEMOTE_STREAK 轮判低才淘汰；无实证/样本不足/陈旧 → 清零
        （保守方向：宁可少汰，不可误汰）；
      - 三重保底：① origin=manual 手工源永不因 cn 淘汰；② 单轮最多
        MAX_CN_DEMOTE_PER_RUN 个；③ 淘汰后 official 不少于 MIN_OFFICIAL；
      - 淘汰即清零 streak（防 30 天冷却回迁的源被旧 streak 瞬杀）。

    零独有淘汰的有效性守卫（2026-10-21 任务#93）：zero_unique_streak 达标的
    源，若持有**充足且新鲜的 cn 实效实证**（Wilson 下界 >= CN_LOW_CI_HIGH，
    见 `_cn_effective_evidence`），不淘汰——记入 rep["guarded"]（含实证
    数字，供审计）。无实证时守卫 inert，行为与改造前一致。设计动机：零独有
    是代理指标（节点与其他源重复≠源无效），2026-10-16 曾据它汰掉 cn 通过率
    全池第二高的 blog.ermao.net；真正无效的源（零真实流量通过/连续抓取失败/
    cn 低产）由既有通道淘汰，不因守卫漏网。

    无实证（缺数据/样本不足/陈旧）时 cn 层整体 no-op，行为与改造前完全一致。
    """
    rep = {"demoted": {}, "guarded": {}}
    cn_candidates: list[tuple[str, float, int, int]] = []
    for entry in sources["official"]:
        url = entry.get("url")
        if not url:
            continue
        r = run.get(url, {})
        h = stats_hist.setdefault(url, {
            "runs": 0, "ok_runs": 0, "fail_streak": 0, "zero_unique_streak": 0,
            "zero_real_streak": 0, "ok_rate_ema": 1.0, "unique_ema": 0.0, "real_ema": 0.0,
        })
        ok = bool(r.get("ok"))
        h["runs"] += 1
        h["ok_runs"] += int(ok)
        h["fail_streak"] = 0 if ok else h.get("fail_streak", 0) + 1
        u = int(r.get("unique_alive", 0))
        h["zero_unique_streak"] = 0 if u > 0 else h.get("zero_unique_streak", 0) + 1
        probed_n = int(r.get("probed", 0))
        real_n = int(r.get("real_ok", 0))
        if probed_n >= 5:
            h["zero_real_streak"] = 0 if real_n > 0 else h.get("zero_real_streak", 0) + 1
        h["ok_rate_ema"] = round(0.8 * h.get("ok_rate_ema", 1.0) + 0.2 * (1.0 if ok else 0.0), 4)
        h["unique_ema"] = round(0.7 * h.get("unique_ema", 0.0) + 0.3 * u, 2)
        h["real_ema"] = round(0.7 * h.get("real_ema", 0.0) + 0.3 * real_n, 2)
        h["last"] = {"date": _today(), **{k: r.get(k) for k in ("count", "alive", "unique_alive", "real_ok", "probed", "tamper", "error")}}

        # ---- cn 维度 streak 维护（与 CI 侧判据独立；无实证即清零）----
        # cn_stats 为 None/空（功能关闭或无报告）时整段跳过：stats_hist 不新增
        # 任何键，降级行为与改造前逐字节一致。
        if cn_stats:
            low, lo, cn_t, cn_p = _cn_low_evidence(url, cn_stats)
            if low:
                h["cn_low_streak"] = int(h.get("cn_low_streak", 0)) + 1
                h["cn_low_last"] = {"date": _today(), "tested": cn_t, "passed": cn_p,
                                    "ci_low": round(lo, 4)}
            else:
                h["cn_low_streak"] = 0
                h.pop("cn_low_last", None)
        else:
            low, lo, cn_t, cn_p = False, 0.0, 0, 0

        reason = None
        tamper, probed = int(r.get("tamper", 0)), max(1, int(r.get("probed", 0)))
        # 转载我们诱饵节点的源（爬虫/聚合站盗用成果）立即淘汰
        if any("bait_reuse" in f for f in r.get("flags", [])):
            reason = "redistributes_bait"
        elif tamper >= 3 and tamper / probed >= 0.25:
            reason = f"honeypot_tamper:{tamper}/{probed}"
        elif int(r.get("cf_blocked", 0)) >= 4 and int(r.get("cf_blocked", 0)) / probed >= 0.3:
            reason = f"cf_blocked:{r.get('cf_blocked')}/{probed}"
        elif h["fail_streak"] >= OFFICIAL_FAIL_DEMOTE:
            reason = f"consecutive_failures:{h['fail_streak']}"
        elif h.get("zero_real_streak", 0) >= OFFICIAL_ZERO_REAL_DEMOTE:
            reason = f"zero_real_ok:{h['zero_real_streak']}runs"
        elif h["zero_unique_streak"] >= OFFICIAL_ZERO_UNIQUE_DEMOTE:
            # 有效性守卫（2026-10-21 任务#93）：零独有是**代理指标**——聚合源
            # 的节点与其他源重复（去重后仍在池中、仍可通过 cn 实测）不代表源
            # 无效。有 cn 实证（样本充足且新鲜、Wilson 下界 >= CN_LOW_CI_HIGH）
            # 的源豁免零独有淘汰；无实证的源仍可汰（真正无效的源由
            # zero_real_ok / fail_streak / cn_low 通道负责，不会漏网）。
            # 事故锚点：blog.ermao.net 12.3% 通过率（全池第二高）因零独有被汰。
            effective, lo, cn_t, cn_p = _cn_effective_evidence(url, cn_stats)
            if effective:
                rep["guarded"][url] = {
                    "guard": "zero_unique_guarded_by_cn_evidence",
                    "zero_unique_streak": h["zero_unique_streak"],
                    "cn_tested": cn_t, "cn_passed": cn_p,
                    "wilson_ci_low": round(lo, 4),
                }
            else:
                reason = f"zero_unique_contribution:{h['zero_unique_streak']}runs"
        # ---- cn 维度淘汰候选（streak 达标且非手工源；不在此刻生效，走三重保底）----
        if (reason is None and low
                and int(h.get("cn_low_streak", 0)) >= config.CN_DEMOTE_STREAK
                and entry.get("origin") != "manual"):
            cn_candidates.append((url, lo, cn_t, cn_p))
        if reason:
            rep["demoted"][url] = reason

    # ---- cn 维度淘汰决策：三重保底（单轮上限 / 保底数量 / 最劣优先）----
    if cn_candidates:
        keep_n = len(sources["official"]) - len(rep["demoted"])
        room = max(0, min(config.MAX_CN_DEMOTE_PER_RUN, keep_n - config.MIN_OFFICIAL))
        # 最劣优先：Wilson 下界升序（越接近 0 越劣），同下界则样本大者优先（证据更硬）
        cn_candidates.sort(key=lambda x: (x[1], -x[2]))
        for url, lo, cn_t, cn_p in cn_candidates[:room]:
            rep["demoted"][url] = f"cn_low_pass_rate:{cn_p}/{cn_t}"

    # N3：排序前一次性读入长期评分，避免在 keep.sort(key=score) 中对每个源
    # 重复 load_json（源多时 I/O 放大与锁竞争）；原写法每次比较都重读整个文件。
    try:
        persisted_scores = load_json(SOURCE_SCORES_FILE, {})
    except Exception:
        persisted_scores = {}

    def score(entry: dict) -> float:
        """综合评分：实时历史 EMA + 持久化 source_scores（含蜜罐/独有贡献维度）。"""
        h = stats_hist.get(entry["url"], {})
        base = (100 * h.get("ok_rate_ema", 1.0) + h.get("unique_ema", 0.0)
                + 2.0 * h.get("real_ema", 0.0)
                + (25 if entry.get("origin") == "manual" else 0))
        # 持久化评分（source_scores.json）作为长期维度：与实时 EMA 相加，
        # 使「长期稳定但近期波动」的源不会被瞬时数据误伤。
        try:
            base += float(persisted_scores.get(entry["url"], {}).get("score", 0.0)) * 0.5
        except Exception:
            pass
        return base

    keep = [e for e in sources["official"] if e["url"] not in rep["demoted"]]
    cap = int(sources.get("max_official", MAX_OFFICIAL))
    if len(keep) > cap:
        keep.sort(key=score, reverse=True)
        for e in keep[cap:]:
            rep["demoted"][e["url"]] = "over_cap_low_score"
        keep = keep[:cap]
    if rep["demoted"]:
        order = {e["url"]: i for i, e in enumerate(sources["official"])}
        keep.sort(key=lambda e: order.get(e["url"], 0))
        sources["official"] = keep
        for url, why in rep["demoted"].items():
            sources["removed"].append({"url": url, "reason": why, "date": _today()})
            # 淘汰即清零 cn streak：防 30 天冷却后回迁的源被旧 streak 瞬杀
            if url in stats_hist:
                stats_hist[url]["cn_low_streak"] = 0
                stats_hist[url].pop("cn_low_last", None)
        sources["removed"] = sources["removed"][-100:]
    return rep


def update_source_scores(sources: dict, per_src: dict, history: dict) -> dict:
    """维护长期源评分 source_scores.json（指数滑动平均，0-100）。

    评分维度：
      - 拉取成功率 success
      - 独有贡献比 unique_ratio（避免纯聚合源刷分）
      - 真实拨测通过比 real_ratio（质量核心）
      - 蜜罐/篡改比例 tamper_ratio（强惩罚）

    该文件为纯增量信息，不参与既有流程的强制判定，读不到时按默认值起算，
    因此对现有状态文件完全向后兼容。
    """
    scores = load_json(SOURCE_SCORES_FILE, {})
    if not isinstance(scores, dict):
        scores = {}
    for url, m in per_src.items():
        prev = scores.get(url) or {"score": 50.0, "runs": 0}
        success = 1.0 if m.get("ok") else 0.0
        alive = max(int(m.get("alive", 0)), 1)
        probed = max(int(m.get("probed", 0)), 1)
        unique_ratio = min(int(m.get("unique_alive", 0)) / alive, 1.0)
        real_ratio = min(int(m.get("real_ok", 0)) / alive, 1.0)
        tamper_ratio = min(int(m.get("tamper", 0)) / probed, 1.0)
        # delta 采用「围绕 50 分」的加权偏移，使好源趋近 100、坏源趋近 0
        delta = (success * 15.0 + unique_ratio * 25.0 + real_ratio * 30.0
                 - tamper_ratio * 40.0 - (0.0 if success else 25.0))
        new_score = float(prev.get("score", 50.0)) * 0.85 + delta
        rec = {
            "score": round(max(0.0, min(100.0, new_score)), 2),
            "runs": int(prev.get("runs", 0)) + 1,
            "role": m.get("role", "official"),
            "last": _today(),
        }
        # 保留进化引擎写入的 cn_* 维度（中国实测通过率），否则本函数每轮重建
        # 条目时会把它抹掉——两处写入方共用 URL 主键，须互不覆盖。
        for ck in ("cn_tested", "cn_passed", "cn_pass_rate", "cn_last"):
            if ck in prev:
                rec[ck] = prev[ck]
        scores[url] = rec
    return scores
