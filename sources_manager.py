#!/usr/bin/env python3
"""Subscription source lifecycle for proxysub.

official (sources.json)  <-- promote --  candidates (candidate_sources.json)  <-- discover -- GitHub search
        |                                         |
        +-- demote (failures / zero contribution / honeypot / cap) --> removed (cooldown)
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote

import requests

SOURCES_FILE = "sources.json"
CANDIDATES_FILE = "candidate_sources.json"

# ---- lifecycle knobs ----
MAX_OFFICIAL = 30
MAX_PROMOTIONS_PER_RUN = 2
PROBATION_RUNS = 3            # consecutive good runs needed (normal reputation)
PROBATION_RUNS_LOW_REP = 5    # low-star / young repos are held longer
PROBATION_MAX_RUNS = 16       # give up on a candidate after this many runs w/o promotion
CANDIDATE_MAX_FAILS = 3
MAX_ACTIVE_CANDIDATES = 15
MIN_CANDIDATE_USABLE = 5      # usable (real-probe ok) nodes per run
MIN_CANDIDATE_UNIQUE = 4      # of which not already offered by official sources
OFFICIAL_FAIL_DEMOTE = 4      # consecutive failed runs (= ~24h at 6h cadence)
OFFICIAL_ZERO_UNIQUE_DEMOTE = 16  # consecutive runs w/o unique alive node (= ~4 days)
OFFICIAL_ZERO_REAL_DEMOTE = 4     # consecutive runs with probes but 0 real-ok (= ~1 day)
REMOVED_COOLDOWN_DAYS = 30

# ---- discovery knobs ----
DISCOVERY_MAX_NEW = 10        # new candidates per run
DISCOVERY_MAX_REPOS = 20      # repo tree lookups per run
DISCOVERY_QUERIES_PER_RUN = 4
DISCOVERY_PUSHED_DAYS = 3
REPO_MIN_AGE_DAYS = 7
REPO_LOW_REP_STARS = 5
REPO_LOW_REP_AGE_DAYS = 60
CANDIDATE_MIN_NODES = 20
MAX_FILE_BYTES = 8 * 1024 * 1024

DISCOVERY_QUERIES = [
    "clash free nodes",
    "free clash subscribe",
    "mihomo free proxies",
    "proxypool clash",
    "免费节点 clash",
    "v2ray free subscription",
    "free vpn subscriptions clash",
    "AutoMergePublicNodes",
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


def load_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")


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
    since = (date.today() - timedelta(days=DISCOVERY_PUSHED_DAYS)).isoformat()

    # rotate queries across runs so each run spends few search calls
    slot = int(time.time() // (6 * 3600))
    qs = [DISCOVERY_QUERIES[(slot * DISCOVERY_QUERIES_PER_RUN + i) % len(DISCOVERY_QUERIES)]
          for i in range(DISCOVERY_QUERIES_PER_RUN)]

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
        if full in known_repos or full in deny:
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
                r = requests.get(url, timeout=20, headers={"User-Agent": "proxysub-discovery/1.0"})
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
    return report


# ====================== probation / promotion / demotion ======================

def evaluate_candidates(cands: dict, run: dict[str, dict], sources: dict) -> dict:
    """run[url] = {ok, count, usable, unique_new, tamper, probed, flags}."""
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
        tamper, probed = r.get("tamper", 0), max(1, r.get("probed", 0))
        if r.get("flags"):
            reason = "honeypot_structure:" + ";".join(r["flags"])
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
    ready.sort(key=lambda kv: -sum(h.get("unique_new", 0) for h in kv[1].get("history", [])))
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


def update_official(sources: dict, stats_hist: dict, run: dict[str, dict]) -> dict:
    """Update per-source history and demote bad / surplus official sources."""
    rep = {"demoted": {}}
    for url in official_urls(sources):
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

        reason = None
        tamper, probed = int(r.get("tamper", 0)), max(1, int(r.get("probed", 0)))
        if tamper >= 3 and tamper / probed >= 0.25:
            reason = f"honeypot_tamper:{tamper}/{probed}"
        elif int(r.get("cf_blocked", 0)) >= 4 and int(r.get("cf_blocked", 0)) / probed >= 0.3:
            reason = f"cf_blocked:{r.get('cf_blocked')}/{probed}"
        elif h["fail_streak"] >= OFFICIAL_FAIL_DEMOTE:
            reason = f"consecutive_failures:{h['fail_streak']}"
        elif h.get("zero_real_streak", 0) >= OFFICIAL_ZERO_REAL_DEMOTE:
            reason = f"zero_real_ok:{h['zero_real_streak']}runs"
        elif h["zero_unique_streak"] >= OFFICIAL_ZERO_UNIQUE_DEMOTE:
            reason = f"zero_unique_contribution:{h['zero_unique_streak']}runs"
        if reason:
            rep["demoted"][url] = reason

    def score(entry: dict) -> float:
        h = stats_hist.get(entry["url"], {})
        return (100 * h.get("ok_rate_ema", 1.0) + h.get("unique_ema", 0.0)
                + 2.0 * h.get("real_ema", 0.0)
                + (25 if entry.get("origin") == "manual" else 0))

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
        sources["removed"] = sources["removed"][-100:]
    return rep
