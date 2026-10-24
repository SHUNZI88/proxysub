"""sources_manager.py 源生命周期单测（P1-2a 覆盖率补齐）。

覆盖此前低覆盖（22%）的组块：
  - sources.json / candidate_sources.json 的加载与默认补齐、候选激活上限、
    removed 冷却判定、raw URL → repo 解析；
  - GitHub.get 的限流感知与重试语义（403/429 判定 exhausted、5xx 重试一次、
    异常重试、remaining 余量保护、exhausted 短路）；
  - repo_reputation 全 verdict（fork/archived/spam/过新/零星低龄/low/ok）；
  - discover 主流程（关闭开关、正常收录、reject、自己/黑名单/冷却跳过、
    文件筛选、抓取失败、节点不足、名额上限、code search、多渠道异常隔离）；
  - evaluate_candidates 各拒绝原因与晋升名额、过期 rejected 清理；
  - update_official 各降级原因、EMA 维护、超额低分裁剪。

全部走 mock：不发真实 GitHub 请求、不读写真实状态文件。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import sources_manager as sm


def _days_ago(n: int) -> str:
    return (datetime.now(timezone.utc).date() - timedelta(days=n)).isoformat()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# 状态文件加载
# ---------------------------------------------------------------------------

class TestSourceFiles:
    def test_load_sources_keeps_valid_and_fills_defaults(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {
            "official": [{"url": "u1"}], "max_official": 7,
        })
        data = sm.load_sources()
        assert data["max_official"] == 7
        assert data["official"] == [{"url": "u1"}]
        assert data["removed"] == [] and data["deny_repos"] == []

    def test_load_sources_rebuilds_from_fallback(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: None)
        data = sm.load_sources(["a", "b"])
        assert [e["url"] for e in data["official"]] == ["a", "b"]
        assert all(e["origin"] == "manual" for e in data["official"])
        assert all(e["added"] == sm._today() for e in data["official"])
        assert data["max_official"] == sm.MAX_OFFICIAL

    def test_load_sources_rebuilds_when_official_not_list(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {"official": "oops"})
        assert sm.load_sources(["z"])["official"][0]["url"] == "z"

    def test_load_sources_rebuilds_when_not_dict(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: [])
        assert sm.load_sources([])["official"] == []

    def test_official_urls_skips_entries_without_url(self):
        assert sm.official_urls({"official": [{"url": "a"}, {}, {"url": ""}]}) == ["a"]

    def test_load_candidates_defaults(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: None)
        assert sm.load_candidates() == {"candidates": {}, "rejected": {}}

    def test_load_candidates_keeps_existing(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {"candidates": {"u": {}}})
        assert sm.load_candidates() == {"candidates": {"u": {}}, "rejected": {}}

    def test_active_candidate_urls_sorted_and_capped(self):
        cands = {
            "candidates": {
                f"u{i}": {"first_seen": _days_ago(40 - i)}
                for i in range(sm.MAX_ACTIVE_CANDIDATES + 3)
            }
        }
        out = sm.active_candidate_urls(cands)
        assert len(out) == sm.MAX_ACTIVE_CANDIDATES
        assert out[0] == "u0" and out[-1] == f"u{sm.MAX_ACTIVE_CANDIDATES - 1}"

    def test_recently_removed_within_cooldown(self):
        sources = {"removed": [{"url": "u", "date": _days_ago(1)}]}
        assert sm._recently_removed(sources, "u") is True

    def test_recently_removed_after_cooldown(self):
        sources = {"removed": [{"url": "u", "date": _days_ago(sm.REMOVED_COOLDOWN_DAYS + 1)}]}
        assert sm._recently_removed(sources, "u") is False

    def test_recently_removed_other_url(self):
        assert sm._recently_removed({"removed": [{"url": "x", "date": _days_ago(1)}]}, "u") is False

    def test_repo_of_raw_url(self):
        assert sm._repo_of("https://raw.githubusercontent.com/Owner/Repo/main/a.yaml") == "owner/repo"

    def test_repo_of_non_raw_url(self):
        assert sm._repo_of("https://example.com/a.yaml") is None


# ---------------------------------------------------------------------------
# GitHub.get
# ---------------------------------------------------------------------------

class _R:
    def __init__(self, status=200, text="", headers=None, payload=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self._payload = payload

    def json(self):
        return self._payload


def _gh(monkeypatch, responses):
    monkeypatch.setattr(sm.time, "sleep", lambda s: None)
    gh = sm.GitHub("tok")
    seq = list(responses)

    def fake_get(url, params=None, timeout=None):
        r = seq.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r

    monkeypatch.setattr(gh.s, "get", fake_get)
    return gh


class TestGitHubGet:
    def test_returns_json_on_200(self, monkeypatch):
        gh = _gh(monkeypatch, [_R(200, payload={"a": 1}, headers={"X-RateLimit-Remaining": "50"})])
        assert gh.get("/x") == {"a": 1}
        assert gh.calls == 1 and gh.exhausted is False and gh.errors == []

    def test_exhausted_short_circuits_without_call(self, monkeypatch):
        gh = _gh(monkeypatch, [])
        gh.exhausted = True
        assert gh.get("/x") is None
        assert gh.calls == 0

    def test_403_with_zero_remaining_marks_exhausted(self, monkeypatch):
        gh = _gh(monkeypatch, [_R(403, "API rate limit exceeded", {"X-RateLimit-Remaining": "0"})])
        assert gh.get("/x") is None
        assert gh.exhausted is True
        assert any("rate_limited" in e for e in gh.errors)

    def test_429_without_header_still_marks_exhausted(self, monkeypatch):
        gh = _gh(monkeypatch, [_R(429, "too many requests rate limit")])
        assert gh.get("/x") is None and gh.exhausted is True

    def test_403_unrelated_is_not_exhausted(self, monkeypatch):
        gh = _gh(monkeypatch, [_R(403, "Forbidden", {"X-RateLimit-Remaining": "30"})])
        assert gh.get("/x") is None
        assert gh.exhausted is False
        assert gh.errors == ["/x: HTTP 403"]

    def test_retries_5xx_once(self, monkeypatch):
        gh = _gh(monkeypatch, [_R(500), _R(200, payload={"ok": True}, headers={})])
        assert gh.get("/x") == {"ok": True} and gh.calls == 2

    def test_gives_up_after_two_5xx(self, monkeypatch):
        gh = _gh(monkeypatch, [_R(500), _R(500)])
        assert gh.get("/x") is None and gh.calls == 2

    def test_retries_on_exception(self, monkeypatch):
        gh = _gh(monkeypatch, [RuntimeError("net down"), _R(200, payload={"ok": 1}, headers={})])
        assert gh.get("/x") == {"ok": 1} and gh.calls == 2

    def test_gives_up_after_repeated_exception(self, monkeypatch):
        gh = _gh(monkeypatch, [RuntimeError("a"), RuntimeError("b")])
        assert gh.get("/x") is None and len(gh.errors) == 2

    def test_404_returns_none_with_error(self, monkeypatch):
        gh = _gh(monkeypatch, [_R(404, headers={"X-RateLimit-Remaining": "40"})])
        assert gh.get("/x") is None and gh.errors == ["/x: HTTP 404"]

    def test_low_remaining_marks_exhausted_but_returns_payload(self, monkeypatch):
        gh = _gh(monkeypatch, [_R(200, payload={"v": 1}, headers={"X-RateLimit-Remaining": "2"})])
        assert gh.get("/x") == {"v": 1}
        assert gh.exhausted is True  # 留余量，但本次响应照用

    def test_non_numeric_remaining_ignored(self, monkeypatch):
        gh = _gh(monkeypatch, [_R(200, payload={"v": 1}, headers={"X-RateLimit-Remaining": "abc"})])
        assert gh.get("/x") == {"v": 1} and gh.exhausted is False


# ---------------------------------------------------------------------------
# repo_reputation
# ---------------------------------------------------------------------------

def _repo(full="o/r", stars=50, days=100, **extra):
    r = {
        "full_name": full,
        "stargazers_count": stars,
        "created_at": _now_iso() if days is None else
        (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(),
        "default_branch": "main",
        "description": "clash nodes",
        "topics": [],
        "fork": False,
        "archived": False,
        "disabled": False,
    }
    r.update(extra)
    return r


class TestRepoReputation:
    def test_fork_rejected(self):
        assert sm.repo_reputation(_repo(fork=True)) == ("reject", "fork")

    def test_archived_rejected(self):
        assert sm.repo_reputation(_repo(archived=True)) == ("reject", "archived")

    def test_disabled_rejected(self):
        assert sm.repo_reputation(_repo(disabled=True)) == ("reject", "archived")

    def test_spam_in_description_rejected(self):
        assert sm.repo_reputation(_repo(description="free casino nodes"))[0] == "reject"
        assert sm.repo_reputation(_repo(description="free casino nodes"))[1] == "spam_keywords"

    def test_spam_in_topics_rejected(self):
        assert sm.repo_reputation(_repo(topics=["airdrop"])) == ("reject", "spam_keywords")

    def test_too_new_rejected(self):
        verdict, why = sm.repo_reputation(_repo(days=3))
        assert verdict == "reject" and why == "too_new:3d"

    def test_zero_stars_young_rejected(self):
        assert sm.repo_reputation(_repo(stars=0, days=30)) == ("reject", "zero_stars_young")

    def test_low_by_stars(self):
        verdict, why = sm.repo_reputation(_repo(stars=3, days=100))
        assert verdict == "low" and why == "stars=3,age=100d"

    def test_low_by_age(self):
        verdict, why = sm.repo_reputation(_repo(stars=10, days=30))
        assert verdict == "low" and why == "stars=10,age=30d"

    def test_ok(self):
        verdict, why = sm.repo_reputation(_repo(stars=50, days=100))
        assert verdict == "ok" and why == "stars=50,age=100d"

    def test_unparsable_created_at_falls_back_to_zero_age(self):
        verdict, why = sm.repo_reputation(_repo(created_at="not-a-date"))
        assert verdict == "reject" and why == "too_new:0d"


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------

class _FakeGH:
    def __init__(self, token):
        self.token = token
        self.exhausted = False
        self.calls = 0
        self.errors: list[str] = []
        self.responses: dict = {}
        self.seen: list[str] = []
        self.exhaust_after: int | None = None

    def get(self, path, params=None):
        self.calls += 1
        self.seen.append(path)
        data = self.responses.get(path)
        if self.exhaust_after is not None and self.calls >= self.exhaust_after:
            self.exhausted = True
        return data


class _Fetch:
    def __init__(self, status_code=200, text="nodes"):
        self.status_code = status_code
        self.text = text


def _install_gh(monkeypatch, responses, exhaust_after=None):
    holder = {}

    def factory(token):
        gh = _FakeGH(token)
        gh.responses = responses
        gh.exhaust_after = exhaust_after
        holder["gh"] = gh
        return gh

    monkeypatch.setattr(sm, "GitHub", factory)
    monkeypatch.setattr(sm.time, "sleep", lambda s: None)
    return holder


def _tree(path="clash.yaml", size=5000):
    return {"path": path, "type": "blob", "size": size}


def _sources(**kw):
    s = {"max_official": 30, "official": [], "removed": [], "deny_repos": []}
    s.update(kw)
    return s


def _cands():
    return {"candidates": {}, "rejected": {}}


def _base_discover_env(monkeypatch, repo=None, tree=None, fetch=None, parse_n=25,
                       exhaust_after=None):
    repo = repo if repo is not None else _repo("o/r")
    responses = {"/search/repositories": {"items": [repo]}}
    if tree is not None:
        responses[f"/repos/{repo['full_name']}/git/trees/main"] = {"tree": tree}
    holder = _install_gh(monkeypatch, responses, exhaust_after)
    monkeypatch.setattr(sm, "safe_http_get", lambda *a, **k: fetch or _Fetch())
    monkeypatch.setattr(sm.channels, "discover_channels", lambda *a, **k: {"added": []})
    return holder


class TestDiscover:
    def test_discovery_disabled_short_circuits(self, monkeypatch):
        monkeypatch.setenv("PROXYSUB_DISCOVERY", "0")
        logs = []
        rep = sm.discover(_sources(), _cands(), lambda t: [], None, logs.append)
        assert rep["added"] == [] and rep["api_calls"] == 0 and rep["searched_repos"] == 0
        assert any("自动发现已关闭" in x for x in logs)

    def test_adds_candidate_when_enough_nodes(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        holder = _base_discover_env(monkeypatch, tree=[_tree()], parse_n=25)
        cands = _cands()
        rep = sm.discover(_sources(), cands, lambda t: [{}] * 25, "tok", lambda m: None)
        url = "https://raw.githubusercontent.com/o/r/main/clash.yaml"
        assert rep["added"] == [url]
        assert rep["searched_repos"] == 1
        c = cands["candidates"][url]
        assert c["repo"] == "o/r" and c["stars"] == 50
        assert c["reputation"] == "ok" and c["required_runs"] == sm.PROBATION_RUNS
        assert c["initial_nodes"] == 25 and c["runs"] == 0 and c["history"] == []
        assert holder["gh"].calls >= 1

    def test_low_reputation_gets_longer_probation(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        holder = _base_discover_env(monkeypatch, repo=_repo("o/r", stars=3, days=100),
                                    tree=[_tree()], parse_n=25)
        cands = _cands()
        sm.discover(_sources(), cands, lambda t: [{}] * 25, "tok", lambda m: None)
        url = "https://raw.githubusercontent.com/o/r/main/clash.yaml"
        assert cands["candidates"][url]["reputation"] == "low"
        assert cands["candidates"][url]["required_runs"] == sm.PROBATION_RUNS_LOW_REP
        assert holder["gh"].calls >= 1

    def test_rejected_repo_recorded_not_added(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, repo=_repo("o/spam", description="casino nodes"),
                           tree=[_tree()], parse_n=25)
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["rejected"] == {"o/spam": "spam_keywords"}
        assert rep["added"] == []

    def test_own_repo_skipped(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.setenv("GITHUB_REPOSITORY", "O/R")
        _base_discover_env(monkeypatch, tree=[_tree()], parse_n=25)
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["added"] == [] and rep["searched_repos"] == 1

    def test_deny_repo_skipped(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, tree=[_tree()], parse_n=25)
        rep = sm.discover(_sources(deny_repos=["o/r"]), _cands(),
                          lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["added"] == []

    def test_recently_removed_url_skipped(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, tree=[_tree()], parse_n=25)
        url = "https://raw.githubusercontent.com/o/r/main/clash.yaml"
        sources = _sources(removed=[{"url": url, "date": _days_ago(1), "reason": "x"}])
        rep = sm.discover(sources, _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["added"] == []

    def test_file_filters_reject_bad_paths_and_sizes(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, tree=[
            _tree("clash.yaml", size=100),             # 过小
            _tree("docs/clash.yaml", size=5000),       # 跳过目录
            _tree("README.md", size=5000),             # 非目标文件名
            {"path": "clash.yaml", "type": "tree", "size": 5000},  # 非 blob
        ], parse_n=25)
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["added"] == []

    def test_missing_tree_skips_repo(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, tree=None, parse_n=25)
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["added"] == []

    def test_new_candidate_cap_breaks_inside_file_loop(self, monkeypatch):
        # 同一仓库两个合格文件：名额为 1 时首个文件收录后即中断内层循环
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        monkeypatch.setattr(sm, "DISCOVERY_MAX_NEW", 1)
        _base_discover_env(monkeypatch, tree=[_tree("clash.yaml"), _tree("nodes.yaml")],
                           parse_n=25)
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert len(rep["added"]) == 1

    def test_fetch_failure_skips_candidate(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, tree=[_tree()], parse_n=25)

        def boom(*a, **k):
            raise OSError("fetch failed")

        monkeypatch.setattr(sm, "safe_http_get", boom)
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["added"] == []

    def test_non_200_fetch_skips_candidate(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, tree=[_tree()], fetch=_Fetch(404, ""), parse_n=25)
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["added"] == []

    def test_too_few_nodes_skips_candidate(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, tree=[_tree()], parse_n=sm.CANDIDATE_MIN_NODES - 1)
        rep = sm.discover(_sources(), _cands(),
                          lambda t: [{}] * (sm.CANDIDATE_MIN_NODES - 1), "tok", lambda m: None)
        assert rep["added"] == []

    def test_exhausted_api_breaks_before_tree_lookup(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        holder = _base_discover_env(monkeypatch, tree=[_tree()], parse_n=25, exhaust_after=1)
        sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert not any("/git/trees/" in p for p in holder["gh"].seen)

    def test_code_search_adds_repo_needing_meta(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        responses = {
            "/search/repositories": {"items": []},
            "/search/code": {"items": [{"repository": {"full_name": "c/d"}}]},
            "/repos/c/d": _repo("c/d"),
            "/repos/c/d/git/trees/main": {"tree": [_tree()]},
        }
        holder = _install_gh(monkeypatch, responses)
        monkeypatch.setattr(sm, "safe_http_get", lambda *a, **k: _Fetch())
        monkeypatch.setattr(sm.channels, "discover_channels", lambda *a, **k: {"added": []})
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["added"] == ["https://raw.githubusercontent.com/c/d/main/clash.yaml"]
        assert "/repos/c/d" in holder["gh"].seen

    def test_code_search_meta_missing_skips(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        responses = {
            "/search/repositories": {"items": []},
            "/search/code": {"items": [{"repository": {"full_name": "c/d"}}]},
            "/repos/c/d": None,  # 元数据取不到
        }
        _install_gh(monkeypatch, responses)
        monkeypatch.setattr(sm, "safe_http_get", lambda *a, **k: _Fetch())
        monkeypatch.setattr(sm.channels, "discover_channels", lambda *a, **k: {"added": []})
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert rep["added"] == []

    def test_channels_failure_is_isolated(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, tree=[_tree()], parse_n=25)

        def boom(*a, **k):
            raise RuntimeError("channels down")

        monkeypatch.setattr(sm.channels, "discover_channels", boom)
        logs = []
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", logs.append)
        assert rep["channels_error"] == "RuntimeError: channels down"
        assert len(rep["added"]) == 1  # GitHub 发现不受影响
        assert any("多渠道搜集异常" in x for x in logs)

    def test_channels_additions_merged(self, monkeypatch):
        monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        _base_discover_env(monkeypatch, tree=[_tree()], parse_n=25)
        monkeypatch.setattr(
            sm.channels, "discover_channels",
            lambda *a, **k: {"added": ["https://chan.example/sub"]},
        )
        rep = sm.discover(_sources(), _cands(), lambda t: [{}] * 25, "tok", lambda m: None)
        assert "https://chan.example/sub" in rep["added"]
        assert rep["channels"]["added"] == ["https://chan.example/sub"]


# ---------------------------------------------------------------------------
# evaluate_candidates
# ---------------------------------------------------------------------------

def _cand(**kw):
    c = {
        "repo": "o/r", "required_runs": sm.PROBATION_RUNS,
        "runs": 0, "good_streak": 0, "fail_streak": 0, "history": [],
        "first_seen": _days_ago(1),
    }
    c.update(kw)
    return c


def _good_run(unique_new=6, **kw):
    r = {"ok": True, "count": 30, "usable": 10, "unique_new": unique_new,
         "tamper": 0, "probed": 20, "cf_blocked": 0, "flags": []}
    r.update(kw)
    return r


class TestEvaluateCandidates:
    def test_inactive_candidate_untouched(self):
        cands = {"candidates": {"u": _cand()}, "rejected": {}}
        rep = sm.evaluate_candidates(cands, {}, {})
        assert cands["candidates"]["u"]["runs"] == 0
        assert rep == {"promoted": [], "rejected": {}}

    def test_promotes_after_required_good_runs(self):
        cands = {"candidates": {"u": _cand(required_runs=1)}, "rejected": {}}
        sources = {"official": []}
        rep = sm.evaluate_candidates(cands, {"u": _good_run()}, sources)
        assert rep["promoted"] == ["u"]
        assert "u" not in cands["candidates"]
        e = sources["official"][0]
        assert e["url"] == "u" and e["origin"] == "discovered" and e["repo"] == "o/r"
        assert e["probation_runs"] == 1

    def test_promotion_capped_and_ranked_by_unique_history(self):
        cands = {"candidates": {f"u{i}": _cand(required_runs=1) for i in range(3)}, "rejected": {}}
        run = {"u0": _good_run(6), "u1": _good_run(2), "u2": _good_run(4)}
        rep = sm.evaluate_candidates(cands, run, {"official": []})
        assert rep["promoted"] == ["u0", "u2"]
        assert "u1" in cands["candidates"]  # 名额用尽，保留继续观察

    def test_good_but_not_ready_stays_candidate(self):
        cands = {"candidates": {"u": _cand(required_runs=3)}, "rejected": {}}
        rep = sm.evaluate_candidates(cands, {"u": _good_run()}, {"official": []})
        assert rep["promoted"] == []
        assert cands["candidates"]["u"]["good_streak"] == 1

    def test_bad_run_resets_good_streak(self):
        cands = {"candidates": {"u": _cand(good_streak=2)}, "rejected": {}}
        sm.evaluate_candidates(cands, {"u": {"ok": True, "usable": 1, "unique_new": 0}},
                               {"official": []})
        assert cands["candidates"]["u"]["good_streak"] == 0

    def test_rejects_bait_reuse(self):
        cands = {"candidates": {"u": _cand()}, "rejected": {}}
        rep = sm.evaluate_candidates(cands, {"u": _good_run(flags=["bait_reuse:abc"])},
                                     {"official": []})
        assert rep["rejected"]["u"] == "redistributes_bait:bait_reuse:abc"
        assert cands["rejected"]["u"]["reason"].startswith("redistributes_bait")

    def test_rejects_honeypot_structure_flags(self):
        cands = {"candidates": {"u": _cand()}, "rejected": {}}
        rep = sm.evaluate_candidates(cands, {"u": _good_run(flags=["cluster_24", "shared_cred"])},
                                     {"official": []})
        assert rep["rejected"]["u"] == "honeypot_structure:cluster_24;shared_cred"

    def test_rejects_by_tamper_count(self):
        cands = {"candidates": {"u": _cand()}, "rejected": {}}
        rep = sm.evaluate_candidates(cands, {"u": _good_run(tamper=3, probed=100)},
                                     {"official": []})
        assert rep["rejected"]["u"] == "honeypot_tamper:3/100"

    def test_rejects_by_tamper_ratio(self):
        cands = {"candidates": {"u": _cand()}, "rejected": {}}
        rep = sm.evaluate_candidates(cands, {"u": _good_run(tamper=1, probed=5)},
                                     {"official": []})
        assert rep["rejected"]["u"] == "honeypot_tamper:1/5"

    def test_rejects_by_cf_blocked(self):
        """语义翻转（任务#105，2026-10-24）：cf_blocked 不再拒绝候选——
        CF 拦美西 Runner 是探测点位问题（ovmvo 10-21 中国通过 33% 仍被汰），
        节点级 CF_BLOCKED_PENALTY 软惩罚保留。"""
        cands = {"candidates": {"u": _cand()}, "rejected": {}}
        rep = sm.evaluate_candidates(cands, {"u": _good_run(cf_blocked=2, probed=8)},
                                     {"official": []})
        assert "rejected" not in rep or "u" not in rep.get("rejected", {})
        assert "u" in cands["candidates"]

    def test_rejects_by_consecutive_failures(self):
        cands = {"candidates": {"u": _cand()}, "rejected": {}}
        rep = None
        for _ in range(sm.CANDIDATE_MAX_FAILS):
            rep = sm.evaluate_candidates(cands, {"u": {"ok": False}}, {"official": []})
        assert rep["rejected"]["u"] == "fetch_failures"

    def test_rejects_after_probation_max_runs(self):
        cands = {"candidates": {"u": _cand(runs=sm.PROBATION_MAX_RUNS - 1)}, "rejected": {}}
        rep = sm.evaluate_candidates(cands, {"u": _good_run()}, {"official": []})
        assert rep["rejected"]["u"] == "no_stable_contribution"

    def test_tolerates_none_probed_and_tamper(self):
        """N2 回归：上游显式传 probed=None / tamper=None 时不得抛 TypeError。

        修复前 evaluate_candidates 用 max(1, r.get('probed', 0))，若值为 None
        则 max(1, None) 抛 TypeError；与同文件 update_official 已做的 int() 兜底
        不一致。修复后须与 update_official 行为对齐。
        """
        cands = {"candidates": {"u": _cand()}, "rejected": {}}
        run = {"u": {"ok": True, "usable": 9, "unique_new": 5,
                     "tamper": None, "probed": None, "flags": []}}
        rep = sm.evaluate_candidates(cands, run, {"official": []})
        # 不崩即过关；None 经 int(... or 0) 兜底为 0，probed 取 1
        assert "u" not in rep["rejected"]  # 优质候选不应因 None 被误拒

    def test_history_keeps_last_eight_entries(self):
        # required_runs 抬高以避免中途晋升（晋升会把它移出 candidates）
        cands = {"candidates": {"u": _cand(required_runs=999)}, "rejected": {}}
        for _ in range(10):
            sm.evaluate_candidates(cands, {"u": _good_run()}, {"official": []})
        assert len(cands["candidates"]["u"]["history"]) == 8
        assert cands["candidates"]["u"]["runs"] == 10

    def test_prunes_rejections_older_than_cooldown(self):
        cands = {"candidates": {}, "rejected": {
            "old": {"reason": "x", "date": _days_ago(sm.REMOVED_COOLDOWN_DAYS + 1)},
            "new": {"reason": "x", "date": _days_ago(1)},
        }}
        sm.evaluate_candidates(cands, {}, {"official": []})
        assert "old" not in cands["rejected"] and "new" in cands["rejected"]


# ---------------------------------------------------------------------------
# update_official
# ---------------------------------------------------------------------------

class TestUpdateOfficial:
    @staticmethod
    def _src(entries=None, **kw):
        s = {"official": entries if entries is not None else [{"url": "u", "origin": "manual"}],
             "removed": [], "max_official": 30}
        s.update(kw)
        return s

    def test_ema_and_history_updated(self):
        sources = self._src()
        hist: dict = {}
        sm.update_official(sources, hist, {"u": {"ok": True, "unique_alive": 4,
                                                 "real_ok": 3, "probed": 10}})
        h = hist["u"]
        assert h["runs"] == 1 and h["ok_runs"] == 1
        assert h["fail_streak"] == 0 and h["zero_unique_streak"] == 0
        assert h["ok_rate_ema"] == 1.0
        assert h["unique_ema"] == round(0.7 * 0.0 + 0.3 * 4, 2)
        assert h["real_ema"] == round(0.7 * 0.0 + 0.3 * 3, 2)
        assert h["last"]["date"] == sm._today()

    def test_demotes_on_bait_reuse(self):
        sources = self._src()
        rep = sm.update_official(sources, {}, {"u": {"ok": True, "flags": ["bait_reuse"]}})
        assert rep["demoted"] == {"u": "redistributes_bait"}
        assert sources["official"] == []
        assert sources["removed"][0]["reason"] == "redistributes_bait"

    def test_demotes_on_honeypot_tamper(self):
        sources = self._src()
        rep = sm.update_official(sources, {}, {"u": {"ok": True, "tamper": 3, "probed": 10}})
        assert rep["demoted"] == {"u": "honeypot_tamper:3/10"}

    def test_demotes_on_cf_blocked(self):
        """语义翻转（任务#105）：cf_blocked 不再整源淘汰——ovmvo 事故复盘
        （中国通过 6/18=33% 的源因 7/20 被 CF 硬杀）后废除，节点级软惩罚保留。"""
        sources = self._src()
        rep = sm.update_official(sources, {}, {"u": {"ok": True, "cf_blocked": 4, "probed": 10}})
        assert rep["demoted"] == {}

    def test_demotes_on_consecutive_failures(self):
        sources = self._src()
        hist: dict = {}
        rep = None
        for _ in range(sm.OFFICIAL_FAIL_DEMOTE):
            rep = sm.update_official(sources, hist, {"u": {"ok": False}})
        assert rep["demoted"] == {"u": f"consecutive_failures:{sm.OFFICIAL_FAIL_DEMOTE}"}

    def test_demotes_on_zero_real_ok(self):
        sources = self._src()
        hist: dict = {}
        rep = None
        for _ in range(sm.OFFICIAL_ZERO_REAL_DEMOTE):
            rep = sm.update_official(sources, hist,
                                     {"u": {"ok": True, "probed": 10, "real_ok": 0}})
        assert rep["demoted"] == {"u": f"zero_real_ok:{sm.OFFICIAL_ZERO_REAL_DEMOTE}runs"}

    def test_zero_real_streak_untouched_below_probe_threshold(self):
        sources = self._src()
        hist: dict = {}
        sm.update_official(sources, hist, {"u": {"ok": True, "probed": 4, "real_ok": 0}})
        assert hist["u"]["zero_real_streak"] == 0

    def test_demotes_on_zero_unique_contribution(self):
        sources = self._src()
        hist: dict = {}
        rep = None
        for _ in range(sm.OFFICIAL_ZERO_UNIQUE_DEMOTE):
            rep = sm.update_official(sources, hist, {"u": {"ok": True, "unique_alive": 0}})
        assert rep["demoted"] == {"u": f"zero_unique_contribution:{sm.OFFICIAL_ZERO_UNIQUE_DEMOTE}runs"}

    def test_over_cap_demotes_lowest_score(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        sources = self._src([
            {"url": "disc", "origin": "discovered"},
            {"url": "manual", "origin": "manual"},
        ], max_official=1)
        rep = sm.update_official(sources, {}, {})
        assert rep["demoted"] == {"disc": "over_cap_low_score"}
        assert [e["url"] for e in sources["official"]] == ["manual"]

    def test_persisted_score_counts_toward_keep_decision(self, monkeypatch):
        # manual 源基础分高 25；给 discovered 源注入足够高的持久化分即可翻盘
        monkeypatch.setattr(
            sm, "load_json",
            lambda *a, **k: {"disc": {"score": 200.0}, "manual": {"score": 0.0}},
        )
        sources = self._src([
            {"url": "disc", "origin": "discovered"},
            {"url": "manual", "origin": "manual"},
        ], max_official=1)
        rep = sm.update_official(sources, {}, {})
        assert rep["demoted"] == {"manual": "over_cap_low_score"}
        assert [e["url"] for e in sources["official"]] == ["disc"]

    def test_persisted_score_read_failure_is_ignored(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("scores unreadable")

        monkeypatch.setattr(sm, "load_json", boom)
        sources = self._src([
            {"url": "disc", "origin": "discovered"},
            {"url": "manual", "origin": "manual"},
        ], max_official=1)
        rep = sm.update_official(sources, {}, {})
        assert rep["demoted"] == {"disc": "over_cap_low_score"}  # 退回纯实时 EMA 评分

    def test_removed_list_capped_at_100(self):
        sources = self._src(removed=[{"url": f"old{i}", "reason": "x", "date": _days_ago(2)}
                                     for i in range(120)])
        sm.update_official(sources, {}, {"u": {"ok": True, "flags": ["bait_reuse"]}})
        assert len(sources["removed"]) == 100
        assert sources["removed"][-1]["url"] == "u"


# ---------------------------------------------------------------------------
# update_source_scores（既有 test_source_scores.py 之外的边界）
# ---------------------------------------------------------------------------

class TestUpdateSourceScores:
    def test_non_dict_scores_file_is_reset(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: ["not", "a", "dict"])
        scores = sm.update_source_scores({}, {"u": {
            "ok": True, "alive": 10, "probed": 10,
            "unique_alive": 5, "real_ok": 5, "tamper": 0,
        }}, {})
        assert set(scores) == {"u"}
        assert scores["u"]["runs"] == 1
        assert 0.0 <= scores["u"]["score"] <= 100.0

    def test_tamper_penalty_drives_score_down(self, monkeypatch):
        monkeypatch.setattr(sm, "load_json", lambda *a, **k: {})
        clean = sm.update_source_scores({}, {"u": {
            "ok": True, "alive": 10, "probed": 10,
            "unique_alive": 5, "real_ok": 5, "tamper": 0,
        }}, {})
        tampered = sm.update_source_scores({}, {"u": {
            "ok": True, "alive": 10, "probed": 10,
            "unique_alive": 5, "real_ok": 5, "tamper": 8,
        }}, {})
        assert tampered["u"]["score"] < clean["u"]["score"]


class TestDiscoveryThroughput:
    """2026-10-20 扩容（任务#88）：用户反馈有效节点数长期 29 不动，根因之一是
    输入池窄（候选池曾枯竭至 2 个、官方源仅 11/30）——免费池 97% 死亡率的
    硬现实下只能扩大源头吞吐。锁定扩容参数与轮换不变量，防回退。"""

    def test_knobs_raised_for_throughput(self):
        assert sm.DISCOVERY_MAX_NEW >= 15        # 原 10
        assert sm.DISCOVERY_MAX_REPOS >= 25      # 原 20：15 个新候选需更多树 lookup
        assert sm.MAX_ACTIVE_CANDIDATES >= 20    # 原 15：窗口即每轮实测候选源数

    def test_query_list_expanded_with_community_terms(self):
        """扩容后覆盖中文社区主流命名（clashnode/nodefree/免费机场/节点分享）。"""
        assert len(sm.DISCOVERY_QUERIES) == 16
        assert len(set(sm.DISCOVERY_QUERIES)) == 16  # 无重复词
        joined = " ".join(sm.DISCOVERY_QUERIES)
        for term in ("clashnode", "nodefree", "免费机场", "免费节点分享",
                     "free proxy list"):
            assert term in joined, term

    def test_query_rotation_covers_all_queries_in_one_day(self):
        """6h 节奏下 4 个槽位覆盖全部 16 词、不重不漏（24h 全覆盖）；
        单轮内 4 词互不相同。同时锁定 len % PER_RUN == 0 的轮换前提。"""
        assert len(sm.DISCOVERY_QUERIES) % sm.DISCOVERY_QUERIES_PER_RUN == 0
        seen: list[str] = []
        for slot in range(len(sm.DISCOVERY_QUERIES) // sm.DISCOVERY_QUERIES_PER_RUN):
            qs = sm.queries_for_slot(slot)
            assert len(qs) == sm.DISCOVERY_QUERIES_PER_RUN
            assert len(set(qs)) == len(qs)      # 单轮不重
            seen.extend(qs)
        assert sorted(seen) == sorted(sm.DISCOVERY_QUERIES)  # 全天不漏不重

    def test_promo_airport_repo_still_rejected_by_spam_filter(self):
        """「免费机场」查询词会命中招商站——SPAM_RE 必须继续拒收（扩容不放宽
        招商过滤，只放宽查询覆盖面）。"""
        repo = _repo("o/promo", description="免费机场 招商 TG@xxx 返利")
        verdict, why = sm.repo_reputation(repo)
        assert verdict == "reject" and why == "spam_keywords"
