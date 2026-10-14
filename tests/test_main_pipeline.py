"""filter_clash.main() 编排主线集成测试（P1-1d，产品评估报告第一阶段）。

main() 是 0→13 阶段的流水线编排，此前**无任何测试覆盖**——最易出 bug 的
编排逻辑恰恰没有安全网，这正是 P1-1（拆 main()）之前的必要前置。

本文件在边界处 mock（网络抓取 / mihomo 拨测 / DNS / gh / 反爬 / 进化引擎），
中间逻辑全部走真实代码，端到端固化以下行为：

  1. 常规路径（反爬关闭 + mihomo 全通过）：输出文件 + 状态持久化 + Step Summary
  2. 拨测禁用路径（PROXYSUB_DISABLE_PROBE=1）：仅 TCP 存活检查也产出输出
  3. mihomo 缺失回退路径：http/socks 简单探测分支（无 http 节点时为空拨测）
  4. tamper 拨测结果 → 自动 blocklist → 节点被排除
  5. skip-cert-verify 节点 → [Insecure] 标签 + 独立分组隔离
  6. Step Summary 缺键不崩（P0-1 回归）

重构 main() 后本文件必须**原样通过**——它是行为保持的安全网。
"""

import json
import os

import pytest
import yaml

import filter_clash as fc

TEST_URL = "https://raw.githubusercontent.com/test/repo/main/sub.yaml"


def _nodes() -> list[dict]:
    """三个不同区域/协议的有效节点（均已验证可通过静态门槛）。"""
    return [
        {"name": "HK-01", "type": "vless", "server": "1.2.3.4", "port": 443,
         "uuid": "11111111-2222-3333-4444-555555555555", "tls": True, "network": "tcp",
         "servername": "www.microsoft.com", "flow": "xtls-rprx-vision",
         "reality-opts": {"public-key": "A" * 43, "short-id": "ab12"},
         "client-fingerprint": "chrome"},
        {"name": "JP-02", "type": "hysteria2", "server": "5.6.7.8", "port": 8443,
         "password": "pw123", "sni": "dl.google.com", "obfs": "salamander",
         "obfs-password": "obf"},
        {"name": "SG-03", "type": "trojan", "server": "9.9.9.9", "port": 443,
         "password": "tp@ss", "sni": "apple.com", "network": "ws",
         "ws-opts": {"path": "/ws", "headers": {"Host": "a.com"}}},
    ]


def _insecure_nodes() -> list[dict]:
    """追加一个 skip-cert-verify 节点（验证 Insecure 隔离）。"""
    nodes = _nodes()
    nodes.append({"name": "US-04", "type": "trojan", "server": "8.8.4.4", "port": 443,
                  "password": "ins", "sni": "example.com", "skip-cert-verify": True})
    return nodes


class _PipelineEnv:
    """main() 运行环境的控制柄：注入 mock 结果 + 断言辅助。"""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.probe_results: dict[str, dict] = {}   # server -> mihomo 结果（按服务器粒度）
        self.calls: dict[str, int] = {}

    def _mihomo_probe(self, proxies, bin_path):
        """按服务器地址返回注入的拨测结果；未注入的默认 ok。"""
        self.calls["mihomo_probe"] = self.calls.get("mihomo_probe", 0) + 1
        out = {}
        for p in proxies:
            r = self.probe_results.get(str(p["server"]),
                                       {"status": "ok", "latency": 120.0, "https_ok": True})
            out[fc.fingerprint(p)] = dict(r)
        return out


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    """在 tmpdir 搭建 main() 完整运行环境；所有副作用落在 tmpdir。"""
    env = _PipelineEnv(tmp_path)
    monkeypatch.chdir(tmp_path)
    # 状态/输出文件全部落在 tmpdir，不触碰仓库真实数据
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("PROXYSUB_DISCOVERY", raising=False)
    monkeypatch.delenv("PROXYSUB_DISABLE_PROBE", raising=False)
    step_summary = tmp_path / "step_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step_summary))

    # ---- sources_manager 边界 ----
    monkeypatch.setattr(fc.sm, "load_sources", lambda *a, **k: {
        "max_official": 20, "deny_repos": [],
        "official": [{"url": TEST_URL, "origin": "manual", "added": "2026-10-01"}],
        "removed": [],
    })
    monkeypatch.setattr(fc.sm, "load_candidates", lambda *a, **k: {"candidates": {}, "rejected": {}})
    monkeypatch.setattr(fc.sm, "discover", lambda *a, **k: {
        "searched_repos": 0, "added": [], "rejected": {}, "api_calls": 0, "errors": []})
    monkeypatch.setattr(fc.sm, "official_urls", lambda s: [TEST_URL])
    monkeypatch.setattr(fc.sm, "active_candidate_urls", lambda c: [])
    monkeypatch.setattr(fc.sm, "evaluate_candidates", lambda *a, **k: {"promoted": [], "rejected": {}})
    monkeypatch.setattr(fc.sm, "update_official", lambda *a, **k: {"demoted": {}})
    monkeypatch.setattr(fc.sm, "update_source_scores", lambda *a, **k: {})

    # ---- honeypot 边界（DNS 必须 mock：沙箱内真实查询慢且不可控）----
    monkeypatch.setattr(fc.hp, "resolve_hosts", lambda hosts: {h: [h] for h in hosts})
    monkeypatch.setattr(fc.hp, "source_cluster_flags", lambda plist, resolved: [])
    monkeypatch.setattr(fc.hp, "credential_of", lambda p: None)

    # ---- 抓取 / 拨测 / 进化引擎边界 ----
    monkeypatch.setattr(fc, "fetch_all_sources",
                        lambda urls: ({TEST_URL: _nodes()},
                                      {TEST_URL: {"ok": True, "count": 3, "error": None}}))
    monkeypatch.setattr(fc, "tcp_probe", lambda p: (True, 50.0))
    monkeypatch.setattr(fc, "mihomo_available", lambda: "/fake/mihomo")
    monkeypatch.setattr(fc, "real_probe_enabled", lambda: True)
    monkeypatch.setattr(fc, "mihomo_probe", env._mihomo_probe)
    # 进化引擎下载上轮报告走 gh 子进程——直接替换入口（返回安全默认值）
    monkeypatch.setattr(fc, "load_evolution_inputs",
                        lambda root: ({}, {"CN_LATENCY_CAP_MS": 3000}, {}))
    return env


def _read_yaml(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# 1. 常规路径
# ---------------------------------------------------------------------------

def test_main_pipeline_happy_path(pipeline):
    """反爬关闭 + mihomo 全通过：完整产出 + 状态持久化 + Step Summary。"""
    fc.main()

    # 主输出与多格式输出
    assert os.path.exists(fc.OUTPUT_FILE)
    cfg = _read_yaml(fc.OUTPUT_FILE)
    assert isinstance(cfg["proxies"], list) and len(cfg["proxies"]) == 3
    assert any(g["name"] == "♻️ 自动选择" for g in cfg["proxy-groups"])
    for f in (fc.OUTPUT_SINGBOX, fc.OUTPUT_V2RAY, fc.OUTPUT_PROXIES_ONLY):
        assert os.path.exists(f), f"{f} 未生成"

    # 状态持久化（safe_io 原子写）
    for f in (fc.SURVIVAL_FILE, fc.SOURCE_STATS_FILE, fc.BAD_SOURCES_FILE):
        assert os.path.exists(f), f"{f} 未持久化"
    assert os.path.exists(fc.sm.SOURCES_FILE)
    stats = _read_yaml(fc.SOURCE_STATS_FILE) if False else json.load(open(fc.SOURCE_STATS_FILE))
    assert stats["sources"][TEST_URL]["role"] == "official"
    assert stats["sources"][TEST_URL]["alive"] == 3

    # survival 记录了本轮存活指纹
    survival = json.load(open(fc.SURVIVAL_FILE))
    assert len(survival) == 3

    # Step Summary 写出且含关键指标
    summary = open(os.environ["GITHUB_STEP_SUMMARY"], encoding="utf-8").read()
    assert "proxysub clean summary" in summary
    assert "Final proxies" in summary

    # 拨测被真实调用过
    assert pipeline.calls["mihomo_probe"] == 1


def test_main_pipeline_min_final_warning_path(pipeline, capsys):
    """候选池远小于 MIN_FINAL(150) 时不得崩溃，走下限警告守卫。"""
    fc.main()
    out = capsys.readouterr().out
    assert "下限" in out  # 节点数下限守卫打印
    cfg = _read_yaml(fc.OUTPUT_FILE)
    assert len(cfg["proxies"]) == 3  # 少量节点仍完整产出，不静默丢


# ---------------------------------------------------------------------------
# 2. 拨测禁用路径
# ---------------------------------------------------------------------------

def test_main_pipeline_probe_disabled(pipeline, monkeypatch, capsys):
    """PROXYSUB_DISABLE_PROBE=1：仅 TCP 存活检查，仍产出输出。"""
    monkeypatch.setattr(fc, "real_probe_enabled", lambda: False)
    fc.main()
    out = capsys.readouterr().out
    assert "云端真实流量拨测已禁用" in out
    cfg = _read_yaml(fc.OUTPUT_FILE)
    # 无拨测闸门：TCP 存活节点全部保留（含 UDP 协议的 hy2）
    assert len(cfg["proxies"]) == 3
    assert pipeline.calls.get("mihomo_probe") is None  # 拨测未被调用


# ---------------------------------------------------------------------------
# 3. mihomo 缺失回退路径
# ---------------------------------------------------------------------------

def test_main_pipeline_no_mihomo_fallback(pipeline, monkeypatch, capsys):
    """mihomo 不可用但拨测启用：走 http/socks 简单探测回退分支。"""
    monkeypatch.setattr(fc, "mihomo_available", lambda: None)
    fc.main()
    out = capsys.readouterr().out
    assert "未找到 mihomo" in out
    cfg = _read_yaml(fc.OUTPUT_FILE)
    assert len(cfg["proxies"]) == 3  # 回退路径同样完整产出


# ---------------------------------------------------------------------------
# 4. tamper → 自动 blocklist → 排除
# ---------------------------------------------------------------------------

def test_main_pipeline_tamper_blocklists_and_excludes(pipeline):
    """拨测判 tamper 的节点进自动 blocklist 且不进最终输出。"""
    pipeline.probe_results["9.9.9.9"] = {"status": "tls_mitm", "latency": 999.0,
                                         "https_ok": False, "detail": "cert mismatch"}
    fc.main()
    cfg = _read_yaml(fc.OUTPUT_FILE)
    names = [p["name"] for p in cfg["proxies"]]
    assert "SG-03" not in names          # tamper 节点被排除
    assert len(cfg["proxies"]) == 2

    # 自动 blocklist 已持久化（tamper 检测路径的直接证据）
    bl = json.load(open(fc.hp.BLOCKLIST_FILE))
    assert "9.9.9.9" in (bl.get("auto") or {}), "tamper 主机应进自动 blocklist"

    # Step Summary 的 probe 拒绝计数 >=1（tamper 统计路径）
    summary = open(os.environ["GITHUB_STEP_SUMMARY"], encoding="utf-8").read()
    assert "Nodes rejected by probe (tamper/MITM/bad egress): **1**" in summary


# ---------------------------------------------------------------------------
# 5. Insecure 隔离
# ---------------------------------------------------------------------------

def test_main_pipeline_insecure_isolation(pipeline, monkeypatch):
    """skip-cert-verify 节点打 [Insecure] 标签并进独立 select 分组。"""
    monkeypatch.setattr(fc, "fetch_all_sources",
                        lambda urls: ({TEST_URL: _insecure_nodes()},
                                      {TEST_URL: {"ok": True, "count": 4, "error": None}}))
    fc.main()
    cfg = _read_yaml(fc.OUTPUT_FILE)
    insecure = [p for p in cfg["proxies"] if "[Insecure]" in p["name"]]
    assert len(insecure) == 1
    # 独立分组存在，且不参与自动选择/故障转移
    groups = {g["name"]: g for g in cfg["proxy-groups"]}
    assert fc.INSECURE_GROUP in groups
    assert groups[fc.INSECURE_GROUP]["type"] == "select"
    auto = next(g for g in cfg["proxy-groups"] if g["name"] == "♻️ 自动选择")
    assert not any("[Insecure]" in n for n in auto["proxies"])
    # 顶层 select 引用独立分组
    assert fc.INSECURE_GROUP in groups["🚀 节点选择"]["proxies"]


# ---------------------------------------------------------------------------
# 6. Step Summary 缺键不崩（P0-1 回归）
# ---------------------------------------------------------------------------

def test_main_pipeline_summary_survives_missing_keys(pipeline, monkeypatch):
    """P0-1 回归：summary_info 缺键时 write_github_summary 不得 KeyError。"""
    calls = {}
    real_write = fc.write_github_summary

    def _spy(info):
        calls["info"] = info
        # 抽掉所有非必需键，模拟未来调用方重构缺键
        for k in ("discovery", "cand_rep", "off_rep", "per_src", "pre_reasons",
                  "probe_reasons", "flags", "anti_crawl"):
            info.pop(k, None)
        return real_write(info)

    monkeypatch.setattr(fc, "write_github_summary", _spy)
    fc.main()   # 不抛 KeyError 即通过
    assert "info" in calls
