#!/usr/bin/env python3
"""proxysub —— 高纯度订阅清洗与结构规范化工具（编排入口）。

本文件是流水线入口：仅保留 main() 编排逻辑；具体实现分散在
common / probe / score / output / handoff 等模块。运行方式不变：
    python filter_clash.py

依赖面（P1-3）：本文件原先用 _reexport() 在运行时把子模块公开符号
动态注入本命名空间——静态分析无法看到这些名字（pyflakes 大量误报），
新增引用时漏 import 也只会在运行期炸 NameError。现改为**按来源模块的
显式 import**：下面这张清单就是本文件的真实外部依赖面，pyflakes 可
静态校验，漏 import 在 CI 即失败。

`import filter_clash as fc` 的既有调用方（测试 / 脚本）仍可访问
fc.<name> —— 显式 import 同样把这些名字绑定到本模块命名空间。
"""


from __future__ import annotations

import json
import os
import re
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import anti_crawl
import common
import evolution
import handoff
import honeypot as hp
import sources_manager as sm
import yaml
from common import (  # 叶子工具函数（配置常量见下面 config import）
    _today,
    _truthy,
    fetch_all_sources,
    fingerprint,
    is_udp_protocol,
    normalize_network,
    parse_subscription_text,
    protocol_gate_reason,
    survival_state_fresh,
)
from config import (  # 可调常量（P1-2 起独立模块）
    AI_LIFECYCLE_ENABLED,
    ASIA_REGIONS,
    BAD_SOURCES_FILE,
    CANDIDATES_CLASH,
    CANDIDATES_PROXIES_ONLY,
    CANDIDATES_SINGBOX,
    CANDIDATES_V2RAY,
    CANDIDATE_ONLY_PENALTY,
    CF_BLOCKED_PENALTY,
    CHANNEL_NODES_KEY,
    CHANNEL_PROBE_QUOTA,
    CN_DECISION_MAX_AGE_S,
    CN_DEMOTE_STREAK,
    CN_HISTORY_FILE,
    CN_LIFECYCLE_ENABLED,
    CN_LOW_CI_HIGH,
    EXCLUDE_KEYWORDS,
    FALLBACK_INTERVAL,
    HISTORY_PASS_RATE_BONUS,   # noqa: F401  兼容面：测试经 fc.<name> 访问
    INSECURE_GROUP,
    INSECURE_TAG,
    MAX_ACCEPT_LATENCY_MS,
    MAX_ACCEPT_LATENCY_MS_US,
    MAX_FINAL,
    MAX_LOW_TIER_PER_REGION,
    MAX_OTHER,
    MAX_PER_CREDENTIAL,
    MAX_PER_EGRESS_IP,
    MAX_PER_EGRESS_IP_PREFERRED,
    MAX_PER_SOURCE_FINAL,
    MAX_US_SHARE,
    MAX_WORKERS,
    MIN_FINAL,
    MULTI_SOURCE_BONUS,
    NO_HTTPS_PENALTY,
    NO_REAL_PROBE_PENALTY,
    OUTPUT_FILE,
    OUTPUT_PROXIES_ONLY,
    OUTPUT_SINGBOX,
    OUTPUT_V2RAY,
    PENDING_PROBE_FILE,
    PENDING_RESCUE_FILE,
    PROBE_FRESH_QUOTA,
    PROBE_LIMIT_OFFICIAL,
    PROBE_PER_CANDIDATE,
    PROBE_PREFERRED_PER_REGION,
    PROBE_RESERVE_PER_REGION,
    PROBE_SOURCE_SAMPLE_CAP,
    PROBE_TILT_MAX,
    PROBE_URL,
    REGION_QUOTAS,
    REGION_RULES,
    REQUIRE_HTTPS_OK_IN_OUTPUT,
    REQUIRE_REAL_PROBE_IN_OUTPUT,
    SOURCE_SCORES_FILE,
    SOURCE_STATS_FILE,
    SURVIVAL_FILE,
    SURVIVAL_PASS_WINDOW,      # noqa: F401  同上
    SURVIVAL_STREAK_FORCE_PROBE,
    TAMPER_STATUSES,
    TCP_LATENCY_CAP_IN_SCORE,
    URLTEST_INTERVAL,
    VERIFICATION_REPORT_FILE,
    real_probe_enabled,
)
from handoff import (  # noqa: F401  （兼容面：测试经 fc.<name> 访问）
    build_pending_doc,
    build_rescue_doc,
    round_stamp,
    select_rescue,
    write_handoff_docs,
)
from output import (  # noqa: F401
    proxy_to_share_link,
    proxy_to_singbox,
    write_github_summary,
    write_outputs,
    write_stats_md,
)
from probe import (  # noqa: F401
    http_socks_probe,
    mihomo_available,
    mihomo_probe,
    tcp_probe,
)
from safe_io import load_json, save_json
from score import (  # noqa: F401
    cap_single_source,
    china_feature_bonus,
    classify_proxy,
    history_bonus,
    is_preferred,
    is_us_node,
    protocol_penalty,
    protocol_tier,
    survival_bonus_ms,
    update_survival,
    us_china_penalty,
)


REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


def _download_verification_report(repo_root: str) -> dict | None:
    """下载上轮沙箱实测报告（Release 资产），失败返回 None（不影响主线）。

    写入系统临时目录（非仓库根），避免被 CI 提交步骤误纳入版本库。
    """
    import tempfile
    path = os.path.join(tempfile.gettempdir(), "_verification_report.json")
    if os.path.exists(path):
        os.remove(path)
    rc = subprocess.run(
        ["gh", "release", "download", "sub", "-p", VERIFICATION_REPORT_FILE,
         "-O", path, "--clobber"], capture_output=True, text=True, timeout=120).returncode
    if rc != 0 or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def load_evolution_inputs(repo_root: str, sources: dict | None = None) -> tuple[dict, dict, dict]:
    """Phase 2 进化引擎入口：下载上轮报告 -> 4 闭环反哺 -> 返回 (cn_hist, learned, source_scores_cn)。

    返回的三份数据供评分阶段复用（中国稳定性加成 / 自学习门槛 / 源级加成）。
    报告缺失或陈旧时返回安全默认值（不信任历史）。

    `sources`：本仓 sources.json（含 official URL 列表），用于构造
    `src_key(url) -> url` 映射，使报告的 owner/repo 键能落到 source_scores 的
    URL 主键上（修复 cn 维度写错键的缺陷，见 evolution.update_source_scores_cn）。
    """
    cn_hist: dict = {}
    source_scores_cn: dict = {}
    learned = {k: v["default"] for k, v in evolution.LEARNED_PARAMS.items()}
    report = _download_verification_report(repo_root)
    if report:
        url_by_src: dict = {}
        for u in (sources or {}).get("official", []):
            url = u.get("url") if isinstance(u, dict) else u
            if url:
                url_by_src.setdefault(common.src_key(url), url)
        summary = evolution.run_evolution(report, repo_root, url_by_src)
        print(f"进化引擎: cn_history={summary['cn_history_nodes']} "
              f"源评分带cn维度={summary['source_scores_with_cn']} "
              f"自学习={summary['learned']}")
        cn_hist = _load_json_safe(os.path.join(repo_root, CN_HISTORY_FILE), {})
        source_scores_cn = _load_json_safe(os.path.join(repo_root, SOURCE_SCORES_FILE), {})
        learned = summary["learned"]
    return cn_hist, learned, source_scores_cn


def _load_json_safe(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def detect_bait_reuse(staged: dict[str, list[dict]], bait_fps: set[str],
                      fingerprint_fn) -> dict[str, list[str]]:
    """检测「源收录了我们生成的诱饵节点」——爬虫/聚合站转载诱饵即自我暴露。

    返回 {url: [flag...]}，flag 为 "bait_reuse"。按源粒度：一个源只要出现过
    诱饵节点即标记（无需逐节点罗列）。调用方按节点粒度丢弃诱饵、按源粒度处置。
    """
    flags: dict[str, list[str]] = {}
    if not bait_fps:
        return flags
    for url, plist in staged.items():
        for p in plist:
            try:
                if fingerprint_fn(p) in bait_fps:
                    flags[url] = ["bait_reuse"]
                    break
            except Exception:
                continue
    return flags


def select_probe_sample(
    tcp_lat: dict[str, float],
    unique: dict[str, dict],
    prov: dict[str, set],
    official_fps: set[str],
    cand_urls: list[str],
    survival: dict,
    today_str: str,
    source_keys=None,
    cn_stats=None,
    ai_stats=None,
) -> list[str]:
    """从 TCP 存活节点中选出进入真实拨测的样本（顺序即优先级）。

    拨测曾经是输出的死活闸门（REQUIRE_REAL_PROBE_IN_OUTPUT）——2026-10-24
    起（任务#102）降级为评分特征：未过拨测节点经 NO_REAL_PROBE_PENALTY
    软惩罚沉底，发布权唯一归属沙箱中国实测。但「选谁去拨测」仍直接决定
    拨测样本覆盖面与 real_hist/特征数据质量。选择原则：

    1) **不迷信历史**：survival.json 可能因任何原因停更（2026-10 曾因工作流
       `git add` 原子失败冻结多轮）。文件一旦陈旧（无今日记录，见
       survival_state_fresh），历史稳定优先整体关闭——否则已死旧节点会凭
       陈旧 streak 霸占拨测预算，新节点无拨测机会，输出质量随轮次持续下滑；
    2) **新节点保底**（PROBE_FRESH_QUOTA）：从未入池的节点保证有拨测机会，
       节点池才能正常轮换；
    3) **区域/协议分层**：亚洲区域与 hy2/reality 优先协议保留各自配额
       （PROBE_RESERVE_PER_REGION / PROBE_PREFERRED_PER_REGION）；
    4) **渠道节点配额**（CHANNEL_PROBE_QUOTA）：多渠道搜集的节点既非正式源
       也非候选源 URL，此前的样本循环永远选不到它们，导致其在评分时全被
       cand_only 闸门丢弃（收集了却永不入选）。给予固定配额，与候选源同等
       参与「通过拨测方可入榜」的试用机制；
    5) **cn 源级配额倾斜**（Phase B，2026-10-20）：有新鲜中国实测实证的源，
       按 evolution.cn_fetch_tilt 的系数调整其占用拨测预算的额度——低产源
       （Wilson 下界 < 5%）减半、高产源（下界 >= 30%）加倍；候选源按同一
       系数缩放 PROBE_PER_CANDIDATE 试用配额。**无实证（缺数据/样本不足/
       陈旧）一律不干预**，行为与改造前完全一致。单源基础上限
       PROBE_SOURCE_SAMPLE_CAP 同样只对有实证的源生效（没证据就不擅自限死，
       避免把未知源一刀切死）；
    6) **AI 源级配额倾斜**（2026-10-21 任务#94）：有新鲜 AI 高产实证的源
       （ai_api/ai_tested 的 Wilson 下界 >= AI_HIGH_YIELD，见
       evolution.ai_fetch_tilt）按 AI_TILT_HIGH 加倍；与 cn 倾斜**相乘
       后封顶 PROBE_TILT_MAX**（双侧实证最多 2 倍，防单一源霸占预算）。
       非对称设计：AI 只有高产档、无低产档——AI 不可达≠节点死亡，减配会
       饿死通用节点供给。两侧都无实证时不干预。

    曾经的阶段 1「轻量探活」已废除：它与 TCP 存活检查同为一次 TCP connect，
    对 3000 个节点重复一遍（通过率 99.7%）只拖慢运行，不提供任何新信息。
    """
    state_fresh = survival_state_fresh(survival, today_str)

    # ---- Phase B：cn/AI 源级拨测配额倾斜。主源口径与评分阶段一致
    # （sorted(prov[fp])[0]）；tilt 按源记忆化，避免逐节点重复计算。
    # 复合规则：cn_tilt × ai_tilt，封顶 PROBE_TILT_MAX；两侧皆无实证
    # （None）才整体不干预——单侧有实证时另一侧按 1.0 中性参与。----
    tilt_cache: dict[str, float | None] = {}

    def _tilt(url: str | None) -> float | None:
        if url is None:
            return None
        if url not in tilt_cache:
            cn_t = (evolution.cn_fetch_tilt(url, cn_stats,
                                            max_age_s=CN_DECISION_MAX_AGE_S)
                    if cn_stats else None)
            ai_t = (evolution.ai_fetch_tilt(url, ai_stats,
                                            max_age_s=CN_DECISION_MAX_AGE_S)
                    if ai_stats else None)
            if cn_t is None and ai_t is None:
                tilt_cache[url] = None
            else:
                tilt_cache[url] = min(PROBE_TILT_MAX,
                                      (cn_t if cn_t is not None else 1.0)
                                      * (ai_t if ai_t is not None else 1.0))
        return tilt_cache[url]

    def _probe_rank(fp: str) -> tuple:
        rec = survival.get(fp, {}) if state_fresh else {}
        streak = int(rec.get("streak", 0))
        seen = int(rec.get("seen_days", 0))
        tier = protocol_tier(unique[fp])
        stable = 0 if streak >= SURVIVAL_STREAK_FORCE_PROBE else 1
        return (stable, tier, -streak, -seen, tcp_lat[fp])

    alive_sorted = sorted(tcp_lat, key=_probe_rank)
    # Stratify: fill per-region reserves first so Asia is actually probed.
    # Within region: take preferred (hy2/reality) quota first, then rest by rank.
    by_region: dict[str, list[str]] = defaultdict(list)
    for fp in alive_sorted:
        if fp not in official_fps:
            continue
        by_region[classify_proxy(unique[fp].get("name", ""))].append(fp)
    sample: list[str] = []
    chosen: set[str] = set()
    src_count: dict[str, int] = defaultdict(int)   # 主源已占用样本数（基础上限语义）

    def _src_cap(fp: str) -> int | None:
        """该节点主源的本轮拨测基础上限；无实证返回 None（不干预）。

        守卫必须两侧联判（cn_stats 与 ai_stats 皆空才返回）——首版只查
        cn_stats，会在「cn 无实证但 AI 有实证」时把 _tilt 的复合结果
        悄悄短路掉（任务#94 接线自查发现）。
        """
        if (not cn_stats and not ai_stats) or not prov.get(fp):
            return None
        t = _tilt(sorted(prov[fp])[0])
        return None if t is None else max(1, int(PROBE_SOURCE_SAMPLE_CAP * t))

    def _take(fp: str) -> None:
        sample.append(fp)
        chosen.add(fp)
        if prov.get(fp):
            src_count[sorted(prov[fp])[0]] += 1

    for region, reserve in PROBE_RESERVE_PER_REGION.items():
        pool = by_region.get(region, [])
        pref_n = PROBE_PREFERRED_PER_REGION.get(region, 0)
        pref = [fp for fp in pool if is_preferred(unique[fp])]
        rest = [fp for fp in pool if fp not in pref]
        ordered = pref[:pref_n] + rest + pref[pref_n:]
        # 上限内尽量填满本区配额：被 cn 上限挡掉的节点顺延到同区下一名
        # （宁可少抓低产源的重复节点，也不把亚洲配额让给别的区）。
        taken = 0
        for fp in ordered:
            if taken >= reserve:
                break
            if fp in chosen:
                continue
            cap = _src_cap(fp)
            if cap is not None and src_count[sorted(prov[fp])[0]] >= cap:
                continue
            _take(fp)
            taken += 1
    # 新节点保底配额：从未进入 survival 的节点优先占用固定名额。
    fresh = [fp for fp in alive_sorted if fp not in survival and fp not in chosen]
    for fp in fresh[:PROBE_FRESH_QUOTA]:
        sample.append(fp)
        chosen.add(fp)
    # UDP protocols (hy2/tuic) skipped TCP probe — force them into the probe
    # sample, otherwise the dead-or-alive gate can never verify them.
    udp_sorted = sorted(
        (fp for fp in alive_sorted if is_udp_protocol(unique[fp]) and fp in official_fps),
        key=_probe_rank,
    )
    for fp in udp_sorted:
        if len(sample) >= PROBE_LIMIT_OFFICIAL:
            break
        if fp not in chosen:
            sample.append(fp)
            chosen.add(fp)
    for fp in alive_sorted:
        if len(sample) >= PROBE_LIMIT_OFFICIAL:
            break
        if fp in official_fps and fp not in chosen:
            cap = _src_cap(fp)
            if cap is not None and src_count[sorted(prov[fp])[0]] >= cap:
                continue
            _take(fp)
    for cu in cand_urls:
        extra = [fp for fp in alive_sorted if cu in prov[fp] and fp not in official_fps and fp not in chosen]
        # 候选源按 cn×AI 复合倾斜系数缩放试用配额（低产少试、高产多试；
        # 无实证原额）。与官方源基础上限共用 _tilt——AI 只有高产档：
        # 低 AI 不减配额（AI 不可达≠节点死亡），低产 down-tilt 由 cn 负责。
        tilt = _tilt(cu)
        quota = PROBE_PER_CANDIDATE if tilt is None else max(1, int(PROBE_PER_CANDIDATE * tilt))
        extra = extra[:quota]
        sample += extra
        chosen.update(extra)
        for fp in extra:
            src_count[sorted(prov[fp])[0]] += 1
    # 多渠道节点保底配额（Telegram/网页分享链接搜集）。
    if source_keys and CHANNEL_NODES_KEY in source_keys:
        ch_fps = [fp for fp in alive_sorted
                  if CHANNEL_NODES_KEY in prov[fp] and fp not in chosen]
        for fp in ch_fps[:CHANNEL_PROBE_QUOTA]:
            sample.append(fp)
            chosen.add(fp)
    return sample


@dataclass
class FetchStageResult:
    """阶段 2（fetch）产出：原始节点 + 抓取统计 + 源失败计数 + 发现报告。"""
    per_source: dict[str, list[dict]]
    fstats: dict[str, dict]
    bad_sources: dict[str, dict]
    disc: dict


@dataclass
class StaticFilterResult:
    """阶段 3（静态过滤）产出：去重后的节点池与各项过滤统计。

    unique/prov/official_fps 供后续探测、评分、交接文档复用；
    pre_reasons/src_flags 供健康报告与 Step Summary 呈现。
    """
    unique: dict[str, dict]
    prov: dict[str, set]
    official_fps: set
    pre_reasons: dict = field(default_factory=lambda: defaultdict(int))
    src_flags: dict = field(default_factory=dict)
    candidates: list = field(default_factory=list)


def discover_and_fetch(sources: dict, cands: dict, off_urls: list[str],
                       cand_urls: list[str]) -> FetchStageResult:
    """阶段 1+2：自动发现 + 抓取全部源 + 多渠道节点 ingest + 源失败计数。

    副作用：读写 BAD_SOURCES_FILE（失败 streak 累积）；读取 collected_nodes.txt
    （channels 模块生成的多渠道搜集产物）。
    """
    disc = sm.discover(sources, cands, parse_subscription_text, os.environ.get("GITHUB_TOKEN"))
    _ch = disc.get("channels", {}) or {}
    print(
        f"自动发现: 新增候选 {len(disc['added'])}"
        f"（GitHub {len(disc['added']) - len(_ch.get('added', []))} + 多渠道 {len(_ch.get('added', []))}），"
        f"扫描仓库 {disc['searched_repos']}；多渠道搜集节点 {_ch.get('nodes_collected', 0)} 条"
        f"，静态源加入 {len(_ch.get('static_added', []))}"
    )

    per_source, fstats = fetch_all_sources(off_urls + cand_urls)
    print(f"原始节点总数: {sum(len(v) for v in per_source.values())}")

    # ---- 2b. 多渠道搜集到的原始节点（Telegram / 网页分享链接） ----
    # 这些节点已写入 collected_nodes.txt，此处 ingest 后与正式源走完全相同的
    # 静态门槛 + 死活闸门清洗，仅白名单协议且通过拨测的节点才会进入最终输出。
    INGEST_MAX_NODES = 300
    _collected_path = "collected_nodes.txt"
    if os.path.exists(_collected_path):
        try:
            with open(_collected_path, encoding="utf-8") as _cf:
                _lines = [ln.strip() for ln in _cf if ln.strip()][-INGEST_MAX_NODES:]
            _plist: list[dict] = []
            for _ln in _lines:
                _plist.extend(parse_subscription_text(_ln))
            if _plist:
                _key = CHANNEL_NODES_KEY
                per_source[_key] = _plist
                fstats[_key] = {"ok": True, "count": len(_plist), "error": None, "ingested": True}
                print(f"多渠道节点: 解析 {len(_plist)} 个（来自 {_collected_path}，上限 {INGEST_MAX_NODES}）")
        except Exception as e:
            print(f"警告: 多渠道节点解析失败（不影响其他源）: {type(e).__name__}: {e}")

    bad_sources = load_json(BAD_SOURCES_FILE, {})
    bad_sources = {u: v for u, v in bad_sources.items() if u in fstats}
    for url, s in fstats.items():
        rec = bad_sources.get(url, {"fail_streak": 0})
        rec["fail_streak"] = 0 if s.get("ok") else int(rec.get("fail_streak", 0)) + 1
        rec["last_error"] = s.get("error")
        rec["last_count"] = s.get("count", 0)
        bad_sources[url] = rec
    return FetchStageResult(per_source, fstats, bad_sources, disc)


def static_filter_stage(per_source: dict[str, list[dict]], off_set: set,
                        bait_fps: set, blocklist) -> StaticFilterResult:
    """阶段 3：静态门槛清洗——关键词/蜜罐/协议白名单/DNS/blocklist/去重。

    顺序有意为之：诱饵回流按节点丢弃 → 静态硬门槛 → 网络参数归一 → 协议白名单
    → DNS 解析与保留地址检查（fake-ip 环境整体降级）→ 网段聚集标记 → 指纹去重。
    """
    exclude_re = re.compile(EXCLUDE_KEYWORDS, re.IGNORECASE)
    pre_reasons: dict[str, int] = defaultdict(int)
    staged: dict[str, list[dict]] = {}
    # 诱饵回流检测：源中一旦出现我们生成的诱饵节点（指纹比对），说明该源在
    # 转载我们的诱饵——候选源将被拒绝、正式源将被淘汰（src_flags -> bait_reuse）。
    # 按节点粒度丢弃诱饵（其余节点照常处理）；标记在静态门槛与 DNS 之前完成，
    # 因为诱饵服务器指向保留域 .invalid，过不了后面的关。
    bait_reuse = detect_bait_reuse(per_source, bait_fps, fingerprint)
    for url, plist in per_source.items():
        keep = []
        for p in plist:
            if bait_fps:
                try:
                    if fingerprint(p) in bait_fps:
                        pre_reasons["bait_reuse"] += 1
                        continue
                except Exception:
                    pass
            if not p.get("server") or not p.get("port") or exclude_re.search(str(p.get("name", ""))):
                continue
            why = hp.static_reject_reason(p)
            if why:
                pre_reasons[why] += 1
                continue
            if not normalize_network(p):
                pre_reasons["network_unsupported"] += 1
                continue
            why = protocol_gate_reason(p)
            if why:
                pre_reasons[why] += 1
                continue
            keep.append(p)
        staged[url] = keep
    hosts = {str(p["server"]).strip().lower().rstrip(".") for pl in staged.values() for p in pl}
    print(f"解析 {len(hosts)} 个主机名...")
    resolved = hp.resolve_hosts(hosts)
    # Guard against fake-IP DNS environments (198.18.0.0/15 etc.): if most domains
    # "resolve" to reserved space, DNS answers are meaningless -> skip that check.
    doms = [h for h in hosts if not h.replace(".", "").isdigit() and ":" not in h]
    bad_dns = sum(1 for h in doms if any(hp.is_bad_ip(i) for i in resolved.get(h, [])))
    dns_trusted = not doms or bad_dns / len(doms) < 0.3
    if not dns_trusted:
        print(f"警告: {bad_dns}/{len(doms)} 个域名解析到保留地址，疑似 fake-ip DNS，跳过 DNS 保留地址检查与源网段聚集检查")

    unique: dict[str, dict] = {}
    prov: dict[str, set] = defaultdict(set)
    src_flags: dict[str, list[str]] = {}
    for url, plist in staged.items():
        # 合并诱饵回流标记、源网段聚集标记与模板×网段联合聚集标记
        # （三者都可能触发拒绝/淘汰；fake-ip DNS 环境下整体跳过网络侧检查）
        flags = bait_reuse.get(url, [])
        if dns_trusted:
            flags += hp.source_cluster_flags(plist, resolved)
            flags += hp.template_ip_cluster_flags(plist, resolved)
        if flags:
            src_flags[url] = flags
        for p in plist:
            host = str(p["server"]).strip().lower().rstrip(".")
            ips = resolved.get(host, [])
            if not ips:
                pre_reasons["unresolvable"] += 1
                continue
            if dns_trusted and any(hp.is_bad_ip(ip) for ip in ips):
                pre_reasons["dns_to_reserved_ip"] += 1
                continue
            hit = blocklist.match(host, ips if dns_trusted else [], fingerprint(p))
            if hit:
                pre_reasons[f"blocklist:{hit.split(':')[0]}"] += 1
                continue
            fp = fingerprint(p)
            unique.setdefault(fp, p)
            prov[fp].add(url)
    official_fps = {fp for fp, s in prov.items() if s & off_set}
    candidates = list(unique.values())
    print(f"去重+过滤后: {len(candidates)}（预过滤拒绝 {sum(pre_reasons.values())}）")
    return StaticFilterResult(unique, prov, official_fps, pre_reasons, src_flags, candidates)


@dataclass
class ProbeStageResult:
    """阶段 4+5（探测）产出。

    tcp_lat 同时承载 TCP 存活节点与 UDP 豁免节点（9999.0 中性延迟）；
    probe 为原始拨测结果；real_ok/tampered/probe_reasons 供评分与报告使用。
    """
    tcp_lat: dict[str, float]
    probe: dict[str, dict]
    sample: list[str]
    bin_path: str | None
    real_ok: dict[str, dict]
    tampered: set
    probe_reasons: dict = field(default_factory=lambda: defaultdict(int))
    host_users: dict = field(default_factory=lambda: defaultdict(int))
    survival_pre: dict = field(default_factory=dict)


def liveness_stage(unique: dict[str, dict]) -> tuple[dict[str, float], int]:
    """阶段 4：TCP 协议走 TCP 握手作在线信号；UDP 协议（hy2/tuic）豁免，
    交由拨测闸门（QUIC）验证死活——中性延迟 9999.0 仅使其进入拨测管道，
    不参与排序。返回 (tcp_lat, udp_exempt)。
    """
    print("开始存活性检测（TCP 协议走 TCP 握手；UDP 协议交由拨测闸门验证）...")
    tcp_lat: dict[str, float] = {}
    tcp_candidates = {fp: p for fp, p in unique.items() if not is_udp_protocol(p)}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        fut_map = {executor.submit(tcp_probe, p): fp for fp, p in tcp_candidates.items()}
        for fut in as_completed(fut_map):
            alive, latency = fut.result()
            if alive:
                tcp_lat[fut_map[fut]] = latency
    udp_exempt = 0
    for fp, p in unique.items():
        if is_udp_protocol(p):
            tcp_lat[fp] = 9999.0  # 中性延迟：不参与排序，仅使其进入拨测管道
            udp_exempt += 1
    print(f"TCP 存活节点: {len(tcp_lat) - udp_exempt} | UDP 协议（hy2/tuic，交拨测验证）: {udp_exempt}")
    return tcp_lat, udp_exempt


def real_probe_stage(tcp_lat: dict[str, float], unique: dict[str, dict], prov: dict[str, set],
                     official_fps: set, cand_urls: list[str], per_source_keys,
                     blocklist, cn_stats=None, ai_stats=None) -> ProbeStageResult:
    """阶段 5：真实拨测（2026-10-24 任务#102 起降级为评分特征）。

    美西拨测 ok 曾是输出的死活闸门（REQUIRE_REAL_PROBE_IN_OUTPUT）——
    现已关闭：未过拨测节点经软惩罚进入排序沉底，发布权唯一归属沙箱中国
    实测（cn.ok）。拨测样本选择仍决定特征数据质量。
    样本选择原则见 select_probe_sample() 的 docstring——2026-10 质量回归后
    修订：历史稳定优先仅在状态新鲜时生效 + 新节点保底配额 + 渠道节点配额；
    2026-10-20 增加 cn 源级配额倾斜（低产源少占预算、高产源多占）。

    tcp_lat 由 liveness_stage() 预先算出（TCP 存活 + UDP 豁免的中性延迟）。
    mihomo 缺失时回退到 http/socks 简单真实探测；tamper 结果自动进 blocklist
    （共享主机按节点粒度封锁，见 host_users 判断）。

    `cn_stats`（可选）：源级中国实测维度，透传给 select_probe_sample 做配额
    倾斜；None/空 = 不干预（改造前行为）。`ai_stats`（可选，2026-10-21
    任务#94）：源级 AI 实证维度，与 cn 倾斜复合（相乘封顶 PROBE_TILT_MAX）；
    None/空 = 不干预。
    """
    survival_pre = load_json(SURVIVAL_FILE, {})
    probe: dict[str, dict] = {}
    bin_path = mihomo_available() if real_probe_enabled() else None
    if not real_probe_enabled():
        print("云端真实流量拨测已禁用（PROXYSUB_DISABLE_PROBE=1）：仅保留 TCP 存活检查，"
              "最终测速/优选由本地客户端通过 gstatic generate_204 完成")
        sample: list[str] = []
    else:
        sample = select_probe_sample(
            tcp_lat, unique, prov, official_fps, cand_urls,
            survival_pre, _today(), per_source_keys, cn_stats, ai_stats,
        )
        state_fresh = survival_state_fresh(survival_pre, _today())
        print(f"拨测样本: {len(sample)}/{len(tcp_lat)}（TCP 存活节点中选出；"
              f"状态{'新鲜' if state_fresh else '陈旧-样本选择与评分均忽略历史优先级'}）")

    if bin_path:
        print(f"使用 mihomo 真实探测 {len(sample)} 个节点: {bin_path}")
        probe = mihomo_probe([unique[fp] for fp in sample], bin_path)
    elif real_probe_enabled():
        print("未找到 mihomo，对 http/socks 做简单真实探测，其余用 TCP 延迟")
        hs = [fp for fp in sample if str(unique[fp].get("type", "")).lower() in ("http", "https", "socks5", "socks5h", "socks")]
        with ThreadPoolExecutor(max_workers=40) as ex:
            fut_map = {ex.submit(http_socks_probe, unique[fp]): fp for fp in hs}
            for fut in as_completed(fut_map):
                ok, lat = fut.result()
                if ok:
                    probe[fut_map[fut]] = {"status": "ok", "latency": lat, "https_ok": False}

    probe_reasons: dict[str, int] = defaultdict(int)
    tampered: set[str] = set()
    host_users: dict[str, int] = defaultdict(int)
    for p in unique.values():
        host_users[str(p["server"]).strip().lower().rstrip(".")] += 1
    for fp, r in probe.items():
        if r["status"] in TAMPER_STATUSES:
            tampered.add(fp)
            probe_reasons[r["status"]] += 1
            host = str(unique[fp]["server"]).strip().lower().rstrip(".")
            # shared hosts (CDN front domains / anycast IPs) are blocked per node, not per host
            key = host if host_users[host] <= 2 else f"fp:{fp}"
            blocklist.auto_add(key, f"{r['status']}:{r.get('detail', '')}"[:100], sorted(prov[fp])[0])
    real_ok = {fp: r for fp, r in probe.items() if r["status"] == "ok"}
    return ProbeStageResult(tcp_lat, probe, sample, bin_path, real_ok, tampered,
                            probe_reasons, host_users, survival_pre)


@dataclass
class ScoringResult:
    """阶段 7（评分）产出。"""
    scored: list = field(default_factory=list)
    survival: dict = field(default_factory=dict)
    diversity_dropped: int = 0


def score_candidates(tcp_lat: dict[str, float], unique: dict[str, dict], prov: dict[str, set],
                     official_fps: set, off_set: set, real_ok: dict[str, dict],
                     tampered: set, bin_path: str | None, survival: dict,
                     cn_latency_cap: float, source_scores_cn: dict,
                     cn_hist: dict, real_probe_on: bool,
                     us_latency_cap: float = MAX_ACCEPT_LATENCY_MS_US,
                     score_latency_cap: float = TCP_LATENCY_CAP_IN_SCORE) -> ScoringResult:
    """阶段 7：评分、排序与多样性/单源上限裁剪。

    Real-probe OK ranks first; TCP-alive (esp. Asia / Hy2/Reality) stays eligible
    so China-path quotas and MIN_FINAL can be filled when US-runner probe is sparse.

    与 select_probe_sample 同一原则：survival 停更（陈旧）时，评分阶段同样
    不信任历史加成——否则陈旧 streak/real_hist 会在排序里继续放大旧时代
    节点的优势，与拨测样本选择的口径相悖（样本已不迷信历史，排序却迷信）。
    update_survival 仍基于真实记录累积（非连续日期会自然重置 streak，自愈）。
    """
    state_fresh = survival_state_fresh(survival, _today())
    score_survival = survival if state_fresh else {}
    scored: list[tuple[dict, float, float, bool, bool, int]] = []
    for fp, tlat in tcp_lat.items():
        if fp in tampered:
            continue
        cand_only = fp not in official_fps
        r = real_ok.get(fp)
        # 任务#102（2026-10-24）：美西拨测降级为评分特征——REQUIRE_…
        # 已置 False，未过拨测节点进入评分，走 NO_REAL_PROBE_PENALTY 软
        # 惩罚沉底；发布权唯一归属沙箱中国实测。开关保留，可一键回滚。
        if bin_path and REQUIRE_REAL_PROBE_IN_OUTPUT and not r:
            continue  # 死活闸门（默认关闭）：本轮未通过真实拨测的节点不进最终列表
        # 试用期源硬卡点同步拆除（任务#102）：cand_only 且未过拨测的节点
        # 不再直接剔除——NO_REAL_PROBE_PENALTY + CANDIDATE_ONLY_PENALTY
        # 双重软惩罚已覆盖排序，中国实测才是它们的生死证。
        if bin_path and REQUIRE_HTTPS_OK_IN_OUTPUT and r and not r.get("https_ok"):
            continue  # AI/CF sites need working HTTPS egress
        display = r["latency"] if r else tlat
        us_like = is_us_node(unique[fp], r)
        lat_cap = us_latency_cap if us_like else cn_latency_cap
        if r and display > lat_cap:
            continue  # extreme outlier on runner RTT
        # Drop open http/socks from final when we have mihomo purity path
        tier = protocol_tier(unique[fp])
        if bin_path and tier >= 3 and str(unique[fp].get("type", "")).lower() in (
            "http", "https", "socks5", "socks5h", "socks",
        ):
            continue
        penalty = 0.0 if r or not bin_path else NO_REAL_PROBE_PENALTY
        if r and bin_path and not r.get("https_ok"):
            penalty += NO_HTTPS_PENALTY  # soft: CF HTTPS not sole veto
            # 跳过证书校验且 HTTPS 探测失败：TLS 链路大概率已被劫持/为空壳，
            # 再追加一等惩罚（Insecure 节点本就应更严格，见命名阶段的安全隔离）。
            if _truthy(unique[fp].get("skip-cert-verify")):
                penalty += NO_HTTPS_PENALTY
        if r and r.get("cf_blocked"):
            penalty += CF_BLOCKED_PENALTY  # soft purity
        if cand_only:
            penalty += CANDIDATE_ONLY_PENALTY
        multi = len(prov[fp] & off_set)
        if multi >= 2:
            penalty -= MULTI_SOURCE_BONUS * min(multi - 1, 3)
        penalty += protocol_penalty(unique[fp])
        penalty += china_feature_bonus(unique[fp])
        penalty += us_china_penalty(unique[fp], r)
        # Phase 2.2 源级中国通过率加成：中国通过率高的源排更前、拿更多配额。
        # 键口径（2026-10-20）：传**完整 URL** 主键——cn_source_bonus 内部
        # 「URL 优先、src_key 镜像兜底」，传镜像键只能走兜底路径读到陈旧数据。
        _src = sorted(prov[fp])[0] if prov.get(fp) else None
        penalty += evolution.cn_source_bonus(_src, source_scores_cn)
        bonus = survival_bonus_ms(fp, score_survival)
        bonus += history_bonus(fp, score_survival)  # 历史真实通过率（持续通过的节点排更前）
        bonus += evolution.cn_stability_bonus_ms(fp, cn_hist)  # Phase 2.1 中国稳定性加成
        if is_preferred(unique[fp]):
            bonus *= 1.5  # keep long-lived hy2/reality even harder
        # TCP 延迟（美西 Runner 测得，≠国内真实路径）仅作粗排信号：贡献设上限，
        # 排序主要由协议质量 / 存活时长 / 多源 / 亚洲路径等静态特征决定。
        score = min(display, score_latency_cap) + penalty + bonus
        scored.append((unique[fp], score, display, is_preferred(unique[fp]), bool(r), tier))

    scored.sort(key=lambda x: (x[5], not x[3], x[1]))
    alive_fps = {fingerprint(p) for p, *_ in scored}
    # 传入本轮真实拨测通过集合，用于维护「真实通过率滑动窗口」（real_hist）
    survival = update_survival(alive_fps, survival,
                               set(real_ok.keys()) if (bin_path or real_probe_on) else None)

    # diversity caps: one credential / one egress IP must not dominate the output
    cred_n: dict[str, int] = defaultdict(int)
    egress_n: dict[str, int] = defaultdict(int)
    diversified = []
    diversity_dropped = 0
    for item in scored:
        fp = fingerprint(item[0])
        cred = hp.credential_of(item[0])
        eg = (real_ok.get(fp) or {}).get("egress")
        # 出口 IP 帽按协议分档（任务#104）：hy2/reality（tier 0）常经 CDN
        # /中转撞同一出口 IP，3 的帽子把活节点成批削掉；放宽到 8。
        eg_cap = (MAX_PER_EGRESS_IP_PREFERRED
                  if protocol_tier(item[0]) == 0 else MAX_PER_EGRESS_IP)
        if (cred and cred_n[cred] >= MAX_PER_CREDENTIAL) or (eg and egress_n[eg] >= eg_cap):
            diversity_dropped += 1
            continue
        if cred:
            cred_n[cred] += 1
        if eg:
            egress_n[eg] += 1
        diversified.append(item)
    scored = diversified

    # per-source cap: one aggregator feed must not dominate the output
    # 任务#104：中国实测已通过的节点不占名额（cn_ok 为最近一轮中国实测滚动值）
    cn_exempt = {fp for fp, v in (cn_hist or {}).items() if v.get("cn_ok")}
    scored, src_dropped = cap_single_source(scored, prov, MAX_PER_SOURCE_FINAL,
                                            cn_exempt=cn_exempt)
    if src_dropped:
        print(f"单一源独占上限 {MAX_PER_SOURCE_FINAL}: 再去掉 {src_dropped} 个（防聚合源垄断）")
    return ScoringResult(scored, survival, diversity_dropped)


def select_final(scored: list, real_ok: dict[str, dict]) -> dict[str, list]:
    """阶段 8+9：区域配额选择 + 美国占比上限 + MIN/MAX_FINAL 强制。

    填充顺序：preferred real → high real → preferred TCP → high TCP → low
    （TCP 档位让亚洲配额在美国 Runner 拨测不足时也能填满）；
    低于下限时按 (非美/亚洲/真实/优先/tier/分数) 回填，高于上限则反向裁剪。
    """
    region_dict: dict[str, list] = defaultdict(list)
    for item in scored:
        region_dict[classify_proxy(item[0].get("name", ""))].append(item)

    def _bucketize(nodes: list) -> tuple[list, list, list, list, list]:
        """Split into: preferred+real, high+real, preferred+TCP, high+TCP, low."""
        pref_real, high_real, pref_tcp, high_tcp, low = [], [], [], [], []
        for item in nodes:
            fp = fingerprint(item[0])
            r = real_ok.get(fp) or {}
            if REQUIRE_HTTPS_OK_IN_OUTPUT and item[4] and not r.get("https_ok"):
                continue
            tier = item[5] if len(item) > 5 else protocol_tier(item[0])
            preferred = bool(item[3] or tier == 0)
            real = bool(item[4])
            if preferred and real:
                pref_real.append(item)
            elif tier <= 1 and real:
                high_real.append(item)
            elif preferred and not real:
                pref_tcp.append(item)
            elif tier <= 1 and not real:
                high_tcp.append(item)
            else:
                low.append(item)
        return pref_real, high_real, pref_tcp, high_tcp, low

    region_selected: dict[str, list] = {}
    for region, nodes in region_dict.items():
        quota = REGION_QUOTAS.get(region, MAX_OTHER)
        # China-path fill order: preferred real → high real → preferred TCP → high TCP → low.
        # TCP tiers let Asia quotas fill when US-runner real probe under-samples Asia.
        pref_real, high_real, pref_tcp, high_tcp, low = _bucketize(nodes)
        selected: list = []
        for bucket in (pref_real, high_real, pref_tcp, high_tcp):
            for item in bucket:
                if len(selected) >= quota:
                    break
                selected.append(item)
            if len(selected) >= quota:
                break
        low_added = 0
        if len(selected) < quota:
            for item in low:
                if len(selected) >= quota or low_added >= MAX_LOW_TIER_PER_REGION:
                    break
                selected.append(item)
                low_added += 1
        region_selected[region] = selected
        pref_count = sum(1 for row in selected if row[3])
        real_count = sum(1 for row in selected if row[4])
        print(
            f"{region}: 候选 {len(selected)}（优先 {pref_count}，真实探测 {real_count}，"
            f"tier0 {sum(1 for r in selected if (r[5] if len(r)>5 else 9)==0)}）"
        )

    # Cap US share of final list (China path: US often unusable).
    flat: list[tuple] = []
    for region, selected in region_selected.items():
        for row in selected:
            flat.append((region, row))
    # Prefer non-US first when trimming
    def _us_rank(pair):
        region, row = pair
        proxy = row[0]
        fp = fingerprint(proxy)
        us = region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fp))
        return (1 if us else 0, row[1])  # non-US first, then better score
    flat.sort(key=_us_rank)
    max_us = max(1, int(len(flat) * MAX_US_SHARE + 0.999)) if flat else 0
    kept: list[tuple] = []
    us_n = 0
    for region, row in flat:
        proxy = row[0]
        fp = fingerprint(proxy)
        us = region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fp))
        if us:
            if us_n >= max_us:
                continue
            us_n += 1
        kept.append((region, row))
    # Re-group for naming/output stability by region order
    final_by_region: dict[str, list] = defaultdict(list)
    for region, row in kept:
        final_by_region[region].append(row)
    us_dropped = len(flat) - len(kept)
    if us_dropped:
        print(f"美国占比上限 {MAX_US_SHARE:.0%}: 再去掉 {us_dropped} 个美国/美国出口节点")

    # ---- enforce MIN_FINAL / MAX_FINAL (100–200) ----
    selected_fps = {fingerprint(row[0]) for _, row in kept}
    total_now = len(selected_fps)

    def _fill_key(item) -> tuple:
        proxy = item[0]
        region = classify_proxy(str(proxy.get("name", "")))
        asia = 0 if region in ASIA_REGIONS else 1
        real = 0 if item[4] else 1
        pref = 0 if item[3] else 1
        us = 1 if (region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fingerprint(proxy)))) else 0
        return (us, asia, real, pref, item[5] if len(item) > 5 else 9, item[1])

    if total_now < MIN_FINAL:
        pool = [item for item in scored if fingerprint(item[0]) not in selected_fps]
        pool.sort(key=_fill_key)
        added = 0
        for item in pool:
            if total_now >= MIN_FINAL or total_now >= MAX_FINAL:
                break
            proxy = item[0]
            fp = fingerprint(proxy)
            region = classify_proxy(str(proxy.get("name", "")))
            us = region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fp))
            # While below floor, still respect US share soft cap on the growing list.
            if us:
                max_us_floor = max(1, int((total_now + 1) * MAX_US_SHARE + 0.999))
                cur_us = sum(
                    1 for reg, rows in final_by_region.items() for row in rows
                    if reg == "🇺🇸 美国" or is_us_node(row[0], real_ok.get(fingerprint(row[0])))
                )
                if cur_us >= max_us_floor:
                    continue
            final_by_region[region].append(item)
            selected_fps.add(fp)
            total_now += 1
            added += 1
        if added:
            print(f"节点数下限 {MIN_FINAL}: 回填 {added} 个（优先亚洲/真实探测/Hy2·Reality）")

    # Trim to MAX_FINAL if over (drop US/low-tier/worst score first).
    flat2: list[tuple] = []
    for region, rows in final_by_region.items():
        for row in rows:
            flat2.append((region, row))
    if len(flat2) > MAX_FINAL:
        def _trim_key(pair):
            region, row = pair
            proxy = row[0]
            fp = fingerprint(proxy)
            us = 1 if (region == "🇺🇸 美国" or is_us_node(proxy, real_ok.get(fp))) else 0
            real = 0 if row[4] else 1
            pref = 0 if row[3] else 1
            # keep best: non-US, real, preferred, better score — sort ascending then keep[:MAX]
            return (us, real, pref, row[5] if len(row) > 5 else 9, row[1])
        flat2.sort(key=_trim_key)
        flat2 = flat2[:MAX_FINAL]
        final_by_region = defaultdict(list)
        for region, row in flat2:
            final_by_region[region].append(row)
        print(f"节点数上限 {MAX_FINAL}: 裁剪后 {len(flat2)}")
    return final_by_region


def per_source_metrics(off_urls: list[str], cand_urls: list[str], off_set: set,
                       per_source: dict[str, list[dict]], prov: dict[str, set],
                       official_fps: set, unique: dict[str, dict], tcp_lat: dict[str, float],
                       real_ok: dict[str, dict], probe: dict[str, dict],
                       tampered: set, fstats: dict[str, dict],
                       src_flags: dict, bin_path) -> dict[str, dict]:
    """阶段 6：按源汇总指标（存活/拨测/tamper/独占计数）。

    渠道节点（CHANNEL_NODES_KEY）也纳入 per-source 指标：此前它不在
    off_urls + cand_urls 中，指标/统计里完全不可见（收集了多少、存活多少、
    拨测通过多少都无从考证）。
    """
    per_src: dict[str, dict] = {}
    metric_urls = off_urls + cand_urls + (
        [CHANNEL_NODES_KEY] if CHANNEL_NODES_KEY in per_source else []
    )
    for url in metric_urls:
        fps = [fp for fp, s in prov.items() if url in s]
        alive = [fp for fp in fps if fp in tcp_lat]
        is_off = url in off_set
        m = dict(fstats.get(url, {}))
        m.update(
            role="official" if is_off else ("channel" if url == CHANNEL_NODES_KEY else "candidate"),
            alive=len(alive),
            real_ok=sum(1 for fp in alive if fp in real_ok),
            probed=sum(1 for fp in fps if fp in probe),
            tamper=sum(1 for fp in fps if fp in tampered),
            cf_blocked=sum(1 for fp in fps if (probe.get(fp) or {}).get("cf_blocked")),
            preferred_ok=sum(1 for fp in alive if fp in real_ok and is_preferred(unique[fp])),
            flags=src_flags.get(url, []),
        )
        if is_off:
            m["unique_alive"] = sum(1 for fp in alive if len(prov[fp] & off_set) == 1)
        else:
            usable = [fp for fp in alive if (fp in real_ok if bin_path else True)]
            m["usable"] = len(usable)
            m["unique_new"] = sum(1 for fp in usable if fp not in official_fps)
        per_src[url] = m
    return per_src


def main() -> None:
    sources = sm.load_sources()
    cands = sm.load_candidates()
    blocklist = hp.Blocklist(load_json(hp.BLOCKLIST_FILE, None))
    expired = blocklist.prune_expired()
    stats_file = load_json(SOURCE_STATS_FILE, {})
    history = stats_file.get("history", {}) if isinstance(stats_file, dict) else {}

    # ---- 0. 反爬与防搜索（默认关闭；开启后固定名写诱饵、真实输出用轮换文件名）----
    ac = anti_crawl.load_config()
    ac_enabled = anti_crawl.is_enabled(ac)
    ac_report: dict = {"enabled": ac_enabled}
    if ac_enabled:
        ac = anti_crawl.begin_run(ac)          # 轮换 token / 重生成诱饵 / 删过期文件
        anti_crawl.write_robots()              # robots.txt（Disallow: /）
        ac_report.update({
            "real_outputs": ac.get("current_outputs", []),
            "rotate_days": ac.get("rotate_days"),
            "stale_outputs": ac.get("stale_outputs", []),
        })
        print(f"反爬已开启: 固定名订阅文件为诱饵内容；真实输出 -> {ac.get('current_outputs')}")
    bait_fps = anti_crawl.bait_fingerprints(ac, fingerprint) if ac_enabled else set()

    # ---- 1+2. discovery + fetch ----
    off_urls = sm.official_urls(sources)
    cand_urls = [u for u in sm.active_candidate_urls(cands) if u not in off_urls]
    off_set = set(off_urls)
    fetched = discover_and_fetch(sources, cands, off_urls, cand_urls)
    per_source, fstats, bad_sources = fetched.per_source, fetched.fstats, fetched.bad_sources
    disc = fetched.disc

    # ---- 3. static filters: keyword / honeypot / 协议白名单与关键参数硬性门槛 ----
    sf = static_filter_stage(per_source, off_set, bait_fps, blocklist)
    unique, prov, official_fps = sf.unique, sf.prov, sf.official_fps
    pre_reasons, src_flags = sf.pre_reasons, sf.src_flags

    # ---- 3.5 进化引擎（Phase 2）：下载上轮沙箱实测报告，反哺本地数据/门槛 ----
    # 提前到探测之前：cn 源级生命周期（拨测配额倾斜 / 源淘汰 / 候选晋升）与本轮
    # 评分都要消费其产物。run_evolution 只依赖 sources.official 列表构造
    # src_key->url 映射，与后续阶段无顺序耦合；写操作均带陈旧守卫（报告过旧
    # 即跳过，见 evolution 模块 docstring），先跑先写不依赖本轮任何结果。
    cn_hist, learned_params, source_scores_cn = load_evolution_inputs(REPO_ROOT, sources)
    cn_stats = evolution.cn_source_stats(source_scores_cn) if CN_LIFECYCLE_ENABLED else {}
    if cn_stats:
        print(f"cn源级生命周期: {len(cn_stats)} 个源有中国实测实证"
              f"（淘汰/晋升/拨测倾斜已启用）")
    elif CN_LIFECYCLE_ENABLED:
        print("cn源级生命周期: 无实证（报告缺失/陈旧——本轮流待观察，不干预）")
    # AI 源级生命周期（2026-10-21 任务#94）：与 cn 共用同一份
    # source_scores（ai_* 字段由 evolution.update_source_scores_ai 写入），
    # 消费点=候选晋升 AI 优先 + 拨测配额复合倾斜；总熔断 AI_LIFECYCLE_ENABLED。
    ai_stats = evolution.ai_source_stats(source_scores_cn) if AI_LIFECYCLE_ENABLED else {}
    if ai_stats:
        print(f"AI源级生命周期: {len(ai_stats)} 个源有 AI 可达性实证"
              f"（晋升优先/拨测倾斜已启用）")
    elif AI_LIFECYCLE_ENABLED:
        print("AI源级生命周期: 无实证（报告缺失/陈旧或证据预算跳过——不干预）")

    # ---- 4+5. 存活性检查 + 真实拨测 ----
    tcp_lat, udp_exempt = liveness_stage(unique)
    ps = real_probe_stage(tcp_lat, unique, prov, official_fps, cand_urls,
                          per_source.keys(), blocklist, cn_stats, ai_stats)
    probe, sample, bin_path = ps.probe, ps.sample, ps.bin_path
    real_ok, tampered, probe_reasons = ps.real_ok, ps.tampered, ps.probe_reasons
    survival_pre = ps.survival_pre

    # ---- 6. per-source metrics + 源级生命周期（cn 实证驱动的淘汰/晋升）----
    per_src = per_source_metrics(off_urls, cand_urls, off_set, per_source, prov,
                                 official_fps, unique, tcp_lat, real_ok, probe,
                                 tampered, fstats, src_flags, bin_path)
    cand_rep = sm.evaluate_candidates(cands, {u: per_src[u] for u in cand_urls},
                                      sources, cn_stats, ai_stats)
    off_rep = sm.update_official(sources, history, {u: per_src[u] for u in off_urls},
                                 cn_stats)
    for u in cand_rep["promoted"]:
        print(f"候选源晋升为正式源: {u}")
    for u, why in {**cand_rep["rejected"], **off_rep["demoted"]}.items():
        print(f"移除源: {u} -> {why}")
    for u, g in off_rep.get("guarded", {}).items():
        # 有效性守卫（2026-10-21 任务#93）：零独有达标但有 cn 实效实证的源
        # 不淘汰——代理指标不得淘汰有效源，留痕供审计。
        print(f"源保留（零独有守卫）: {u} -> cn 实证 {g['cn_passed']}/{g['cn_tested']}"
              f"（Wilson 下界 {g['wilson_ci_low']:.1%}），零独有 "
              f"{g['zero_unique_streak']} 轮未汰")
    cn_demoted = [u for u, why in off_rep["demoted"].items()
                  if why.startswith("cn_low_pass_rate")]
    if cn_demoted:
        print(f"cn源级淘汰: {len(cn_demoted)} 个低产源（中国实测 Wilson 下界 "
              f"< {CN_LOW_CI_HIGH:.0%}，连续 {CN_DEMOTE_STREAK} 轮）")

    # ---- 7. scoring ----
    cn_latency_cap = learned_params.get("CN_LATENCY_CAP_MS", MAX_ACCEPT_LATENCY_MS)
    us_latency_cap = learned_params.get("US_LATENCY_CAP_MS", MAX_ACCEPT_LATENCY_MS_US)
    score_latency_cap = learned_params.get("SCORE_LATENCY_CAP_MS", TCP_LATENCY_CAP_IN_SCORE)
    sr = score_candidates(tcp_lat, unique, prov, official_fps, off_set, real_ok,
                          tampered, bin_path, survival_pre, cn_latency_cap,
                          source_scores_cn, cn_hist, real_probe_enabled(),
                          us_latency_cap, score_latency_cap)
    scored, survival, diversity_dropped = sr.scored, sr.survival, sr.diversity_dropped

    # ---- 8+9. 区域配额选择 + 美国占比上限 + MIN/MAX_FINAL 强制 ----
    final_by_region = select_final(scored, real_ok)

    # ---- 10+11. 命名与安全隔离 + Clash 配置构建 ----
    nr = name_and_isolate(final_by_region)
    final_proxies, insecure_proxies = nr.final_proxies, nr.insecure_proxies
    final_name_by_fp, total_final = nr.final_name_by_fp, nr.total_final
    config = build_clash_config(final_proxies, insecure_proxies)

    # ---- 12. persist + 13. summary ----
    _persist_stage(ac_enabled, ac, config, final_proxies, insecure_proxies,
                   sample, unique, real_ok, prov, tampered, tcp_lat, final_name_by_fp,
                   per_src, sources, cands, history, survival, bad_sources, blocklist,
                   expired, disc, cand_rep, off_rep, pre_reasons, probe_reasons,
                   diversity_dropped, src_flags, probe, ac_report, total_final, bin_path)


@dataclass
class NamingResult:
    """阶段 10（命名与隔离）产出。"""
    final_proxies: list = field(default_factory=list)      # 合规节点
    insecure_proxies: list = field(default_factory=list)   # 高风险节点（跳过证书校验）
    final_name_by_fp: dict = field(default_factory=dict)
    total_final: int = 0


def name_and_isolate(final_by_region: dict[str, list]) -> NamingResult:
    """阶段 10：命名与安全隔离。

    1) 不再附加美西 Runner 测得的延迟标签——该延迟不代表国内真实路径，只会误导用户；
       最终测速/优选完全由本地客户端的 url-test（gstatic generate_204）动态完成。
    2) skip-cert-verify: true 的节点：名称打 [Insecure] 标签 + 独立分组隔离，
       不与合规节点无差别混同，也不进入自动选择/故障转移/地区分组。

    final_name_by_fp 是 fp -> 最终发布名（含 [Insecure] 标签与去重后缀）的映射：
    交接文档用它与已发布资产对齐——沙箱据通过名单按此名过滤各格式候选资产。
    """
    def _base_name(p: dict) -> str:
        base = re.sub(r"\s+\d+ms$", "", str(p.get("name", "node"))).strip()
        return base or "node"

    seen_names: dict[str, int] = {}
    final_proxies: list[dict] = []      # 合规节点
    insecure_proxies: list[dict] = []   # 高风险节点（跳过证书校验）
    for region in list(REGION_RULES.keys()) + ["🌐 其他"]:
        selected = final_by_region.get(region, [])
        for row in selected:
            proxy = row[0]
            np = dict(proxy)
            insecure = _truthy(np.get("skip-cert-verify"))
            full = _base_name(np) + (INSECURE_TAG if insecure else "")
            if full in seen_names:
                seen_names[full] += 1
                full = f"{full}#{seen_names[full]}"
            else:
                seen_names[full] = 1
            np["name"] = full
            (insecure_proxies if insecure else final_proxies).append(np)
        if selected:
            print(f"{region}: 最终保留 {len(selected)}")
    if insecure_proxies:
        print(f"安全隔离: {len(insecure_proxies)} 个 skip-cert-verify 节点已标记{INSECURE_TAG}并独立分组")
    total_final = len(final_proxies) + len(insecure_proxies)
    if total_final < MIN_FINAL:
        print(f"警告: 最终 {total_final} < 下限 {MIN_FINAL}（候选池不足）")
    final_name_by_fp = {fingerprint(p): p["name"] for p in final_proxies + insecure_proxies}
    print(f"\n最终精简节点数: {total_final}（合规 {len(final_proxies)}，高风险隔离 {len(insecure_proxies)}）")
    return NamingResult(final_proxies, insecure_proxies, final_name_by_fp, total_final)


def build_clash_config(final_proxies: list[dict], insecure_proxies: list[dict]) -> dict:
    """阶段 11：构建 Clash 配置——选择组 + 自动测速/故障转移 + 地区分组 + Insecure 隔离池。

    自动选择/故障转移仅包含合规节点；url-test 由客户端本地动态测速。
    """
    names = [p["name"] for p in final_proxies]
    groups = [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": ["♻️ 自动选择", "🔯 故障转移", "DIRECT"] + list(REGION_RULES.keys()) + ["🌐 其他"],
        },
        {"name": "♻️ 自动选择", "type": "url-test", "proxies": names, "url": PROBE_URL,
         "interval": URLTEST_INTERVAL, "tolerance": 50},
        {"name": "🔯 故障转移", "type": "fallback", "proxies": names, "url": PROBE_URL,
         "interval": FALLBACK_INTERVAL},
    ]
    for region in list(REGION_RULES.keys()) + ["🌐 其他"]:
        region_names = [p["name"] for p in final_proxies if classify_proxy(p.get("name", "")) == region]
        region_names = list(dict.fromkeys(region_names))
        if region_names:
            groups.append({"name": region, "type": "url-test", "proxies": region_names,
                           "url": PROBE_URL, "interval": URLTEST_INTERVAL})
    # 高风险节点独立池：仅供手动选择，不参与任何自动测速/故障转移
    insecure_names = [p["name"] for p in insecure_proxies]
    if insecure_names:
        groups.append({"name": INSECURE_GROUP, "type": "select", "proxies": insecure_names})
        groups[0]["proxies"].append(INSECURE_GROUP)
    # a select group referencing an empty region group would break the config
    present = {g["name"] for g in groups}
    groups[0]["proxies"] = [n for n in groups[0]["proxies"] if n in present or n == "DIRECT"]

    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": final_proxies + insecure_proxies,
        "proxy-groups": groups,
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }


def _persist_stage(ac_enabled, ac, config, final_proxies, insecure_proxies,
                   sample, unique, real_ok, prov, tampered, tcp_lat, final_name_by_fp,
                   per_src, sources, cands, history, survival, bad_sources, blocklist,
                   expired, disc, cand_rep, off_rep, pre_reasons, probe_reasons,
                   diversity_dropped, src_flags, probe, ac_report, total_final, bin_path):
    """阶段 12+13：持久化、发布与汇总报告（反爬开启/关闭两条路径）。

    反爬开启时：固定名文件写诱饵内容；真实输出的去向由 publish_release 决定——
      release 模式（默认）：写入 .publish/<随机资产名>，由工作流发布为滚动
        GitHub Release，订阅地址永久不变（一次复制，长期有效）；
      rotate 模式：写轮换文件名，链接每 rotate_days 天失效一次。

    无论哪条路径，状态文件（survival/bad_sources/source_stats/sources/candidates/
    blocklist/source_scores）都会原子落盘；最后生成 stats.md 与 Step Summary。
    """
    if ac_enabled:
        if anti_crawl.publish_mode(ac):
            paths = anti_crawl.publish_paths(ac)
            os.makedirs(anti_crawl.PUBLISH_DIR, exist_ok=True)
            real_main = paths[OUTPUT_FILE]
            with open(real_main, "w", encoding="utf-8") as f:
                yaml.dump(config, f, allow_unicode=True, sort_keys=False)
            write_outputs(final_proxies + insecure_proxies, namer=lambda b: paths[b])
            decoy_stat = anti_crawl.write_decoy_outputs(ac)
            # 候选集固定名副本（candidates_*）：主资产（p_* 随机名，订阅永久
            # 地址）在实测验证新鲜时归沙箱实测集所有（CI 不覆盖，见工作流
            # 发布步骤的所有权切换逻辑）；候选集以固定名常驻发布，供透明
            # 备查、CI 兜底与沙箱侧交叉核对。
            cand_names = {OUTPUT_PROXIES_ONLY: CANDIDATES_PROXIES_ONLY,
                          OUTPUT_SINGBOX: CANDIDATES_SINGBOX,
                          OUTPUT_V2RAY: CANDIDATES_V2RAY}
            with open(os.path.join(anti_crawl.PUBLISH_DIR, CANDIDATES_CLASH),
                      "w", encoding="utf-8") as f:
                yaml.dump(config, f, allow_unicode=True, sort_keys=False)
            write_outputs(final_proxies + insecure_proxies,
                          namer=lambda b: os.path.join(
                              anti_crawl.PUBLISH_DIR, cand_names.get(b, b)))
            # 交接文档（中国出口实测接力）：待测集 = 拨测样本 ∪ 最终输出；
            # 救援集 = 静态可行但未入样节点（RESCUE_QUOTA，lost-and-found）。
            # 随 .publish/* 发布为 Release 资产——上传顺序上订阅资产
            # （candidates_* 先于 pending_*，见工作流 files 清单）保证
            # 沙箱轮次闸门读到新 pending_probe.json 时订阅内容必已就绪。
            handoff_rid, handoff_now = handoff.round_stamp()
            handoff_stat = handoff.write_handoff_docs(
                anti_crawl.PUBLISH_DIR,
                handoff.build_pending_doc(
                    round_id=handoff_rid, generated_at=handoff_now,
                    sample_fps=sample, final_names=final_name_by_fp,
                    unique=unique, real_ok=real_ok, prov=prov),
                handoff.build_rescue_doc(
                    round_id=handoff_rid, generated_at=handoff_now,
                    rescue_fps=handoff.select_rescue(
                        tcp_lat=tcp_lat, unique=unique, tampered=tampered,
                        excluded=set(sample) | set(final_name_by_fp),
                        is_preferred=is_preferred, protocol_tier=protocol_tier,
                        static_pool=unique),
                    unique=unique, prov=prov),
            )
            ac_report.update({
                "mode": "release",
                "real_outputs": list(paths.values()),
                "candidates": [CANDIDATES_CLASH, CANDIDATES_SINGBOX,
                               CANDIDATES_V2RAY, CANDIDATES_PROXIES_ONLY],
                "release_urls": anti_crawl.release_urls(ac),
            })
            print(f"反爬: 真实输出 -> {anti_crawl.PUBLISH_DIR}/（发布为滚动 Release 永久地址；"
                  f"固定名文件已写为诱饵 {decoy_stat.get('total', 0)} 个节点）")
            print(f"交接: 待测 {handoff_stat[PENDING_PROBE_FILE]} 个 | "
                  f"救援 {handoff_stat[PENDING_RESCUE_FILE]} 个 "
                  f"（round {handoff_rid}，交沙箱中国出口实测）")
        else:
            namer = anti_crawl.make_namer(ac)
            real_main = namer(OUTPUT_FILE)
            with open(real_main, "w", encoding="utf-8") as f:
                yaml.dump(config, f, allow_unicode=True, sort_keys=False)
            write_outputs(final_proxies + insecure_proxies, namer=namer)
            decoy_stat = anti_crawl.write_decoy_outputs(ac)
            ac_report.update({"mode": "rotate", "real_outputs": ac.get("current_outputs", [])})
            print(f"反爬: 真实输出 -> {real_main}（固定名文件已写为诱饵 {decoy_stat.get('total', 0)} 个节点）")
    else:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)
        # 多格式输出 + 健康报告（同一份最终节点列表的不同封装）
        write_outputs(final_proxies + insecure_proxies)
    save_json(SURVIVAL_FILE, survival)
    save_json(BAD_SOURCES_FILE, bad_sources)
    save_json(SOURCE_STATS_FILE, {"date": _today(), "sources": per_src, "history": history})
    sm.save_json(sm.SOURCES_FILE, sources)
    sm.save_json(sm.CANDIDATES_FILE, cands)
    sm.save_json(hp.BLOCKLIST_FILE, blocklist.data)
    # 源评分（单调递增/衰减，独立文件，向后兼容）
    try:
        scores = sm.update_source_scores(sources, per_src, history)
        sm.save_json(SOURCE_SCORES_FILE, scores)
    except Exception as e:  # 评分失败不应影响主产出
        print(f"警告: 源评分更新失败（不影响输出）: {type(e).__name__}: {e}")

    print(f"\n✅ 已生成: {real_main if ac_enabled else OUTPUT_FILE}"
          + ("（固定名文件为诱饵内容；永久订阅地址见 Actions Step Summary）" if ac_enabled else ""))
    summary_info = {
        "final": total_final, "compliant": len(final_proxies), "insecure": len(insecure_proxies),
        "tcp": len(tcp_lat), "real": len(real_ok),
        "probe_mode": ("disabled (client-side testing)" if not real_probe_enabled()
                       else ("mihomo" if bin_path else "tcp-only")),
        "https": sum(1 for r in real_ok.values() if r.get("https_ok")),
        "n_official": len(sources["official"]), "n_cands": len(cands["candidates"]),
        "discovery": disc, "cand_rep": cand_rep, "off_rep": off_rep,
        "pre_reasons": dict(pre_reasons), "probe_reasons": dict(probe_reasons),
        "auto_added": len(blocklist.added_this_run), "expired": expired,
        "diversity_dropped": diversity_dropped,
        "flags": "; ".join(f"{u.split('/')[3] if '//' in u else u}: {','.join(f)}" for u, f in src_flags.items()),
        "per_src": per_src,
        "final_proxies": final_proxies + insecure_proxies,
        "probed_total": len(probe),
        "anti_crawl": ac_report,
    }
    write_stats_md(summary_info)
    write_github_summary(summary_info)


if __name__ == "__main__":
    main()
