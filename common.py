#!/usr/bin/env python3
"""proxysub 公共层：配置常量与叶子级工具函数。

本模块是架构的「叶子」：仅依赖第三方库（requests / yaml）、honeypot、
sources_manager、safe_io，不依赖 probe / score / output，因此可被它们
安全地无循环地 import。拆分自原 filter_clash.py（~90KB）以降低维护成本。

维护说明：本文件放的是「跨模块共享且自身不再依赖其他业务模块」的内容
（配置常量 + 指纹/解析/静态过滤/协议门槛等纯函数）。任何会反向引用
probe / score / output 的逻辑都不应放这里。
"""


from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from collections import defaultdict
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from urllib.parse import parse_qs, unquote, urlparse

import requests
import yaml

import honeypot as hp
import sources_manager as sm
from safe_io import load_json, save_json  # 原子化读写，防止 JSON 截断损坏

# ====================== 配置区 ======================
# 订阅源已移到 sources.json（正式源）和 candidate_sources.json（候选/试用源），
# 由 sources_manager.py 负责自动发现、试用、晋升与淘汰。

EXCLUDE_KEYWORDS = r"(官网|流量|到期|过期|剩余|测试|无效|假|防失联|127\.0\.0|IPv6|试用|公告|电报|TG|频道)"

REGION_RULES = {
    # Order matters: first match wins. Asia first (China client path).
    # 短代码（HK/JP/SG/TW/KR/US/UK 等）强制加 \b 单词边界，防止子串误判
    # （如 Russia 包含 us、AUS 包含 US、UKRAINE 包含 UK 被错归为美国/英国）。
    "🇭🇰 香港": r"(香港|\bHK\b|Hong\s?Kong)",
    "🇯🇵 日本": r"(日本|\bJP\b|Japan|东京|大阪|Tokyo|Osaka)",
    "🇸🇬 新加坡": r"(新加坡|\bSG\b|Singapore|狮城)",
    "🇹🇼 台湾": r"(台湾|台灣|\bTW\b|Taiwan)",
    "🇰🇷 韩国": r"(韩国|韓國|\bKR\b|Korea|首尔|首爾|Seoul)",
    "🇺🇸 美国": r"(美国|美國|\bUS\b|\bUSA\b|United States|\bAmerica\b)",
    "🇬🇧 英国": r"(英国|英國|\bUK\b|United Kingdom|London|伦敦)",
}

# China-path tilt: Asia quotas up, US/UK down (US runner ≠ China client).
# Quotas sum ~180 so we can land in the 100–200 final band after US-share trim.
REGION_QUOTAS = {
    "🇭🇰 香港": 40,
    "🇯🇵 日本": 35,
    "🇸🇬 新加坡": 30,
    "🇹🇼 台湾": 22,
    "🇰🇷 韩国": 20,
    "🇺🇸 美国": 30,   # soft; also capped by MAX_US_SHARE
    "🇬🇧 英国": 8,
}
# EU/CA/AU and misc: 活节点池的大头常落在「其他」区（免费源多为冷门地区），
# 配额过小会把大量真实探测存活的节点直接丢弃。
MAX_OTHER = 60  # misc; still ranked by score
# Hard band for final subscription size (China FLClash needs enough candidates):
# 云端只做死活闸门，「美国能通但国内被墙」的残余筛选必须靠客户端 url-test 完成，
# 因此给客户端尽量大的活节点备选池（探测存活 700+ 时全部给出）。
MIN_FINAL = 150
MAX_FINAL = 300
MAX_PER_SOURCE_FINAL = 25   # 单一订阅源在最终输出中的独占上限

# ====================== 硬性静态门槛（协议白名单 + 关键参数校验） ======================
# 云端剥离真实流量拨测后，源质量完全依赖静态门槛把关：
#   1) 协议白名单：仅收录优质现代协议（Hysteria2 / VLESS-Reality / Trojan / TUIC 等），
#      彻底排除 ss / ssr / vmess / http / socks 等大量掺假的 legacy 垃圾协议；
#   2) 关键参数校验：SNI、Reality Public-Key / Short-Id、UUID、密码等必须合法匹配；
#   3) 深度指纹去重：见 fingerprint()。
PROTOCOL_WHITELIST = {
    "hysteria2", "hy2",
    "vless",      # 必须为 Reality 或显式 TLS（见 protocol_gate_reason）
    "trojan",
    "tuic",
    "anytls",
    "hysteria",
}
# 标准 UUID（8-4-4-4-12 hex）
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
# Reality short-id：0-8 字节的 hex（偶数位，最长 16 字符）
SHORT_ID_RE = re.compile(r"^([0-9a-f]{2}){0,8}$", re.I)
# X25519 公钥：base64url 编码 32 字节 = 43 字符（可带 1 个 '=' 填充）
X25519_PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}={0,1}$")
# mihomo vless 支持的 flow
SUPPORTED_FLOWS = {"", "xtls-rprx-vision"}

# skip-cert-verify 节点（削弱 TLS 身份认证的高风险节点）的处理：
# 名称打 [Insecure] 标签 + 独立分组隔离，不进入自动选择/故障转移/地区分组
INSECURE_TAG = " [Insecure]"
INSECURE_GROUP = "⚠️ 高风险(跳过证书校验)"

# 云端真实流量拨测总开关：PROXYSUB_DISABLE_PROBE=1 时跳过 mihomo / http-socks 拨测，
# 仅保留 TCP 存活检查。注意：禁用拨测后输出会被「TCP 可达但协议层已死」的僵尸节点
# 淹没（免费源中此类节点占绝对多数），仅建议临时调试使用，CI 常规运行必须开启。
def real_probe_enabled() -> bool:
    return os.environ.get("PROXYSUB_DISABLE_PROBE", "0") != "1"

# 评分时 TCP 延迟（美西 Runner 测得，不代表国内真实路径）的贡献上限：
# 仅作为存活/粗排信号，不允许主导排序（排序主要由协议质量/存活时长/多源等静态特征决定）。
TCP_LATENCY_CAP_IN_SCORE = 600.0

TCP_TIMEOUT = 3.5
PROBE_TIMEOUT = 8.0
MAX_WORKERS = 60
FETCH_WORKERS = 8
FETCH_RETRIES = 2  # at most 2 attempts per source per run
FETCH_TIMEOUT = 25

# url-test / fallback intervals (seconds)
URLTEST_INTERVAL = 150
FALLBACK_INTERVAL = 180

OUTPUT_FILE = "clean_clash.yaml"
# 多格式输出（由 write_outputs() 统一生成；均为同一份最终节点列表的不同封装）
OUTPUT_SINGBOX = "clean_singbox.json"          # sing-box outbounds 列表
OUTPUT_V2RAY = "clean_v2ray.txt"               # base64 分享链接（v2ray/nekobox 等可导入）
OUTPUT_PROXIES_ONLY = "clean_proxies_only.yaml"  # 仅 proxies 段，供客户端 proxy-providers 使用
STATS_MD = "stats.md"                          # 健康报告
SOURCE_SCORES_FILE = "source_scores.json"      # 源评分
SURVIVAL_FILE = "survival.json"
SOURCE_STATS_FILE = "source_stats.json"
BAD_SOURCES_FILE = "bad_sources.json"
# China-client connectivity URLs first (Asia egress reaches them more easily from US runners).
# Runner probe: China-client-ish URLs first (any 1 pass). US runner≠China path,
# so HTTP ok is a soft quality signal — NOT the sole admission gate.
PROBE_URLS = [
    "http://connectivitycheck.platform.hicloud.com/generate_204",  # Huawei
    "http://wifi.vivo.com.cn/generate_204",                        # vivo
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://captive.apple.com/hotspot-detect.html",                # Apple captive
    "http://www.msftconnecttest.com/connecttest.txt",              # Microsoft
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
]
PROBE_PASS_NEED = 1  # any 1 success => HTTP ok (China-friendly)
# FLClash url-test: overseas egress usually reaches gstatic; keep stable for clients.
PROBE_URL = "http://www.gstatic.com/generate_204"
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"  # soft HTTPS signal + egress IP/loc
PROBE_LIMIT_OFFICIAL = 980
PROBE_PER_CANDIDATE = 20
# 新节点保底拨测配额：从未进入 survival 的节点保证有拨测机会，
# 节点池才能正常轮换（2026-10 质量回归修订：此前历史稳定节点
# 可以凭 streak 把新节点完全挤出 980 个拨测预算）。
PROBE_FRESH_QUOTA = 250
# 多渠道节点（Telegram/网页分享链接）在 per_source 中的伪键名。
# 它们既非正式源也非候选源 URL，此前的样本循环永远选不到它们，
# 导致渠道节点在评分时全被 cand_only 闸门丢弃（收集了却永不入选）。
CHANNEL_NODES_KEY = "__channel_nodes__"
# 多渠道节点保底拨测配额：与候选源同等参与「通过拨测方可入榜」机制。
CHANNEL_PROBE_QUOTA = 60
# ---- CI → 沙箱交接文档（中国出口实测接力，Phase 1）----
# 每轮把待测节点集/救援集写入 .publish/，随滚动 Release 发布为资产；
# 沙箱定时任务下载后用中国出口实测筛选，通过者覆盖发布为主资产。
# 交接走 Release 资产而非 git 提交：无提交竞态、无仓库膨胀，两侧解耦。
# 上传顺序依赖：订阅资产（p_* 随机名）字母序先于 pending_*，即新鲜
# pending_probe.json 上架时订阅资产必已就绪（见工作流发布步骤注释）。
PENDING_PROBE_FILE = "pending_probe.json"
PENDING_RESCUE_FILE = "pending_rescue.json"
# 救援集上限：静态可行但未入拨测样本的节点（「美国不通、中国通」
# lost-and-found 池——样本有配额上限，被挤出的节点仍可能中国可用）。
RESCUE_QUOTA = 100
# 交接文档 schema 版本：变更节点字段/语义时递增，沙箱侧据此兼容。
HANDOFF_GENERATOR = "proxysub-handoff/1"
# ---- 主资产归属：CI 候选集 vs 沙箱实测集 ----
# 主资产（p_* 随机名，订阅永久地址指向）的所有权按验证新鲜度切换：
#   verification_report.json 新鲜（<12h 且通过数 ≥15）→ 主资产归沙箱实测
#     集所有，CI 只发布候选集固定名副本与交接文档（避免发布后即被覆盖的
#     抖动，订阅者长时间拿到实测优选集）；
#   否则（无验证/验证陈旧/沙箱连续未产出）→ CI 兜底把候选集发布到主资产，
#     保证订阅永不枯竭。两侧阈值由此处统一，工作流发布步骤 import 使用。
CANDIDATES_CLASH = "candidates_clash.yaml"
CANDIDATES_SINGBOX = "candidates_singbox.json"
CANDIDATES_V2RAY = "candidates_v2ray.txt"
CANDIDATES_PROXIES_ONLY = "candidates_proxies_only.yaml"
VERIFICATION_REPORT_FILE = "verification_report.json"
VERIFICATION_MAX_AGE_S = 12 * 3600
VERIFICATION_MIN_PASSED = 15
PROBE_BATCH = 100
PROBE_CONCURRENCY = 32
# Reserve real-probe slots: Asia heavy, US light.
PROBE_RESERVE_PER_REGION = {
    "🇭🇰 香港": 220,
    "🇯🇵 日本": 180,
    "🇸🇬 新加坡": 160,
    "🇹🇼 台湾": 110,
    "🇰🇷 韩国": 100,
    "🇺🇸 美国": 150,
    "🇬🇧 英国": 30,
    "🌐 其他": 300,
}
# Within each region reserve, probe this many preferred (hy2/reality) first.
PROBE_PREFERRED_PER_REGION = {
    "🇭🇰 香港": 140,
    "🇯🇵 日本": 110,
    "🇸🇬 新加坡": 100,
    "🇹🇼 台湾": 70,
    "🇰🇷 韩国": 60,
    "🇺🇸 美国": 80,
    "🇬🇧 英国": 10,
    "🌐 其他": 100,
}
CANDIDATE_ONLY_PENALTY = 800.0   # nodes only offered by probation sources rank lower
NO_HTTPS_PENALTY = 180.0         # soft: CF HTTPS is a signal, not a sole veto
# TCP-alive without real-ok（仅禁用拨测时出现）: rank worse but still eligible.
NO_REAL_PROBE_PENALTY = 1600.0
MULTI_SOURCE_BONUS = 80.0        # ms-equivalent: appear in multiple official sources
SEEN_DAYS_WEIGHT = 55            # longevity: lifetime seen_days (capped)
MAX_PER_CREDENTIAL = 6           # diversity (slightly looser so floor can be met)
MAX_PER_EGRESS_IP = 3            # diversity (slightly looser)
# Hard rejects only; cf_blocked is soft (many China-usable nodes are CF-risked).
TAMPER_STATUSES = ("tamper_http", "tamper_https", "tls_mitm", "bad_egress")
# 云端拨测 = 死活闸门：连美国都无法代理成功的节点必然已死（凭证过期/后端下线/
# CDN 空壳），不允许进入最终列表。探测延迟不参与排序（见 TCP_LATENCY_CAP_IN_SCORE）。
# 注意：工作流实际开启拨测（未设 PROXYSUB_DISABLE_PROBE）——美西 Runner 的
# 连通性结论作为「节点是否已死」的闸门是可靠的（死节点在哪都死），仅延迟数值
# 不作为国内路径依据（见 is_us_node / us_china_penalty 的软惩罚）。
REQUIRE_REAL_PROBE_IN_OUTPUT = True
# CF HTTPS trace is soft — do NOT hard-exclude; apply NO_HTTPS_PENALTY instead.
REQUIRE_HTTPS_OK_IN_OUTPUT = False
# Soft latency gate: US runner RTT ≠ China RTT; only drop extreme outliers.
MAX_ACCEPT_LATENCY_MS = 4500.0
MAX_ACCEPT_LATENCY_MS_US = 2800.0  # stricter for US-named / US-egress
# Soft cap: low-tier fill per region after preferred/high (raised to hit 100–200 band).
MAX_LOW_TIER_PER_REGION = 10
# Protocol score: Hy2 > VLESS+Reality > Trojan > else (ms-equivalent; lower = better).
PROTOCOL_BONUS_HY2 = -420.0
PROTOCOL_BONUS_REALITY = -380.0
PROTOCOL_BONUS_TROJAN = -220.0
PROTOCOL_BONUS_TLS_OK = -80.0
PROTOCOL_PENALTY_VMESS = 280.0
PROTOCOL_PENALTY_SS = 360.0
PROTOCOL_PENALTY_HTTP_SOCKS = 900.0
PROTOCOL_PENALTY_OTHER_LOW = 400.0
# China-friendly feature bonuses (SNI / port / Reality fingerprint).
SNI_WHITELIST_SUFFIXES = (
    "microsoft.com", "apple.com", "cloudflare.com", "icloud.com",
    "gateway.icloud.com", "dl.google.com", "windows.com", "office.com",
    "mzstatic.com", "akamai.net", "akamaized.net",
)
FRIENDLY_PORTS = {443, 8443, 2053, 2083, 2087, 2096}
SNI_BONUS = -120.0
PORT_BONUS = -80.0
REALITY_FP_BONUS = -100.0
# Asia score bonus / US China-path penalties (ms-equivalent).
ASIA_REGIONS = {"🇭🇰 香港", "🇯🇵 日本", "🇸🇬 新加坡", "🇹🇼 台湾", "🇰🇷 韩国"}
ASIA_SCORE_BONUS = -220.0
US_REGION_DELAY_PENALTY = 120.0   # named US region: mild penalty only (relaxed)
US_EGRESS_PENALTY_HY2_REALITY = 120.0
US_EGRESS_PENALTY_MID = 180.0
US_EGRESS_PENALTY_SS_VMESS = 250.0
MAX_US_SHARE = 0.40               # final list US share <= 40% (no over-discrimination)
CF_BLOCKED_PENALTY = 320.0        # soft purity hit (not hard veto)
US_HOST_HINTS = re.compile(
    r"(digitalocean|vultr|linode|oracle|amazonaws|aws\.amazon|googleusercontent|"
    r"azure|choopa|bandwagon|bwh|contabo|north\s*bergen|secaucus|"
    r"los\s*angeles|new\s*york|dallas|miami|chicago|ashburn|\bSJC\b|\bLAX\b|\bNYC\b)",
    re.I,
)
# Soft purity check: flag CF Error 1005; do not sole-veto (China-usable often CF-risked).
PURITY_URL = "https://grok.com/"
PURITY_TIMEOUT = 6.0

# Cross-day survival: raise weight — multi-day survivors more likely usable from China.
SURVIVAL_WEIGHT = 240  # ms-equivalent bonus per consecutive day (lower score = better)
MAX_SURVIVAL_DAYS = 28

# UDP 协议（hysteria2/tuic/hysteria，走 QUIC）：服务器通常不监听 TCP，
# TCP 检查必然失败——这曾把对墙穿透性最好的 hy2 系统性排除出输出
#（12000+ 节点的源里仅漏进 3~8 个）。因此 UDP 协议跳过 TCP 检查，
# 由 mihomo 拨测（QUIC）作为其死活闸门。
UDP_PROTOCOLS = {"hysteria2", "hy2", "tuic", "hysteria", "quic"}

# 跨天存活达到此天数的节点，在 survival 状态新鲜时强制优先进入拨测样本
# （历史稳定性强绑定）。注意：状态一旦陈旧（停更），select_probe_sample 会
# 整体忽略该优先级，防止已死旧节点凭陈旧 streak 霸占拨测预算。
SURVIVAL_STREAK_FORCE_PROBE = 3
# 历史真实通过率加成（过去 N 次运行的 real_ok 比率，见 update_survival）
HISTORY_PASS_RATE_BONUS = 150.0
SURVIVAL_PASS_WINDOW = 7

def _today() -> str:
    return date.today().isoformat()


def survival_state_fresh(survival: dict, today_str: str) -> bool:
    """survival 状态是否新鲜（存在今日记录）。

    状态文件可能因任何原因停更（2026-10 曾因工作流 `git add` 原子失败冻结
    多轮）。一旦陈旧，拨测样本选择（select_probe_sample）与评分阶段都整体
    忽略历史记录——否则已死旧节点会凭陈旧 streak/real_hist 霸占拨测预算
    与排序优势，新节点永无拨测机会，输出质量逐轮下滑。
    """
    return any(str(rec.get("last_seen", "")) == today_str
               for rec in (survival or {}).values())


# load_json / save_json 统一由 safe_io 提供（原子写入 + 文件锁 + 损坏自愈）。


# 指纹计算时忽略的易变字段：改名不影响节点身份；latency/history 是运行期数据。
FINGERPRINT_IGNORE_KEYS = {"name", "latency", "history"}


def _canonicalize(obj: Any) -> Any:
    """递归规范化：dict 按键名排序、list/tuple 保序，用于稳定的深度序列化。"""
    if isinstance(obj, dict):
        return {str(k): _canonicalize(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(v) for v in obj]
    return obj


def fingerprint(proxy: dict) -> str:
    """深度指纹：协议 + 服务器 + 端口 + 全部嵌套连接参数。

    采用「递归规范化 + 深度序列化」：除名称等易变字段外，任意层级的嵌套参数
    （reality-opts 的 public-key/short-id、ws-opts 的 path/headers、grpc-opts 的
    grpc-service-name、tls/alpn 置信等）都参与哈希。
    这修复了旧实现只哈希平铺字段的问题——旧实现会遗漏嵌套参数，导致
    「仅 WS 路径不同」「仅 Reality 公钥不同」的节点被错误合并（或被误去重丢弃）。
    """
    payload = {k: v for k, v in proxy.items() if k not in FINGERPRINT_IGNORE_KEYS}
    # 归一化类型/端口，避免 int 与 str 表示差异产生不同指纹
    payload["type"] = str(payload.get("type", "")).lower().strip()
    try:
        payload["port"] = int(payload.get("port"))
    except Exception:
        payload["port"] = str(payload.get("port"))
    raw = json.dumps(_canonicalize(payload), ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


# ====================== 硬性静态门槛校验 ======================

def _truthy(v: Any) -> bool:
    return v in (True, 1, "1", "true", "True", "yes", "on")


def _sni_of(proxy: dict) -> str:
    return str(proxy.get("servername") or proxy.get("sni") or "").strip()

def _bad_sni_reason(proxy: dict) -> str | None:
    """SNI 必须是合法主机名（Reality 借用真实站点证书，SNI 必须可解析成域名形态）。"""
    sni = _sni_of(proxy)
    if sni and not hp.HOST_RE.match(sni):
        return "bad_sni"
    return None

def _gate_hysteria2(p: dict) -> str | None:
    if not str(p.get("password") or "").strip():
        return "missing_password"
    obfs = str(p.get("obfs") or "").strip()
    if obfs and obfs != "salamander":
        return "unsupported_obfs"
    if obfs == "salamander" and not str(p.get("obfs-password") or "").strip():
        return "missing_obfs_password"
    return None

def _gate_vless(p: dict) -> str | None:
    uuid_v = str(p.get("uuid") or "").strip()
    if not uuid_v or not UUID_RE.match(uuid_v):
        return "invalid_uuid"
    flow = str(p.get("flow") or "").strip()
    if flow not in SUPPORTED_FLOWS:
        return "unsupported_flow"
    ro = p.get("reality-opts")
    if isinstance(ro, dict) and ro:
        # VLESS + Reality：public-key / short-id / SNI 三要素必须合法
        pk = str(ro.get("public-key") or "").strip()
        if not pk or not X25519_PUBLIC_KEY_RE.match(pk):
            return "invalid_reality_public_key"
        sid = str(ro.get("short-id") or "").strip()
        if sid and not SHORT_ID_RE.match(sid):
            return "invalid_reality_short_id"
        if not _sni_of(p):
            return "reality_missing_sni"
        return None
    # 非 Reality 的 vless 必须显式开启 TLS（裸 VLESS 明文传输，风险不可接受）
    if not _truthy(p.get("tls")):
        return "vless_no_tls"
    return None

def _gate_trojan(p: dict) -> str | None:
    if not str(p.get("password") or "").strip():
        return "missing_password"
    return None

def _gate_tuic(p: dict) -> str | None:
    uuid_v = str(p.get("uuid") or "").strip()
    if uuid_v and not UUID_RE.match(uuid_v):
        return "invalid_uuid"
    if not (uuid_v or str(p.get("password") or "").strip() or str(p.get("token") or "").strip()):
        return "missing_credentials"
    return None

def _gate_generic_password(p: dict) -> str | None:
    if not str(p.get("password") or "").strip():
        return "missing_password"
    return None

def _gate_hysteria(p: dict) -> str | None:
    auth = str(p.get("auth-str") or p.get("auth") or p.get("password") or "").strip()
    if not auth:
        return "missing_credentials"
    return None

_PROTOCOL_GATES = {
    "hysteria2": _gate_hysteria2,
    "hy2": _gate_hysteria2,
    "vless": _gate_vless,
    "trojan": _gate_trojan,
    "tuic": _gate_tuic,
    "anytls": _gate_generic_password,
    "hysteria": _gate_hysteria,
}

VALID_NETWORKS = {"tcp", "ws", "http", "h2", "grpc"}
NETWORK_ALIASES = {"raw": "tcp"}  # Xray 新命名 -> mihomo 等价值

def normalize_network(proxy: dict) -> bool:
    """规范 transport network 字段，确保 mihomo/FlClash 能加载。

    实测线上产物中 12/100 节点带非法 network 值导致客户端整体加载失败：
      - "raw"（Xray 新命名）→ 归一为 "tcp"；
      - "xhttp"（Xray 专属，mihomo 不支持）→ 拒绝；
      - 垃圾值（如 "tcp#5🔥@oneclickvpnkeys"）→ 拒绝。
    返回 False 表示应拒绝该节点。
    """
    if "network" not in proxy:
        return True
    net = str(proxy.get("network", "")).lower().strip()
    if not net:
        proxy["network"] = "tcp"
        return True
    net = NETWORK_ALIASES.get(net, net)
    if net not in VALID_NETWORKS:
        return False
    proxy["network"] = net
    return True

def protocol_gate_reason(proxy: dict) -> str | None:
    """硬性静态门槛：协议白名单 + 关键参数完整性。返回拒绝原因（None = 通过）。

    这是云端失去真实流量拨测后的核心质量闸门：
      - 不在白名单内的协议（ss/ssr/vmess/http/socks/未知类型）整体拒绝；
      - 白名单协议的关键参数（SNI、Reality public-key/short-id、UUID、密码等）
        不合法或缺失的节点拒绝。
    """
    ptype = str(proxy.get("type", "")).lower().strip()
    if ptype not in PROTOCOL_WHITELIST:
        return f"protocol_not_whitelisted:{ptype or 'unknown'}"
    reason = _bad_sni_reason(proxy)
    if reason:
        return reason
    gate = _PROTOCOL_GATES.get(ptype)
    if gate is not None:
        return gate(proxy)
    return None

def _try_b64_decode(text: str) -> str | None:
    s = "".join(text.strip().split())
    if not s:
        return None
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        try:
            return base64.b64decode(s).decode("utf-8", errors="ignore")
        except Exception:
            return None

def _parse_ss_uri(uri: str) -> dict | None:
    # ss://BASE64(method:pass@host:port)#name  or ss://method:pass@host:port
    try:
        if not uri.startswith("ss://"):
            return None
        rest = uri[5:]
        name = "ss"
        if "#" in rest:
            rest, name = rest.split("#", 1)
            name = unquote(name)
        if "@" not in rest:
            decoded = _try_b64_decode(rest)
            if not decoded or "@" not in decoded:
                return None
            rest = decoded
        userinfo, hostport = rest.rsplit("@", 1)
        if ":" not in hostport:
            return None
        host, port = hostport.rsplit(":", 1)
        # userinfo may still be base64
        if ":" not in userinfo:
            d = _try_b64_decode(userinfo)
            if d and ":" in d:
                userinfo = d
        method, password = userinfo.split(":", 1)
        return {
            "name": name or f"ss-{host}",
            "type": "ss",
            "server": host,
            "port": int(port),
            "cipher": method,
            "password": password,
        }
    except Exception:
        return None

def _parse_vmess_uri(uri: str) -> dict | None:
    try:
        if not uri.startswith("vmess://"):
            return None
        raw = _try_b64_decode(uri[8:])
        if not raw:
            return None
        obj = json.loads(raw)
        net = obj.get("net") or "tcp"
        proxy = {
            "name": obj.get("ps") or f"vmess-{obj.get('add')}",
            "type": "vmess",
            "server": obj.get("add"),
            "port": int(obj.get("port")),
            "uuid": obj.get("id"),
            "alterId": int(obj.get("aid") or 0),
            "cipher": obj.get("scy") or "auto",
            "network": net,
            "tls": True if obj.get("tls") in ("tls", True, "1") else False,
        }
        if obj.get("sni") or obj.get("host"):
            proxy["servername"] = obj.get("sni") or obj.get("host")
        return proxy
    except Exception:
        return None

def _parse_trojan_uri(uri: str) -> dict | None:
    try:
        if not uri.startswith("trojan://"):
            return None
        u = urlparse(uri)
        password = unquote(u.username or "")
        host = u.hostname
        port = u.port or 443
        qs = parse_qs(u.query)
        name = unquote(u.fragment) if u.fragment else f"trojan-{host}"
        proxy = {
            "name": name,
            "type": "trojan",
            "server": host,
            "port": int(port),
            "password": password,
        }
        sni = (qs.get("sni") or qs.get("peer") or [None])[0]
        if sni:
            proxy["sni"] = sni
        return proxy
    except Exception:
        return None

def _parse_vless_uri(uri: str) -> dict | None:
    """解析 vless:// UUID@host:port?params#name（含 Reality / TLS / 传输层）。"""
    try:
        if not uri.lower().startswith("vless://"):
            return None
        rest = uri[len("vless://"):].strip()
        name = None
        if "#" in rest:
            rest, frag = rest.split("#", 1)
            name = unquote(frag)
        qs = ""
        if "?" in rest:
            auth, qs = rest.split("?", 1)
        else:
            auth = rest
        if "@" not in auth:
            return None
        uid, netloc = auth.split("@", 1)
        if ":" not in netloc:
            return None
        host, _, port = netloc.rpartition(":")
        try:
            port = int(port)
        except ValueError:
            return None
        p = {
            "name": name or f"vless-{host}",
            "type": "vless",
            "server": host,
            "port": port,
            "uuid": uid,
        }
        params = parse_qs(qs)
        sec = (params.get("security") or ["none"])[0].lower()
        if sec and sec != "none":
            p["tls"] = True
            sni = (params.get("sni") or params.get("peer") or [None])[0]
            if sni:
                p["sni"] = sni
        fp = (params.get("fp") or [None])[0]
        if fp:
            p["client-fingerprint"] = fp
        typ = (params.get("type") or [""])[0]
        if typ:
            p["network"] = typ
        pbk = (params.get("pbk") or [None])[0]
        sid = (params.get("sid") or [None])[0]
        if pbk:
            p["reality-opts"] = {"public-key": pbk}
            if sid:
                p["reality-opts"]["short-id"] = sid
        return p
    except Exception:
        return None

def parse_subscription_text(text: str) -> list[dict]:
    """Parse Clash YAML, base64 blob, or line-based share links."""
    text = text.strip()
    if not text:
        return []

    # Try YAML first
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            proxies = data.get("proxies")
            if isinstance(proxies, list):
                return [p for p in proxies if isinstance(p, dict)]
            # some feeds are just a list under other keys
            for key in ("Proxy", "proxy"):
                if isinstance(data.get(key), list):
                    return [p for p in data[key] if isinstance(p, dict)]
        if isinstance(data, list) and data and isinstance(data[0], dict) and "server" in data[0]:
            return [p for p in data if isinstance(p, dict)]
    except Exception:
        pass

    # Maybe whole body is base64.
    # 仅当正文只含 base64 字符集（字母/数字/+/-/_/= 与空白）时才尝试整段解码：
    # b64decode(validate=False) 会丢弃非法字符强行解码，若对「分享链接列表」
    # （含 : / # @）整段解码会得到垃圾并吞掉后续逐行解析（Python 3.12/3.13
    # 的解码严格度不同，曾导致多链接源在 3.12 上被解析为空）。
    compact = "".join(text.split())
    if compact and re.fullmatch(r"[A-Za-z0-9+/_=-]+", compact):
        decoded = _try_b64_decode(text)
        if decoded and decoded != text:
            return parse_subscription_text(decoded)

    # Line-based URIs
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for parser in (_parse_ss_uri, _parse_vmess_uri, _parse_trojan_uri, _parse_vless_uri):
            p = parser(line)
            if p:
                out.append(p)
                break
    return out

def fetch_one(url: str) -> tuple[str, list[dict], str | None]:
    """Return (url, proxies, error)."""
    last_err = None
    for attempt in range(1, FETCH_RETRIES + 1):
        try:
            r = requests.get(
                url,
                timeout=FETCH_TIMEOUT,
                headers={"User-Agent": "proxysub-cleaner/2.0"},
            )
            r.raise_for_status()
            # 编码：requests 对未声明 charset 的 text/* 响应按 HTTP/1.1 规定默认
            # ISO-8859-1，会导致中文节点名乱码、地区正则全部失配。
            # 显式声明了合法 charset 就用它；未声明（默认 iso-8859-1）时用
            # apparent_encoding 探测，仍失败退 utf-8。
            charset = r.encoding
            if not charset or charset.lower() in ("iso-8859-1", "latin-1", "latin1"):
                charset = r.apparent_encoding or "utf-8"
            try:
                content = r.content.decode(charset, errors="ignore")
            except (LookupError, UnicodeDecodeError):
                content = r.content.decode("utf-8", errors="ignore")
            proxies = parse_subscription_text(content)
            if not proxies:
                # try raw bytes as base64
                proxies = parse_subscription_text(r.text)
            return url, proxies, None if proxies else "empty_or_unparsed"
        except Exception as e:
            last_err = str(e)
            time.sleep(0.6 * attempt)
    return url, [], last_err or "unknown"

def fetch_all_sources(urls: list[str]) -> tuple[dict[str, list[dict]], dict]:
    stats: dict[str, Any] = {}
    per_source: dict[str, list[dict]] = {}
    print(f"并行拉取 {len(urls)} 个源（workers={FETCH_WORKERS}, retries={FETCH_RETRIES})...")
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        futs = {ex.submit(fetch_one, u): u for u in urls}
        for fut in as_completed(futs):
            url, proxies, err = fut.result()
            stats[url] = {"ok": err is None, "count": len(proxies), "error": err}
            per_source[url] = proxies if not err else []
            print(f"{'失败' if err else '拉取'}: {url} -> {err or len(proxies)}")
    return per_source, stats

def is_udp_protocol(proxy: dict) -> bool:
    return str(proxy.get("type", "")).lower().strip() in UDP_PROTOCOLS

def _has_reality(proxy: dict) -> bool:
    if proxy.get("reality-opts"):
        return True
    name = str(proxy.get("name", "")).lower()
    if "reality" in name:
        return True
    sni = str(proxy.get("servername") or proxy.get("sni") or "").lower()
    if proxy.get("flow") and "reality" in sni:
        return True
    return False
