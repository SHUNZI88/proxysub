#!/usr/bin/env python3
"""proxysub —— 高纯度订阅清洗与结构规范化工具。

定位：本仓库负责把公开免费订阅源清洗成「干净、格式标准、且确认存活」的节点列表；
测速与优选（延迟排序、自动切换）完全交由用户本地客户端（FlClash / Clash Verge
Rev 等）在真实国内网络环境下通过 http://www.gstatic.com/generate_204 完成。

云端（GitHub Actions，美西机房）物理上无法穿越防火墙，无法预测国内连通性，
因此：
  1. 云端真实流量探测只用作「死活闸门」——连美国都无法代理成功的节点必然是
     僵尸节点（凭证过期/后端已死/CDN 空壳），直接淘汰；
  2. 探测延迟绝不参与排序与命名——美西延迟不代表国内路径，曾因用美西低延迟
     选点而误选大量国内不可用节点；
  3. 源质量的静态把关由「协议白名单 + 关键参数校验 + 深度指纹去重」完成。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
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
    "🇺🇸 美国": 18,   # soft; also capped by MAX_US_SHARE
    "🇬🇧 英国": 8,
}
MAX_OTHER = 15  # EU/CA/AU and misc; still ranked by latency+survival
# Hard band for final subscription size (China FLClash needs enough candidates).
MIN_FINAL = 100
MAX_FINAL = 200

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
PROBE_BATCH = 100
PROBE_CONCURRENCY = 32
# Reserve real-probe slots: Asia heavy, US light.
PROBE_RESERVE_PER_REGION = {
    "🇭🇰 香港": 220,
    "🇯🇵 日本": 180,
    "🇸🇬 新加坡": 160,
    "🇹🇼 台湾": 110,
    "🇰🇷 韩国": 100,
    "🇺🇸 美国": 120,
    "🇬🇧 英国": 30,
    "🌐 其他": 40,
}
# Within each region reserve, probe this many preferred (hy2/reality) first.
PROBE_PREFERRED_PER_REGION = {
    "🇭🇰 香港": 140,
    "🇯🇵 日本": 110,
    "🇸🇬 新加坡": 100,
    "🇹🇼 台湾": 70,
    "🇰🇷 韩国": 60,
    "🇺🇸 美国": 60,
    "🇬🇧 英国": 10,
    "🌐 其他": 14,
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

# ====================================================


def _today() -> str:
    return date.today().isoformat()


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
        for parser in (_parse_ss_uri, _parse_vmess_uri, _parse_trojan_uri):
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
            # prefer text; some feeds mislabel encoding
            content = r.content.decode(r.encoding or "utf-8", errors="ignore")
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


def tcp_probe(proxy: dict) -> tuple[bool, float]:
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False, 9999.0
    try:
        start = time.time()
        with socket.create_connection((server, int(port)), timeout=TCP_TIMEOUT):
            return True, round((time.time() - start) * 1000, 1)
    except Exception:
        return False, 9999.0


def http_socks_probe(proxy: dict) -> tuple[bool, float]:
    """Real request through http/socks proxies when possible."""
    ptype = str(proxy.get("type", "")).lower()
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False, 9999.0

    auth = ""
    user = proxy.get("username")
    password = proxy.get("password")
    if user is not None:
        auth = f"{user}:{password}@"

    if ptype in ("http", "https"):
        proxy_url = f"http://{auth}{server}:{port}"
    elif ptype in ("socks5", "socks5h", "socks"):
        proxy_url = f"socks5h://{auth}{server}:{port}"
    else:
        return False, 9999.0

    px = {"http": proxy_url, "https": proxy_url}
    try:
        ok, lat, _tamper, _d = _probe_http_china_friendly(px)
        if ok and lat is not None:
            return True, lat
        return False, 9999.0
    except Exception:
        return False, 9999.0


def mihomo_available() -> str | None:
    for cand in (
        os.environ.get("MIHOMO_BIN"),
        "mihomo",
        "clash-meta",
        "/usr/local/bin/mihomo",
        "/usr/bin/mihomo",
    ):
        if not cand:
            continue
        try:
            subprocess.run(
                [cand, "-v"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            return cand
        except Exception:
            continue
    return None


def _expected_probe_response(url: str, r: requests.Response) -> bool:
    """True when response matches the connectivity-check contract for that URL."""
    if "connecttest.txt" in url:
        body = (r.text or "").strip()
        return r.status_code == 200 and ("Microsoft" in body or "Connect Test" in body or len(body) < 80)
    if "hotspot-detect" in url or "success.html" in url:
        body = (r.text or "")
        return r.status_code == 200 and ("Success" in body or "success" in body.lower() or len(body.strip()) < 120)
    # generate_204 family: empty 204 (some CDNs return 200 empty)
    if r.status_code == 204 and not r.content:
        return True
    if r.status_code == 200 and not r.content:
        return True
    return False


def _probe_http_china_friendly(px: dict) -> tuple[bool, float | None, bool, str]:
    """Try PROBE_URLS; pass if PROBE_PASS_NEED succeed. Returns (ok, latency, tamper, detail)."""
    successes = 0
    tamper_like = 0
    lat: float | None = None
    details: list[str] = []
    for url in PROBE_URLS:
        try:
            t0 = time.time()
            r = requests.get(url, proxies=px, timeout=PROBE_TIMEOUT, allow_redirects=False)
            lat_i = round((time.time() - t0) * 1000, 1)
        except Exception as e:
            details.append(f"err:{type(e).__name__}")
            continue
        if r.status_code >= 400:
            details.append(f"{r.status_code}")
            continue
        if _expected_probe_response(url, r):
            successes += 1
            if lat is None:
                lat = lat_i
            if successes >= PROBE_PASS_NEED:
                return True, lat, False, f"ok:{successes}"
        else:
            tamper_like += 1
            details.append(f"bad{r.status_code}")
    if successes >= PROBE_PASS_NEED:
        return True, lat, False, f"ok:{successes}"
    if successes == 0 and tamper_like >= 2:
        return False, None, True, "/".join(details[:4])
    return False, None, False, "/".join(details[:4])


def _probe_through(port: int) -> dict:
    """Probe one local mihomo listener. China-friendly HTTP URLs; CF HTTPS is soft."""
    px = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
    ok, lat, tamper, detail = _probe_http_china_friendly(px)
    if tamper:
        return {"status": "tamper_http", "detail": detail[:120]}
    if not ok:
        return {"status": "fail"}
    res: dict[str, Any] = {"status": "ok", "latency": lat if lat is not None else 9999.0, "https_ok": False}
    # Soft CF HTTPS trace: useful for egress IP/loc, NOT a sole veto.
    try:
        t = requests.get(TRACE_URL, proxies=px, timeout=PROBE_TIMEOUT, allow_redirects=False)
        body = t.text if t.status_code == 200 else ""
        kv = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
        if t.status_code == 200 and kv.get("ip") and kv.get("h"):
            if hp.is_bad_ip(kv["ip"]):
                return {"status": "bad_egress", "detail": kv["ip"]}
            res.update(https_ok=True, egress=kv["ip"], loc=kv.get("loc"))
        # wrong/redirect body: leave https_ok=False (soft), do not hard-fail
    except requests.exceptions.SSLError as e:
        msg = str(e)
        if re.search(r"CERTIFICATE_VERIFY_FAILED|certificate verify failed|hostname mismatch|doesn't match", msg, re.I):
            m = re.search(r"(certificate verify failed[^)'\"]*|hostname mismatch[^)'\"]*)", msg, re.I)
            return {"status": "tls_mitm", "detail": (m.group(1) if m else msg[-120:])[:120]}
    except Exception:
        pass
    # Soft purity: flag CF blocks; keep node (China-usable nodes are often CF-risked).
    if PURITY_URL:
        try:
            pr = requests.get(
                PURITY_URL,
                proxies=px,
                timeout=PURITY_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; proxysub-purity/1.0)"},
            )
            body = (pr.text or "")[:4000]
            blocked = bool(re.search(
                r"Error 1005|Access Denied|access denied|cf-error-details|Sorry, you have been blocked",
                body,
                re.I,
            ))
            if blocked or (pr.status_code in (403, 503) and "cloudflare" in body.lower()):
                res["cf_blocked"] = True
                res["cf_detail"] = f"http{pr.status_code}"
        except Exception:
            pass
    return res


def _mihomo_batch(batch: list[dict], bin_path: str) -> dict[int, dict] | None:
    """Start one mihomo with one listener per node; probe concurrently. None => config rejected."""
    base_port, controller = 21000, "127.0.0.1:19090"
    named = []
    for i, p in enumerate(batch):
        q = dict(p)
        q["name"] = f"n{i}"
        named.append(q)
    cfg = {
        "allow-lan": False,
        "mode": "rule",
        "log-level": "silent",
        "ipv6": False,
        "external-controller": controller,
        "proxies": named,
        "listeners": [
            {"name": f"in{i}", "type": "mixed", "listen": "127.0.0.1", "port": base_port + i, "proxy": f"n{i}"}
            for i in range(len(named))
        ],
        "rules": ["MATCH,DIRECT"],
    }
    with tempfile.TemporaryDirectory(prefix="mihomo-probe-") as td:
        cfg_path = Path(td) / "config.yaml"
        cfg_path.write_text(yaml.dump(cfg, allow_unicode=True), encoding="utf-8")
        proc = subprocess.Popen([bin_path, "-d", td, "-f", str(cfg_path)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            ready = False
            for _ in range(60):
                if proc.poll() is not None:
                    return None
                try:
                    requests.get(f"http://{controller}/version", timeout=0.5)
                    ready = True
                    break
                except Exception:
                    time.sleep(0.2)
            if not ready:
                return None
            time.sleep(0.5)
            out: dict[int, dict] = {}
            with ThreadPoolExecutor(max_workers=PROBE_CONCURRENCY) as ex:
                futs = {ex.submit(_probe_through, base_port + i): i for i in range(len(named))}
                for fut in as_completed(futs):
                    out[futs[fut]] = fut.result()
            return out
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


def mihomo_probe(proxies: list[dict], bin_path: str) -> dict[str, dict]:
    """fingerprint -> probe result. Bad node configs are isolated by bisecting a failed batch."""
    results: dict[str, dict] = {}
    queue = [proxies[i:i + PROBE_BATCH] for i in range(0, len(proxies), PROBE_BATCH)]
    skipped = 0
    while queue:
        batch = queue.pop(0)
        out = _mihomo_batch(batch, bin_path)
        if out is None:
            if len(batch) <= 6:
                skipped += len(batch)
                continue
            mid = len(batch) // 2
            queue[:0] = [batch[:mid], batch[mid:]]
            continue
        for i, r in out.items():
            results[fingerprint(batch[i])] = r
    ok = sum(1 for r in results.values() if r["status"] == "ok")
    print(f"mihomo 真实探测: ok {ok}/{len(proxies)}，配置无法加载跳过 {skipped}")
    return results


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


def is_preferred(proxy: dict) -> bool:
    """Hysteria2 / VLESS+Reality — user-requested keep-priority protocols."""
    ptype = str(proxy.get("type", "")).lower()
    if ptype in ("hysteria2", "hy2"):
        return True
    if ptype == "vless" and _has_reality(proxy):
        return True
    return False


def protocol_tier(proxy: dict) -> int:
    """0=best (hy2/reality), 1=tls modern, 2=legacy encrypted, 3=open/plain junk."""
    ptype = str(proxy.get("type", "")).lower()
    if ptype in ("hysteria2", "hy2"):
        return 0
    if ptype == "vless" and _has_reality(proxy):
        return 0
    if ptype in ("anytls", "tuic", "hysteria", "trojan"):
        return 1
    if ptype == "vless":
        return 1
    if ptype == "vmess":
        tls = proxy.get("tls") in (True, "tls", "1", 1)
        return 2 if tls else 3
    if ptype in ("ss", "ssr"):
        return 3
    if ptype in ("http", "https", "socks5", "socks5h", "socks"):
        return 3
    return 2


def protocol_penalty(proxy: dict) -> float:
    ptype = str(proxy.get("type", "")).lower()
    if ptype in ("hysteria2", "hy2"):
        return PROTOCOL_BONUS_HY2
    if ptype == "vless" and _has_reality(proxy):
        return PROTOCOL_BONUS_REALITY
    if ptype == "trojan":
        return PROTOCOL_BONUS_TROJAN
    if ptype in ("anytls", "tuic", "hysteria"):
        return PROTOCOL_BONUS_TLS_OK
    if ptype == "vless":
        return PROTOCOL_BONUS_TLS_OK
    if ptype == "vmess":
        return PROTOCOL_PENALTY_VMESS
    if ptype in ("ss", "ssr"):
        return PROTOCOL_PENALTY_SS
    if ptype in ("http", "https", "socks5", "socks5h", "socks"):
        return PROTOCOL_PENALTY_HTTP_SOCKS
    return PROTOCOL_PENALTY_OTHER_LOW


def china_feature_bonus(proxy: dict) -> float:
    """SNI whitelist / common ports / Reality chrome|firefox fingerprint."""
    bonus = 0.0
    sni = str(proxy.get("servername") or proxy.get("sni") or "").lower().strip(".")
    if sni and any(sni == s or sni.endswith("." + s) for s in SNI_WHITELIST_SUFFIXES):
        bonus += SNI_BONUS
    try:
        port = int(proxy.get("port", 0))
    except Exception:
        port = 0
    if port in FRIENDLY_PORTS:
        bonus += PORT_BONUS
    cfp = str(proxy.get("client-fingerprint") or proxy.get("client_fingerprint") or "").lower()
    if not cfp:
        ro = proxy.get("reality-opts") or {}
        if isinstance(ro, dict):
            cfp = str(ro.get("client-fingerprint") or ro.get("fingerprint") or "").lower()
    if _has_reality(proxy) and cfp in ("chrome", "firefox", "safari", "ios", "edge", "android"):
        bonus += REALITY_FP_BONUS
    return bonus


def is_us_node(proxy: dict, probe_result: dict | None = None) -> bool:
    """US by region name, CF trace loc, or common US VPS host hints."""
    if classify_proxy(str(proxy.get("name", ""))) == "🇺🇸 美国":
        return True
    if probe_result and str(probe_result.get("loc") or "").upper() == "US":
        return True
    blob = f"{proxy.get('name', '')} {proxy.get('server', '')}"
    if US_HOST_HINTS.search(blob):
        return True
    return False


def us_china_penalty(proxy: dict, probe_result: dict | None = None) -> float:
    """Extra ms penalty for US egress/region when ranking for China clients."""
    region = classify_proxy(str(proxy.get("name", "")))
    pen = 0.0
    if region == "🇺🇸 美国":
        pen += US_REGION_DELAY_PENALTY
    elif region in ASIA_REGIONS:
        pen += ASIA_SCORE_BONUS
    if not is_us_node(proxy, probe_result):
        return pen
    # Already counted region penalty; add egress-style protocol-tiered penalty once.
    # If region was not US but egress/host is US, apply full egress penalty.
    ptype = str(proxy.get("type", "")).lower()
    if ptype in ("hysteria2", "hy2") or (ptype == "vless" and _has_reality(proxy)):
        egress_pen = US_EGRESS_PENALTY_HY2_REALITY
    elif ptype in ("ss", "ssr", "vmess") or ptype in ("http", "https", "socks5", "socks5h", "socks"):
        egress_pen = US_EGRESS_PENALTY_SS_VMESS
    else:
        egress_pen = US_EGRESS_PENALTY_MID
    if region == "🇺🇸 美国":
        # region already +400; add only the delta so Hy2 US is lighter than SS US overall
        # Hy2: 400+300=700, SS: 400+600=1000, Mid: 400+450=850
        pen += egress_pen
    else:
        pen += egress_pen
    return pen


def classify_proxy(name: str) -> str:
    for region, pattern in REGION_RULES.items():
        if re.search(pattern, name, re.IGNORECASE):
            return region
    return "🌐 其他"


def update_survival(alive_fps: set[str], survival: dict) -> dict:
    today = _today()
    updated = dict(survival)
    for fp in list(updated.keys()):
        rec = updated[fp]
        last = rec.get("last_seen")
        if fp in alive_fps:
            if last == today:
                pass
            else:
                # consecutive day?
                try:
                    last_d = date.fromisoformat(last) if last else None
                except Exception:
                    last_d = None
                if last_d and (date.today() - last_d).days == 1:
                    rec["streak"] = int(rec.get("streak", 1)) + 1
                elif last_d and (date.today() - last_d).days == 0:
                    pass
                else:
                    rec["streak"] = 1
                rec["last_seen"] = today
                rec["seen_days"] = int(rec.get("seen_days", 0)) + (0 if last == today else 1)
            updated[fp] = rec
        else:
            # decay: if missing > 2 days, reset streak
            try:
                last_d = date.fromisoformat(last) if last else None
                if last_d and (date.today() - last_d).days > 2:
                    rec["streak"] = 0
                    updated[fp] = rec
            except Exception:
                pass

    for fp in alive_fps:
        if fp not in updated:
            updated[fp] = {"streak": 1, "last_seen": today, "seen_days": 1}
    return updated


def survival_bonus_ms(fp: str, survival: dict) -> float:
    rec = survival.get(fp, {})
    streak = int(rec.get("streak", 0))
    streak = max(0, min(streak, MAX_SURVIVAL_DAYS))
    seen = int(rec.get("seen_days", 0))
    seen = max(0, min(seen, MAX_SURVIVAL_DAYS))
    # higher streak / lifetime => lower effective score (prefer long-lived nodes)
    return -SURVIVAL_WEIGHT * streak - SEEN_DAYS_WEIGHT * seen


def write_github_summary(info: dict) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    d, c, o = info["discovery"], info["cand_rep"], info["off_rep"]
    lines = [
        "# proxysub clean summary",
        "",
        f"- Time (UTC): {datetime.now(timezone.utc).isoformat()}",
        f"- Probe mode: **{info.get('probe_mode', 'n/a')}** (final liveness/speed testing is done client-side)",
        f"- Final proxies: **{info['final']}** (compliant {info.get('compliant', info['final'])}, "
        f"insecure-isolated {info.get('insecure', 0)}) | TCP alive: **{info['tcp']}** | real probe ok: **{info['real']}** (HTTPS ok {info['https']})",
        "",
        "## Sources lifecycle",
        "",
        f"- Official sources: **{info['n_official']}** | active candidates: **{info['n_cands']}**",
        f"- Discovered (new candidates): **{len(d['added'])}** (repos scanned {d['searched_repos']}, API calls {d['api_calls']}, repo rejects {len(d['rejected'])})",
        f"- Promoted: **{len(c['promoted'])}** | candidates rejected: **{len(c['rejected'])}** | official demoted: **{len(o['demoted'])}**",
    ]
    for u in d["added"]:
        lines.append(f"  - discovered `{u}`")
    for u in c["promoted"]:
        lines.append(f"  - promoted `{u}`")
    for u, why in c["rejected"].items():
        lines.append(f"  - candidate rejected `{u}`: {why}")
    for u, why in o["demoted"].items():
        lines.append(f"  - demoted `{u}`: {why}")
    if d.get("errors"):
        lines.append(f"- Discovery notes: {'; '.join(d['errors'][:5])}")
    lines += [
        "",
        "## Anti-honeypot",
        "",
        f"- Nodes rejected before probing: **{sum(info['pre_reasons'].values())}** ({hp.summarize_reasons(info['pre_reasons'])})",
        f"- Nodes rejected by probe (tamper/MITM/bad egress): **{sum(info['probe_reasons'].values())}** ({hp.summarize_reasons(info['probe_reasons'])})",
        f"- Auto-blocklisted this run: **{info['auto_added']}** | expired auto entries pruned: {info['expired']}",
        f"- Diversity caps dropped: {info['diversity_dropped']}",
        f"- Suspicious source structure: {info['flags'] or '-'}",
        "",
        "## Sources",
        "",
        "| Source | Role | OK | Count | Alive | Unique | Real ok | Tamper | Error |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for url, s in info["per_src"].items():
        err = (s.get("error") or "").replace("|", "/")
        lines.append(
            f"| `{url}` | {s.get('role')} | {s.get('ok')} | {s.get('count')} | {s.get('alive', 0)} | "
            f"{s.get('unique_alive', s.get('unique_new', 0))} | {s.get('real_ok', 0)} | {s.get('tamper', 0)} | {err} |"
        )
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> None:
    sources = sm.load_sources()
    cands = sm.load_candidates()
    blocklist = hp.Blocklist(load_json(hp.BLOCKLIST_FILE, None))
    expired = blocklist.prune_expired()
    stats_file = load_json(SOURCE_STATS_FILE, {})
    history = stats_file.get("history", {}) if isinstance(stats_file, dict) else {}

    # ---- 1. discovery ----
    disc = sm.discover(sources, cands, parse_subscription_text, os.environ.get("GITHUB_TOKEN"))
    print(f"自动发现: 新增候选 {len(disc['added'])}，扫描仓库 {disc['searched_repos']}")

    off_urls = sm.official_urls(sources)
    cand_urls = [u for u in sm.active_candidate_urls(cands) if u not in off_urls]
    off_set = set(off_urls)

    # ---- 2. fetch ----
    per_source, fstats = fetch_all_sources(off_urls + cand_urls)
    print(f"原始节点总数: {sum(len(v) for v in per_source.values())}")

    bad_sources = load_json(BAD_SOURCES_FILE, {})
    bad_sources = {u: v for u, v in bad_sources.items() if u in fstats}
    for url, s in fstats.items():
        rec = bad_sources.get(url, {"fail_streak": 0})
        rec["fail_streak"] = 0 if s.get("ok") else int(rec.get("fail_streak", 0)) + 1
        rec["last_error"] = s.get("error")
        rec["last_count"] = s.get("count", 0)
        bad_sources[url] = rec

    # ---- 3. static filters: keyword / honeypot / 协议白名单与关键参数硬性门槛 ----
    exclude_re = re.compile(EXCLUDE_KEYWORDS, re.IGNORECASE)
    pre_reasons: dict[str, int] = defaultdict(int)
    staged: dict[str, list[dict]] = {}
    for url, plist in per_source.items():
        keep = []
        for p in plist:
            if not p.get("server") or not p.get("port") or exclude_re.search(str(p.get("name", ""))):
                continue
            why = hp.static_reject_reason(p)
            if why:
                pre_reasons[why] += 1
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
        flags = hp.source_cluster_flags(plist, resolved) if dns_trusted else []
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

    # ---- 4. TCP 存活性检查（仅作服务器在线信号，不代表国内连通性/延迟） ----
    print("开始 TCP 连通性检测（仅存活信号；真实测速由本地客户端完成）...")
    tcp_lat: dict[str, float] = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        fut_map = {executor.submit(tcp_probe, p): fp for fp, p in unique.items()}
        for fut in as_completed(fut_map):
            alive, latency = fut.result()
            if alive:
                tcp_lat[fut_map[fut]] = latency
    print(f"TCP 存活节点: {len(tcp_lat)}")

    # ---- 5. real probe (OPTIONAL, local-only) ----
    # GitHub Actions（美西机房）无法穿越防火墙，测得的「真实连通性」对中国大陆
    # 用户没有参考价值，反而会误选美国垃圾节点。CI 通过 PROXYSUB_DISABLE_PROBE=1
    # 彻底禁用本环节（见 .github/workflows/daily-update.yml）；仅本地手动运行且
    # 装有 mihomo 时才做真实探测。最终活性测试由用户本地客户端完成。
    survival_pre = load_json(SURVIVAL_FILE, {})
    probe: dict[str, dict] = {}
    bin_path = mihomo_available() if real_probe_enabled() else None
    if not real_probe_enabled():
        print("云端真实流量拨测已禁用（PROXYSUB_DISABLE_PROBE=1）：仅保留 TCP 存活检查，"
              "最终测速/优选由本地客户端通过 gstatic generate_204 完成")
    if not real_probe_enabled():
        sample: list[str] = []
    else:
        def _probe_rank(fp: str) -> tuple:
            # Preferred protocols first, then survivors, then low TCP latency.
            rec = survival_pre.get(fp, {})
            streak = int(rec.get("streak", 0))
            seen = int(rec.get("seen_days", 0))
            tier = protocol_tier(unique[fp])
            return (tier, -streak, -seen, tcp_lat[fp])

        alive_sorted = sorted(tcp_lat, key=_probe_rank)
        # Stratify: fill per-region reserves first so Asia is actually probed.
        # Within region: take preferred (hy2/reality) quota first, then rest by rank.
        by_region: dict[str, list[str]] = defaultdict(list)
        for fp in alive_sorted:
            if fp not in official_fps:
                continue
            by_region[classify_proxy(unique[fp].get("name", ""))].append(fp)
        sample = []
        chosen: set[str] = set()
        for region, reserve in PROBE_RESERVE_PER_REGION.items():
            pool = by_region.get(region, [])
            pref_n = PROBE_PREFERRED_PER_REGION.get(region, 0)
            pref = [fp for fp in pool if is_preferred(unique[fp])]
            rest = [fp for fp in pool if fp not in pref]
            ordered = pref[:pref_n] + rest + pref[pref_n:]
            for fp in ordered[:reserve]:
                if fp not in chosen:
                    sample.append(fp)
                    chosen.add(fp)
        for fp in alive_sorted:
            if len(sample) >= PROBE_LIMIT_OFFICIAL:
                break
            if fp in official_fps and fp not in chosen:
                sample.append(fp)
                chosen.add(fp)
        for cu in cand_urls:
            extra = [fp for fp in alive_sorted if cu in prov[fp] and fp not in official_fps and fp not in chosen]
            extra = extra[:PROBE_PER_CANDIDATE]
            sample += extra
            chosen.update(extra)

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

    # ---- 6. per-source metrics ----
    per_src: dict[str, dict] = {}
    for url in off_urls + cand_urls:
        fps = [fp for fp, s in prov.items() if url in s]
        alive = [fp for fp in fps if fp in tcp_lat]
        is_off = url in off_set
        m = dict(fstats.get(url, {}))
        m.update(
            role="official" if is_off else "candidate",
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

    cand_rep = sm.evaluate_candidates(cands, {u: per_src[u] for u in cand_urls}, sources)
    off_rep = sm.update_official(sources, history, {u: per_src[u] for u in off_urls})
    for u in cand_rep["promoted"]:
        print(f"候选源晋升为正式源: {u}")
    for u, why in {**cand_rep["rejected"], **off_rep["demoted"]}.items():
        print(f"移除源: {u} -> {why}")

    # ---- 7. scoring ----
    # Real-probe OK ranks first; TCP-alive (esp. Asia / Hy2/Reality) stays eligible
    # so China-path quotas and MIN_FINAL can be filled when US-runner probe is sparse.
    survival = survival_pre
    scored: list[tuple[dict, float, float, bool, bool, int]] = []
    for fp, tlat in tcp_lat.items():
        if fp in tampered:
            continue
        cand_only = fp not in official_fps
        r = real_ok.get(fp)
        if bin_path and REQUIRE_REAL_PROBE_IN_OUTPUT and not r:
            continue  # legacy hard gate (off by default for China-path floor)
        if cand_only and bin_path and not r:
            continue  # probation-source nodes must pass the real probe
        if bin_path and REQUIRE_HTTPS_OK_IN_OUTPUT and r and not r.get("https_ok"):
            continue  # AI/CF sites need working HTTPS egress
        display = r["latency"] if r else tlat
        us_like = is_us_node(unique[fp], r)
        lat_cap = MAX_ACCEPT_LATENCY_MS_US if us_like else MAX_ACCEPT_LATENCY_MS
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
        bonus = survival_bonus_ms(fp, survival)
        if is_preferred(unique[fp]):
            bonus *= 1.5  # keep long-lived hy2/reality even harder
        # TCP 延迟（美西 Runner 测得，≠国内真实路径）仅作粗排信号：贡献设上限，
        # 排序主要由协议质量 / 存活时长 / 多源 / 亚洲路径等静态特征决定。
        score = min(display, TCP_LATENCY_CAP_IN_SCORE) + penalty + bonus
        scored.append((unique[fp], score, display, is_preferred(unique[fp]), bool(r), tier))

    scored.sort(key=lambda x: (x[5], not x[3], x[1]))
    alive_fps = {fingerprint(p) for p, *_ in scored}
    survival = update_survival(alive_fps, survival)

    # diversity caps: one credential / one egress IP must not dominate the output
    cred_n: dict[str, int] = defaultdict(int)
    egress_n: dict[str, int] = defaultdict(int)
    diversified = []
    diversity_dropped = 0
    for item in scored:
        fp = fingerprint(item[0])
        cred = hp.credential_of(item[0])
        eg = (real_ok.get(fp) or {}).get("egress")
        if (cred and cred_n[cred] >= MAX_PER_CREDENTIAL) or (eg and egress_n[eg] >= MAX_PER_EGRESS_IP):
            diversity_dropped += 1
            continue
        if cred:
            cred_n[cred] += 1
        if eg:
            egress_n[eg] += 1
        diversified.append(item)
    scored = diversified

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

    # ---- 命名与安全隔离 ----
    # 1) 不再附加美西 Runner 测得的延迟标签——该延迟不代表国内真实路径，只会误导用户；
    #    最终测速/优选完全由本地客户端的 url-test（gstatic generate_204）动态完成。
    # 2) skip-cert-verify: true 的节点：名称打 [Insecure] 标签 + 独立分组隔离，
    #    不与合规节点无差别混同，也不进入自动选择/故障转移/地区分组。
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

    print(f"\n最终精简节点数: {total_final}（合规 {len(final_proxies)}，高风险隔离 {len(insecure_proxies)}）")
    # 自动选择/故障转移仅包含合规节点；url-test 由客户端本地动态测速
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

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": final_proxies + insecure_proxies,
        "proxy-groups": groups,
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }

    # ---- 8. persist ----
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    save_json(SURVIVAL_FILE, survival)
    save_json(BAD_SOURCES_FILE, bad_sources)
    save_json(SOURCE_STATS_FILE, {"date": _today(), "sources": per_src, "history": history})
    sm.save_json(sm.SOURCES_FILE, sources)
    sm.save_json(sm.CANDIDATES_FILE, cands)
    sm.save_json(hp.BLOCKLIST_FILE, blocklist.data)

    print(f"\n✅ 已生成: {OUTPUT_FILE}")
    write_github_summary({
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
    })


if __name__ == "__main__":
    main()
