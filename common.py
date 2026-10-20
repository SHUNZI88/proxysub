#!/usr/bin/env python3
"""proxysub 公共层：叶子级工具函数（P1-2 起配置常量已迁至 config.py）。

本模块是架构的「叶子」：仅依赖第三方库（yaml）、honeypot、net_safety
与 config，不依赖 probe / score / output / sources_manager，因此可被它们
安全地无循环地 import。拆分自原 filter_clash.py（~90KB）以降低维护成本。

维护说明：本文件放的是「跨模块共享且自身不再依赖其他业务模块」的纯函数
（指纹 / 订阅解析 / 静态门槛 / 协议门槛 / 抓取）。**可调常量一律放
config.py**（含「为什么是这个值」的理由注释），本文件只按需 import。
任何会反向引用 probe / score / output 的逻辑都不应放这里。
"""


from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from urllib.parse import parse_qs, unquote, urlparse

import yaml

import honeypot as hp
from net_safety import safe_http_get  # SSRF 防护抓取（安全评估 F1）
from config import (  # 配置常量（P1-2 迁出）；仅导入本文件实际用到的
    FETCH_RETRIES,
    FETCH_TIMEOUT,
    FETCH_WORKERS,
    FINGERPRINT_IGNORE_KEYS,
    NETWORK_ALIASES,
    PROTOCOL_WHITELIST,
    SHORT_ID_RE,
    SUPPORTED_FLOWS,
    UDP_PROTOCOLS,
    UUID_RE,
    VALID_NETWORKS,
    X25519_PUBLIC_KEY_RE,
)


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
            r = safe_http_get(
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


# -------------------------------------------------- Phase 2 进化引擎基础工具
def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson 得分区间（95%）——小样本下比正态近似稳健（n=0 时返回 (0,0)）。

    唯一实现：沙箱侧 `scripts/cn_probe.py::_wilson_ci` 已上收此处（改为委托），
    CI 侧源级淘汰/晋升/倾斜共用，避免两侧实现漂移（2026-10-15 复盘教训：
    镜像逻辑必须单一来源）。

    为什么用 Wilson 而非裸通过率：小样本下点估计极不稳定——如 4/27 裸通过率
    14.8% 看似中等，但其 95% 下界仅 5.9%；而 0/58 的下界恒为 0。源级淘汰判据
    用下界（保守侧），确保"样本不足/偶发通过"的源不被误杀。
    """
    if n <= 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z / denom * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, center - margin), min(1.0, center + margin)


def src_key(url: str) -> str:
    """订阅源稳定短键：GitHub raw/owner/repo -> 'owner/repo'；其它 -> 域名+路径前段。

    作为 source_scores.json 的 cn 维度键与报告 by_source 聚合键，须与 CI
    侧一致。长度受控（避免 1081 节点交接文档体积膨胀）。
    """
    if not url:
        return "?"
    try:
        p = urlparse(url)
        path = p.path.strip("/")
        if "github" in p.netloc and path.count("/") >= 2:
            return "/".join(path.split("/")[:2])      # owner/repo（含 raw.githubusercontent.com）
        if path:
            return f"{p.netloc}/{path[:32]}"
        return p.netloc or "?"
    except Exception:
        return str(url)[:48]
