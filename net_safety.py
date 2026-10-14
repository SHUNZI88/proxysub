"""安全 HTTP 抓取（SSRF 防护）——叶子模块，仅依赖标准库 + requests。

背景（安全评估 F1 / CWE-918）：channels 发现与订阅源抓取会对**外部可控
URL**（Telegram 频道/网页中出现的链接、sources.json 录入源）发起请求。
若不校验落点，攻击者在被监控页面放置内网/元数据地址即可让运行机
（GitHub Actions runner 或自托管沙箱）代发请求：

- 云元数据服务 ``http://169.254.169.254/latest/meta-data/``（泄漏临时凭证；
  Actions runner 同样暴露该地址，且本仓工作流 token 具备 contents:write，
  一旦泄漏可被用于推送仓库）；
- 内网服务 ``http://10.x/...``、``http://127.0.0.1:...``。

防护策略（OWASP SSRF Prevention Cheat Sheet）：
1. 协议白名单（仅 http/https）；
2. 解析主机名全部 A/AAAA 记录，任一落在私网/回环/链路本地/组播/保留/
   未指定/非全局地址即拒绝（兼顾 DNS 重绑定：解析后拒绝私网落点）；
3. 不自动跟随重定向；对 3xx 显式解析 Location 并**重新走完整校验**后
   手动跟随（上限 max_redirects 跳），防止「公网 URL → 302 → 内网」穿透；
4. GitHub 官方主机（raw.githubusercontent.com 等）加入豁免集：其地址由
   GitHub 基础设施掌握、代码内写死可信，且可减少每源一次 DNS 解析开销。

注意：本模块做的是**落点校验**，不替代 TLS 证书校验（requests 默认开启）。
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests

ALLOWED_SCHEMES = {"http", "https"}

# 可信 GitHub 官方主机：免 DNS 落点校验（其 IP 由 GitHub 掌握，且项目内
# 多处写死使用；豁免同时避免对每个订阅源重复解析的开销）。
TRUSTED_HOSTS = frozenset({
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "gist.githubusercontent.com",
    "github.io",
    "pages.github.com",
})

DEFAULT_TIMEOUT = 20
DEFAULT_MAX_REDIRECTS = 3


def is_blocked_ip(ip: str) -> bool:
    """IP 字符串是否落在应拦截的范围。

    解析失败一律视为不可信（防御畸形输入）。拦截：私网 / 回环 / 链路本地
    （含 169.254.x 云元数据）/ CGNAT / 组播 / 未指定 / 保留 / 非全局。
    """
    try:
        a = ipaddress.ip_address(str(ip).strip("[]"))
    except ValueError:
        return True
    return (
        not a.is_global
        or a.is_loopback
        or a.is_link_local
        or a.is_multicast
        or a.is_reserved
        or a.is_unspecified
    )


def host_is_trusted(host: str) -> bool:
    """主机是否在可信豁免集（含子域）。"""
    host = (host or "").lower().rstrip(".")
    return host in TRUSTED_HOSTS or any(
        host.endswith("." + t) for t in TRUSTED_HOSTS
    )


def validate_url_target(url: str) -> None:
    """校验 URL 目标可安全抓取；不合法抛 ValueError。

    步骤：协议白名单 → 主机名非空 → 可信豁免跳过 DNS → 否则解析全部
    A/AAAA 记录并逐一校验落点（任一命中拦截范围即拒绝）。
    """
    p = urlparse(url)
    scheme = (p.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"blocked scheme: {scheme!r} in {url!r}")
    host = p.hostname
    if not host:
        raise ValueError(f"no host in url: {url!r}")
    if host_is_trusted(host):
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ValueError(f"dns resolve failed for {host!r}: {e}") from e
    ips = {info[4][0] for info in infos}
    if not ips:
        raise ValueError(f"dns returned no records for {host!r}")
    for ip in ips:
        if is_blocked_ip(ip):
            raise ValueError(
                f"blocked target host {host!r} resolves to non-public {ip}"
            )


def safe_http_get(url: str, *, timeout: int = DEFAULT_TIMEOUT, headers=None,
                  max_redirects: int = DEFAULT_MAX_REDIRECTS, **kw):
    """带 SSRF 防护的 GET：校验落点 + 手动跟随重定向（每跳重新校验）。

    替代裸 ``requests.get`` 用于所有外部可控 URL 的抓取。抛出的
    ValueError 表示目标被安全策略拦截；调用方应按普通抓取失败处理。
    """
    kw.setdefault("allow_redirects", False)
    current = url
    for _ in range(max_redirects + 1):
        validate_url_target(current)
        r = requests.get(current, timeout=timeout, headers=headers or {}, **kw)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            if not loc:
                return r
            # 相对 Location 基于当前 URL 解析为绝对地址，下一轮重新完整校验
            current = urljoin(current, loc)
            continue
        return r
    raise ValueError(f"too many redirects (> {max_redirects}) from {url!r}")
