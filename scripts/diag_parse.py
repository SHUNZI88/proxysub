#!/usr/bin/env python3
"""诊断：解析层在不同源上的丢包率（按协议、按失败原因）。

线索：ss://…@host:port?#name 这种带空查询串的写法，port 被解析成 "19999?",
int() 抛错被吞，节点静默消失——而这批节点恰好是国内可用率最高的一批。
本脚本量化「解析层到底丢了多少」，避免只修一个样本就宣称解决。
"""
from __future__ import annotations

import base64
import collections
import json
import sys
import urllib.request

sys.path.insert(0, "scripts")
import common  # noqa: E402

SOURCES = [
    ("v2rayfree", "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub"),
    ("Pawdroid", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"),
    ("kooker", "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/kooker.jp.txt"),
    ("free18", "https://raw.githubusercontent.com/free18/v2ray/main/c.yaml"),
    ("chengaopan", "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.meta.yml"),
]
MIRROR = [
    "{}",
    "https://gcore.jsdelivr.net/gh/{o}/{r}@{b}/{p}",
    "https://cdn.jsdelivr.net/gh/{o}/{r}@{b}/{p}",
]


def fetch(url: str) -> str:
    import re
    m = re.match(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$", url)
    chans = [url]
    if m:
        o, r, b, p = m.groups()
        chans += [c.format(o=o, r=r, b=b, p=p) for c in MIRROR[1:]]
    for c in chans:
        try:
            req = urllib.request.Request(c, headers={"User-Agent": "curl/8"})
            t = urllib.request.urlopen(req, timeout=25).read().decode("utf-8", "ignore")
            if t:
                return t
        except Exception:   # noqa: BLE001
            continue
    return ""


def lines_of(text: str) -> list[str]:
    """把订阅正文拆成「单条链接」列表，兼容 base64 整包与 yaml。"""
    t = text.strip()
    if "://" not in t[:200]:
        try:
            dec = base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", "ignore")
            if "://" in dec:
                return [x.strip() for x in dec.splitlines() if x.strip()]
        except Exception:   # noqa: BLE001
            pass
    return [x.strip() for x in t.splitlines() if x.strip()]


def main() -> int:
    total = collections.Counter()
    for label, url in SOURCES:
        txt = fetch(url)
        if not txt:
            print(f"== {label}: 抓取失败")
            continue
        if "://" not in txt[:200]:
            try:
                txt = base64.b64decode(txt.strip() + "=" * (-len(txt.strip()) % 4)).decode("utf-8", "ignore")
            except Exception:   # noqa: BLE001
                pass
        nodes = common.parse_subscription_text(txt)
        got = collections.Counter(n.get("type") for n in nodes)
        # 逐条比对：订阅里出现的 scheme 与解析结果
        schemes = collections.Counter()
        for ln in lines_of(txt) if "://" in txt[:200] else []:
            if "://" in ln:
                schemes[ln.split("://")[0].split(":")[0].lower()] += 1
        print(f"== {label}: 正文 {len(txt)}B  链接 {sum(schemes.values()) or 'yaml'}  "
              f"解析出 {len(nodes)}  {dict(got)}")
        if schemes:
            print(f"   原文 scheme 分布: {dict(schemes)}")
            for s, c in schemes.items():
                s2 = {"vless": "vless", "vmess": "vmess", "ss": "ss",
                      "trojan": "trojan", "hysteria2": "hysteria2",
                      "hy2": "hysteria2", "hysteria": "hysteria",
                      "tuic": "tuic"}.get(s, s)
                g = got.get(s2, 0)
                if c and g < c:
                    print(f"   丢包 {s}: {c} → {s2}:{g}（丢 {c-g}）")
                total[s] += c - g
    print("\n合计丢包:", dict(total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
