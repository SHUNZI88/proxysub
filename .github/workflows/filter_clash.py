import requests
import yaml
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ====================== 配置区 ======================
SOURCE_URLS = [
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml",
    "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/clash.yaml",
    "https://raw.githubusercontent.com/PuddinCat/BestClash/refs/heads/main/proxies.yaml",
    "https://raw.githubusercontent.com/yy1588133/proxy-pool/main/clash.yaml",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
    "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/clash_config.yaml",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.meta.yml",
    "https://raw.githubusercontent.com/Russ534/clash/cdf534db8f8c9306d61c630b840d0a1936d09dd2/bp.yaml",
    "https://raw.githubusercontent.com/shaoyouvip/free/main/mihomo.yaml",
    "https://raw.githubusercontent.com/zhangkaiitugithub/passcro/main/speednodes.yaml",
    "https://blog.ermao.net/sub/clash/ermao.net",
    "https://sunmiao4458.github.io/free-proxy-airport/clash.yaml",
    "https://raw.githubusercontent.com/lanzm/MetaFetch/master/list.meta.yml",
]

# 排除垃圾节点
EXCLUDE_KEYWORDS = r"(官网|流量|到期|过期|剩余|测试|无效|假|防失联|127\.0\.0|IPv6|试用|公告|电报|TG|频道)"

# 地区分类规则（按优先级）
REGION_RULES = {
    "🇭🇰 香港": r"(香港|HK|Hong Kong|HongKong)",
    "🇯🇵 日本": r"(日本|JP|Japan)",
    "🇸🇬 新加坡": r"(新加坡|SG|Singapore|狮城)",
    "🇺🇸 美国": r"(美国|US|United States|USA)",
    "🇹🇼 台湾": r"(台湾|TW|Taiwan)",
}

# 每个地区最多保留多少个节点
MAX_PER_REGION = 40
MAX_OTHER = 30

# TCP 检测超时（秒）
TCP_TIMEOUT = 3
MAX_WORKERS = 50          # 并发检测数

OUTPUT_FILE = "clean_clash.yaml"
# ====================================================

def fetch_proxies(url):
    try:
        print(f"拉取: {url}")
        r = requests.get(url, timeout=25)
        r.raise_for_status()
        data = yaml.safe_load(r.text)
        return data.get("proxies", []) if isinstance(data, dict) else []
    except Exception as e:
        print(f"失败: {e}")
        return []

def is_port_open(server, port):
    try:
        with socket.create_connection((server, int(port)), timeout=TCP_TIMEOUT):
            return True
    except:
        return False

def test_proxy(proxy):
    server = proxy.get("server")
    port = proxy.get("port")
    if not server or not port:
        return False
    return is_port_open(server, port)

def classify_proxy(name):
    for region, pattern in REGION_RULES.items():
        if re.search(pattern, name, re.IGNORECASE):
            return region
    return "🌐 其他"

def main():
    # 1. 拉取所有源
    all_proxies = []
    for url in SOURCE_URLS:
        all_proxies.extend(fetch_proxies(url))
    print(f"原始节点总数: {len(all_proxies)}")

    # 2. 基础过滤 + 去重
    exclude_re = re.compile(EXCLUDE_KEYWORDS, re.IGNORECASE)
    unique = {}
    for p in all_proxies:
        name = p.get("name", "")
        server = p.get("server", "")
        port = p.get("port", "")
        if not server or not port:
            continue
        if exclude_re.search(name):
            continue
        key = f"{server}:{port}"
        if key not in unique:
            unique[key] = p

    candidates = list(unique.values())
    print(f"去重+关键词过滤后: {len(candidates)}")

    # 3. TCP 有效性测试
    print("开始 TCP 连通性检测...")
    alive = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_proxy = {executor.submit(test_proxy, p): p for p in candidates}
        for future in as_completed(future_to_proxy):
            proxy = future_to_proxy[future]
            if future.result():
                alive.append(proxy)

    print(f"TCP 存活节点: {len(alive)}")

    # 4. 按地区分类并精简
    region_dict = defaultdict(list)
    for p in alive:
        region = classify_proxy(p.get("name", ""))
        region_dict[region].append(p)

    final_proxies = []
    for region, nodes in region_dict.items():
        limit = MAX_PER_REGION if region != "🌐 其他" else MAX_OTHER
        selected = nodes[:limit]
        final_proxies.extend(selected)
        print(f"{region}: {len(selected)} 个")

    print(f"最终精简节点数: {len(final_proxies)}")

    # 5. 生成配置
    names = [p["name"] for p in final_proxies]
    groups = [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": ["♻️ 自动选择", "DIRECT"] + list(REGION_RULES.keys()) + ["🌐 其他"]
        },
        {
            "name": "♻️ 自动选择",
            "type": "url-test",
            "proxies": names,
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50
        }
    ]

    # 添加地区组
    for region in list(REGION_RULES.keys()) + ["🌐 其他"]:
        region_names = [p["name"] for p in final_proxies if classify_proxy(p["name"]) == region]
        if region_names:
            groups.append({
                "name": region,
                "type": "url-test",
                "proxies": region_names,
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            })

    config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": final_proxies,
        "proxy-groups": groups,
        "rules": [
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择"
        ]
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    print(f"\n✅ 已生成: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()