# proxysub 健康报告

更新时间：2026-10-22 21:33 UTC
运行模式：**mihomo**

## 概览

- 最终节点：**118**（合规 74，高风险隔离 44）
- 真实拨测通过率：**46.2%**（363/786）
- TCP 存活：1046 | 正式源 9 个 | 候选源 5 个

## 协议分布

| 协议 | 数量 |
|---|---|
| VLESS-TLS | 35 |
| Hysteria2 | 32 |
| VLESS-Reality | 27 |
| Trojan | 15 |
| Anytls | 5 |
| Hysteria | 4 |

## 区域分布

| 区域 | 数量 |
|---|---|
| 🌐 其他 | 94 |
| 🇺🇸 美国 | 8 |
| 🇯🇵 日本 | 5 |
| 🇸🇬 新加坡 | 5 |
| 🇭🇰 香港 | 4 |
| 🇹🇼 台湾 | 1 |
| 🇰🇷 韩国 | 1 |

## 源贡献 Top 10（正式源）

| 源 | 真实通过 | 独有存活 | 存活 |
|---|---|---|---|
| `Au1rxx/free-vpn-subscriptions` | 147 | 409 | 416 |
| `yy1588133/proxy-pool` | 126 | 207 | 410 |
| `peasoft/NoMoreWalls` | 78 | 19 | 204 |
| `chengaopan/AutoMergePublicNodes` | 78 | 2 | 202 |
| `ermaozi/get_subscribe` | 58 | 22 | 152 |
| `lanzm/MetaFetch` | 25 | 74 | 78 |
| `ovmvo/FreeSub` | 11 | 17 | 17 |
| `shaoyouvip/free` | 10 | 9 | 10 |
| `Russ534/clash` | 0 | 1 | 1 |
| `awesome-vpn/awesome-vpn` | 0 | 0 | 0 |

## 警告

- 淘汰源 `https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/reachable/clash.yml`：cn_low_pass_rate:5/49
- 可疑源结构：Au1rxx: template_cluster:d501ee79:103.106.229.0/24(46/92)
- ⚠️ 最终节点数 118 低于下限 150（候选池不足）
