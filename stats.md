# proxysub 健康报告

更新时间：2026-11-20 21:35 UTC
运行模式：**mihomo**

## 概览

- 最终节点：**180**（合规 129，高风险隔离 51）
- 真实拨测通过率：**43.2%**（423/980）
- TCP 存活：2573 | 正式源 22 个 | 候选源 1 个

## 协议分布

| 协议 | 数量 |
|---|---|
| VLESS-Reality | 74 |
| Hysteria2 | 52 |
| VLESS-TLS | 22 |
| Trojan | 17 |
| Ss | 14 |
| Hysteria | 1 |

## 区域分布

| 区域 | 数量 |
|---|---|
| 🌐 其他 | 60 |
| 🇯🇵 日本 | 35 |
| 🇺🇸 美国 | 30 |
| 🇭🇰 香港 | 19 |
| 🇸🇬 新加坡 | 17 |
| 🇬🇧 英国 | 8 |
| 🇹🇼 台湾 | 7 |
| 🇰🇷 韩国 | 4 |

## 源贡献 Top 10（正式源）

| 源 | 真实通过 | 独有存活 | 存活 |
|---|---|---|---|
| `lanzm/MetaFetch` | 94 | 150 | 189 |
| `FlyingDashie/Free-node-autotest` | 85 | 107 | 194 |
| `Au1rxx/free-vpn-subscriptions` | 80 | 931 | 990 |
| `yy1588133/proxy-pool` | 69 | 30 | 512 |
| `mahdibland/V2RayAggregator` | 49 | 83 | 163 |
| `bily1258-design/beimi` | 41 | 339 | 371 |
| `ermaozi/get_subscribe` | 36 | 9 | 184 |
| `kooker/FreeSubsCheck` | 31 | 166 | 274 |
| `chengaopan/AutoMergePublicNodes` | 30 | 4 | 209 |
| `free18/v2ray` | 20 | 65 | 303 |

## 警告

- 淘汰源 `https://raw.githubusercontent.com/Russ534/clash/cdf534db8f8c9306d61c630b840d0a1936d09dd2/bp.yaml`：cn_low_pass_rate:0/30
- 淘汰源 `https://raw.githubusercontent.com/mfuu/v2ray/master/sub`：cn_low_pass_rate:0/21
- 可疑源结构：bily1258-design: template_cluster:786c671e:104.16.10.0/24(11/22); Au1rxx: template_cluster:fbc280a6:118.253.167.0/24(27/27),template_cluster:5482e58f:42.51.25.0/24(22/22)
