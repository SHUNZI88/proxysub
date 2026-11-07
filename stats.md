# proxysub 健康报告

更新时间：2026-11-07 20:38 UTC
运行模式：**mihomo**

## 概览

- 最终节点：**182**（合规 118，高风险隔离 64）
- 真实拨测通过率：**24.3%**（283/1163）
- TCP 存活：5892 | 正式源 19 个 | 候选源 18 个

## 协议分布

| 协议 | 数量 |
|---|---|
| VLESS-Reality | 61 |
| Hysteria2 | 43 |
| VLESS-TLS | 36 |
| Trojan | 29 |
| Ss | 5 |
| Hysteria | 5 |
| Anytls | 3 |

## 区域分布

| 区域 | 数量 |
|---|---|
| 🌐 其他 | 60 |
| 🇯🇵 日本 | 35 |
| 🇺🇸 美国 | 30 |
| 🇸🇬 新加坡 | 22 |
| 🇰🇷 韩国 | 11 |
| 🇭🇰 香港 | 8 |
| 🇹🇼 台湾 | 8 |
| 🇬🇧 英国 | 8 |

## 源贡献 Top 10（正式源）

| 源 | 真实通过 | 独有存活 | 存活 |
|---|---|---|---|
| `yy1588133/proxy-pool` | 94 | 512 | 814 |
| `tomjiu/proxy-pipeline` | 89 | 576 | 974 |
| `ermaozi/get_subscribe` | 71 | 6 | 214 |
| `chengaopan/AutoMergePublicNodes` | 61 | 0 | 232 |
| `peasoft/NoMoreWalls` | 61 | 0 | 232 |
| `chengaopan/AutoMergePublicNodes` | 61 | 0 | 232 |
| `tomjiu/proxy-pipeline` | 58 | 7 | 329 |
| `mahdibland/ShadowsocksAggregator` | 45 | 16 | 174 |
| `lanzm/MetaFetch` | 34 | 815 | 1057 |
| `Au1rxx/free-vpn-subscriptions` | 31 | 360 | 744 |

## 警告

- 淘汰源 `https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml`：cn_low_pass_rate:0/39
- 可疑源结构：yy1588133: template_cluster:7e0be0a5:52.195.225.0/24(26/35); lanzm: template_cluster:7e0be0a5:52.195.225.0/24(26/35); Au1rxx: template_cluster:e67f6d48:82.38.31.0/24(78/152)
