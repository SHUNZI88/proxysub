# proxysub 健康报告

更新时间：2026-11-07 11:25 UTC
运行模式：**mihomo**

## 概览

- 最终节点：**197**（合规 136，高风险隔离 61）
- 真实拨测通过率：**27.4%**（301/1099）
- TCP 存活：5473 | 正式源 20 个 | 候选源 19 个

## 协议分布

| 协议 | 数量 |
|---|---|
| VLESS-Reality | 79 |
| Hysteria2 | 58 |
| VLESS-TLS | 29 |
| Trojan | 21 |
| Ss | 6 |
| Anytls | 3 |
| Hysteria | 1 |

## 区域分布

| 区域 | 数量 |
|---|---|
| 🌐 其他 | 60 |
| 🇯🇵 日本 | 35 |
| 🇺🇸 美国 | 30 |
| 🇸🇬 新加坡 | 26 |
| 🇭🇰 香港 | 19 |
| 🇹🇼 台湾 | 11 |
| 🇰🇷 韩国 | 10 |
| 🇬🇧 英国 | 6 |

## 源贡献 Top 10（正式源）

| 源 | 真实通过 | 独有存活 | 存活 |
|---|---|---|---|
| `yy1588133/proxy-pool` | 92 | 82 | 847 |
| `Au1rxx/free-vpn-subscriptions` | 86 | 361 | 744 |
| `Au1rxx/free-vpn-subscriptions` | 72 | 211 | 683 |
| `VPN-Subcription-Links/ClashX-V2Ray-TopFreeProxy` | 62 | 47 | 1208 |
| `tomjiu/proxy-pipeline` | 53 | 548 | 970 |
| `tomjiu/proxy-pipeline` | 43 | 9 | 303 |
| `peasoft/NoMoreWalls` | 41 | 18 | 224 |
| `chengaopan/AutoMergePublicNodes` | 32 | 0 | 215 |
| `chengaopan/AutoMergePublicNodes` | 32 | 0 | 215 |
| `ermaozi/get_subscribe` | 30 | 0 | 270 |

## 警告

- 淘汰源 `https://raw.githubusercontent.com/VPN-Subcription-Links/ClashX-V2Ray-TopFreeProxy/main/combine/clash.config.yaml`：cn_low_pass_rate:0/74
- 淘汰源 `https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml`：cn_low_pass_rate:0/24
- 淘汰源 `https://blog.ermao.net/sub/clash/ermao.net`：cn_low_pass_rate:0/20
- 可疑源结构：yy1588133: template_cluster:7e0be0a5:52.195.225.0/24(26/35); Au1rxx: template_cluster:e67f6d48:82.38.31.0/24(78/152); VPN-Subcription-Links: template_cluster:7e0be0a5:52.195.225.0/24(26/35)
