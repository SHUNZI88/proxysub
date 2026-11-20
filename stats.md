# proxysub 健康报告

更新时间：2026-11-20 22:58 UTC
运行模式：**mihomo**

## 概览

- 最终节点：**178**（合规 124，高风险隔离 54）
- 真实拨测通过率：**43.8%**（429/980）
- TCP 存活：2551 | 正式源 19 个 | 候选源 1 个

## 协议分布

| 协议 | 数量 |
|---|---|
| VLESS-Reality | 68 |
| Hysteria2 | 63 |
| VLESS-TLS | 22 |
| Ss | 13 |
| Trojan | 11 |
| Anytls | 1 |

## 区域分布

| 区域 | 数量 |
|---|---|
| 🌐 其他 | 60 |
| 🇯🇵 日本 | 35 |
| 🇺🇸 美国 | 30 |
| 🇸🇬 新加坡 | 19 |
| 🇭🇰 香港 | 15 |
| 🇬🇧 英国 | 8 |
| 🇰🇷 韩国 | 6 |
| 🇹🇼 台湾 | 5 |

## 源贡献 Top 10（正式源）

| 源 | 真实通过 | 独有存活 | 存活 |
|---|---|---|---|
| `lanzm/MetaFetch` | 95 | 147 | 190 |
| `yy1588133/proxy-pool` | 81 | 30 | 510 |
| `Au1rxx/free-vpn-subscriptions` | 73 | 934 | 995 |
| `FlyingDashie/Free-node-autotest` | 64 | 84 | 175 |
| `mahdibland/V2RayAggregator` | 46 | 83 | 163 |
| `bily1258-design/beimi` | 42 | 337 | 369 |
| `kooker/FreeSubsCheck` | 42 | 178 | 286 |
| `ermaozi/get_subscribe` | 38 | 8 | 180 |
| `chengaopan/AutoMergePublicNodes` | 37 | 4 | 205 |
| `free18/v2ray` | 22 | 71 | 306 |

## 警告

- 淘汰源 `https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/clash.yaml`：cn_low_pass_rate:0/30
- 淘汰源 `https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/Eternity.yml`：cn_low_pass_rate:0/30
- 淘汰源 `https://raw.githubusercontent.com/ovmvo/FreeSub/main/sub/permanent/mihomo.yaml`：cn_low_pass_rate:0/29
- 可疑源结构：bily1258-design: template_cluster:786c671e:104.16.10.0/24(11/22); Au1rxx: template_cluster:fbc280a6:118.253.167.0/24(27/27),template_cluster:5482e58f:42.51.25.0/24(22/22)
