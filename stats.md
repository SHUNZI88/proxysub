# proxysub 健康报告

更新时间：2026-10-28 21:16 UTC
运行模式：**mihomo**

## 概览

- 最终节点：**119**（合规 75，高风险隔离 44）
- 真实拨测通过率：**48.4%**（140/289）
- TCP 存活：690 | 正式源 6 个 | 候选源 4 个

## 协议分布

| 协议 | 数量 |
|---|---|
| Hysteria2 | 51 |
| VLESS-TLS | 33 |
| VLESS-Reality | 21 |
| Trojan | 9 |
| Anytls | 5 |

## 区域分布

| 区域 | 数量 |
|---|---|
| 🌐 其他 | 86 |
| 🇯🇵 日本 | 12 |
| 🇭🇰 香港 | 7 |
| 🇸🇬 新加坡 | 5 |
| 🇺🇸 美国 | 4 |
| 🇰🇷 韩国 | 3 |
| 🇹🇼 台湾 | 2 |

## 源贡献 Top 10（正式源）

| 源 | 真实通过 | 独有存活 | 存活 |
|---|---|---|---|
| `tomjiu/proxy-pipeline` | 78 | 293 | 294 |
| `Ruk1ng001/freeSub` | 27 | 31 | 31 |
| `peasoft/NoMoreWalls` | 6 | 227 | 227 |
| `shaoyouvip/free` | 6 | 6 | 6 |
| `awesome-vpn/awesome-vpn` | 3 | 2 | 3 |
| `Russ534/clash` | 0 | 1 | 1 |

## 警告

- 淘汰源 `https://raw.githubusercontent.com/tomjiu/proxy-pipeline/main/dist/clean/clash-renamed.yaml`：cn_low_pass_rate:0/118
- ⚠️ 最终节点数 119 低于下限 150（候选池不足）
