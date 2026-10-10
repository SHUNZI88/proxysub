# proxysub

每 6 小时（北京时间 0/6/12/18，GitHub Actions 定时 + 可手动 `workflow_dispatch`）自动抓取公开免费订阅源，清洗、探测、排序后生成：

订阅地址：`https://raw.githubusercontent.com/SHUNZI88/proxysub/main/clean_clash.yaml`

## 文件说明

| 文件 | 作用 |
|---|---|
| `filter_clash.py` | 主流程：抓取 → 过滤 → TCP → mihomo 真实探测 → 打分 → 输出 |
| `sources_manager.py` | 订阅源生命周期：自动发现、试用、晋升、淘汰、上限 |
| `honeypot.py` | 防蜜罐过滤：地址校验、DNS 校验、黑名单、源结构检测 |
| `sources.json` | 正式源列表（可手工编辑；`deny_repos` 填永不收录的 `owner/repo`） |
| `candidate_sources.json` | 候选（试用期）源及被拒记录 |
| `honeypot_blocklist.json` | 黑名单：手工 `domains/ips/cidrs/keywords` + 自动条目（14 天过期） |
| `source_stats.json` / `bad_sources.json` / `survival.json` | 源统计、失败计数、节点跨天存活 |

## 订阅源自动发现与淘汰

1. **发现**：每次运行用 Actions 自带 `GITHUB_TOKEN`（只读搜索）在 GitHub 搜最近 3 天有更新的相关仓库，查找 `clash.yaml / mihomo.yaml / list.meta.yml / proxies.yaml` 等文件。每次最多查看 20 个仓库、新增 10 个候选；接近限额自动停止。
2. **仓库信誉**：fork、已归档、创建不足 7 天、0 星且新建、名称/简介含推广/博彩等垃圾词的仓库直接拒绝；星数少（<5）或较新（<60 天）的仓库试用期从 3 次延长到 5 次。
3. **试用期**：候选源每次都被抓取和探测，需**连续 N 次**同时满足：真实探测可用节点 ≥3，且其中 ≥3 个是正式源里没有的新节点，才能晋升；每次最多晋升 2 个。连续 3 次拉取失败、或 16 次仍未达标则拒绝。候选源节点权重更低（必须通过真实探测，且排序额外加 400ms 惩罚）。
4. **淘汰**：正式源连续 4 次（约 24 小时）拉取失败，连续约 1 天探测但 0 真实可用、Cloudflare 拉黑比例过高、或连续约 4 天没有独有存活节点，自动移除；被移除的源 30 天内不会被重新发现。
5. **上限**：正式源最多 30 个，超出时按「拉取成功率 + 独有贡献」排序淘汰末尾（手工源有少量加分）。

## 防蜜罐措施

- **地址校验**：服务器为私有/保留/回环/CGNAT/组播 IP、非法主机名（`localhost`、`.local`、`.internal` 等）、非法端口，直接丢弃；域名解析到这些地址的也丢弃。
- **黑名单**：`honeypot_blocklist.json` 支持域名后缀、IP、网段、关键词；探测中发现篡改的节点服务器会自动加入（14 天后过期，避免长期误杀）。
- **真实探测校验内容**：通过 mihomo 逐节点访问 `generate_204`，必须是 204 且无内容；出现跳转或注入内容时再用另一个端点（cp.cloudflare.com）复核，两次都异常才判为篡改。再经 HTTPS（开启证书校验）访问 Cloudflare trace：证书错误判为中间人；返回内容异常判为篡改；出口 IP 为保留地址也判为异常。
- **源结构检测**：某个源的节点 ≥60% 集中在同一个 /24（或 ≥85% 在同一 /16），或同一密码/UUID 被大量不同服务器共用，标记可疑；候选源直接拒绝，正式源仅记录。候选源篡改节点较多也会被拒；正式源篡改比例过高会被移除。
- **分散度**：最终订阅中同一凭证最多 4 个节点、同一出口 IP 最多 2 个，避免被单一运营者主导。
- **质量优先（宁缺毋滥）**：最终列表只收真实探测通过且 HTTPS（Cloudflare trace）成功的节点；延迟 >1800ms 丢弃；区域配额缩小，低质量协议（明文 SS/无 TLS vmess/http/socks）每区最多 1 个凑数。
- **协议优先级**：Hysteria2 / VLESS+Reality 探测配额与排序大幅优先，trojan/vless-TLS 次之，SS/vmess/http/socks 降权。
- **纯净度**：HTTPS 成功后再访问 grok.com；出现 Cloudflare Error 1005 / Access Denied 的出口记为 `cf_blocked` 并拉黑，避免「能通 204 但 AI 站被墙」的节点进订阅。
- **寿命**：跨天存活加权提高；长期存活的 hy2/reality 额外加权。

### 局限（请知悉）

- **无法保证 100% 无蜜罐**。如果节点运营者如实转发流量、只在后台记录，从外部探测无法区分。免费节点请勿用于登录重要账户、支付、传输敏感信息；HTTPS 能保护内容，但运营者仍能看到访问的域名和你的 IP。
- 没有使用 ASN 数据库，「同一运营者」只用 /24、/16 和共用凭证近似判断；Cloudflare 优选 IP 类节点可能被误判为集中。
- 真实探测按地区分层，亚洲与 Hysteria2/Reality 有额外探测配额；其余未探测节点不进最终订阅。
- GitHub 搜索有频率限制，代码搜索对 `GITHUB_TOKEN` 可能不可用（失败时自动跳过，只用仓库搜索）。
- 自动黑名单可能误伤共享 CDN 域名的正常节点，条目 14 天后自动过期；可在 JSON 里手工删除。

## 手动控制

- 关闭自动发现：工作流环境变量 `PROXYSUB_DISCOVERY: '0'`。
- 手工加源：在 `sources.json` 的 `official` 里加一条 `{"url": "...", "origin": "manual"}`。
- 禁止某仓库：在 `deny_repos` 里加 `owner/repo`。
