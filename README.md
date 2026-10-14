# proxysub

**高纯度订阅清洗与结构规范化工具**：每 6 小时（北京时间 0/6/12/18，GitHub Actions 定时 + 可手动 `workflow_dispatch`）自动抓取公开免费订阅源，经「协议白名单 + 关键参数校验 + 深度指纹去重 + 防蜜罐静态检测」清洗后，输出干净、格式标准、结构统一的节点列表。

> **本仓库已开启反爬（anti-crawl）**：固定名 raw 地址（`.../main/clean_clash.yaml` 等）现为**诱饵内容**，请勿订阅。
> 真实订阅通过滚动 GitHub Release 分发，地址形如
> `https://github.com/SHUNZI88/proxysub/releases/latest/download/p_<随机资产名>`，
> **永久有效、无需更换**；具体地址仅仓库所有者可见（Actions 运行页 Step Summary），不在此公开悬挂。
> 机制与效果边界详见「反爬与防搜索」一节。

### 运行态速览（三行，先读这个）

| 项 | 当前值 |
|---|---|
| **订什么** | Release 永久地址 `.../latest/download/p_<随机名>_c.yaml`（随机名见 Actions Step Summary，不在此悬挂）；**勿订**固定名 raw（诱饵） |
| **最后中国实测** | 见 Release `verification_report.json` 的 `generated_at` 字段（沙箱 09:18 / 16:18 北京窗口产出） |
| **最后 CI 抓取** | 见 `stats.md` 顶部时间戳（CI 每 6h：00:17/06:17/12:17/18:17 UTC+8 名义） |

> **指标分离（重要）**：`stats.md` = **美西候选健康度**（CI 侧，未经中国实测）；
> 订阅主列表节点数 = **中国实测通过集**（沙箱侧，以 `verification_report.json` 为准）。
> 二者**不可混读**——主列表厚度看报告，不代表美西候选规模，反之亦然。

### 多格式订阅地址（反爬开启后，固定名地址为诱饵，仅列出格式对应关系）

| 格式 | Release 资产名规则 | 适用客户端 |
|---|---|---|
| Clash / mihomo | `releases/latest/download/p_*_c.yaml` | FlClash、Clash Verge Rev、mihomo |
| 仅 proxies 段 | `releases/latest/download/p_*_p.yaml` | 客户端 `proxy-providers` 引用 |
| sing-box | `releases/latest/download/p_*_s.json` | sing-box（outbounds 列表） |
| v2ray 分享链接 | `releases/latest/download/p_*_v.txt` | v2rayN、NekoBox（base64 整段导入） |
| 健康报告 | `stats.md`（仓库内，公开） | 浏览器查看 |

> 关闭反爬（`anti_crawl.json` 的 `"enabled": false`）后，固定名 raw 地址即恢复为真实内容：
> `https://raw.githubusercontent.com/SHUNZI88/proxysub/main/clean_clash.yaml` 等（jsDelivr 镜像同理）。

### 更新时效与外部心跳

- 定时触发为 **UTC 17 分（北京 0:17 / 6:17 / 12:17 / 18:17）**，刻意避开整点高峰以降低 GitHub 队列延迟；
- GitHub 对公共仓库的 `schedule` 存在固有延迟甚至偶发跳过，属平台行为。若需更准时，可配置外部心跳（如 cron-job.org）每 6 小时调用一次：

```
POST https://api.github.com/repos/SHUNZI88/proxysub/dispatches
Authorization: token <你的 PAT（repo 权限）>
Content-Type: application/json

{"event_type": "external-trigger"}
```

工作流已声明 `repository_dispatch: [external-trigger]`，收到即立刻运行。

## 设计定位（重要）

**云端探测只做「死活闸门」，不做「延迟排序」；测速与优选由你的本地客户端完成。**

原因：GitHub Actions 运行在美国美西机房，物理上无法穿越防火墙（GFW），无法预测中国大陆用户的真实连通性与延迟。因此云端探测的延迟数据不用于任何排序和命名。

但「探测」本身必须保留：免费订阅源中绝大多数节点是「端口开着但代理协议已失效」的僵尸节点（凭证过期、后端下线、CDN 空壳）——TCP 可达完全无法区分它们。云端用 mihomo 做一次真实代理请求（中国友好的 generate_204 检测 URL），**连美国都无法代理成功的节点必然已死，直接淘汰**；探测通过的节点才进入输出列表。实测此举可将输出的实际可用率从约 3% 提升到绝大多数可用（残余的「美国能通、国内不通」节点由客户端 url-test 二次筛除）。

因此本仓库的职责边界是：

| 仓库负责（云端） | 交给客户端（本地动态） |
|---|---|
| 订阅源发现、试用、晋升、淘汰 | 真实国内网络环境下的连通性验证 |
| 协议白名单与关键参数硬性门槛 | 延迟测速与自动优选（url-test） |
| 深度指纹去重、结构规范化 | 节点可用性的最终裁决 |
| 防蜜罐静态检测、风险节点隔离 | 故障切换（fallback） |
| 真实代理请求死活闸门（淘汰僵尸节点） | |

**排序原则**：排序只依据静态质量信号（协议层级、跨天存活、多源出现、亚洲路径偏好、SNI/端口特征），不使用任何美西测得的延迟。美国节点不做过度歧视：质量同样由死活闸门把关，仅保留轻度排序惩罚，最终占比上限 40%。

**本地客户端使用方法**：在 FlClash / Clash Verge Rev / mihomo 内核客户端中添加本订阅，客户端会通过 `http://www.gstatic.com/generate_204` 自动完成动态测速与优选（配置内建的 ♻️ 自动选择 / 🔯 故障转移 / 地区分组均为 url-test/fallback 类型）。更新订阅后执行一次全局测速，即可在真实网络环境下筛出可用节点。

## 硬性静态门槛（云端质量闸门）

剥离云端测速后，源质量完全由静态门槛把关：

1. **协议白名单**：仅收录优质现代协议 —— Hysteria2、VLESS（Reality 或显式 TLS）、Trojan、TUIC、AnyTLS、Hysteria。ss / ssr / vmess / http / socks 及未知类型整体拒绝。
2. **关键参数校验**：
   - VLESS + Reality：`public-key` 必须是合法 X25519 公钥（base64url 43 字符），`short-id` 必须是合法 hex（≤8 字节），SNI 必须存在且为合法主机名；
   - VLESS 必须为 Reality 或显式 `tls: true`（裸 VLESS 明文传输直接拒绝）；
   - Hysteria2 / Trojan / AnyTLS 必须有密码；TUIC 必须有凭证；obfs 仅支持 salamander 且须带 obfs-password；
   - 所有协议的 SNI 必须是合法主机名形态。
3. **深度指纹去重**：指纹采用「递归规范化 + 深度序列化」，完整纳入所有嵌套连接参数（`reality-opts`、`ws-opts`、`grpc-opts`、TLS/alpn 等）。仅 Reality 公钥、WS 路径或 gRPC service-name 不同的节点不会被误合并/误丢弃；仅名称不同或键顺序不同的节点也不会重复计数。
4. **风险节点隔离**：`skip-cert-verify: true`（跳过证书校验，削弱 TLS 身份认证）的节点名称会打上 `[Insecure]` 标签，并隔离到独立的 `⚠️ 高风险(跳过证书校验)` 分组——不进入自动选择、故障转移与地区分组，不与合规节点无差别混同。

## 文件说明

| 文件 | 作用 |
|---|---|
| `filter_clash.py` | 编排入口（`main()`）：抓取 → 静态门槛 → 两阶段探活/拨测 → 打分 → 多格式输出；具体实现分散到下列 4 个模块（直接 `python filter_clash.py` 运行方式不变） |
| `common.py` | 公共层（架构叶子，无循环依赖）：全部配置常量 + 指纹/解析/静态过滤/协议门槛等纯函数 |
| `probe.py` | 探测层：TCP/QUIC 存活检查与 mihomo 真实拨测（仅依赖 common） |
| `score.py` | 评分层：协议分层、中美路径惩罚、跨天存活与历史稳定性（仅依赖 common） |
| `output.py` | 输出层：分享链接 / sing-box 转换与多格式文件、健康报告（依赖 common + score） |
| `sources_manager.py` | 订阅源生命周期：自动发现、试用、晋升、淘汰、上限、长期评分 |
| `channels.py` | **多渠道搜集引擎**：从 Telegram 频道 / 网页 / 手工静态源提取订阅源 URL 与原始节点链接（仅依赖 safe_io + requests，无循环依赖） |
| `channels.json` | 多渠道采集配置：Telegram 频道列表、监控网页列表、手工静态源（默认空，由用户按渠道填充） |
| `honeypot.py` | 防蜜罐过滤：地址校验、DNS 校验、黑名单、源结构检测 |
| `anti_crawl.py` | **反爬与防搜索**（默认关闭）：诱饵分流、滚动 Release 永久地址 / 文件名轮换、诱饵回流检测、robots.txt |
| `anti_crawl.json` | 反爬配置与自动维护状态（`enabled` 开启；`publish_release` 控制永久地址/轮换模式；token/资产名/诱饵节点由程序维护，勿手改） |
| `robots.txt` | 反爬开启时生成的 `Disallow: /` 声明 |
| `collected_nodes.txt` | 多渠道搜集到的原始节点分享链接（vmess/vless/trojan/ss），经同样的静态门槛与死活闸门清洗后进入输出 |
| `safe_io.py` | JSON 原子化读写：临时文件 + `os.replace` + filelock，损坏自愈 |
| `net_safety.py` | **安全 HTTP 抓取**（SSRF 防护）：协议白名单 + DNS 落点校验（私网/回环/链路本地/元数据拦截）+ 重定向目标重新校验；所有外部可控 URL 的抓取均经此模块 |
| `clean_clash.yaml` | **主订阅**（Clash / mihomo 完整配置） |
| `clean_proxies_only.yaml` | 仅 `proxies` 段，供客户端 `proxy-providers` 引用 |
| `clean_singbox.json` | sing-box `outbounds` 列表 |
| `clean_v2ray.txt` | base64 编码的分享链接（v2rayN / NekoBox 可导入） |
| `stats.md` | 每次运行生成的健康报告（协议/区域分布、源贡献、警告） |
| `sources.json` | 正式源列表（可手工编辑；`deny_repos` 填永不收录的 `owner/repo`） |
| `candidate_sources.json` | 候选（试用期）源及被拒记录 |
| `honeypot_blocklist.json` | 黑名单：手工 `domains/ips/cidrs/keywords` + 自动条目（14 天过期） |
| `source_stats.json` / `bad_sources.json` / `survival.json` | 源统计、失败计数、节点跨天存活与真实通过率 |
| `source_scores.json` | 源长期评分（成功率 / 独有贡献 / 真实通过 / 蜜罐惩罚的指数滑动平均） |
| `requirements.txt` | Python 依赖（requests / PyYAML / filelock / pytest / pyflakes） |
| `tests/` | 单元测试：指纹去重、地区识别、静态门槛、订阅解析、原子写入、拨测样本选择、多格式输出、源评分 |

## 探测流程（TCP 预筛 + 拨测闸门）

1. **TCP 预筛**：并发 TCP 握手粗筛，快速砍掉已下线节点；UDP 协议（hy2/tuic）不做 TCP 检查，直接交拨测验证。
2. **拨测样本选择（select_probe_sample）**：从 TCP 存活节点中选出进入真实拨测的样本（预算 980 + 每候选源 20）。选择原则：
   - **不迷信历史**：`survival.json` 一旦停更陈旧（无今日记录），历史稳定优先整体关闭——否则已死旧节点会凭陈旧 streak 霸占预算，新节点永无拨测机会；
   - **新节点保底**：从未入池的节点保证 250 个拨测名额，节点池正常轮换；
   - **区域/协议分层**：亚洲区域与 hy2/reality 优先协议保留各自配额；
   - **渠道节点配额**：Telegram/网页分享链接搜集的节点给予 60 个保底名额（此前它们既非正式源也非候选源，永远选不中）；
   - **UDP 强制入样**：hy2/tuic 跳过 TCP 检查，必须进拨测样本，否则死活永远无法验证。
3. **真实拨测（死活闸门）**：mihomo 通过节点发起真实代理请求（中国友好 `generate_204`），只有本轮通过的节点才能进入最终列表。
4. **打分排序**：协议层级 / 跨天存活 / 历史真实通过率 / 多源出现 / 亚洲路径偏好；美西测得延迟不进名称、贡献设上限。survival 状态陈旧时，排序同样忽略历史加成（与样本选择同一原则）。

## 中国出口实测接力（沙箱侧）

云端拨测在美国进行，「美国能通、国内不通」的节点会混入订阅。为此增加第二实测 vantage：

1. **CI 交接**：每轮运行把待测节点写成 `.publish/pending_probe.json`（待测集 = 拨测样本 ∪ 最终输出）与 `.publish/pending_rescue.json`（救援集：CI 淘汰但静态可行的节点，上限 100），随滚动 Release 发布；
2. **沙箱实测**：定时任务（北京 09:18 / 16:18，CI 名义时段 06:17/12:17 后 ~45min，避开凌晨沙箱易休眠窗口）运行 `scripts/cn_probe.py`——**轮次闸门**（与上轮报告 `tested_round` 比对：新轮次立即测，年龄不是新鲜信号；等不到至多 20min，未测轮次顺延至下一实测轮、不丢失）→ **预算裁剪**（按剩余 1800s 预算折算节点上限、优先级 carryover>pending>rescue，硬保任务超时不击穿；未测节点由 CI 下轮待测文档自然再现）→ mihomo 中国出口拨测 → 出口 IP/地区取证 → 通过者覆盖发布为主资产（**订阅永久地址不变**）→ 发布 `verification_report.json`；
3. **滚动携带**：每轮测试集含上一轮验证集，通过的留、败的汰（免费节点寿命以小时计，自清洁）；通过数 <15 时保上轮验证集不动；
4. **所有权切换**：验证报告新鲜（<12h 且通过数 ≥15）时 CI 不覆盖主资产（归实测集）；陈旧时 CI 兜底发布候选集到主资产，订阅永不枯竭。候选集以 `candidates_*` 固定名副本常驻备查；
5. **熔断**：沙箱自身网络故障 / mihomo 异常 / 低通过率时绝不发布主资产，仅更新报告。

详见 `docs/cn_probe.md`（运行手册）。救援队列与进化引擎（源级中国通过率评分、静态门槛自学习）见文末「Phase 2」。

## 订阅源自动发现与淘汰

1. **发现（多渠道）**：每次运行除在 GitHub 搜索外，还会从 `channels.json` 配置的多渠道搜集订阅源：
   - **GitHub 搜索**：用 Actions 自带 `GITHUB_TOKEN`（只读）搜最近 3 天有更新的相关仓库，查找 `clash.yaml / mihomo.yaml / list.meta.yml / proxies.yaml` 等文件（每次最多查看 20 个仓库、新增 10 个候选）。
   - **Telegram 频道**：抓取 `https://t.me/s/<频道>` 的公开消息，提取订阅链接与节点分享链接（带 3s 限流，失败自动跳过）。
   - **网页**：抓取配置的网页，提取其中的订阅链接与节点链接（博客 / 聚合页 / 论坛帖等）。
   - **手工静态源**：`channels.json` 的 `static_sources` 里粘入从任意渠道搜集到的源，等同手工源**直接转正**为正式源，无需试用期。
   所有渠道发现的 URL 都经过同一套验证（拉取并解析出 ≥20 个节点）与候选→试用期→淘汰流程，天然继承蜜罐检测、配额与上限防护。
2. **仓库信誉**：fork、已归档、创建不足 7 天、0 星且新建、名称/简介含推广/博彩等垃圾词的仓库直接拒绝；星数少（<5）或较新（<60 天）的仓库试用期从 3 次延长到 5 次。
3. **试用期**：候选源需**连续 N 次**同时满足：通过静态门槛且 TCP 存活节点 ≥5，且其中 ≥4 个是正式源里没有的新节点，才能晋升；每次最多晋升 2 个。连续 3 次拉取失败、或 16 次仍未达标则拒绝。候选源节点排序额外加惩罚。
4. **淘汰**：正式源连续 4 次（约 24 小时）拉取失败、连续约 4 天没有独有存活节点、蜜罐结构/篡改比例过高，自动移除；被移除的源 30 天内不会被重新发现。
5. **上限**：正式源最多 30 个，超出时按「拉取成功率 + 独有贡献」排序淘汰末尾（手工源有少量加分）。

## 多渠道搜集配置（Telegram 等）

编辑仓库根目录 `channels.json`（默认空，需自行按渠道填充）：

```json
{
  "enabled": true,
  "telegram": ["FreeNodes", "v2rayng_free"],          // Telegram 频道用户名（不含 @，程序抓取 t.me/s/<用户名>）
  "web": ["https://example.com/free-nodes.html"],      // 监控的网页 URL
  "static_sources": [                                  // 手工维护的订阅源（直接转正为正式源）
    "https://raw.githubusercontent.com/xxx/yyy/main/clash.yaml"
  ]
}
```

- 多渠道搜集的订阅源 URL 与 GitHub 发现完全共享晋升/淘汰机制；搜集到的原始节点链接
  （`vmess://` / `vless://` / `trojan://` / `ss://`）则写入 `collected_nodes.txt`，主流程
  会将其 ingest 后经过**同样的静态门槛 + 死活闸门**清洗，仅白名单协议且通过拨测的节点进入输出。
- 关闭方式：工作流环境变量 `PROXYSUB_DISCOVERY: '0'`，或在 `channels.json` 设 `"enabled": false`。
- 推荐只填写你信任、确实发布订阅链接的频道；所有外部抓取均带超时与限流，失败不影响主流程。

## 防蜜罐措施

- **地址校验**：服务器为私有/保留/回环/CGNAT/组播 IP、非法主机名、非法端口直接丢弃；域名解析到这些地址的也丢弃。
- **黑名单**：`honeypot_blocklist.json` 支持域名后缀、IP、网段、关键词；本地探测（可选）中发现篡改的节点服务器会自动加入（14 天后过期）。
- **中国路径优先**：区域配额向港/日/新/台/韩倾斜，美国占比 ≤25%；排序对亚洲加分、对美国出口加延迟惩罚。
- **源结构检测**：某个源的节点 ≥60% 集中在同一个 /24（或 ≥85% 在同一 /16），或同一密码/UUID 被大量不同服务器共用，标记可疑；候选源直接拒绝。
- **分散度**：同一凭证最多 6 个节点。
- **寿命加权**：跨天存活（TCP）权重高，长期存活的 hy2/reality 额外加成——服务器长期在线是质量最可靠的静态代理信号。
- **死活闸门（核心）**：mihomo 通过节点发起真实代理请求（华为/vivo/gstatic 等 generate_204 检测 URL），无法完成代理的僵尸节点（凭证过期/后端下线/CDN 空壳）直接淘汰，无论其 TCP 端口是否开放。
- **TCP 存活检查**：作为拨测前的廉价预筛（TCP 不通直接跳过拨测）；测得的 RTT 不进入节点名称、评分贡献设上限，不代表国内真实延迟。

## 反爬与防搜索（anti-crawl）

> **当前状态：已开启**（`anti_crawl.json` 的 `"enabled": true`，`publish_release: true` 永久地址模式）。
> 固定名 raw 地址为诱饵内容；真实订阅经滚动 Release 分发，地址永久不变（见页首）。
> 关闭方式：`"enabled": false`，或工作流环境变量 `PROXYSUB_ANTI_CRAWL: '0'` 临时强制关闭。

public 仓库的订阅文件对任何人可读，且会被「按固定路径扫描」的爬虫 / 聚合站收录。在 `anti_crawl.json` 设 `"enabled": true` 后：

1. **诱饵分流**：固定名订阅文件（`clean_clash.yaml` 等）改写为**诱饵内容**——大量形态合法但必定不可用的诱饵节点（名称带 `[BAIT]` 标记，服务器指向 RFC 保留域 `.invalid`，任何客户端都无法连通；混合 VLESS-Reality / Trojan / Hysteria2 三种形态，与真实输出完全同构）。按固定路径扫描 raw 的爬虫，扫到的永远是诱饵。
2. **永久订阅地址（滚动 Release，默认模式 `publish_release: true`）**：真实输出由工作流发布到仓库的滚动 GitHub Release（tag 可配，默认 `sub`），**资产名为首次生成的随机字符串**（如 `p_5d0dc339da_c.yaml`，之后永久不变）。订阅地址形如：
   ```
   https://github.com/SHUNZI88/proxysub/releases/latest/download/p_5d0dc339da_c.yaml
   ```
   **一次复制，永久有效，无需任何手动维护**；且该路径不在任何 raw 扫描器的目标清单上，也不从任何公开文件链接（地址只在 Actions Step Summary 可见）。
3. **诱饵回流检测**：若某个订阅源收录了我们生成的诱饵节点（指纹比对，在静态门槛与 DNS 之前完成），该源会被标记 `bait_reuse`——**候选源直接拒绝、正式源自动淘汰**（`redistributes_bait`）。爬虫转载诱饵即自我暴露。
4. **robots.txt**：生成 `Disallow: /` 声明，劝阻合规爬虫。
5. **真实订阅地址只写入 GitHub Actions 的 Step Summary**（仅仓库所有者可见），不进入任何公开文件。
6. 工作流加固：`workflow_dispatch` 限定**仅仓库所有者**可手动触发（public 仓库默认任何人可点）；失败告警 Issue 默认关闭（`ALERT_ISSUE: '1'` 可重开）。

> 备选模式：`"publish_release": false` 退回**文件名轮换**（真实输出写 `clean_clash.<token>.yaml`，每 `rotate_days` 天更换、过期自动删除）——适合「分享出去的链接应过期」的场景，但订阅地址需定期更新。默认不启用。

### 效果边界（重要，请如实知悉）

| 措施 | 防住 | 防不住 |
|---|---|---|
| 诱饵分流 + Release 永久地址 | 按固定路径扫描 raw 的大众爬虫 / 聚合站（扫到的只有诱饵） | 会去读 Releases 页 / 解析 `anti_crawl.json` 的针对性爬虫；人工分析 |
| 诱饵回流检测 | 转载诱饵的源被自动拒绝/淘汰 | 只爬不用、或清洗掉诱饵后再转载的爬虫 |
| robots.txt | 遵守 robots 规范的合规爬虫 | 不遵守的爬虫；GitHub 站内搜索与代码索引 |
| owner-only dispatch | 陌生人手动触发工作流 | 定时触发本身 |
| 失败告警关闭 | Issues 页暴露运行信息 | — |

- **public 仓库无法从根本上避免被检索**：GitHub 仓库页/README/代码会被站内搜索与外部搜索引擎索引，个人仓库内的文件（含 robots.txt）不能控制这一点。
- 永久地址的随机资产名记录在公开的 `anti_crawl.json` 中——这是「提高门槛」而非「加密保密」。如要求资产名完全不落仓库，可用仓库 secret 传入环境变量 `PROXYSUB_ASSET_NAMES`（JSON，如 `{"clean_clash.yaml":"my_name.yaml"}`），指定后程序不再生成也不再写入配置。
- 滚动 Release 页面本身是公开的（任何人可看到资产存在），但资产名为随机字符串，且发布动作每轮静默更新，对「扫路径」的自动化爬虫不可见。
- 开启反爬后，**README 顶部的订阅地址表会指向诱饵文件**，请按需删除或改写该段（真实永久地址在 Actions Step Summary，不会变）。
- **要彻底隐藏**（搜索/索引/raw 直链全部失效）：将仓库转为 **private**。代价：raw 订阅直链与 Release 资产对 private 仓库都需要 token 才能下载，客户端无法直接订阅，需改用 GitHub API 带 token 下载或 Actions artifact；外部心跳 `repository_dispatch` 不受影响（本就用 PAT），且免费账户 private 仓库每月有 2000 分钟 Actions 额度（本工作流日均 4 次、单次数分钟，远低于上限）。

## 工程化

- **原子化 JSON 读写**（`safe_io.py`）：所有状态文件（sources.json / survival.json / source_stats.json 等）通过「临时文件 + fsync + `os.replace` + filelock」写入，进程中断不会产生截断/空文件；损坏文件自动备份为 `.corrupt` 并自愈重启，不会导致流水线崩溃。
- **工作流健壮性**：
  - 提交步骤**逐文件** `git add`（任一文件如 `collected_nodes.txt` 缺席不影响其余文件）——曾经的坑：整单 `git add a b c ... || true` 是原子操作，一个未跟踪文件的缺席让整个 add 失败被吞掉，导致 survival/source_scores 等状态文件连续多轮停更（2026-10 质量回归根因之一）；
  - **发布先于提交**：滚动 Release 发布失败时绝不先提交——否则仓库状态已前进而永久地址仍指向旧资产，下一轮基于失同步状态选样；
  - **发布前诱饵 sanity 检查**：`.publish/` 下文件为空或含诱饵标记（bait_host / `[BAIT]`）时发布步骤直接失败，永久地址不可能再服务纯诱饵内容；
  - 无文件变动时通过 `git diff --staged --quiet` 安全跳过提交（不会非零退出报错）；依赖通过 `requirements.txt` 固定安装并启用 pip 缓存。
- **回归测试**：`tests/` 覆盖订阅解析、指纹去重（嵌套参数变更不被误判）、地区识别（Russia 不误判为美国等边界用例）、协议门槛、原子写入（并发/截断/失败场景）、多渠道搜集、反爬（诱饵形态/永久地址/轮换/回流检测）、评分函数全分支（含 pyflakes「未定义名字」静态门禁，防拆模块后漏 import 常量——2026-10-13 daily 崩溃事故的回归防线）。CI 在每次代码变更时自动运行（`.github/workflows/tests.yml`）。

## 安全加固（2026-10-14 安全评估整改）

针对外部安全评估发现的问题已完成整改，测试与 CI 门禁同步固化：

| 编号 | 问题 | 整改 |
|---|---|---|
| F1 | 多渠道/源抓取存在 SSRF 面（CWE-918） | 新增 `net_safety.py`：所有外部可控 URL（channels 三处发现 + `fetch_one` + sources_manager 新源试用）统一走 `safe_http_get`——协议白名单、DNS 落点校验（私网/回环/链路本地含 169.254 元数据/组播拦截）、重定向目标**逐跳重新校验**（防公网→内网穿透）。28 项专项测试 |
| F2 | 依赖版本范围过宽、无审计（CWE-937） | `requests>=2.32`（避开 CVE-2024-35195）、`PyYAML>=6.0.1`、pytest 去掉大版本上限（避开 PYSEC-2026-1845）；CI 增加 `pip-audit` 步骤，本地复验 `No known vulnerabilities found` |
| F3 | mihomo 二进制仅校验 ELF 魔数（CWE-345） | 下载后先 `sha256sum -c` 校验 pin 的已知完整包 hash（基线取自官方 Release API 元数据），再解压 + ELF 复核。升级 `MIHOMO_VERSION` 必须同步 hash，否则工作流故意失败 |
| F4 | 资产名未做路径穿越校验（CWE-22） | `asset_name` 出口统一 `safe_asset_name` basename 校验（env override 与持久化值两条路径）；`stale_outputs` 清理限定在 `.publish/` 与仓库根级，`../`/绝对路径一律不删 |
| F5 | 工作流 token 过度授权（CWE-250） | `daily-update.yml` 拆两个 job：**update**（`contents: read`，跑抓取/拨测/生成，不碰外部输入的写操作）+ **publish**（`contents: write` + `issues: write`，只处理本仓生成文件）；生成物经 actions artifact 传递。GITHUB_TOKEN 无法 step 级提权，故按职责拆 job 而非声明式收紧 |

本地运行测试：

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## 手动控制

- 临时禁用云端真实流量拨测（仅调试用，输出会混入僵尸节点）：环境变量 `PROXYSUB_DISABLE_PROBE=1`。
- 本地运行真实探测：配置 `MIHOMO_BIN` 指向 mihomo 可执行文件（不设置禁用变量即可）。
- 关闭自动发现：工作流环境变量 `PROXYSUB_DISCOVERY: '0'`。
- 手工加源：在 `sources.json` 的 `official` 里加一条 `{"url": "...", "origin": "manual"}`。
- 多渠道加源：编辑 `channels.json`，在 `telegram` / `web` / `static_sources` 填入对应渠道（详见上文「多渠道搜集配置」）。
- 开启/关闭反爬：编辑 `anti_crawl.json` 的 `"enabled"`（默认 false）；或工作流环境变量 `PROXYSUB_ANTI_CRAWL: '0'` 临时强制关闭。开启后**永久订阅地址**（滚动 Release，不会变）见 Actions 运行页的 Step Summary。
- 禁止某仓库：在 `deny_repos` 里加 `owner/repo`。

### 局限（请知悉）

- **无法保证 100% 无蜜罐**。静态门槛只能保证结构与参数合规；如果节点运营者如实转发流量、只在后台记录，从外部无法区分。免费节点请勿用于登录重要账户、支付、传输敏感信息；HTTPS 能保护内容，但运营者仍能看到访问的域名和你的 IP。
- 云端探测在美国进行，「美国能通、国内不通」的节点仍会混入输出——这部分由本地客户端 url-test 二次筛除。
- 白名单协议的活节点总量有限时，最终列表可能低于 100 个下限：宁缺毋滥，绝不回填未通过死活闸门的 TCP 存活僵尸节点。
- 没有使用 ASN 数据库，「同一运营者」只用 /24、/16 和共用凭证近似判断；Cloudflare 优选 IP 类节点可能被误判为集中。
- GitHub 搜索有频率限制，代码搜索对 `GITHUB_TOKEN` 可能不可用（失败时自动跳过，只用仓库搜索）。
