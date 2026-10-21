# proxysub

> 🤖 **AI 协作者必读**：本仓库有强制规则文件 **[`AGENTS.md`](AGENTS.md)**（摘要见 [`.github/copilot-instructions.md`](.github/copilot-instructions.md)）。
> 两条铁律：**① 先验新鲜度，再采信**（任何输入先看生成时间与有无更新版本）；**② 断言"没有凭据"前，必须查 `/root/.github_pat` + 项目文档 + 环境变量 三处**。
> 另：**每次会话请检查 [`docs/protocol_weights_todo.md`](docs/protocol_weights_todo.md)**（协议权重化评估的待办看板）。
> 立此规则的原因（2026-10-15 事故复盘）见 `AGENTS.md` 开头。

**高纯度订阅清洗与结构规范化工具**：每 6 小时（北京时间 0/6/12/18，GitHub Actions 定时 + 可手动 `workflow_dispatch`）自动抓取公开免费订阅源，经「协议白名单 + 关键参数校验 + 深度指纹去重 + 防蜜罐静态检测」清洗后，输出干净、格式标准、结构统一的节点列表。

> **本仓库已开启反爬（anti-crawl）**：固定名 raw 地址（`.../main/clean_clash.yaml` 等）现为**诱饵内容**，请勿订阅。
> 真实订阅通过滚动 GitHub Release 分发，地址形如
> `https://github.com/SHUNZI88/proxysub/releases/download/sub/p_<随机资产名>`，
> **永久有效、无需更换**；具体地址仅仓库所有者可见（Actions 运行页 Step Summary），不在此公开悬挂。
> 机制与效果边界详见「反爬与防搜索」一节及 [`docs/anti_crawl_design.md`](docs/anti_crawl_design.md)。

### 运行态速览（三行，先读这个）

| 项 | 当前值 |
|---|---|
| **订什么** | Release 永久地址 `.../download/sub/p_<随机名>_c.yaml`（随机名见 Actions Step Summary，不在此悬挂）；**勿订**固定名 raw（诱饵） |
| **最后中国实测** | 见 Release `verification_report.json` 的 `generated_at` 字段（沙箱 09:18 / 16:18 北京窗口产出） |
| **最后 CI 抓取** | 见 `stats.md` 顶部时间戳（CI 每 6h：00:17/06:17/12:17/18:17 UTC+8 名义） |

> **指标分离（重要）**：`stats.md` = **美西候选健康度**（CI 侧，未经中国实测）；
> 订阅主列表节点数 = **中国实测通过集**（沙箱侧，以 `verification_report.json` 为准）。
> 二者**不可混读**——主列表厚度看报告，不代表美西候选规模，反之亦然。

### 多格式订阅地址（反爬开启后，固定名地址为诱饵，仅列出格式对应关系）

| 格式 | Release 资产名规则 | 适用客户端 |
|---|---|---|
| Clash / mihomo | `releases/download/sub/p_*_c.yaml` | FlClash、Clash Verge Rev、mihomo |
| 仅 proxies 段 | `releases/download/sub/p_*_p.yaml` | 客户端 `proxy-providers` 引用 |
| sing-box | `releases/download/sub/p_*_s.json` | sing-box（outbounds 列表） |
| v2ray 分享链接 | `releases/download/sub/p_*_v.txt` | v2rayN、NekoBox（base64 整段导入） |
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
| `filter_clash.py` | 编排入口：`main()` 仅 83 行阶段序列（抓取 → 静态门槛 → 两阶段探活/拨测 → 打分 → 命名/分组 → 持久化/发布），具体逻辑拆为 10 个命名阶段函数（结果经 `@dataclass` 容器传递），可单测；底层能力分散到下列模块（直接 `python filter_clash.py` 运行方式不变） |
| `common.py` | 公共层（架构叶子，无循环依赖）：指纹/解析/静态过滤/协议门槛等纯函数（配置常量自 P1-2 起迁至 `config.py`） |
| `config.py` | 配置层（架构最底层叶子，仅依赖标准库）：全部可调常量——区域规则/配额、协议白名单与奖惩参数、超时与并发旋钮、输出/状态文件名、探测 URL 与配额；改参数只动这一处 |
| `probe.py` | 探测层：TCP/QUIC 存活检查与 mihomo 真实拨测（依赖 common + config） |
| `score.py` | 评分层：协议分层、中美路径惩罚、跨天存活与历史稳定性（依赖 common + config） |
| `output.py` | 输出层：分享链接 / sing-box 转换与多格式文件、健康报告（依赖 common + config + score） |
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
| `requirements.txt` | Python 依赖（requests / PyYAML / filelock / pytest / pytest-cov / pyflakes） |
| `scripts/doctor.py` | **上手自检（只读）**：fork 后 / 提 Issue 前跑 `python3 scripts/doctor.py`——依赖版本、配置 JSON 可解析性与结构一致性（反爬开启必须配 Release 资产名、正式源非空等）、工作流 YAML、mihomo 可发现性、`.corrupt` 自愈备份；退出码 0 = 通过（可含警告）、1 = 有错误。输出可直接贴进 Issue 表单 |
| `scripts/dashboard.py` | **运行态面板生成**：读 `probe_history.jsonl` 产出单文件 HTML（内联 SVG 趋势图 / 通过构成堆叠条 / 源贡献表，无 JS 无外部依赖）；定时任务将其发布到独立滚动 Release（tag `status`），详见「运行态观测」一节 |
| `scripts/cn_probe.py` | **中国出口实测轮**（沙箱侧入口）：轮次闸门 → 预算裁剪 → mihomo 拨测 → **证据收集**（单次切组 8 路并行：出口取证 + AI 可达性探测 chatgpt/claude/gemini/copilot/openai_api 状态码，证据+排序信号，不构成闸门）→ 通过者按「AI 可用优先」排序覆盖发布主资产 + `verification_report.json`，详见「中国出口实测接力」一节与 `docs/cn_probe.md` |
| `scripts/cron_watchdog.py` | **cron 看门狗**：每 2h 巡检 cron 守护进程（死亡自动拉起）与实测连续性（漏跑 >8h 自动补测），退出码恒 0，详见「中国出口实测接力」第 6 条 |
| `scripts/install_cron.sh` | **cron 槽位幂等安装**：沙箱重建 / cron 丢失后一条命令恢复实测轮 + 看门狗两条定时条目（自检条目数，防重复） |
| `.coveragerc` | 覆盖率门禁配置：语句覆盖 `fail_under=80`；计量范围为库模块（`tests/`、`scripts/` 运维脚本、monitor 一次性脚本按配置排除并注明理由） |
| `tests/` | 单元 + 集成测试（710 项）：指纹去重、地区识别、静态门槛、订阅解析、原子写入、拨测样本选择、多格式输出、源评分、cn/AI 源级生命周期（淘汰/晋升/配额倾斜/熔断）、cron 看门狗、AI 可达性探测（状态码捕获/分级判据/AI 优先排序）；`test_main_pipeline.py`（mock 边界的 main() 全链路集成）+ `test_stage_functions.py`（阶段函数单测，配额/回填/加成等分支）+ `test_probe_mihomo.py`（mihomo 进程编排 mock）+ `test_sources_lifecycle.py`（源生命周期 mock）+ `test_dashboard.py`（面板解析容错 / 渲染 / HTML 转义注入防护） |

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
2. **沙箱实测**：定时任务（北京 01:18/07:18/13:18/19:18 每日 4 轮，各接住 1 小时前的 CI 待测文档）运行 `scripts/cn_probe.py`——**轮次闸门**（与上轮报告 `tested_round` 比对：新轮次立即测，年龄不是新鲜信号；等不到至多 20min，未测轮次顺延至下一实测轮、不丢失）→ **预算裁剪**（按剩余 1800s 预算折算节点上限、优先级 carryover>pending>rescue，硬保任务超时不击穿；未测节点由 CI 下轮待测文档自然再现）→ mihomo 中国出口拨测 → **证据收集**（单次切组 8 路并行：出口 IP/地区取证 + AI 可达性探测；任何 HTTP 响应含 403/401 算可达，api.openai.com 非 403 算 API 层可用——沙箱诊断发现约半数已发布节点完全不通 AI，既有闸门对此盲视）→ 通过者按「AI 可用优先 + 双 vantage 强者 + 低延迟」覆盖发布为主资产（**订阅永久地址不变**）→ 发布 `verification_report.json`（含 `counts.ai` 统计与逐节点证据）；
3. **滚动携带**：每轮测试集含上一轮验证集，通过的留、败的汰（免费节点寿命以小时计，自清洁）；通过数 <15 时保上轮验证集不动；
4. **所有权切换**：验证报告新鲜（<24h 且通过数 ≥15，或最近一次有效发布 <24h 且通过数 ≥15）时 CI 不覆盖主资产（归实测集）；陈旧时 CI 兜底发布候选集到主资产，订阅永不枯竭。候选集以 `candidates_*` 固定名副本常驻备查；
5. **熔断**：沙箱自身网络故障 / mihomo 异常 / 低通过率时绝不发布主资产，仅更新报告。
6. **看门狗保活**（2026-10-20 事故后固化）：`scripts/cron_watchdog.py` 每 2h 巡检——cron 守护进程死亡自动拉起、漏跑（>8h 无活动）自动补测；`scripts/install_cron.sh` 幂等恢复全部 cron 槽位。与云端自动化补跑、CI 兜底共同构成四层触发保障，详见 `docs/cn_probe.md` §8。

详见 `docs/cn_probe.md`（运行手册）。实测数据经进化引擎反哺 CI：节点级中国稳定性加成、源级中国通过率评分（淘汰/晋升/拨测配额倾斜，见下文「订阅源自动发现与淘汰」）、静态门槛自学习（延迟上限按实测分布收紧，含历史审计）。

## 订阅源自动发现与淘汰

1. **发现（多渠道）**：每次运行除在 GitHub 搜索外，还会从 `channels.json` 配置的多渠道搜集订阅源：
   - **GitHub 搜索**：用 Actions 自带 `GITHUB_TOKEN`（只读）搜最近 3 天有更新的相关仓库，查找 `clash.yaml / mihomo.yaml / list.meta.yml / proxies.yaml` 等文件（每次最多查看 25 个仓库、新增 15 个候选；16 个查询词含 clashnode / nodefree / 免费机场 / 节点分享等中文社区主流命名，按 6h 槽位轮换、24h 全覆盖——2026-10-20 扩容：实测候选池曾枯竭至 2 个，免费节点池 97% 死亡率下只能扩大源头吞吐；「免费机场」等词命中的招商站由仓库信誉的垃圾词过滤拒收）。
   - **Telegram 频道**：抓取 `https://t.me/s/<频道>` 的公开消息，提取订阅链接与节点分享链接（带 3s 限流，失败自动跳过）。
   - **网页**：抓取配置的网页，提取其中的订阅链接与节点链接（博客 / 聚合页 / 论坛帖等）。
   - **手工静态源**：`channels.json` 的 `static_sources` 里粘入从任意渠道搜集到的源，等同手工源**直接转正**为正式源，无需试用期。
   所有渠道发现的 URL 都经过同一套验证（拉取并解析出 ≥20 个节点）与候选→试用期→淘汰流程，天然继承蜜罐检测、配额与上限防护。
2. **仓库信誉**：fork、已归档、创建不足 7 天、0 星且新建、名称/简介含推广/博彩等垃圾词的仓库直接拒绝；星数少（<5）或较新（<60 天）的仓库试用期从 3 次延长到 5 次。
3. **试用期**：候选源需**连续 N 次**同时满足：通过静态门槛且 TCP 存活节点 ≥5，且其中 ≥4 个是正式源里没有的新节点，才能晋升；每次最多晋升 2 个。连续 3 次拉取失败、或 16 次仍未达标则拒绝。候选源节点排序额外加惩罚。若候选源已有实测实证，按实证**优先晋升**：AI 实证（`ai_tested ≥ 6` 且 `ai_api ≥ 1`）排最前，其后是中国实测正向实证者按 Wilson 95% 下界降序——用户核心诉求是「可用于 AI 连接的节点」，AI 高产源应优先补入正式源池。
4. **淘汰**：正式源连续 4 次（约 24 小时）拉取失败、连续约 4 天没有独有存活节点、蜜罐结构/篡改比例过高，自动移除；被移除的源 30 天内不会被重新发现。**中国实测维度**（与 CI 侧判据并联，任一命中即淘汰）：沙箱拨测显示某源贡献的节点中国可用率 Wilson 95% 下界 < 5%（样本 ≥20）且**连续 2 轮**如此，自动移除——三重保底：手工源豁免、单轮最多汰 3 个、淘汰后正式源不少于 6 个；无实证（缺数据/样本不足/数据超过 48h）一律不干预。**有效性守卫**（2026-10-21）：零独有（代理指标）淘汰对有充足且新鲜中国实效实证（下界 ≥ 5%）的源豁免，记入运行日志审计行（`源保留（零独有守卫）`）——原则：源的生命周期由节点有效性反哺，代理指标只配做观察信号；无实证时守卫自动失效（无效源仍由拉取失败/零真实通过/cn 低产通道淘汰，不漏网）。
5. **上限**：正式源最多 30 个，超出时按「拉取成功率 + 独有贡献」排序淘汰末尾（手工源有少量加分）。
6. **拨测配额倾斜**：有实测实证的源按实证调整其占用拨测预算的额度——中国实测低产源（下界 < 5%）减半、高产源（下界 ≥ 30%）加倍；AI 高产源（`ai_api/ai_tested` 下界 ≥ 40%，样本 ≥6）按 1.5 倍倾斜（**无低产档**：AI 不可达≠节点死亡，减配会饿死通用节点供给）；两侧倾斜**相乘后封顶 2 倍**（单源最多拿 2 倍配额，防霸占拨测预算）；单源基础上限 240，无实证的源不受影响。

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

public 仓库的订阅文件对任何人可读，会被「按固定路径扫描」的爬虫 / 聚合站收录。开启反爬后：

- **固定名 raw 地址（`clean_clash.yaml` 等）为诱饵内容**，请勿订阅——按固定路径扫描的爬虫只会
  扫到不可用的诱饵。
- **真实订阅经滚动 Release 分发**，地址永久不变（见页首「怎么订阅」），仅在 Actions 的 Step
  Summary 显示。
- **转载诱饵的订阅源会被自动拒绝 / 淘汰**（诱饵回流检测）。

**能力边界（请如实知悉）**：反爬是「提高发现门槛」而非「彻底隐藏」。public 仓库无法从根本上
避免被站内搜索 / 外部搜索引擎索引，针对性的（会读 Releases 页的）爬虫亦可绕过。**要彻底隐藏
需将仓库转为 private**（代价：客户端无法直接订阅 raw 直链）。

> 机制细节（诱饵形态、永久地址与资产名、回流检测、robots、效果边界逐项、开关与运维）见内部文档
> [`docs/anti_crawl_design.md`](docs/anti_crawl_design.md)。

## 工程化

- **原子化 JSON 读写**（`safe_io.py`）：所有状态文件（sources.json / survival.json / source_stats.json 等）通过「临时文件 + fsync + `os.replace` + filelock」写入，进程中断不会产生截断/空文件；损坏文件自动备份为 `.corrupt` 并自愈重启，不会导致流水线崩溃。
- **工作流健壮性**：
  - 提交步骤**逐文件** `git add`（任一文件如 `collected_nodes.txt` 缺席不影响其余文件）——曾经的坑：整单 `git add a b c ... || true` 是原子操作，一个未跟踪文件的缺席让整个 add 失败被吞掉，导致 survival/source_scores 等状态文件连续多轮停更（2026-10 质量回归根因之一）；
  - **发布先于提交**：滚动 Release 发布失败时绝不先提交——否则仓库状态已前进而永久地址仍指向旧资产，下一轮基于失同步状态选样；
  - **发布前诱饵 sanity 检查**：`.publish/` 下文件为空或含诱饵标记（bait_host / `[BAIT]`）时发布步骤直接失败，永久地址不可能再服务纯诱饵内容；
  - 无文件变动时通过 `git diff --staged --quiet` 安全跳过提交（不会非零退出报错）；依赖通过 `requirements.txt` 固定安装并启用 pip 缓存。
- **编排主线可测化（P1-1）**：`filter_clash.main()` 原为 685 行不可测巨函数，已拆为 83 行薄编排 + 10 个命名阶段函数（`discover_and_fetch` / `static_filter_stage` / `liveness_stage` / `real_probe_stage` / `per_source_metrics` / `score_candidates` / `select_final` / `name_and_isolate` / `build_clash_config` / `_persist_stage`），阶段间经 `@dataclass` 结果容器传递多产出。重构遵循「安全网先行」：先建 mock 集成测试（变异验证：故意注入缺陷须被抓到）再动结构。
- **回归测试**：`tests/` 覆盖订阅解析、指纹去重（嵌套参数变更不被误判）、地区识别（Russia 不误判为美国等边界用例）、协议门槛、原子写入（并发/截断/失败场景）、多渠道搜集、反爬（诱饵形态/永久地址/轮换/回流检测）、评分函数全分支、fetch 编码决策（iso-8859-1→apparent→utf-8 三级回落）、探测响应契约、源结构聚类、渠道候选校验（含 pyflakes「未定义名字」静态门禁，防拆模块后漏 import 常量——2026-10-13 daily 崩溃事故的回归防线）。
- **覆盖率门禁（P1-1d）**：CI 每次代码变更跑 `pytest --cov`，库模块语句覆盖 **≥80%** 未达标即阻断合入（`.coveragerc` `fail_under=80`）。当前 **544 项测试、总覆盖 91.59%**（`filter_clash.py` 88%）。
- **低覆盖模块补齐（P1-2a）**：`probe.py` 的 mihomo 进程编排（`_probe_through` 各出口/篡改/TLS 中间人/CF 拦截分支、`_mihomo_batch` 进程早退与 controller 未就绪、`mihomo_probe` 大批量二分重试）与 `sources_manager.py` 源生命周期（GitHub 限流重试、仓库声誉全 verdict、discover 收录/跳过路径、试用期拒绝与晋升、正式源降级与超额裁剪）已用 mock 全面覆盖，两模块分别达 **99% / 100%**。
- **反馈闭环（产品化）**：Issue 表单模板（订阅质量问题 / 功能建议，默认拒空白 issue 并引导至 README 与健康报告）；`ci-failure` 标签 + 失败自动开 Issue 开关（`ALERT_ISSUE`，默认关闭以守反爬边界）；README「反馈与告警」一节明确订阅者反馈纪律（勿贴私人订阅地址）与维护者三条告警通道（Watch Actions 邮件 / Actions 页订阅 / 自动开 Issue）。
- **上手助手（产品化）**：`scripts/doctor.py` 一条命令自检配置与环境（19 项测试覆盖全部分支），把「fork 后配错 → CI 跑 50 分钟才炸」的反馈路径压缩为本地 1 秒；与反馈闭环联动——Issue 表单引导上报前先跑 doctor 并附输出，「环境-配置」类问题不再来回确认。
- **观测面板（产品化）**：`scripts/dashboard.py` 把每轮拨测审计（`probe_history.jsonl`）渲染为单文件 HTML——通过率趋势折线（内联 SVG）、通过构成堆叠条、源贡献累计表；纯标准库零依赖、无 JS、动态文本全量转义（注入防护 15 项测试钉死）。发布面为独立滚动 Release（tag `status`）：不进 git 历史（每轮变化会淹没订阅更新提交）、与订阅 `sub` Release 职责分离、固定资产名链接永久可收藏。面板失败设 `continue-on-error`——观测件不是关键路径，绝不阻断订阅更新。
- **配置独立（P1-2）**：`common.py` 原为 757 行「常量 + 工具函数」混合体（102 个配置常量），认知负担大。已拆出 `config.py`（287 行，仅依赖标准库的架构最底层叶子）专收全部可调常量——区域规则/配额、协议白名单与奖惩参数、超时/并发旋钮、输出与状态文件名、探测 URL 与配额；`common.py` 瘦身为 502 行纯函数层，按需 `from config import`。调参只动 `config.py` 一处，模块职责单一可读。
- **显式 import（P1-3）**：`filter_clash.py` 原用 `_reexport()` 在运行时把子模块符号动态 `setdefault` 进命名空间——依赖面静态不可见（pyflakes 199 条告警）、漏 import 只在运行期炸 `NameError`（2026-10-13 daily 工作流崩溃根因）。已改为按来源模块的显式 import（5 组、88 个名字），依赖面成为文件内可读清单；`filter_clash.py` 同步纳入「未定义名字」静态门禁，漏 import 在 CI 即失败。

## 安全加固（2026-10-14 安全评估整改）

针对外部安全评估发现的问题已完成整改，测试与 CI 门禁同步固化：

| 编号 | 问题 | 整改 |
|---|---|---|
| F1 | 多渠道/源抓取存在 SSRF 面（CWE-918） | 新增 `net_safety.py`：所有外部可控 URL（channels 三处发现 + `fetch_one` + sources_manager 新源试用）统一走 `safe_http_get`——协议白名单、DNS 落点校验（私网/回环/链路本地含 169.254 元数据/组播拦截）、重定向目标**逐跳重新校验**（防公网→内网穿透）。28 项专项测试 |
| F2 | 依赖版本范围过宽、无审计（CWE-937） | `requests>=2.32`（避开 CVE-2024-35195）、`PyYAML>=6.0.1`、pytest 去掉大版本上限（避开 PYSEC-2026-1845）；`requirements.lock` 带 hash 锁文件（CI 优先 `--require-hashes` 安装，可复现）；CI 增加 `pip-audit` 步骤，本地复验 `No known vulnerabilities found` |
| F3 | mihomo 二进制仅校验 ELF 魔数（CWE-345） | 下载后先 `sha256sum -c` 校验 pin 的已知完整包 hash（基线取自官方 Release API 元数据），再解压 + ELF 复核。升级 `MIHOMO_VERSION` 必须同步 hash，否则工作流故意失败 |
| F4 | 资产名未做路径穿越校验（CWE-22） | `asset_name` 出口统一 `safe_asset_name` basename 校验（env override 与持久化值两条路径）；`stale_outputs` 清理限定在 `.publish/` 与仓库根级，`../`/绝对路径一律不删 |
| F5 | 工作流 token 过度授权（CWE-250） | `daily-update.yml` 拆两个 job：**update**（`contents: read`，跑抓取/拨测/生成，不碰外部输入的写操作）+ **publish**（`contents: write` + `issues: write`，只处理本仓生成文件）；生成物经 actions artifact 传递。GITHUB_TOKEN 无法 step 级提权，故按职责拆 job 而非声明式收紧 |

本地运行测试：

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

## 反馈与告警

**订阅者反馈**：节点不可用 / 订阅异常请开 Issue（已配表单模板，按格式与客户端填报即可）。

> ⚠️ **请勿在 Issue 粘贴你的私人订阅地址**——反爬机制下资产名属敏感信息，公开悬挂会削弱防搜索效果。描述现象用「格式 + 客户端 + 大致节点名」即可（如「Clash 格式，Verge Rev 导入后列表为空」）。

**维护者告警通道**（定时任务失败时如何第一时间知道）：

| 通道 | 配置 | 说明 |
|---|---|---|
| 邮件 / 推送通知 | Watch 本仓库 → Custom → 勾选 **Actions** | GitHub 原生通道，不暴露任何运行信息，**推荐** |
| Actions 页 | 订阅 workflow 通知 | 失败run 出现在 `Daily Clean Clash Subscription` 页 |
| 自动开 Issue | `daily-update.yml` 的 `ALERT_ISSUE` 改 `'1'` | 默认关闭：失败详情公开悬挂与反爬冲突，仅建议短期排查期开启；自动打 `ci-failure` 标签 |

> 2026-10-13 曾发生定时任务失败数小时无人知晓的事故（运行期 `NameError`，CI 红但无告警）——此后 Tests 门禁 + 覆盖率门禁 + 上表告警通道共同构成「失败必被发现」的闭环。

## 运行态观测（Dashboard）

每轮拨测的聚合统计渲染为单文件 HTML 面板（`scripts/dashboard.py`，纯标准库、无 JS、内联 SVG），随定时任务发布到**独立滚动 Release（tag `status`，固定资产名 `dashboard.html`，下载链接永久有效）**——与订阅内容的 `sub` Release 完全分离。面板含四块：

- **关键指标**：最新轮通过率 / 通过数（含较上轮涨跌，涨红跌绿）、累计测试与通过；
- **通过率趋势**：逐轮通过率折线（悬停数据点看该轮明细）；
- **通过构成**：每轮「新测通过 / 救回 / 结转」占测试量比例的堆叠条；
- **源贡献**：最新轮 top 5 源明细 + 全历史累计贡献前 10 源（含最近出现轮次）。

隐私纪律：面板**只含聚合统计**，不含节点内容与订阅地址；源仓库路径本就是公开信息（同 `stats.md` 的公开口径）。本地生成：`python3 scripts/dashboard.py`（输出 `dashboard.html`，浏览器直接打开）。

## 手动控制

- **自检（fork 后 / 改配置后 / 提 Issue 前）**：`python3 scripts/doctor.py`——一条命令检查依赖版本、配置一致性与结构、工作流 YAML、mihomo 可发现性；退出码 0 = 通过（可有警告），1 = 有错误项（附输出提 Issue 可加速定位）。
- 临时禁用云端真实流量拨测（仅调试用，输出会混入僵尸节点）：环境变量 `PROXYSUB_DISABLE_PROBE=1`。
- 本地运行真实探测：配置 `MIHOMO_BIN` 指向 mihomo 可执行文件（不设置禁用变量即可）。
- 关闭自动发现：工作流环境变量 `PROXYSUB_DISCOVERY: '0'`。
- 手工加源：在 `sources.json` 的 `official` 里加一条 `{"url": "...", "origin": "manual"}`。
- 多渠道加源：编辑 `channels.json`，在 `telegram` / `web` / `static_sources` 填入对应渠道（详见上文「多渠道搜集配置」）。
- 开启/关闭反爬：编辑 `anti_crawl.json` 的 `"enabled"`（默认 false）；或工作流环境变量 `PROXYSUB_ANTI_CRAWL: '0'` 临时强制关闭。开启后**永久订阅地址**（滚动 Release，不会变）见 Actions 运行页的 Step Summary。
- **熔断实测源级生命周期**（淘汰/晋升优先/拨测配额倾斜）：编辑 `config.py` 的 `CN_LIFECYCLE_ENABLED = False`（中国实测维度）或 `AI_LIFECYCLE_ENABLED = False`（AI 维度，消费点=晋升优先/拨测倾斜，独立熔断）。置 False 后对应消费点全部退化为改造前行为（无实证 = 不干预），无需回滚代码即可止血。
- 禁止某仓库：在 `deny_repos` 里加 `owner/repo`。

### 局限（请知悉）

- **无法保证 100% 无蜜罐**。静态门槛只能保证结构与参数合规；如果节点运营者如实转发流量、只在后台记录，从外部无法区分。免费节点请勿用于登录重要账户、支付、传输敏感信息；HTTPS 能保护内容，但运营者仍能看到访问的域名和你的 IP。
- 云端探测在美国进行，「美国能通、国内不通」的节点仍会混入输出——这部分由本地客户端 url-test 二次筛除。
- 白名单协议的活节点总量有限时，最终列表可能低于 100 个下限：宁缺毋滥，绝不回填未通过死活闸门的 TCP 存活僵尸节点。
- 没有使用 ASN 数据库，「同一运营者」只用 /24、/16 和共用凭证近似判断；Cloudflare 优选 IP 类节点可能被误判为集中。
- GitHub 搜索有频率限制，代码搜索对 `GITHUB_TOKEN` 可能不可用（失败时自动跳过，只用仓库搜索）。
