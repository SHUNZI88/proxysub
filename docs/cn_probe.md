# 中国出口节点实测（沙箱侧运行手册）

本手册是定时任务「中国出口节点实测轮」的执行依据。脚本 `scripts/cn_probe.py`
与仓库同版本发布，改进脚本即改进实测行为（git pull 即生效）。

## 1. 任务定位

CI（GitHub Actions，美国出口）每轮产出「拟交沙箱待测节点文档」，本任务从
中国出口（湖南机房）实测筛选，通过者覆盖发布为主资产——解决「美国能通、
国内不通」的节点混入订阅的难题。

## 2. 时间安排（北京）与四层触发

| 时刻（CST） | 事件 |
|---|---|
| 00:17 / 06:17 / 12:17 / 18:17 | CI 定时运行（候选集 + 待测文档，cron `17 4,10,16,22 UTC`） |
| 05:18 | 外部心跳触发 CI（保活，`repository_dispatch: external-trigger`） |
| **01:18 / 07:18 / 13:18 / 19:18** | **本任务正式轮**（L1 系统 cron `18 1,7,13,19 * * *`，分别接住 1 小时前的 CI 待测文档） |
| 每 2 小时（:17 分） | **看门狗巡检**（L2，cron `17 */2 * * *`，见 §8） |
| 沙箱休眠期间 | **云端自动化补跑**（L3，WorkBuddy 定时任务，不依赖本机 cron） |

> **窗口演进**：初版 01:02/07:02 落在北京凌晨（沙箱易休眠）→ 2026-10-14 改
> 09:18/16:18 两轮 → 2026-10-19 改**每日 4 轮** 01:18/07:18/13:18/19:18：
> 每轮接住 1 小时前的 CI 产出（pending 文档就绪），轮次密度提升缩短验证陈旧
> 窗口；休眠漏跑由 L2 看门狗补测 + L3 云端补跑兜底。恢复/重建 cron 用
> `scripts/install_cron.sh`（幂等）。
>
> **GitHub 调度延迟**（2026-10-11～13 实测）：定时运行的实际创建时刻比 cron
> 名义时刻晚 18–159 分钟（作业内仅 ~19 分钟，延迟全在调度器排队），CI 实际
> 发布 = 名义时段 +40min～+3h。加之定时任务执行超时上限 1800s，探针不可能
> 在会话内长等——故闸门设计为**轮次比对**（§3 步 2）：新轮次立即测，等不到
> 就测 carryover，**未测轮次顺延至下一实测轮，不丢失**。

## 3. 单轮流程

1. **自检**：沙箱直连探测（baidu / api.github.com）。失败即中止——避免把
   沙箱自身故障误判为节点全失效；
2. **轮次闸门**：下载上轮 `verification_report.json` 取 `tested_round`（已测
   轮次）；下载 `pending_probe.json` 取 `round_id`——不同即新轮次，**立即测**
   （文档只是节点清单，活性由实时拨测决定，年龄不是新鲜信号）；相同则轮询
   等待新轮次至多 **20 分钟**（受任务 1800s 超时约束）；等不到则仅测
   carryover——未测轮次顺延至下一实测轮，不丢失。首轮无报告时任何现有
   文档都算新轮次；
3. **测试集** = carryover（当前主资产，滚动携带+自清洁）∪ pending（待测
   文档）∪ rescue（救援文档，CI 淘汰但静态可行的节点）；
4. **预算裁剪**（截止时间感知）：按剩余预算（1800s − 预留 300s − 已耗时）
   折算可测节点上限 `int(预算 ÷ 1.0s/节点)`，按**优先级填充**裁剪——
   carryover 最高优先、pending 次之、rescue 最低（本轮 0/100 通过，产能低）；
   未测节点由 CI 下轮待测文档从当前候选池重新生成时再现，**不丢失**。
   预算耗尽（上限=0）时返回空集，main() 据此跳过本轮、保留上一轮已发布
   验证集，硬保 1800s 任务超时不被击穿。见 §6。
5. **拨测**：mihomo external-controller delay API，`generate_204`
   （HTTPS+204 双信号），12 并发，失败重试一次；
6. **证据收集**（2026-10-21 合并，任务#91）：通过节点**单次切组 + 8 路
   并行**收集出口证据（cip.cc → ipip → ip-api，取首个成功）与 AI 可达性
   （chatgpt/claude/gemini/copilot/openai_api 状态码）；统一预算 120s
   （`EVIDENCE_BUDGET_S`），仅留痕、不构成闸门。合并前是两个顺序循环
   （各 120s、各覆盖一半节点）；单请求有线程级硬超时（GEO socket 5s /
   AI 8s，硬截断 +2s）——urllib socket timeout 是每次 recv 超时，龟速
   节点上的滴流响应实测可拖到 24s+（见 §9.4）；
7. **AI 可达性判据**：任何 HTTP 响应（含 403/401/302）算可达，
   api.openai.com 非 403 算 API 层可用；**不构成闸门**——AI 不可达的
   节点仍是可用代理，仅排序沉底。判据与已知坑见 §9；
8. **合并发布**：通过节点按「AI 可用性 > 双 vantage 强者 > 延迟」排序
   （订阅顺序即用户可见性顺序），构建 clash/sing-box/v2ray/proxies-only
   四格式，覆盖发布到主资产（p_* 随机名，**订阅永久地址不变**），并发布
   `verification_report.json`；
9. **轮转**：本轮消费的待测文档备份为 `pending_probe.prev.json`。

## 6. 1800s 预算加固（截止时间感知测试集上限）

定时任务超时硬顶 1800s。本轮实测 1193 节点端到端 902s（拨测约
0.62s/节点）；但轮询等待最多 20min（1200s）会挤占预算，最坏
1200+902=2102s **击穿超时**。措施：

- 常量：`TASK_BUDGET_S=1800`、`PUBLISH_RESERVE_S=300`（2026-10-21 重算：
  真实流量 ~24s + 证据收集 ≤120s + 多格式输出/发布/收尾 ~60s ≈ 204s，
  合并证据段后由 360s 降回 300s）、`PER_NODE_S=1.2`（实测 0.62s/节点
  取悲观 ×2；2.0 过度保守曾误裁 413 节点，见 §8.1）；
- `cap_test_set(nodes, budget_s)`：按优先级填充裁剪，保留集规模恒
  `≤ int(budget_s / PER_NODE_S)`，硬保不超时；
- 优先级：carryover > pending > rescue（rescue 产能低、未测节点由 CI 下轮
  文档自然再现，不丢失）；
- 预算耗尽（上限=0）返回空集 → main() 跳过本轮、保留上一轮已发布验证集；
- 实测推演（悲观 1.0s/节点）：常态（无轮询）1193 节点不裁剪，总耗时约
  1234s；最坏（轮询占满 20min）裁剪至 290 节点，总耗时恒 ≤1800s。

## 4. 熔断与降级

| 情况 | 行为 |
|---|---|
| 沙箱自身网络不可用 | 中止，不发布（退出码 2） |
| mihomo 不可用/控制器未就绪/拨测异常 | 中止，不发布（退出码 3） |
| 通过数 < 15（`VERIFICATION_MIN_PASSED`） | 不碰主资产（保留上轮验证集或 CI 兜底候选集），仅更新报告 |
| 无任何可测节点 | 退出码 4，不发布 |

CI 侧联动：`verification_report.json` 新鲜（<24h 且通过数 ≥15）时，CI 只
发布 `candidates_*` 与 `pending_*`，**不覆盖主资产**；验证陈旧时 CI 兜底
把候选集发布到主资产，订阅永不枯竭。

## 5. 产物与所有权

| 资产 | 属主 | 说明 |
|---|---|---|
| `p_<hex>_c/p/s/v.*`（主资产） | 本任务（验证新鲜时）/ CI（兜底时） | 订阅永久地址 |
| `candidates_clash.yaml` 等 4 个 | CI | 候选集固定名副本，透明备查 |
| `pending_probe.json` / `pending_rescue.json` | CI | 交接文档（待测/救援） |
| `pending_probe.prev.json` | 本任务 | 上轮待测文档备份 |
| `verification_report.json` | 本任务 | 证据+统计（每节点延迟/出口 IP/地区/vantage/AI 可达性）；`tested_round` 字段记录已测轮次，供下一轮闸门判定 |

## 6. 手动执行（调试/补跑）

```bash
cd <仓库根>
export GITHUB_TOKEN="$(cat /root/.github_pat)"   # 持久化 PAT（chmod 600）
export GH_TOKEN="$GITHUB_TOKEN"
python3 scripts/cn_probe.py --dry-run   # 不发布，产物落 /tmp/cn_probe
python3 scripts/cn_probe.py             # 正式一轮
```

> ⚠️ **给 AI 协作者（重要）**：GitHub 凭据**不在环境变量里**，而在 **`/root/.github_pat`**（上表即正确用法）。
> **绝不可因为 `env | grep GH_TOKEN` 为空就断言"没有 token"** —— 2026-10-15 有 AI 因此连续误判 3 次，并导致评估基于过期 20 小时的数据。
> 断言"没有凭据"前，必须查完三处：①`/root/.github_pat`；②本项目文档（本文件、`scripts/cn_probe.py`、`monitor_1617_run.py`）；③环境变量。
> 完整规则见仓库根目录 [`AGENTS.md`](../AGENTS.md)。

> 单实例锁：另一实例运行中时直接退出（`/tmp/cn_probe/cn_probe.lock`），
> 防任务重试/调度重叠导致并发发布。

## 7. Phase 2 预告（进化引擎）

`verification_report.json` 的节点级/源级证据将回流 CI：指纹级「中国通过史」
加成（带陈旧守卫）、订阅源中国通过率评分、静态门槛自学习（护栏+审计）。
届时本手册同步更新。

## 8. 看门狗与 cron 保活（L2，2026-10-20 固化）

2026-10-20 事故：cron 服务未运行 → 实测中断 → 验证陈旧超 24h → CI 兜底
把候选集覆盖主资产，质量闸门失效数小时。除「多重触发」（L1/L3/L4）外，
把保障固化为**看门狗制度**：

| 组件 | 职责 |
|---|---|
| `scripts/cron_watchdog.py` | 每 2h 一拍：① `pgrep -x cron` 查守护进程，死亡则 `service cron start` 拉起；② 距最后活动（cron.log / 验证报告 mtime 较大者）超 **8h**（槽间隔 6h + 宽限 2h）判定漏跑，经单实例锁补测一轮；③ 状态写 `/tmp/cn_probe/watchdog.log`（滚动 500 行）与 `watchdog_state.json` |
| `scripts/install_cron.sh` | 幂等安装/修复 crontab（L1+L2 两条标记块）。沙箱重建、cron 丢失、看门狗报「拉起失败」后一条命令恢复 |

设计约束：看门狗**不碰仓库任何状态文件**；任何异常吞掉记日志、退出码恒 0
（自身失败不污染 cron 邮件）；补测冷却 3h（失败风暴最密每 3h 一次）；
全新环境（无活动记录）不补测——首轮交由定时槽或人工触发。

```bash
# 手动巡检（只报告不动作）
python3 scripts/cron_watchdog.py --dry-run
# 恢复 cron 槽位（沙箱重建后）
bash scripts/install_cron.sh
```

已知局限（需人工）：cn_probe 进程**卡死**（mihomo 僵尸）时，看门狗只能
观察到「活动停滞」，补测会被单实例锁挡回——需人工 `pkill -f cn_probe.py`
后由下一拍补测。卡死识别与处置刻意不做自动化：误杀正在跑的实测轮代价
高于漏跑（漏跑有 L3/L4 兜底，误杀没有）。

### 8.1 事故记录：看门狗补测路径 bug + cron 休眠死亡（2026-10-21）

**事故链**：10-20 凌晨最后一轮实测成功后，沙箱休眠杀死 cron 服务
（开机自启启用着，但休眠恢复不重启服务）→ 四个定时槽全部静默 →
看门狗 12:17 拍检测到漏跑（活动 8.8h 前）并触发补测，但补测命令路径
拼错（`repo_root / CN_PROBE.name` 只剩基名、丢掉 `scripts/` 目录），
每次都是 `can't open file .../proxysub/cn_probe.py` 退出码 2——
**看门狗自上线起从未成功补测过一轮**（单测只断言了返回码、没断言
命令路径形状）→ 报告陈旧超 24h → CI 兜底把 140 个未测试候选节点
覆盖主资产，订阅质量静默降级。

**修复**（commit 见文末 git log）：
1. `run_catchup` 路径改为 `repo_root / "scripts" / CN_PROBE.name`；
2. 回归测试 `test_run_catchup_uses_full_script_path` 锁死命令路径形状
   （endswith `scripts/cn_probe.py` 且文件真实存在）；
3. `service cron start` 恢复服务；AGENTS.md 新增铁律第 5 条：
   补偿机制必须实测验证补偿路径本身、且须知其自身依赖（看门狗跑在
   cron 上，cron 死看门狗也死——真正不依赖本机 cron 的只有 L3）。

**待办（架构层）**：L3 WorkBuddy 云端自动化补跑目前只是设计文档中的
一层，未经验证其真实存在与可用；沙箱休眠杀死本机 cron 的问题会复发
（每次休眠都会）。彻底解法二选一：把实测主循环迁到不休眠的云端
Runner，或把 L3 落实为可观测、可验证的真实任务。

## 9. AI 可达性探测（2026-10-20 新增，不构成闸门）

### 9.1 背景：29 节点平稳的真因之一——AI 盲区

订阅有效节点数长期停在 29，沙箱诊断（v1→v2）定位到三层原因，AI 盲区是
既有闸门的设计缺口：

| 诊断事实（29 个已发布节点） | 数字 |
|---|---|
| 任一 AI 域有 HTTP 响应 | 15～16 |
| **对全部 5 个 AI 域均无响应** | **13** |
| 沙箱直连基线（验证测试有效性） | chatgpt/copilot 不可达、claude 302、gemini 不可达——测试本身有效 |

既有闸门只验证 Google 连通（generate_204）与 Cloudflare 下载，对
「能否连 AI」完全盲视：约一半已发布节点对中国用户实际不可用于 AI 连接。

### 9.2 判据（v1 诊断实测踩坑后确立）

| 判据 | 定义 |
|---|---|
| `ai_reachable` | 任一 AI 域有 **HTTP 响应**（含 403/302/401） |
| `ai_api` | `api.openai.com` 返回 **非 403**（典型 401 无密钥响应）⇒ API 层未被区域封锁 |

- chatgpt.com 403 = Cloudflare 区域拦截（网页端被拒），**≠** API 不可用；
  api.openai.com 401 = 无密钥的正常响应，是「真 AI 可用」的最强信号。两者
  必须分开记录、不可互推。

### 9.3 v1 诊断的三个方法学错误（修复记录，防复踩）

1. **`mode:"global"` 使 select 组不生效**——所有流量同一出口，29 行结果全同、
   country 全 China 是铁证；必须 `mode:"rule"` + `MATCH,PROBE`；
2. **`curl -f` 把 403/404/401 吞成失败**——必须捕获状态码，任何响应都算
   「有响应」（生产用 urllib 的 `HTTPError.code` 路径，见
   `_http_status_via_proxy`）；
3. **探针 URL 路径不当**——早期用 `/cdn-cgi/trace`，非 Cloudflare 站点
   （gemini/copilot）没有该路径，404 被误读为「不可达」；一律用站点根路径。

### 9.4 成本与边界

- 仅对终筛通过节点执行（约 30 个）：**单次切组 + 8 路并行**（GEO 3 源 +
  AI 5 域），节点间串行（共享 PROBE 选择器，并发切组会互相踩）；
- 2026-10-21 合并（任务#91）：原 GEO 与 AI 是两个顺序循环、各 120s 预算，
  手动轮实测每循环各覆盖一半通过节点——**一半节点没有 AI 数据**，排序时
  按「未知」沉底，有效节点被埋。合并为 `node_evidence`（一次切组 + 8 路
  并行）后同预算覆盖率达 54%（15/28，旧实现 AI 50%+GEO 28% 且总耗时
  240s → 合并后 122s）；
- **单请求线程级硬超时**（`_hard_timeout_call`）：urllib socket timeout
  是每次 recv 超时而非整体超时——实测龟速节点上 gemini 302 链耗时
  24.31s（socket timeout 仅 8s），单节点均摊 10.5s、120s 只覆盖 13/28。
  GEO socket 5s / AI 8s、硬截断各 +2s；GEO 收紧不丢证据（三源并行取
  首个成功，且 GEO 仅信息性留痕）；
- 统一预算 `EVIDENCE_BUDGET_S=120s`；耗时上界 真实流量 ~24s + 证据
  ≤120s + 发布 ~60s ≈ 204s < `PUBLISH_RESERVE_S` 300s，不击穿任务超时；
- **不设硬闸门**：AI 不可达不是节点死亡，节点仍是可用代理——仅排序沉底
  （`verified_rank`：AI API 可用 > AI 可达 > 无数据 > 原双 vantage 序）。

### 9.5 报告字段（增量，CI 侧只读既有键、不受影响）

- `counts.ai`：`{probed, reachable, api_ok, by_domain}`——每轮 AI 盲区
  量化，供后续源级反哺（哪些源产的节点 AI 可用率高）；
- `counts.by_source[*]`：2026-10-21 起（任务#92）在 `{tested, passed}`
  之外扩出 `{ai_tested, ai_reachable, ai_api}`——分源 AI 证据口径
  （只覆盖有 ai 数据的通过节点；无证据记 0 而非缺键）。CI 侧
  `evolution.update_source_scores_ai` 据此折回 `source_scores.json` 的
  `ai_*` 字段（只在 `ai_tested>0` 时写、不抹零），接入候选晋升 AI 优先
  与拨测复合倾斜（cn×AI 相乘封顶 2.0，任务#94，2026-10-21 完成）；
- `nodes[].ai`：`{codes, reach, ai_reachable, ai_api}` 逐节点证据；
- `dimensions.ai`：语义说明（与 us_ok/cn_ok 并列的第三测量维度）。
