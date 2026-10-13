# 中国出口节点实测（沙箱侧运行手册）

本手册是定时任务「中国出口节点实测轮」的执行依据。脚本 `scripts/cn_probe.py`
与仓库同版本发布，改进脚本即改进实测行为（git pull 即生效）。

## 1. 任务定位

CI（GitHub Actions，美国出口）每轮产出「拟交沙箱待测节点文档」，本任务从
中国出口（湖南机房）实测筛选，通过者覆盖发布为主资产——解决「美国能通、
国内不通」的节点混入订阅的难题。

## 2. 时间安排（北京）

| 时刻 | 事件 |
|---|---|
| 00:17 | CI 定时运行（候选集 + 待测文档） |
| **01:02** | **本任务第 1 轮**（CI 后 ~45min） |
| 05:18 | 外部心跳触发 CI（保活） |
| 06:17 | CI 定时运行（候选集 + 待测文档） |
| **07:02** | **本任务第 2 轮** |
| 12:17 / 18:17 | CI 定时运行（候选集常驻 + 交接文档） |

> 05:18 心跳运行产出的待测文档会被 06:17 运行刷新覆盖，故第 2 轮以 06:17
> 的文档为准（心跳运行的保活目的不受影响）。CI 队列延迟 0–6min 由新鲜度
> 闸门吸收（§4），定时偏差无害。

## 3. 单轮流程

1. **自检**：沙箱直连探测（baidu / api.github.com）。失败即中止——避免把
   沙箱自身故障误判为节点全失效；
2. **新鲜度闸门**：下载 `pending_probe.json`，`generated_at` ≤3h 直接测；
   否则轮询等待至多 20 分钟；仍陈旧（CI 故障）则退化为仅测 carryover；
3. **测试集** = carryover（当前主资产，滚动携带+自清洁）∪ pending（待测
   文档）∪ rescue（救援文档，CI 淘汰但静态可行的节点）；
4. **拨测**：mihomo external-controller delay API，`generate_204`
   （HTTPS+204 双信号），12 并发，失败重试一次；
5. **出口证据**：通过节点逐个切流量取出口 IP/地区（cip.cc → ipip →
   ip-api 依次回退），仅留痕、不构成闸门；
6. **合并发布**：通过节点按「双 vantage 强者优先 + 延迟」排序，构建
   clash/sing-box/v2ray/proxies-only 四格式，覆盖发布到主资产
   （p_* 随机名，**订阅永久地址不变**），并发布 `verification_report.json`；
7. **轮转**：本轮消费的待测文档备份为 `pending_probe.prev.json`。

## 4. 熔断与降级

| 情况 | 行为 |
|---|---|
| 沙箱自身网络不可用 | 中止，不发布（退出码 2） |
| mihomo 不可用/控制器未就绪/拨测异常 | 中止，不发布（退出码 3） |
| 通过数 < 15（`VERIFICATION_MIN_PASSED`） | 不碰主资产（保留上轮验证集或 CI 兜底候选集），仅更新报告 |
| 无任何可测节点 | 退出码 4，不发布 |

CI 侧联动：`verification_report.json` 新鲜（<12h 且通过数 ≥15）时，CI 只
发布 `candidates_*` 与 `pending_*`，**不覆盖主资产**；验证陈旧时 CI 兜底
把候选集发布到主资产，订阅永不枯竭。

## 5. 产物与所有权

| 资产 | 属主 | 说明 |
|---|---|---|
| `p_<hex>_c/p/s/v.*`（主资产） | 本任务（验证新鲜时）/ CI（兜底时） | 订阅永久地址 |
| `candidates_clash.yaml` 等 4 个 | CI | 候选集固定名副本，透明备查 |
| `pending_probe.json` / `pending_rescue.json` | CI | 交接文档（待测/救援） |
| `pending_probe.prev.json` | 本任务 | 上轮待测文档备份 |
| `verification_report.json` | 本任务 | 证据+统计（每节点延迟/出口 IP/地区/vantage） |

## 6. 手动执行（调试/补跑）

```bash
cd <仓库根>
source /root/.codebuddy/skills/github-connector/scripts/get_token.sh github
python3 scripts/cn_probe.py --dry-run   # 不发布，产物落 /tmp/cn_probe
python3 scripts/cn_probe.py             # 正式一轮
```

## 7. Phase 2 预告（进化引擎）

`verification_report.json` 的节点级/源级证据将回流 CI：指纹级「中国通过史」
加成（带陈旧守卫）、订阅源中国通过率评分、静态门槛自学习（护栏+审计）。
届时本手册同步更新。
