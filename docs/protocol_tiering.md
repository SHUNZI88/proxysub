# 协议分层证据积累机制（P2-a / P2-b / P2-c）

> 建立日期：2026-10-15
> 起因：评估报告 §十、§十一 的结论——协议维度存在显著差异（如 anytls vs vless），
> 但**单轮小样本不具统计效力**，不能据此调整采样/评分权重。故先建"证据积累基建"。

---

## 一、要解决的问题

免费订阅源中 vless 供给占比约 60%（源侧），待测池 vless 占比 67.9%，但其中国通过率仅 **2.8%**。
而 anytls 单轮 7/8 = 87.5%。**表面差异巨大，但**：

| 问题 | 说明 |
|---|---|
| 样本量不足 | anytls 仅 8 个样本，95% CI = [52.9%, 97.8%]，掉 1 个即跌破 50% |
| 单轮无验证 | 仅 1 轮数据，跨轮方向一致性完全未知 |
| 因果未解耦 | 分不清是"协议好"还是"恰好来自好源" |
| 反身性风险 | 若边跑边加权，会自我强化（高通过率→更多配额→更显著→更高权重） |

**结论：现在不能实施按协议权重化。先建可逆的证据积累机制。**

---

## 二、三项基建（P2-a / P2-b / P2-c）

### P2-a：报告增协议分层统计（含样本量与置信区间）

`scripts/cn_probe.py` 的 `_agg_two(..., with_ci=True)` 在 `by_protocol` 中新增：

| 字段 | 含义 |
|---|---|
| `pass_rate` | 通过率（passed/tested） |
| `ci95_low` / `ci95_high` | **95% Wilson 置信区间**（小样本稳健） |
| `sample_ok` | `tested >= PROTOCOL_MIN_SAMPLE(30)` 才为 True |

> 纯增字段，不改 schema，不影响既有消费方（默认 `with_ci=False` 保持原行为）。

### P2-b：跨轮协议聚合

`evolution.py` 的 `update_protocol_history()` → 写入 `protocol_history.json`：

```json
{
  "hysteria2": {
    "rounds": 2, "tested": 250, "passed": 50,
    "last_round": "20261014T1200Z", "last_ts": "...",
    "recent": [{"round": "...", "tested": N, "passed": M}, ...]
  }
}
```

- **幂等**：同轮重复执行不重复累加（CI 重试安全）；
- **陈旧守卫**：报告 age > 12h 则跳过（与其他反哺闭环一致）；
- **有界**：`recent` 仅保留最近 `PROTOCOL_HISTORY_KEEP_ROUNDS(30)` 轮。

### P2-c：权重化实施门槛（硬性前置条件）

`config.py` 定义，**三条须同时满足**才允许按协议设定权重：

1. 累计样本 `tested ≥ PROTOCOL_WEIGHT_MIN_CUM_SAMPLE`（50）；
2. 跨轮方向一致 ≥ `PROTOCOL_WEIGHT_MIN_ROUNDS`（5）轮；
3. 在 `protocol_history.json` 中留痕（可审计、可复算）。

---

## 三、数据流

```
沙箱实测 ──> verification_report.json
                    ├─ counts.by_protocol（含 pass_rate/ci95/sample_ok）   [P2-a]
                    └─ run_evolution()
                         └─ update_protocol_history() ──> protocol_history.json  [P2-b]
                                                                │
                                    达到 P2-c 门槛（n≥50 且 ≥5 轮同向）│
                                                                ▼
                                                  允许评估「协议分层权重」
```

---

## 四、当前基线（首轮回填，round 20261014T2306Z）

| 协议 | tested | passed | pass_rate | sample_ok |
|---|---|---|---|---|
| vless | 820 | 23 | 2.8% | ✅ |
| trojan | 202 | 5 | 2.5% | ✅ |
| hysteria2 | 166 | 9 | 5.4% | ✅ |
| anytls | 8 | 7 | 87.5% | ❌（样本不足） |
| tuic | 7 | 0 | 0.0% | ❌ |
| hysteria | 4 | 2 | 50.0% | ❌ |

**任何权重决策在 `protocol_history.json` 显示"达门槛"之前，一律不实施。**

---

## 五、与设计原则的关系

本机制严格遵循项目"**用数据反哺设计**"原则：
- **不预测**协议优劣（避免先验偏见）；
- **只积累**证据（让小样本协议随轮次自然显形）；
- **设门槛**再行动（防止"看着有差异就改"的过拟合）。
