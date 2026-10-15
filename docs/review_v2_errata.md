# 复评报告（v2）勘误记录

> **勘误对象**：2026-10-15《proxysub 复评报告（v2）》（评估视角：产品管理，自称"复评依据版本：GitHub `main` 分支当前状态"）
> **勘误时间**：2026-10-15
> **勘误方法**：不采信报告自称，逐项用 **git 历史 + 当前源码** 双重核对（铁律零：先验新鲜度，再采信）
> **一句话结论**：报告的核心头条论断（`output.py` 四处 P0、`common.py` 双份常量、`main()` 巨型函数"均未修"）**与当前代码严重不符**——这些修复在报告复评日之前就已完成，报告基于的是**过期代码快照**；其"关闭 P0 四项即可解锁 A"的评级前提已不成立。

---

## 一、勘误总览

| 报告编号 | 报告论断 | 报告结论 | 实际状态 | 修复 commit | 修复时间 |
|---|---|---|---|---|---|
| P0-1 | `write_github_summary` 仍用下标 | **未修** | ✅ **已修** | `f3f6bc9` | 2026-10-14 19:25 |
| P0-2 | TUIC 链接冗余 `password` query | **未修** | ✅ **已修** | `f3f6bc9` | 2026-10-14 19:25 |
| P0-3 | sing-box Trojan 缺 `utls` | **未修** | ✅ **已修** | `f3f6bc9` | 2026-10-14 19:25 |
| P0-4 | Hysteria2 `obfs` 两函数判定不一致 | **未修** | ✅ **已修** | `f3f6bc9` | 2026-10-14 19:25 |
| N1 | `common.py` 与 `config.py` 双份常量 | **未修** | ✅ **已修** | `887eb8f` | 2026-10-15 01:00 |
| P1-5 | `main()` 仍约 290 行 | **未修** | ✅ **已拆解** | `1e64c21` | 2026-10-14 22:53 |
| 数据 | "沙箱实测 1292 节点 / 33 个美西不通国内通" | 当作当前状态 | ⚠️ **历史论据，非当前 Release 实时值** | — | 见第四节 |

---

## 二、逐条勘误详述

### P0-1 `write_github_summary` 下标取键 —— ✅ 已修

- **报告称**：`d, c, o = info["discovery"], info["cand_rep"], info["off_rep"]` 仍用下标，未修。
- **实际**：`output.py:350-352` 已改为防御性写法：
  ```python
  d = info.get("discovery", {}) or {}
  c = info.get("cand_rep", {}) or {}
  o = info.get("off_rep", {}) or {}
  ```
- **证据**：commit `f3f6bc9`（2026-10-14 19:25:14 +0800），message 明确含 "write_github_summary 容错 + 6 项回归测试"。

### P0-2 TUIC 分享链接冗余 `password` query —— ✅ 已修

- **报告称**：`proxy_to_share_link` TUIC 分支 `params["password"]` 与 userinfo 重复，未修。
- **实际**：`output.py:127-137` 密码仅写入 userinfo（`tuic://uuid:password@host:port`），query 不再含 password；代码注释直接标注"（P0-2）"。
- **证据**：commit `f3f6bc9`，message 含 "修复 TUIC 冗余密码"。

### P0-3 sing-box Trojan 缺 `utls` 指纹 —— ✅ 已修

- **报告称**：通用 `tls` 字典在 VLESS 分支写 `utls`、Trojan 分支无，未修。
- **实际**：`output.py:196-197` Trojan 分支已补：
  ```python
  if p.get("client-fingerprint"):
      tls["utls"] = {"enabled": True, "fingerprint": p["client-fingerprint"]}
  ```
  代码注释直接标注"（P0-3）：与 VLESS 分支保持一致"。
- **证据**：commit `f3f6bc9`，message 含 "VLESS-Trojan utls 不一致"。

### P0-4 Hysteria2 `obfs` 两函数判定不一致 —— ✅ 已修

- **报告称**：分享链接 `if p.get("obfs"):` vs sing-box `== "salamander"`，口径不同，未修。
- **实际**：两处均已归一为 `obfs == "salamander"` 判定：
  - 分享链接分支 `output.py:112-121`
  - sing-box 分支 `output.py:212-214`
  两处代码注释均直接标注"（P0-4）"。
- **证据**：commit `f3f6bc9`，message 含 "Hy2 obfs 归一"。

### N1 `common.py` / `config.py` 双份常量 —— ✅ 已修

- **报告称**：`config.py` 与 `common.py` 各存一份全部常量，且 `common.py` 不 `import config`，未修。
- **实际**：`common.py:31` 已改为 `from config import (...)`，按需消费 config 常量，消除双份真理。
- **证据**：commit `887eb8f`（2026-10-15 01:00:03 +0800），message "refactor(P1-2): common.py 配置常量迁出 config.py，common 757→502 行"。

### P1-5 `main()` 巨型函数拆分 —— ✅ 已大幅拆解

- **报告称**：`filter_clash.py` 的 `main()` 仍约 290 行，阶段逻辑全内联，未修。
- **实际**：AST 实测 `main()` 现为 **83 行**（`filter_clash.py:899-981`），已薄编排化 + 阶段函数化。
- **证据**：commit `1e64c21`（2026-10-14 22:53:19 +0800），message "refactor(filter_clash,P1-1): main() 685→83 行薄编排 + 阶段函数化 + 测试安全网"。

---

## 三、关键时间线（本勘误的核心铁证）

报告自称"复评依据版本：GitHub `main` 分支**当前状态**"、复评时间 2026-10-15，但其指称"未修"的全部修复，commit 时间**均早于报告复评日**：

```
2026-10-14 19:25  f3f6bc9  fix(output,P0)      ← P0-1/2/3/4 四项修复
2026-10-14 22:53  1e64c21  refactor(P1-1)      ← main() 685→83 行拆分
2026-10-15 01:00  887eb8f  refactor(P1-2)      ← common.py 常量迁出 config
─────────────────────────────────────────────────────────────
2026-10-15        （报告复评日）报告却称以上各项"未修"
```

> **结论**：报告"阶段 0 关闭 P0 四项即可解锁 A"这一评级前提**已不存在**——这四项连同 N1、P1-5 都早已修完。报告基于过期快照，其"A- 受 P0 制约"的评级结论失去依据。

---

## 四、数据勘误：1292 节点 / 33 个

- **报告称**："沙箱实测 **1292 节点**交叉表显示 **33 个**节点美西不通国内通"，并以此作为当前 Release 的实测状态呈现。
- **实际**：该数字出自 `config.py:237-238` 的**代码注释**，是对**某一历史轮次**交叉表的记载（作为"证伪'连美国都代理不成功=节点已死'旧表述"的论据被写入注释），**并非当前 Release 的实时快照**。
- **当前口径**（`stats.md`，更新于 2026-10-15 00:50 UTC）：TCP 存活 **2139**、拨测样本 **1005**（通过 460，45.8%）、最终节点 **165**——与"1292 节点"不是同一口径、也不是同一时点。
- **处置**：引用该交叉表数据时必须标注 `round_id` 并说明口径（见 AGENTS.md「数据规则」）；本项目内部此前已确认该交叉表存在"本地残留 vs Release"的口径争议。

> 这条勘误本身就是对**铁律零**的反讽印证：连一份自称"复评"的报告，也踩进了陈旧数据陷阱——而团队上一轮才刚花整轮力气把同类过期数据从交付物里清出去。

---

## 五、报告中仍成立、且本轮已修复的项

报告并非全错——以下 N 系列隐患经代码核验**真实存在**，已在本轮修复：

| 项 | 问题 | 处置 |
|---|---|---|
| **N2** | `sources_manager.evaluate_candidates` 的 `probed`/`tamper` 未 `int()` 兜底（同文件 `update_official` 已做，两处不一致；上游显式传 `None` 时 `max(1, None)` 抛 `TypeError`） | ✅ 已修 `e333506`：统一 `int(... or 0)` 兜底 + 回归测试 `test_tolerates_none_probed_and_tamper` |
| **N3** | `update_official` 的 `score()` 在 `keep.sort()` 时对每源各读一次 `SOURCE_SCORES_FILE`（源多时 I/O 放大 + 锁竞争） | ✅ 已修 `e333506`：排序前一次性读入 |

测试：**581 passed**（原 580），无回归；已推送 `e333506` 至 `main`。

---

## 六、报告其它项判定

| 项 | 判定 |
|---|---|
| **P1-8** `us_china_penalty` 已修 | ✅ 报告说"已修"正确，与记录一致（commit `0795893`） |
| **N4** `update_source_scores(..., history)` 参数冗余 | ⚠️ 确实未使用，但调用方（`filter_clash.py`）与 12 处测试均按 3 参调用，**删除需连带改大量调用点、收益极低，本次不动** |
| **P1-7** `_reexport` hack 仍存在 | ⚠️ 属实，但已被 `test_no_undefined_names`（pyflakes）门禁守护，非优先项 |
| **N6 / P2-11** README 完整公开反爬诱饵形态 | ⚠️ 大概率仍成立，属**产品化**范畴，未在本轮处理 |

---

## 七、教训固化（元原则闭环）

按 AGENTS.md「元原则：发现即反思，反思即固化」，本次发现已落地为制度：

1. **新增规则**：AGENTS.md 新增「🧪 外部评估报告的采信」一节——外部评估报告（包括自称"复评报告"的）**可能基于过期快照**；采信其"未修 / 仍存在"类论断前，**必须先用 `git log` 核对相关修复 commit 是否已存在、再看当前代码**，不能因其自称"当前状态"就照单全收。
2. **本勘误记录**即沉淀物，供后续会话复核该报告时直接引用，避免重复核验或再次被其误导。

---

*本记录由 AI 协作者经 git 历史与当前源码逐行核验后生成；所有 commit hash、代码行号、时间戳均可在仓库中复核。*
