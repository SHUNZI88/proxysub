# 反爬与防搜索 · 设计文档（内部）

> 本文档是反爬模块（`anti_crawl.py` / `anti_crawl.json`）的设计与运维说明。
> README 只保留面向**订阅使用者**的「怎么订阅 + 能力边界结论」；机制细节集中于本文档，
> 避免在仓库首页逐条列举「防不住什么」，降低针对性攻击者的检索成本。
>
> ⚠️ 注意：本仓库为 public 仓库，本文档与源码（`anti_crawl.py`）同为公开可读。
> **反爬的有效性依赖资产名保密（仅 Step Summary 可见），而非算法保密**——机制本身公开，
> 详见「效果边界」一节的坦白说明。

---

## 一、要解决的问题

public 仓库的订阅文件（`clean_clash.yaml` 等固定名 raw 路径）对任何人可读，会被「按固定
路径扫描」的爬虫 / 聚合站批量收录，进而：① 真实订阅被无关流量灌爆；② 我们的输出被第三方
聚合站转卖或转载。反爬的目标不是「彻底不可发现」（public 仓库做不到），而是**把被动扫描
的爬虫引向无价值目标，让真实订阅地址避开自动化发现路径**。

## 二、机制构成（`anti_crawl.json` 的 `"enabled": true` 时生效）

1. **诱饵分流**：固定名订阅文件（`clean_clash.yaml` 等）改写为**诱饵内容**——大量形态合法
   但必定不可用的诱饵节点：名称带 `[BAIT]` 标记、服务器指向 RFC 保留域 `.invalid`（任何
   客户端都无法连通）、混合 VLESS-Reality / Trojan / Hysteria2 三种形态，与真实输出**完全
   同构**（连字段结构、参数命名都一致），使扫描器无法靠形态区分真假。按固定路径扫描 raw 的
   爬虫，扫到的永远是诱饵。

2. **永久订阅地址（滚动 Release，默认模式 `publish_release: true`）**：真实输出由工作流发布
   到仓库的滚动 GitHub Release（tag 可配，默认 `sub`），**资产名为首次生成的随机字符串**
   （如 `p_5d0dc339da_c.yaml`，之后永久不变）。订阅地址形如：

   ```
   https://github.com/SHUNZI88/proxysub/releases/download/sub/p_5d0dc339da_c.yaml
   ```

   一次复制永久有效、无需手动维护；该路径不在任何 raw 扫描器的目标清单上，也不从任何公开
   文件链接（地址只在 Actions Step Summary 可见）。

3. **诱饵回流检测**：若某个订阅源收录了我们生成的诱饵节点（指纹比对，在静态门槛与 DNS
   之前完成），该源会被标记 `bait_reuse`——**候选源直接拒绝、正式源自动淘汰**
   （原因 `redistributes_bait`）。爬虫转载诱饵即自我暴露。

4. **robots.txt**：生成 `Disallow: /` 声明，劝阻合规爬虫（对不遵守者无效，见「效果边界」）。

5. **真实订阅地址只写入 GitHub Actions 的 Step Summary**（仅仓库所有者可见），不进入任何
   公开文件。

6. **工作流加固**：`workflow_dispatch` 限定**仅仓库所有者**可手动触发（public 仓库默认任何
   人可点）；失败告警 Issue 默认关闭（反爬边界优先）。

> **备选模式**：`"publish_release": false` 退回**文件名轮换**（真实输出写
> `clean_clash.<token>.yaml`，每 `rotate_days` 天更换、过期自动删除）——适合「分享出去的链接
> 应过期」的场景，但订阅地址需定期更新。默认不启用。

## 三、效果边界（内部知悉，README 不逐条列举）

| 措施 | 防住 | 防不住 |
|---|---|---|
| 诱饵分流 + Release 永久地址 | 按固定路径扫描 raw 的大众爬虫 / 聚合站（扫到的只有诱饵） | 会去读 Releases 页 / 解析 `anti_crawl.json` 的针对性爬虫；人工分析 |
| 诱饵回流检测 | 转载诱饵的源被自动拒绝/淘汰 | 只爬不用、或清洗掉诱饵后再转载的爬虫 |
| robots.txt | 遵守 robots 规范的合规爬虫 | 不遵守的爬虫；GitHub 站内搜索与代码索引 |
| owner-only dispatch | 陌生人手动触发工作流 | 定时触发本身 |
| 失败告警关闭 | Issues 页暴露运行信息 | — |

- **public 仓库无法从根本上避免被检索**：仓库页/README/代码会被站内搜索与外部搜索引擎索引，
  个人仓库内的文件（含 robots.txt）不能控制这一点。
- 永久地址的随机资产名记录在公开的 `anti_crawl.json` 中——这是「提高门槛」而非「加密保密」。
  **如要求资产名完全不落仓库**：用仓库 secret 传入环境变量 `PROXYSUB_ASSET_NAMES`（JSON，
  如 `{"clean_clash.yaml":"my_name.yaml"}`），指定后程序不再生成也不再写入配置。
- 滚动 Release 页面本身是公开的（任何人可看到资产存在），但资产名为随机字符串、发布动作每轮
  静默更新，对「扫路径」的自动化爬虫不可见。
- **要彻底隐藏**（搜索/索引/raw 直链全部失效）：将仓库转为 **private**。代价：raw 订阅直链与
  Release 资产需 token 才能下载，客户端无法直接订阅，需改用 GitHub API 带 token 下载或
  Actions artifact；外部心跳 `repository_dispatch` 不受影响（本就用 PAT）；免费账户 private
  仓库每月 2000 分钟 Actions 额度（本工作流日均 4 次、单次数分钟，远低于上限）。

## 四、运维要点

- **开关**：编辑 `anti_crawl.json` 的 `"enabled"`（默认 false）；或工作流环境变量
  `PROXYSUB_ANTI_CRAWL: '0'` 临时强制关闭。开启后**永久订阅地址**（滚动 Release，不会变）
  见 Actions 运行页的 Step Summary。
- **不要手改 `anti_crawl.json` 中由程序维护的字段**（token / 资产名 / 诱饵节点），否则会破坏
  地址的永久性或诱饵的一致性。
- **发布前诱饵 sanity 检查**：`.publish/` 下文件为空或含诱饵标记（bait_host / `[BAIT]`）时
  发布步骤直接失败——永久地址不可能再服务纯诱饵内容。
- **发布先于提交**：滚动 Release 发布失败时绝不先提交，否则仓库状态前进而永久地址仍指向旧资产。
