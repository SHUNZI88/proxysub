#!/usr/bin/env python3
"""proxysub 配置层：全部可调常量、正则与运行旋钮（P1-2 从 common.py 迁出）。

设计约定：
  - 本模块**只放配置**——常量、预编译正则、env 读取开关。不放业务函数，
    不 import common / score / probe / output（保持为架构最底层叶子）；
  - 每个常量附近保留其「为什么是这个值」的理由注释（免费源生态多变，
    调参必须知道当初的约束条件）；
  - 运行期覆盖一律走 env（如 PROXYSUB_DISABLE_PROBE / PROXYSUB_DISCOVERY），
    不在此处读配置文件——配置即代码，变更经 git review。

消费方按需 import：`from config import REGION_QUOTAS, MIN_FINAL, ...`。
"""

from __future__ import annotations

import os
import re

# ====================== 订阅源 ======================
# 订阅源已移到 sources.json（正式源）和 candidate_sources.json（候选/试用源），
# 由 sources_manager.py 负责自动发现、试用、晋升与淘汰。

EXCLUDE_KEYWORDS = r"(官网|流量|到期|过期|剩余|测试|无效|假|防失联|127\.0\.0|IPv6|试用|公告|电报|TG|频道)"

REGION_RULES = {
    # Order matters: first match wins. Asia first (China client path).
    # 短代码（HK/JP/SG/TW/KR/US/UK 等）强制加 \b 单词边界，防止子串误判
    # （如 Russia 包含 us、AUS 包含 US、UKRAINE 包含 UK 被错归为美国/英国）。
    "🇭🇰 香港": r"(香港|\bHK\b|Hong\s?Kong)",
    "🇯🇵 日本": r"(日本|\bJP\b|Japan|东京|大阪|Tokyo|Osaka)",
    "🇸🇬 新加坡": r"(新加坡|\bSG\b|Singapore|狮城)",
    "🇹🇼 台湾": r"(台湾|台灣|\bTW\b|Taiwan)",
    "🇰🇷 韩国": r"(韩国|韓國|\bKR\b|Korea|首尔|首爾|Seoul)",
    "🇺🇸 美国": r"(美国|美國|\bUS\b|\bUSA\b|United States|\bAmerica\b)",
    "🇬🇧 英国": r"(英国|英國|\bUK\b|United Kingdom|London|伦敦)",
}

# China-path tilt: Asia quotas up, US/UK down (US runner ≠ China client).
# Quotas sum ~180 so we can land in the 100–200 final band after US-share trim.
REGION_QUOTAS = {
    "🇭🇰 香港": 40,
    "🇯🇵 日本": 35,
    "🇸🇬 新加坡": 30,
    "🇹🇼 台湾": 22,
    "🇰🇷 韩国": 20,
    "🇺🇸 美国": 30,   # soft; also capped by MAX_US_SHARE
    "🇬🇧 英国": 8,
}
# EU/CA/AU and misc: 活节点池的大头常落在「其他」区（免费源多为冷门地区），
# 配额过小会把大量真实探测存活的节点直接丢弃。
MAX_OTHER = 60  # misc; still ranked by score
# Hard band for final subscription size (China FLClash needs enough candidates):
# 云端只做死活闸门，「美国能通但国内被墙」的残余筛选必须靠客户端 url-test 完成，
# 因此给客户端尽量大的活节点备选池（探测存活 700+ 时全部给出）。
MIN_FINAL = 150
MAX_FINAL = 300
MAX_PER_SOURCE_FINAL = 25   # 单一订阅源在最终输出中的独占上限

# ====================== 硬性静态门槛（协议白名单 + 关键参数校验）=====================
# 云端剥离真实流量拨测后，源质量完全依赖静态门槛把关：
#   1) 协议白名单：仅收录优质现代协议（Hysteria2 / VLESS-Reality / Trojan / TUIC 等），
#      彻底排除 ss / ssr / vmess / http / socks 等大量掺假的 legacy 垃圾协议；
#   2) 关键参数校验：SNI、Reality Public-Key / Short-Id、UUID、密码等必须合法匹配；
#   3) 深度指纹去重：见 common.fingerprint()。
PROTOCOL_WHITELIST = {
    "hysteria2", "hy2",
    "vless",      # 必须为 Reality 或显式 TLS（见 common.protocol_gate_reason）
    "trojan",
    "tuic",
    "anytls",
    "hysteria",
}
# 标准 UUID（8-4-4-4-12 hex）
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
# Reality short-id：0-8 字节的 hex（偶数位，最长 16 字符）
SHORT_ID_RE = re.compile(r"^([0-9a-f]{2}){0,8}$", re.I)
# X25519 公钥：base64url 编码 32 字节 = 43 字符（可带 1 个 '=' 填充）
X25519_PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{43}={0,1}$")
# mihomo vless 支持的 flow
SUPPORTED_FLOWS = {"", "xtls-rprx-vision"}

# skip-cert-verify 节点（削弱 TLS 身份认证的高风险节点）的处理：
# 名称打 [Insecure] 标签 + 独立分组隔离，不进入自动选择/故障转移/地区分组
INSECURE_TAG = " [Insecure]"
INSECURE_GROUP = "⚠️ 高风险(跳过证书校验)"

# 云端真实流量拨测总开关：PROXYSUB_DISABLE_PROBE=1 时跳过 mihomo / http-socks 拨测，
# 仅保留 TCP 存活检查。注意：禁用拨测后输出会被「TCP 可达但协议层已死」的僵尸节点
# 淹没（免费源中此类节点占绝对多数），仅建议临时调试使用，CI 常规运行必须开启。
def real_probe_enabled() -> bool:
    return os.environ.get("PROXYSUB_DISABLE_PROBE", "0") != "1"

# 评分时 TCP 延迟（美西 Runner 测得，不代表国内真实路径）的贡献上限：
# 仅作为存活/粗排信号，不允许主导排序（排序主要由协议质量/存活时长/多源等静态特征决定）。
TCP_LATENCY_CAP_IN_SCORE = 600.0

TCP_TIMEOUT = 3.5
PROBE_TIMEOUT = 8.0
MAX_WORKERS = 60
FETCH_WORKERS = 8
FETCH_RETRIES = 2  # at most 2 attempts per source per run
FETCH_TIMEOUT = 25

# url-test / fallback intervals (seconds)
URLTEST_INTERVAL = 150
FALLBACK_INTERVAL = 180

OUTPUT_FILE = "clean_clash.yaml"
# 多格式输出（由 output.write_outputs() 统一生成；均为同一份最终节点列表的不同封装）
OUTPUT_SINGBOX = "clean_singbox.json"          # sing-box outbounds 列表
OUTPUT_V2RAY = "clean_v2ray.txt"               # base64 分享链接（v2ray/nekobox 等可导入）
OUTPUT_PROXIES_ONLY = "clean_proxies_only.yaml"  # 仅 proxies 段，供客户端 proxy-providers 使用
STATS_MD = "stats.md"                          # 健康报告
SOURCE_SCORES_FILE = "source_scores.json"      # 源评分
SURVIVAL_FILE = "survival.json"
SOURCE_STATS_FILE = "source_stats.json"
BAD_SOURCES_FILE = "bad_sources.json"
# Phase 2 进化引擎数据落盘
CN_HISTORY_FILE = "cn_history.json"          # 节点级中国通过史（fp -> 通过/失败/延迟/出口）
PROBE_HISTORY_FILE = "probe_history.jsonl"  # 每轮审计行（可 grep、随 CI 进 git）
LEARNED_THRESHOLDS_FILE = "learned_thresholds.json"  # 静态门槛自学习结果
THRESHOLD_HISTORY_FILE = "threshold_history.json"    # 门槛变更审计（旧值/新值/样本/理由）
# 协议分层证据积累（P2-b，2026-10-15）：跨轮累积分协议 tested/passed，
# 供后续「协议维度权重化」决策读取累计样本与跨轮一致性。单轮不具统计效力。
PROTOCOL_HISTORY_FILE = "protocol_history.json"
PROTOCOL_HISTORY_KEEP_ROUNDS = 30     # 每协议保留最近 K 轮明细（控制体积）
# 协议样本量门槛（P2-a）：低于此值的协议通过率标记 sample_ok=False，
# 不得据此调整采样/评分权重（避免小样本误判，2026-10-15 复盘教训）。
PROTOCOL_MIN_SAMPLE = 30
# 协议权重化「实施门槛」（P2-c，2026-10-15）：仅当同时满足以下三条，
# 才允许按协议分层设定采样/评分权重，否则一律不实施（防小样本/单轮误判）：
#   ① 该协议累计样本 tested ≥ PROTOCOL_WEIGHT_MIN_CUM_SAMPLE；
#   ② 跨轮方向一致（累计通过率与各轮通过率同向，无反转）达
#      PROTOCOL_WEIGHT_MIN_ROUNDS 轮以上；
#   ③ 已在 protocol_history.json 中留痕（可审计、可复算）。
# 背景：单轮 anytls 7/8=87.5% 曾被误当"可加权"依据，但其 95%CI=[52.9%,97.8%]，
# 掉 1 个样本即跌破 50%，且仅 1 轮——统计上不成立。详见评估报告 §十/§十一。
PROTOCOL_WEIGHT_MIN_CUM_SAMPLE = 50
PROTOCOL_WEIGHT_MIN_ROUNDS = 5
# China-client connectivity URLs first (Asia egress reaches them more easily from US runners).
# Runner probe: China-client-ish URLs first (any 1 pass). US runner≠China path,
# so HTTP ok is a soft quality signal — NOT the sole admission gate.
PROBE_URLS = [
    "http://connectivitycheck.platform.hicloud.com/generate_204",  # Huawei
    "http://wifi.vivo.com.cn/generate_204",                        # vivo
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://captive.apple.com/hotspot-detect.html",                # Apple captive
    "http://www.msftconnecttest.com/connecttest.txt",              # Microsoft
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
]
PROBE_PASS_NEED = 1  # any 1 success => HTTP ok (China-friendly)
# FLClash url-test: overseas egress usually reaches gstatic; keep stable for clients.
PROBE_URL = "http://www.gstatic.com/generate_204"
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"  # soft HTTPS signal + egress IP/loc
PROBE_LIMIT_OFFICIAL = 980
PROBE_PER_CANDIDATE = 20
# 新节点保底拨测配额：从未进入 survival 的节点保证有拨测机会，
# 节点池才能正常轮换（2026-10 质量回归修订：此前历史稳定节点
# 可以凭 streak 把新节点完全挤出 980 个拨测预算）。
PROBE_FRESH_QUOTA = 250
# 多渠道节点（Telegram/网页分享链接）在 per_source 中的伪键名。
# 它们既非正式源也非候选源 URL，此前的样本循环永远选不到它们，
# 导致渠道节点在评分时全被 cand_only 闸门丢弃（收集了却永不入选）。
CHANNEL_NODES_KEY = "__channel_nodes__"
# 多渠道节点保底拨测配额：与候选源同等参与「通过拨测方可入榜」机制。
CHANNEL_PROBE_QUOTA = 60
# ---- CI → 沙箱交接文档（中国出口实测接力，Phase 1）----
# 每轮把待测节点集/救援集写入 .publish/，随滚动 Release 发布为资产；
# 沙箱定时任务下载后用中国出口实测筛选，通过者覆盖发布为主资产。
# 交接走 Release 资产而非 git 提交：无提交竞态、无仓库膨胀，两侧解耦。
# 上传顺序依赖：订阅资产（p_* 随机名）字母序先于 pending_*，即新鲜
# pending_probe.json 上架时订阅资产必已就绪（见工作流发布步骤注释）。
PENDING_PROBE_FILE = "pending_probe.json"
PENDING_RESCUE_FILE = "pending_rescue.json"
# 救援集上限：静态可行但未入拨测样本的节点（「美国不通、中国通」
# lost-and-found 池——样本有配额上限，被挤出的节点仍可能中国可用）。
RESCUE_QUOTA = 100
# 救援集「每协议保底配额」：实测 rescue 池全被 vless（占存活 72%）占满，
# 通过率仅 3.0%；而小众协议通过率更高（anytls 60%、hy2 7.7%）却因数量
# 稀少永选不进。此值保证每协议至少有若干实测机会，再按全局排序填余量。
# 取 5：既给小众协议入场券，又不挤占主流协议主体配额（100/5≈20 协议上限）。
RESCUE_PER_PROTO_MIN = 5
# 交接文档 schema 版本：变更节点字段/语义时递增，沙箱侧据此兼容。
HANDOFF_GENERATOR = "proxysub-handoff/1"
# ---- 主资产归属：CI 候选集 vs 沙箱实测集 ----
# 主资产（p_* 随机名，订阅永久地址指向）的所有权按验证新鲜度切换：
#   verification_report.json 新鲜（<24h 且通过数 ≥15，阈值见下方）→ 主资产归
#     沙箱实测集所有，CI 只发布候选集固定名副本与交接文档（避免发布后即被覆盖的
#     抖动，订阅者长时间拿到实测优选集）；
#   否则（无验证/验证陈旧/沙箱连续未产出）→ CI 兜底把候选集发布到主资产，
#     保证订阅永不枯竭。两侧阈值由此处统一，工作流发布步骤 import 使用。
CANDIDATES_CLASH = "candidates_clash.yaml"
CANDIDATES_SINGBOX = "candidates_singbox.json"
CANDIDATES_V2RAY = "candidates_v2ray.txt"
CANDIDATES_PROXIES_ONLY = "candidates_proxies_only.yaml"
VERIFICATION_REPORT_FILE = "verification_report.json"
# 12h 是 2026-10-17 覆盖事故的直接成因：当时沙箱实测 crontab 仅 2 次/天
# （本地 01:18/08:18），相邻间隔 7h 与 **17h**；17h 空窗 > 12h 窗口，导致每天
# 必有约 5h 的"验证过期"窗口被 CI 兜底成 150 候选集（本地实测可用 <15）。
# 现实测已提频至 4 次/天（每 6h，最大空窗 6h），正常 age 恒 <6h；本阈值转为
# **容错缓冲**：容忍沙箱偶发休眠/漏跑连续 4 次仍不降级。
# 权衡依据：即便 24h 前的实测集（39 个，部分免费节点已失效）也显著优于
# 150 个候选集（本地实测可用 <15）。兜底是"保不枯竭"的降级手段而非常态，
# 故把持有期放宽，避免频繁跌落。超过 24h 仍会兜底，不会永久枯竭。
VERIFICATION_MAX_AGE_S = 24 * 3600
VERIFICATION_MIN_PASSED = 15
PROBE_BATCH = 100
PROBE_CONCURRENCY = 32
# Reserve real-probe slots: Asia heavy, US light.
PROBE_RESERVE_PER_REGION = {
    "🇭🇰 香港": 220,
    "🇯🇵 日本": 180,
    "🇸🇬 新加坡": 160,
    "🇹🇼 台湾": 110,
    "🇰🇷 韩国": 100,
    "🇺🇸 美国": 150,
    "🇬🇧 英国": 30,
    "🌐 其他": 300,
}
# Within each region reserve, probe this many preferred (hy2/reality) first.
PROBE_PREFERRED_PER_REGION = {
    "🇭🇰 香港": 140,
    "🇯🇵 日本": 110,
    "🇸🇬 新加坡": 100,
    "🇹🇼 台湾": 70,
    "🇰🇷 韩国": 60,
    "🇺🇸 美国": 80,
    "🇬🇧 英国": 10,
    "🌐 其他": 100,
}
CANDIDATE_ONLY_PENALTY = 800.0   # nodes only offered by probation sources rank lower
NO_HTTPS_PENALTY = 180.0         # soft: CF HTTPS is a signal, not a sole veto
# TCP-alive without real-ok（仅禁用拨测时出现）: rank worse but still eligible.
NO_REAL_PROBE_PENALTY = 1600.0
MULTI_SOURCE_BONUS = 80.0        # ms-equivalent: appear in multiple official sources
SEEN_DAYS_WEIGHT = 55            # longevity: lifetime seen_days (capped)
MAX_PER_CREDENTIAL = 6           # diversity (slightly looser so floor can be met)
MAX_PER_EGRESS_IP = 3            # diversity (slightly looser)
# Hard rejects only; cf_blocked is soft (many China-usable nodes are CF-risked).
TAMPER_STATUSES = ("tamper_http", "tamper_https", "tls_mitm", "bad_egress")
# 云端拨测 = 「美西可达性」闸门（**口径已修正，2026-10-15**）：
# 历史表述为「连美国都无法代理成功的节点必然已死」，但沙箱实测数据证伪——
# 1292 节点交叉表显示 33 个节点「美西不通、国内通」（其中 29 个是 carryover
# 老节点、4 个是当轮新节点）。美西不通的真实原因多为**该方向路径被墙/QoS**，
# 而非节点死亡（国内方向仍可用）。故本闸门语义严格限定为：
#   ✅ 美西拨测回答「该节点对美西出口是否可达」；
#   ❌ 不冒充「节点死活」判定——死活由 survival 跨天出现史（出现即活）承担。
# ⚠️ 已知取舍：因 CI 先跑、无法预知国内结果，美西不通节点难以在当轮区分
# 「路径被墙（国内可用）」与「真死」。当前缓解手段是 rescue 池（把美西未入样
# 的静态可行节点交沙箱复测，含协议多样化保底）——但实测 rescue 与 pending
# 通过率同档（3% vs 4.7%），故扩大该闸门放宽幅度**无数据支撑**，暂不实施。
# 探测延迟不参与排序（见 TCP_LATENCY_CAP_IN_SCORE）。
REQUIRE_REAL_PROBE_IN_OUTPUT = True
# CF HTTPS trace is soft — do NOT hard-exclude; apply NO_HTTPS_PENALTY instead.
REQUIRE_HTTPS_OK_IN_OUTPUT = False
# Soft latency gate: US runner RTT ≠ China RTT; only drop extreme outliers.
MAX_ACCEPT_LATENCY_MS = 4500.0
MAX_ACCEPT_LATENCY_MS_US = 2800.0  # stricter for US-named / US-egress
# Soft cap: low-tier fill per region after preferred/high (raised to hit 100–200 band).
MAX_LOW_TIER_PER_REGION = 10
# 协议评分（ms 等价，越低越好）：总分 = min(延迟, TCP_LATENCY_CAP_IN_SCORE) + 惩罚 + 加成。
# 刻度参照：协议全档跨度 = -420(hy2) ~ +900(http/socks) ≈ 1320ms，即「协议偏好」最多
# 可抵消约 1.3s 美西 Runner RTT——足以让首选协议压过次优但低延迟节点，又不碾压延迟事实。
# 相邻档位差（40~540）决定排序分层：现代协议内部差距小、明文开放代理一档甩开。
PROTOCOL_BONUS_HY2 = -420.0          # 首选：QUIC 穿透+延迟最优，最大加成
PROTOCOL_BONUS_REALITY = -380.0       # VLESS+Reality 次选；与 hy2 仅差 40（均具伪站指纹，差距小）
PROTOCOL_BONUS_TROJAN = -220.0        # 现代 TLS 伪装；比 reality 弱一档（缺 reality 指纹伪站）
PROTOCOL_BONUS_TLS_OK = -80.0         # 仅普通 TLS 的 vless/trojan：基础加成
PROTOCOL_PENALTY_VMESS = 280.0        # VMess 协议开销大、特征明显且常无 reality：正惩罚
PROTOCOL_PENALTY_SS = 360.0           # SS 抗检测弱、国内易被识别：惩罚更高
PROTOCOL_PENALTY_HTTP_SOCKS = 900.0   # 明文开放代理：纯度最低、最易被墙/滥用，最大惩罚
PROTOCOL_PENALTY_OTHER_LOW = 400.0    # 其他低质明文协议（与 SS 同量级，略低于 http/socks）
# China-friendly feature bonuses (SNI / port / Reality fingerprint).
SNI_WHITELIST_SUFFIXES = (
    "microsoft.com", "apple.com", "cloudflare.com", "icloud.com",
    "gateway.icloud.com", "dl.google.com", "windows.com", "office.com",
    "mzstatic.com", "akamai.net", "akamaized.net",
)
FRIENDLY_PORTS = {443, 8443, 2053, 2083, 2087, 2096}
# 三者加成量级（-80~-120）刻意小于协议档位差：伪装特征只是「加分项」，
# 不喧宾夺主——节点是否可用仍由拨测与协议分层主导。
SNI_BONUS = -120.0                    # SNI 指向白名单大厂：疑似正规业务流量，难被特征识别
PORT_BONUS = -80.0                    # 标准 HTTPS 端口（443 等）：与正常 Web 流量同形
REALITY_FP_BONUS = -100.0             # 具 reality 指纹伪站：抗主动探测，价值高于普通 SNI
# Asia score bonus / US China-path penalties (ms-equivalent).
ASIA_REGIONS = {"🇭🇰 香港", "🇯🇵 日本", "🇸🇬 新加坡", "🇹🇼 台湾", "🇰🇷 韩国"}
ASIA_SCORE_BONUS = -220.0          # 亚洲（港日新台韩）对国内路径友好：加成（与 reality 同量级）
US_REGION_DELAY_PENALTY = 120.0   # 仅命名美国区：轻微延迟惩罚（已放松，不硬歧视）
US_EGRESS_PENALTY_HY2_REALITY = 120.0  # 美国出口+现代协议：最轻（现代协议在美出口下延迟更稳）
US_EGRESS_PENALTY_MID = 180.0      # 美国出口+普通 TLS 协议：居中
US_EGRESS_PENALTY_SS_VMESS = 250.0 # 美国出口+弱抗检协议：最重（SS/VMess 在美出口最易被识别）
MAX_US_SHARE = 0.40               # final list US share <= 40% (no over-discrimination)
CF_BLOCKED_PENALTY = 320.0        # soft purity hit (not hard veto)
US_HOST_HINTS = re.compile(
    r"(digitalocean|vultr|linode|oracle|amazonaws|aws\.amazon|googleusercontent|"
    r"azure|choopa|bandwagon|bwh|contabo|north\s*bergen|secaucus|"
    r"los\s*angeles|new\s*york|dallas|miami|chicago|ashburn|\bSJC\b|\bLAX\b|\bNYC\b)",
    re.I,
)
# Soft purity check: flag CF Error 1005; do not sole-veto (China-usable often CF-risked).
PURITY_URL = "https://grok.com/"
PURITY_TIMEOUT = 6.0

# Cross-day survival: raise weight — multi-day survivors more likely usable from China.
# 刻度：survival_bonus = min(streak, MAX_SURVIVAL_DAYS) * SURVIVAL_WEIGHT，约 28 天封顶
# ≈ 6720ms 加成——足够把「长期存活」推到首选协议之前（存活是可用性最硬的证据）。
SURVIVAL_WEIGHT = 240  # ms 等价：每连续存活 1 天加成（越低越好）
MAX_SURVIVAL_DAYS = 28  # 存活天数上限（防陈旧 streak 无限放大，也对齐多数免费源月级寿命）

# UDP 协议（hysteria2/tuic/hysteria，走 QUIC）：服务器通常不监听 TCP，
# TCP 检查必然失败——这曾把对墙穿透性最好的 hy2 系统性排除出输出
#（12000+ 节点的源里仅漏进 3~8 个）。因此 UDP 协议跳过 TCP 检查，
# 由 mihomo 拨测（QUIC）作为其死活闸门。
UDP_PROTOCOLS = {"hysteria2", "hy2", "tuic", "hysteria", "quic"}

# 跨天存活达到此天数的节点，在 survival 状态新鲜时强制优先进入拨测样本
# （历史稳定性强绑定）。注意：状态一旦陈旧（停更），select_probe_sample 会
# 整体忽略该优先级，防止已死旧节点凭陈旧 streak 霸占拨测预算。
SURVIVAL_STREAK_FORCE_PROBE = 3
# 历史真实通过率加成（过去 N 次运行的 real_ok 比率，见 common.update_survival）
# 150 < SURVIVAL_WEIGHT(240)：历史通过率只是「稳健性佐证」，权重低于连续存活天数；
# 且受陈旧守卫约束（survival 停更则归零），避免陈旧记录误导排序。
HISTORY_PASS_RATE_BONUS = 150.0
SURVIVAL_PASS_WINDOW = 7
# ---- survival.json 僵尸记录清理（prune_survival）----
# 见 score.prune_survival：不仅省体积，更修正「陈旧 seen_days 白送长寿加成」
# 的评分隐患（僵尸记录诈尸复活时会立刻继承中断已久的历史加成）。
# 判据 A：last_seen 距今 > 14 天（长期机制；远大于"连续存活"关注尺度
#   MAX_SURVIVAL_DAYS=28 的一半，给周末停机/调度抖动留足容错，宁留勿删）。
SURVIVAL_PRUNE_IDLE_DAYS = 14
# 判据 B：已中断（streak=0 且非当日）且 seen_days ≤ 此值（项目早期数据仅
#   数天、判据 A 尚不触发时启用）。取 2：出现 1–2 天即消失 = 无历史厚度。
SURVIVAL_PRUNE_ZOMBIE_SEEN_MAX = 2
# 高价值豁免：seen_days ≥ 此值的节点无论多久未出现都保留（历史有长期价值）。
SURVIVAL_PRUNE_KEEP_SEEN = 3

# 指纹计算时忽略的易变字段：改名不影响节点身份；latency/history 是运行期数据。
FINGERPRINT_IGNORE_KEYS = {"name", "latency", "history"}

# transport network 合法性（mihomo/FlClash 可加载的值）；别名见 NETWORK_ALIASES。
VALID_NETWORKS = {"tcp", "ws", "http", "h2", "grpc"}
NETWORK_ALIASES = {"raw": "tcp"}  # Xray 新命名 -> mihomo 等价值
