#!/usr/bin/env python3
"""中国出口节点实测（沙箱侧）——Phase 1 核心工作者。

定时任务（北京 01:18/07:18/13:18/19:18 四轮，cron 看门狗每 2h 巡检保活；
等不到新轮次顺延、不丢失）启动本脚本：

  1. 自检：沙箱自身网络必须直连可用（否则节点全挂是冤枉的）；
  2. 下载 CI 交接文档 pending_probe.json / pending_rescue.json，按
     round_id 与上轮报告 tested_round 做**轮次闸门**：新轮次立即测
     （文档只是节点清单，活性由实时拨测决定，年龄不是新鲜信号）；
     已测过则轮询等待新轮次至多 --max-wait 分钟（默认 20，受定时
     任务 1800s 超时约束）；等不到则仅测 carryover——未测轮次顺延
     至下一实测轮测试，不丢失；
  3. carryover：解析当前主资产（p_*_c.yaml，上一轮发布集）——实测集滚动
     携带，本轮未通过的节点自然淘汰（免费节点寿命以小时计，自清洁）；
  4. 预算裁剪：按剩余时间预算（--budget，默认 1800s 对齐任务超时）裁剪
     测试集——rescue 先裁、pending 次之、carryover 不裁；未测节点由 CI
     下轮待测文档从当前候选池重新生成时再现，不丢失；
  5. mihomo 并发拨测（external-controller delay API，gstatic generate_204，
     HTTPS+204 双信号），通过节点**单次切组并行**收集出口 IP/地区证据与
     AI 服务可达性（chatgpt/claude/gemini/copilot/openai_api 状态码，
     证据+排序信号，不构成闸门）；
  6. 合并发布：通过节点构建验证集（clash + sing-box + v2ray + proxies-only），
     AI 可用节点排前（订阅顺序即用户可见性顺序），覆盖发布到主资产 p_*
     （订阅永久地址不变），并发布 verification_report.json（证据 + 统计，
     CI 据此切换主资产所有权）；
  7. 熔断：自检失败/mihomo 起不来/通过数 < VERIFICATION_MIN_PASSED 时
     绝不发布主资产（保留上一轮验证集或 CI 兜底候选集），仅出报告。

所有权约定（与 CI 工作流联动）：
  - 验证新鲜时主资产归本脚本；CI 只发布 candidates_* 与 pending_*；
  - 验证陈旧（连续未产出）时 CI 兜底把候选集发布到主资产。

用法：
  GH_TOKEN=... python3 scripts/cn_probe.py [--dry-run] [--max-wait 20]
  [--budget 1800]
  GH_TOKEN 由调度 prompt 从 /root/.github_pat（持久化 PAT）注入。
"""

from __future__ import annotations

import argparse
import datetime
import glob
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

# 已知持久化 PAT 路径（沙箱内）；环境变量为空时自动兜底载入。
# 绝不可因环境变量为空就断言"没有 token"——见仓库根目录 AGENTS.md。
PERSISTED_PAT_PATH = os.environ.get("PERSISTED_PAT_PATH", "/root/.github_pat")

import common  # noqa: E402
import config  # noqa: E402
import yaml  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gh_compat  # noqa: E402  - GitHub Release 读写适配（gh 优先，REST 兜底）
import xlock  # noqa: E402  - 跨平台文件锁（POSIX flock / Windows msvcrt）

try:
    from output import write_outputs  # noqa: E402
    from score import classify_proxy  # noqa: E402
except Exception:  # 仓库模块缺失时明确失败（脚本与仓库同版本发布）
    write_outputs = None
    classify_proxy = None

# 直连 opener（任务#121）：测量类请求必须绕开一切环境代理。
# 家宽机器上通常常驻 FlClash/Clash（本机 127.0.0.1:7890），若 HTTP(S)_PROXY
# 泄进探针进程，`sandbox_selfcheck` 会变成"经代理能通"（自检失去意义），
# `_sandbox_ip` 会回报代理出口 IP 而非家宽出口（报告字段直接失真）。
# 显式空 ProxyHandler = 无论环境变量怎么写都直连。
_DIRECT_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

GENERATE_204 = "https://www.google.com/robots.txt"
# 真实流量测试：必须是中国大陆被封锁、只有经代理才能访问的海外地址。
# 早期用 robots.txt / cdn-cgi/trace「几行字」+ 403/非空 body 兜底作判据，放行大量
# 「能握手但下载龟速」的伪可用节点（用户本地实测即暴露无效）。2026-10-17 改为
# 「硬超时真实下载速度」闸门（见 real_traffic_test / _timed_download）。
REAL_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=50000000"  # 50MB，够跑满
# 多源交叉验证（2026-10-26，全面调研后重写测速机制）：
# 实证根因——单源测速会被三类假象误导：①机场对已知测速域名（speed.cloudflare.com）
# 做 QoS 白名单/劫持，测出「先快后断」的假速度；②目标站对代理出口 IP 限流
# （实测 SGP2 直接返回 HTTP 429）；③节点对单一 CDN 路由差、对另一 CDN 正常
# （实测 SG14 在 CF 96KB/s、在阿里云镜像 787KB/s）。
# 调研结论（ipok.io 双源交叉、跨界测速指南、机场 QoS 识别讨论）：必须用
# **互不相关的多套基建**交叉验证，任一源异常不单独定性。
SPEED_SOURCES = [
    # (名称, URL, 权重说明)
    ("cloudflare", "https://speed.cloudflare.com/__down?bytes=50000000"),
    # OVH 法国骨干网测速站：与 CF 完全独立基建，单线程大文件
    ("ovh", "https://proof.ovh.net/files/100Mb.dat"),
    # 阿里云公共镜像：国内 CDN 回源海外，反映「回国链路」质量，
    # 也是用户实际刷国内站点的体感来源（且不易被机场针对性 QoS）
    ("aliyun", "https://mirrors.aliyun.com/ubuntu/ls-lR.gz"),
]
# 测速引擎改用 curl（2026-10-26 实证）：urllib 在经代理下载大体量数据时
# 频繁抛 "TLS/SSL connection has been closed (EOF)" 直接计 0，而同一时刻
# curl 能拿到真实速度——引擎本身的缺陷会把好节点误判为死节点。
# curl 还天然支持 --max-time 整体硬超时与 %{speed_download} 实测速率。
SPEED_TEST_TIMEOUT_S = 10        # 单源单次测速硬超时（秒）
# 快档：至少 2 个源各自达到该速率才算真快（单源达标可能是该源被特殊优化）
REAL_MIN_BYTES_PER_SEC = 128 * 1024   # 128KB/s ≈ 1Mbps，网页/视频可用底线
SPEED_MIN_SOURCES_OK = 2              # 通过源数下限（共 3 源交叉）
# 源能力差异（2026-11-04 实证，任务#117）：三个测速源的固有上限天差地别——
# 沙箱直连 CF 6356KB/s、OVH 3126KB/s、阿里云 15716KB/s，但经免费节点代理后
# 阿里云中位 72KB/s、OVH 中位 61KB/s、CF 中位 0KB/s。用统一的 128KB/s 去卡
# 每个源，等于要求 OVH 这条慢链路达标——本轮 4 个「阿里云 306~1054KB/s」的
# 好节点就因「只有 1 源达标 < 2」被整批判死，是「节点越来越少」的直接成因。
# 改为双档判据：1 源强达标（≥128KB/s）即可，或 2 源弱达标（≥48KB/s）。
WEAK_MIN_BPS = 48 * 1024              # 弱达标速率下限（≈384Kbps，能开网页）
WEAK_MIN_BYTES = 256 * 1024           # 弱达标下载量下限（防「慢慢凑数」）
FLOW_MIN_BYTES = 256 * 1024           # 「该源确有真实流量」的计数门槛
# 稳定性采样（2026-10-26）：单次测速只反映瞬时。「先快后断」的节点第一次
# 能到 768KB、5 分钟后归零（实证 8 个发布节点里 6 个如此）。故要求分两个
# 时间窗口各测一次，两次都达标才算稳定。
SPEED_STABLE_GAP_S = 8           # 两次采样间隔
REAL_MIN_BYTES = 768 * 1024   # 单次采样至少下载 768KB（≈96KB/s）才算真能应用
# 慢档阈值（2026-10-24 任务#97）：8s 内有真实流量但不足快档——「能连但慢」。
# 这类节点不进主资产（快档标准不放松），但进第二资产 p_*_d.yaml 供用户备选。
# 依据：用户本地测速只要求「有延迟反应」，32KB（≈4KB/s）即有明显体感；
# 旧口径一刀切淘汰了大批「能连但慢」节点，是 326 节点源 0 通过的成因之一。
REAL_SLOW_MIN_BYTES = 32 * 1024
# 主资产延迟上限（2026-10-24 设立 2500ms → 11-04 收紧 1500ms → 11-04 回调 3000ms）。
# 回调理由（任务#117 自我纠错）：1500ms 的依据是「用户客户端实测 2646ms 起全超时」，
# 但**客户端 RTT ≠ 沙箱 RTT**——两者路由、TLS 栈、并发度都不同，不能直接换算。
# 本轮实证反例：RTT 1839ms / 3297ms 的节点真实下载 12.9MB / 11.4MB、398 / 659KB/s，
# 是全批仅有的两个真快节点，却被 1500ms 闸门踢出主资产；而提级进来的 1064/1414ms
# 节点速度只有 114/96KB/s。**延迟高但吞吐好 = 握手慢链路通，不该当废节点**。
# 结论：速度是硬判据，延迟降为排序因子 + 5000ms 极端兜底（挡真死节点）。
CN_MAX_PUBLISH_LATENCY_MS = 3000
REAL_PROBE_URLS = [           # 仅作出口可达性辅助参考，不再单独作为闸门
    "https://www.google.com/robots.txt",
    "https://www.cloudflare.com/cdn-cgi/trace",
]
GEO_URLS = ["https://cip.cc", "https://myip.ipip.net", "http://ip-api.com/json"]
# AI 服务可达性探测（2026-10-20 新增）。背景：沙箱诊断发现已发布的 29 个
# 节点中 13 个对全部 5 个 AI 域无任何 HTTP 响应，而既有闸门只验证
# Google/Cloudflare 可达，对「能否连 AI」完全盲视——订阅地址节点数长期
# 停在 29 且用户实际不可用的重要原因之一。判据要点（v1 诊断实测踩坑后确立）：
#   ① 任何 HTTP 响应（含 403/302/401）都算「可达」——403 是 Cloudflare
#      区域拦截（服务在、该出口被拒），与「无响应」必须分开记录；
#   ② api.openai.com 返回非 403（典型 401 无密钥响应）⇒ API 层未被区域
#      封锁，是「真 AI 可用」的最强信号；chatgpt.com 403 ≠ API 不可用；
#   ③ 禁用 curl -f / urllib 抛异常判失败——它们把 403/404/401 吞成失败，
#      正是 v1 诊断结论全盘失真的原因。
# 探针 URL 一律用站点根路径（早期 v1 用 /cdn-cgi/trace，非 Cloudflare 站点
# 没有该路径，404 被误读为「不可达」）。
AI_TARGETS = {
    "chatgpt": "https://chatgpt.com/",
    "claude": "https://claude.ai/",
    "gemini": "https://gemini.google.com/",
    "copilot": "https://copilot.microsoft.com/",
    "openai_api": "https://api.openai.com/v1/models",
}
AI_TIMEOUT_S = 8
AI_CONCURRENCY = 5     # 单节点 5 个 AI 域并行（共享同一 PROBE 选择，节点间必须串行）
EVIDENCE_CONCURRENCY = 8   # 单节点证据总并行度：GEO 3 源 + AI 5 域（任务#91 合并）
# 证据收集时间预算（秒）：2026-10-21 合并（任务#91）——原 GEO 与 AI 是两个
# 顺序循环、各 120s 预算，36 节点实测每循环各覆盖 18 个（各跳一半，一半
# 节点没有 AI 数据）。合并为单次切组 + 8 路并行后，单节点耗时从
# GEO(≤24s)+AI(≤8s) 降为 ≈ max(8s)，同预算内可全覆盖典型通过规模。
# 实测修正（同日）：8 路并行经同一节点有带宽争抢，且 urllib socket timeout
# 是每次 recv 超时——龟速节点上 gemini 302 链实测耗时 24.31s，单节点均摊
# 10.5s、120s 仅覆盖 13/28。已加线程级硬超时（_hard_timeout_call：
# socket 8s + 硬截断 10s）封顶单请求成本。
# 证据仅留痕、不构成闸门，无数据不影响发布。耗时上界：真实流量 ~24s +
# 证据 ≤120s + 发布 ~60s ≈ 204s < PUBLISH_RESERVE_S 300s。
EVIDENCE_BUDGET_S = 120
MIHOMO_VERSION = os.environ.get("MIHOMO_VERSION", "v1.19.32")

# 测量 vantage 标签（任务#121）：同一份代码既可在沙箱跑，也可在本机家宽跑。
# 二者网络路径不同（沙箱出口 vs 家宽出口），报告必须能区分——「沙箱测着活、
# 本地用着死」的复盘全靠这两个口径分开统计。默认值保持沙箱不变，避免既有
# 历史数据出现断层。
VANTAGE_LABEL = os.environ.get("PROXYSUB_VANTAGE", "cn-hn-sandbox")
DELAY_TIMEOUT_MS = 5000
DELAY_CONCURRENCY = 16  # 2026-10-27：12→16，提高单轮覆盖（用户痛点「可用节点太少」）
REAL_TRAFFIC_TIMEOUT_S = 8    # 真实下载硬超时预算（秒）
# 并发下调（2026-10-26）：多源交叉 + 两轮采样让单节点耗时增至约 60s
# （3源×10s + 间隔8s + 3源×10s），12 并发会互相抢带宽、把「快节点」
# 压成「慢节点」——测速并发必须低于节点带宽承载，否则自己制造假阴性。
REAL_TRAFFIC_CONCURRENCY = 6
# 出口证据节点数上限（顺序取证时代的限量残留；预算由 EVIDENCE_BUDGET_S
# 统一封顶，此上限仅在极端通过规模下兜底）。
GEO_MAX_NODES = 120
# GEO socket 超时（5s）**低于** AI_TIMEOUT_S（8s）：实测单节点成本常被
# cip.cc 的 8s 超时主导（myip/ip-api 1~2s 即回），而 GEO 证据是信息性的
# （仅喂 cn_history.cn_egress，非闸门）——三源并行取首个成功，收紧 GEO
# 超时不丢证据（另两源兜底），却能把预算内覆盖节点数提升 ~60%。
# AI 状态码是排序信号，值得满 8s。两者硬截断分别为 7s/10s（_hard_timeout_call）。
GEO_TIMEOUT_S = 5
SELFCHECK_URLS = ["https://www.baidu.com", "https://api.github.com"]
ASSET_RE = re.compile(r"^p_[0-9a-f]+_([cpsvd])\.(yaml|json|txt)$")
ASSET_FORMAT = {"c": "clash", "p": "proxies_only", "s": "singbox", "v": "v2ray",
                "d": "degraded"}
VERIFIED_FILE = {
    "clash": "verified_clash.yaml",
    "proxies_only": "verified_proxies_only.yaml",
    "singbox": "verified_singbox.json",
    "v2ray": "verified_v2ray.txt",
}

# 闸门轮询默认窗口（分钟）：受定时任务超时上限 1800s 约束——轮询
# 20min + 有界工作（自检/下载/拨测/取证/发布 ≈6.5min）+ 代理开销，
# 必须留余量。等不到新轮次不影响正确性：该轮次由轮次闸门顺延到
# 下一实测轮测试（不丢失），本轮退化为仅测 carryover 保订阅新鲜。
PENDING_POLL_WINDOW_MIN = 20
# 总时间预算（秒）：与定时任务 timeout 对齐（scheduler-api 上限）。
# 本轮实测 1193 节点端到端 902s（拨测 ~0.62s/节点）；但轮询等待
# 最多 20min 会挤占预算，最坏 1200+902=2102s 击穿超时——故按
# 剩余预算裁剪测试集（见 cap_test_set）。
TASK_BUDGET_S = 1800
# 拨测后预留（秒）：真实流量测试 + 证据收集（GEO+AI 合并，≤EVIDENCE_BUDGET_S）
# + 多格式输出 + 发布 + 收尾开销。真实流量测试加入后，通过节点需经 mixed-port
# 二次访问海外目标，预留从 300s 提升到 360s。
# 2026-10-21 重算（任务#91）：证据段从「GEO ≤120s + AI ≤120s 两个顺序循环」
# 合并为单次切组 8 路并行（≤120s 封顶），预留按 真实流量 ~24s + 证据 ≤120s
# + 发布 ~60s ≈ 204s 估算，降为 300s（留 ~47% 余量）。
PUBLISH_RESERVE_S = 300
# 单节点拨测耗时悲观估计（秒），用于 cap_test_set 预算裁剪。
# 实测耗时构成：delay 初筛（并发 12，约 0.66s/节点，是绝对大头）
# + 真实流量终筛（仅对 delay 通过的少数节点跑，1142 节点轮仅 6s 边际，
# 已被并发+少数稀释、可忽略）。故 PER_NODE_S 只需覆盖 delay 初筛成本，
# 取 1.2 留约 80% 余量吸收个别慢节点/抖动即可。
# 2.0 是过度保守——2026-10-17 一例，误以为真实流量终筛会对每节点翻倍
# 耗时，把 PER_NODE_S 从 1.0 误调到 2.0，导致本轮无故裁剪 413 个待测节点。
PER_NODE_S = 1.2

# 纯 carryover 轮次「保留已发布集」允许的波动带（节点数）。当本轮没有新 CI
# 待测文档（测试集全为 carryover）且重测通过数比已发布集少 ≤ 该值时，视为正常
# 单快照波动（用户自述约 6 个节点浮动），整体保留已发布集而非发布更小的重测
# 子集，避免逐轮侵蚀（39→37→…）违背「固化」诉求；超过该值视为真实退化，走
# 正常自清洁（发布重测通过的子集）。新 CI 轮次（含 pending/rescue）不受此约束。
CARRYOVER_FLUCTUATION_BAND = 8

# ---- 断点续跑（任务#120，2026-11-05）---------------------------------------
# 背景：沙箱按「无活动即休眠」回收，实测轮被杀的位置高度集中在 delay 初筛
# 之后（2026-11-05 的 07:21、13:13 两轮均如此）。此前拨测结果只存在内存
# dict，进程一被杀即整轮白跑：初筛耗时白烧，下一轮从头再来，实测产能被
# 反复清零——这是「13h 未刷新主资产」在执行侧的成因（守护侧另见 #120 的
# 冷却语义修复）。
# 对策：把逐节点结果增量落盘，重启时按「测试集签名」复用。签名只由测试集
# 的 probe_name 集合决定：同一批节点才复用，测试集变了（新交接文档 / 新
# carryover）签名即变、旧检查点自动作废，不会张冠李戴。
CHECKPOINT_FILE = "probe_checkpoint.json"
# 复用有效期（秒）：免费节点寿命以小时计，旧结果不再可信。默认 45 分钟，
# 覆盖「被杀 → 沙箱唤醒 → 守护补跑」的典型间隔，又不至于跨轮复用。
CHECKPOINT_TTL_S = int(os.environ.get("PROXYSUB_CHECKPOINT_TTL_S", "2700"))
# 增量落盘节流（秒）：太密拖慢拨测，太疏丢失已完成的工作。
CHECKPOINT_FLUSH_S = float(os.environ.get("PROXYSUB_CHECKPOINT_FLUSH_S", "15"))


def checkpoint_signature(probe_names: list[str]) -> str:
    """测试集签名：节点名集合 + 数量。集合变了签名就变，旧检查点自动作废。"""
    h = hashlib.sha1()  # noqa: S324 - 仅作集合指纹，非安全用途
    for name in sorted(probe_names):
        h.update(str(name).encode("utf-8", "replace"))
        h.update(b"\x00")
    return f"{len(probe_names)}:{h.hexdigest()[:16]}"


class ProbeCheckpoint:
    """拨测结果的增量检查点（初筛/终筛分阶段，可跨进程复用）。

    只做一件事：让「被打断的轮次」在下次启动时接着跑，而不是从零开始。
    语义边界：
      * 仅在**签名一致且未过期**时复用；
      * 复用不改变判定标准——复用的就是当时同一套 mihomo 探测的结论；
      * 成功发布后由调用方 clear()，避免下一轮误用（新一轮必须重新实测，
        活性由实时拨测决定，这是项目的核心口径）。
    """

    def __init__(self, workdir: str, signature: str, round_id: str,
                 *, ttl_s: int | None = None,
                 flush_s: float | None = None,
                 now: float | None = None) -> None:
        self.path = os.path.join(workdir, CHECKPOINT_FILE)
        self.signature = signature
        self.round_id = round_id
        self.ttl_s = CHECKPOINT_TTL_S if ttl_s is None else ttl_s
        self.flush_s = CHECKPOINT_FLUSH_S if flush_s is None else flush_s
        self.now = now
        self.delay_done: set[str] = set()
        self.real_done: set[str] = set()
        self.results: dict[str, dict] = {}
        self._last_flush = 0.0
        self._dirty = False

    def _ts(self) -> float:
        return time.time() if self.now is None else self.now

    def load(self) -> tuple[set[str], set[str], dict[str, dict]]:
        """读检查点。签名不符 / 过期 / 损坏 / 缺字段一律当作不存在。"""
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return set(), set(), {}
        if not isinstance(data, dict) or data.get("signature") != self.signature:
            return set(), set(), {}
        try:
            age = self._ts() - float(data.get("saved_at") or 0)
        except (TypeError, ValueError):
            return set(), set(), {}
        if age < 0 or age > self.ttl_s:
            return set(), set(), {}
        results = data.get("results") if isinstance(data.get("results"), dict) else {}
        self.results = {k: v for k, v in results.items() if isinstance(v, dict)}
        self.delay_done = set(self.results)
        # 终筛已做的判据是「有 real_traffic 字段」：主循环对每个进入终筛的
        # 节点都无条件写入该字段（无论通过与否），故它等价于「该节点已定论」。
        self.real_done = {k for k, v in self.results.items() if "real_traffic" in v}
        return set(self.delay_done), set(self.real_done), dict(self.results)

    def mark_delay(self, name: str, result: dict) -> None:
        self.results[name] = dict(result)
        self.delay_done.add(name)
        self._dirty = True
        self.flush()

    def mark_real(self, name: str, result: dict) -> None:
        self.results[name] = dict(result)
        self.real_done.add(name)
        self._dirty = True
        self.flush()

    def flush(self, force: bool = False) -> None:
        """节流落盘（原子写：临时文件 + os.replace，避免半截 JSON 被复用）。"""
        if not self._dirty:
            return
        now = self._ts()
        if not force and now - self._last_flush < self.flush_s:
            return
        payload = {
            "version": 1,
            "signature": self.signature,
            "round_id": self.round_id,
            "saved_at": now,
            "results": self.results,
        }
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, default=str)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            self._last_flush = now
            self._dirty = False
        except OSError:
            # 检查点写失败不致命：最坏结果退化为「整轮重跑」，与修复前一致。
            pass

    def clear(self) -> None:
        """删除检查点（成功发布后调用，防下一轮误用旧结论）。"""
        for p in (self.path, self.path + ".tmp"):
            try:
                os.unlink(p)
            except OSError:
                pass
        self.delay_done.clear()
        self.real_done.clear()
        self.results.clear()
        self._dirty = False



ASSET_FORMAT_REV = {"clean_proxies_only.yaml": "proxies_only",
                    "clean_singbox.json": "singbox",
                    "clean_v2ray.txt": "v2ray"}


def default_tag() -> str:
    """Release tag：与 CI 工作流同源（anti_crawl.json 的 release_tag）。"""
    try:
        with open(os.path.join(REPO_ROOT, "anti_crawl.json"), encoding="utf-8") as f:
            return json.load(f).get("release_tag") or "sub"
    except Exception:
        return "sub"


def log(msg: str) -> None:
    print(f"[cn-probe {datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def run(cmd: list[str], timeout: int = 120, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def upload_asset_with_retry(tag: str, staged: str,
                            attempts: int = 3) -> tuple[bool, str]:
    """上传 Release 资产并重试（任务#116，纯 I/O 封装）。

    实证：2026-11-04 09:36 上传 clash 资产返回 HTTP 502，旧实现只记一条警告
    就继续——结果 clash 停在上一轮的 12 个旧节点、其余格式已是新的 2 个，
    用户订阅各格式内容不一致（clash 用户仍在用废节点）。GitHub Release
    上传偶发 5xx 属常态，必须退避重试。

    实现走 gh_compat（gh 优先、REST 兜底）：本机无 gh 时仍可上传，
    沙箱里 gh 偶发 5xx/挂起时也多一条可用路径。
    """
    last = ""
    for i in range(max(1, attempts)):
        ok, err = gh_compat.upload_asset(tag, staged)
        if ok:
            return True, ""
        last = (err or "").strip()[:200]
        if i < attempts - 1:
            time.sleep(2 * (i + 1))
    return False, last


def _upload_report(tag: str, path: str) -> None:
    """上传 verification_report.json（CI 判定主资产所有权的唯一来源）。

    失败必须显式告警：CI 读不到新报告就会认为本 vantage 没有产出，进而兜底
    把候选集覆盖主资产（2026-10-17「五层根因」之一），静默失败代价极高。
    """
    ok, err = gh_compat.upload_asset(tag, path)
    if not ok:
        log(f"警告: 上传 {os.path.basename(path)} 失败: {err}")


def _assets_from_prev_report(report_path: str) -> list[dict]:
    """从上一轮 verification_report.json 反推主/第二资产名（任务#121 兜底）。

    `main_assets` 是上一轮**实际发布成功**的资产名列表，`degraded_asset` 是
    第二资产——两者合起来足以支撑 carryover 加载，不需要再查 Release API。
    读取失败一律返回空列表（调用方按「无 carryover」降级，行为与改动前一致）。
    """
    try:
        with open(report_path, encoding="utf-8") as f:
            rep = json.load(f)
    except (OSError, ValueError):
        return []
    names: list[str] = []
    for n in (rep.get("main_assets") or []):
        if isinstance(n, str) and n:
            names.append(n)
    deg = rep.get("degraded_asset")
    if isinstance(deg, str) and deg:
        names.append(deg)
    return [{"name": n} for n in dict.fromkeys(names)]


def gh_download(tag: str, pattern: str, dest: str, retries: int = 1) -> bool:
    """下载 Release 资产：优先 gh，失败/超时自动回退 curl（Bearer token）。

    回退原因（grok 2.4）：实测某些沙箱环境下 `gh release download` 会长时间
    挂起无响应，而直连 `curl` 走 API 更稳定。两者任一成功即视为下载成功。

    ⚠️ 健壮性铁律（2026-10-17 续）：gh 与 curl 的挂起都表现为
    `subprocess.TimeoutExpired`（**异常**），而非非零返回码。早期实现只判
    `returncode`、未捕获超时异常，于是一次网络抖动就让 `gh_download` 抛异常、
    整脚本崩溃——本次重测即因此：curl 下载 `pending_rescue.json` 超时 120s、
    异常未捕获，新轮次实测尚未开始就崩。现改为：gh + curl 两路**均显式捕获
    TimeoutExpired**，整函数重试 `retries` 次，最终仍失败**优雅返回 False**
    （绝不抛出），由调用方决定降级策略（如 rescue 缺失则退化为 carryover 实測）。
    """
    last_err = "未执行"
    for attempt in range(retries + 1):
        # 单一入口交给 gh_compat：gh 优先、失败自动回退直链下载。
        # 直链对公开仓库免 token——这是本机（Windows，无 gh）能跑通实测的前提。
        try:
            if gh_compat.download_asset(tag, pattern, dest, timeout=60):
                return True
            last_err = "gh 与直链均失败"
        except subprocess.TimeoutExpired:
            last_err = "下载超时"
            log(f"提示: 下载 {pattern} 超时")
        except Exception as e:  # noqa: BLE001 - 下载失败绝不向上抛
            last_err = f"{type(e).__name__}: {e}"
        if attempt < retries:
            log(f"下载 {pattern} 失败（{last_err}），8s 后重试（第 {attempt + 2}/{retries + 1} 次）")
            time.sleep(8)
    log(f"熔断: 下载 {pattern} 重试 {retries} 次仍失败（{last_err}）——将由调用方降级处理")
    return False


def auth_selfcheck(required: bool = True) -> bool:
    """鉴权自检（grok 2.3）：GH_TOKEN 缺失或凭据无效则立即失败，避免空转。

    `required=False` 用于 `--dry-run`：本机验证链路时常常还没有 PAT，而
    匿名足以读取公开 Release；dry-run 本来就不发布，不必被 token 挡住。

    返回 True 表示可继续；False 表示应非 0 退出。

    注（2026-10-15 复盘）：本函数的失败信息必须给出「去哪找凭据」的指引，
    否则 AI 协作者容易把「环境变量为空」误判为「没有 token」——项目里有持久化
    PAT，路径见下方提示与仓库根目录 AGENTS.md。
    """
    # 自动兜底：环境变量缺失时，从已知持久化路径补充（避免误判"没有 token"）。
    # 候选路径由 gh_compat 统一维护：沙箱 /root/.github_pat、家宽 ~/.proxysub_pat。
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        token = gh_compat.token()
        if token:
            os.environ["GH_TOKEN"] = token
            log("提示: 环境变量无 token，已载入凭据（来源: "
                + gh_compat.token_source() + "）")
    if not token:
        if not required:
            log("提示: dry-run 且无 token——仅匿名读取公开 Release，本轮不发布")
            return True
        _paths = " / ".join(gh_compat.pat_paths())
        log(
            "熔断: 环境变量 GH_TOKEN/GITHUB_TOKEN 均未设置，且持久化路径"
            f"（{_paths}）均不存在——无法读写 Release，中止。\n"
            "  【给 AI 协作者】本仓库凭据存在多处，环境变量通常为空，"
            "绝不等于\"没有 token\"。断言前请依次检查：\n"
            f"    ① 持久化 PAT 文件: {_paths}（本机放 ~/.proxysub_pat）\n"
            "    ② 项目文档: docs/cn_probe.md、scripts/cn_probe.py、monitor_1617_run.py\n"
            "    ③ 环境变量: GH_TOKEN / GITHUB_TOKEN\n"
            "  正确用法: export GH_TOKEN=\"$(cat /root/.github_pat)\"（沙箱）\n"
            "  完整规则见仓库根目录 AGENTS.md。"
        )
        return False
    # gh 自动从 GH_TOKEN 读取；有 gh 时用 `gh auth status`（含 401 检测），
    # 没有 gh（本机 Windows）时打一次 REST /user——同一件事两种通道，
    # 否则本机连「token 是否可用」都无法自检。
    ok, detail = gh_compat.auth_ok()
    if not ok:
        log(
            f"熔断: 鉴权失败（{detail}）——中止。\n"
            f"  【给 AI 协作者】token 可能已失效/轮换，请核对 "
            f"{' / '.join(gh_compat.pat_paths())} 是否为最新，"
            "并参考 AGENTS.md 的凭据规则。"
        )
        return False
    log(f"鉴权自检通过: {detail}")
    return True


def _official_url_map() -> dict:
    """构造 src_key(url) -> url 映射（任务#117）。

    报告里 by_source 的键是 `owner/repo`，而 source_scores.json 的主键是完整
    URL。不传映射时 evolution 会写「影子短键」，主 URL 永远拿不到 cn 维度——
    实证 79 源仅 26 个有 cn 实证，头部零产源（311 测 0 通过）恰好是盲区。
    """
    try:
        with open(os.path.join(REPO_ROOT, "sources.json"), encoding="utf-8") as f:
            src = json.load(f)
    except Exception:
        return {}
    out: dict = {}
    for u in (src.get("official") or []):
        url = u.get("url") if isinstance(u, dict) else u
        if url:
            out.setdefault(common.src_key(url), url)
    return out


def release_assets(tag: str) -> list[dict]:
    """列出 tag 下的资产。走 gh_compat：有 gh 用 gh，没有走 REST。

    原实现直连 `gh release view`，Windows 本机没有 gh 时恒返回空列表，
    于是 carryover 全丢、只能测候选集——这是「搬到家宽」必须解掉的绑定。
    """
    return gh_compat.release_assets(tag)


def parse_ts(s: str) -> datetime.datetime | None:
    try:
        dt = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return None


# ---------------------------------------------------------------- 轮次闸门
def gate_decision(doc_round: str | None, last_round: str | None) -> str:
    """交接文档闸门判定（轮次比对，替代早期的年龄比对）。

    CI 定时运行受 GitHub 调度器排队影响（实测 18–159 分钟），发布时刻
    不可预期；交接文档本质是「节点清单」，活性由实时拨测决定，故年龄
    不是有效的新鲜信号，「轮次是否测过」才是。新轮次立即测；重度延迟
    未赶上的轮次顺延到下一实测轮——由 cadence 匹配保证不丢失。

    返回 "test"（新轮次，立即测）/ "wait"（无新轮次，可轮候）。
    """
    if doc_round and doc_round != last_round:
        return "test"
    return "wait"


def doc_round_id(path: str) -> str | None:
    """读取交接文档的 round_id（缺失/不可解析返回 None）。"""
    try:
        with open(path, encoding="utf-8") as f:
            rid = json.load(f).get("round_id")
        return str(rid) if rid else None
    except Exception:
        return None


def resolve_tested_round(consumed_round: str | None,
                         last_round: str | None) -> str | None:
    """报告记录的 tested_round：本轮消费的轮次；未消费则继承上轮。

    继承而非清空：仅测 carryover 的轮次若把已测信息抹掉，下一轮会
    重复测试同一文档。
    """
    return consumed_round or last_round


def cap_test_set(nodes: list[dict], budget_s: float,
                 per_node_s: float = PER_NODE_S) -> tuple[list[dict], int]:
    """按剩余时间预算裁剪测试集，返回 (保留集, 裁剪数)。

    轮询等待（至多 20min）会挤占 1800s 预算：本轮实测 1193 节点端到端
    902s，若文档在轮询尾声才出现，1200+902=2102s 必超时。按**优先级
    填充**裁剪（保留集规模恒 ≤ max_nodes，硬保 1800s 不击穿）：
      - carryover 最高优先级（订阅生命线，已发布节点重测开销小）；
      - pending 次之（含最终发布集，订阅骨干）；
      - rescue 最低（救援池产能低——本轮 0/100 通过）；
    未测节点不丢失：CI 下轮待测文档从当前候选池重新生成时再现。
    预算耗尽（max_nodes=0）时返回空集——main() 据此跳过本轮、保留
    上一轮已发布验证集，绝不把规模失控的拨测推过超时线。
    """
    max_nodes = max(0, int(budget_s / per_node_s))
    if len(nodes) <= max_nodes:
        return nodes, 0
    carry = [n for n in nodes if n.get("origin") in ("carryover", "user_pool")]
    pend = [n for n in nodes if n.get("origin") == "pending"]
    resc = [n for n in nodes if n.get("origin") == "rescue"]
    kept: list[dict] = []
    # 优先级：carryover+user_pool（订阅生命线与地面真相）> pending > rescue
    for bucket in (carry, pend, resc):
        room = max_nodes - len(kept)
        if room <= 0:
            break
        kept.extend(bucket[:room])
    return kept, len(nodes) - len(kept)


def _wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson 得分区间（95%）——小样本下比正态近似稳健（n=0 时返回 (0,0)）。

    用于协议分层统计（P2-a）：小样本协议（如 anytls n=8）的朴素通过率极不稳定，
    必须同时给出置信区间，才能避免"看数字下结论"（2026-10-15 复盘教训）。

    实现已上收 `common.wilson_ci`（2026-10-20）：CI 侧源级淘汰/晋升/倾斜判据
    共用同一实现，避免两侧漂移。本包装仅保留原名供既有调用与测试使用。
    """
    return common.wilson_ci(k, n, z)


def _agg_two(nodes: list[dict], verified: list[dict], key_fn,
             *, with_ci: bool = False) -> dict:
    """按 key_fn 聚合 tested/passed 双口径（Phase 2.2，分源/分协议）。

    返回 {key: {"tested": N, "passed": M}}，按通过数降序、再按待测数降序。
    with_ci=True 时额外给出 pass_rate 与 95% Wilson 置信区间（P2-a，分协议用），
    用于判断小样本协议的通过率是否具备统计显著性。
    """
    tested: dict[str, int] = {}
    passed: dict[str, int] = {}
    for n in nodes:
        k = key_fn(n)
        tested[k] = tested.get(k, 0) + 1
    for n in verified:
        k = key_fn(n)
        passed[k] = passed.get(k, 0) + 1
    keys = sorted(tested, key=lambda k: (-passed.get(k, 0), -tested[k]))
    out: dict[str, dict] = {}
    for k in keys:
        t, p = tested[k], passed.get(k, 0)
        row: dict = {"tested": t, "passed": p}
        if with_ci:
            lo, hi = _wilson_ci(p, t)
            row["pass_rate"] = round(p / t, 4) if t else 0.0
            row["ci95_low"] = round(lo, 4)
            row["ci95_high"] = round(hi, 4)
            row["sample_ok"] = t >= config.PROTOCOL_MIN_SAMPLE
        out[k] = row
    return out


def _agg_source_ai(nodes: list[dict], verified: list[dict],
                   results: dict) -> dict:
    """分源聚合：tested/passed + AI 证据三口径（2026-10-21，任务#92）。

    `by_source` 每行由 `{tested, passed}` 扩为 `{tested, passed,
    ai_tested, ai_reachable, ai_api}`。AI 口径只覆盖**有 ai 数据的
    通过节点**——证据收集仅对通过节点执行且受 EVIDENCE_BUDGET_S 约束
    （可能跳过尾部），ai_tested 即该源实际探测数；无 AI 数据的源三项
    记 0 而非缺键（「无证据」与「零」必须可区分，下游按 ai_tested==0
    判无证据）。排序沿用 tested/passed 口径（通过数降序、待测数降序）。

    用途（任务#94 接线）：CI 侧 evolution 据此计算分源 AI 效率，作为
    候选晋升与拨测配额倾斜的**有效性**判据——源的反哺口径必须是节点
    真实可用性（cn 通过 + AI 可达），而非独有性等代理指标。
    """
    rows = _agg_two(nodes, verified, key_fn=lambda n: n["src"])
    ai_t: dict[str, int] = {}
    ai_r: dict[str, int] = {}
    ai_a: dict[str, int] = {}
    for n in verified:
        ai = results.get(n["probe_name"], {}).get("ai")
        if not ai:
            continue
        k = n["src"]
        ai_t[k] = ai_t.get(k, 0) + 1
        if ai.get("ai_reachable"):
            ai_r[k] = ai_r.get(k, 0) + 1
        if ai.get("ai_api"):
            ai_a[k] = ai_a.get(k, 0) + 1
    for k, row in rows.items():
        row["ai_tested"] = ai_t.get(k, 0)
        row["ai_reachable"] = ai_r.get(k, 0)
        row["ai_api"] = ai_a.get(k, 0)
    return rows


# ---------------------------------------------------------------- 自检
def sandbox_selfcheck() -> bool:
    for url in SELFCHECK_URLS:
        try:
            req = urllib.request.Request(url, method="HEAD")
            with _DIRECT_OPENER.open(req, timeout=10) as resp:
                if resp.status < 400:
                    return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------- 节点装载
def load_doc_nodes(path: str, origin: str) -> list[dict]:
    """交接文档 -> 节点记录（clash 原生 proxies 直接可用）。"""
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except Exception as e:
        log(f"警告: 解析 {os.path.basename(path)} 失败: {e}")
        return []
    nodes = []
    for n in doc.get("nodes", []):
        proxy = n.get("proxy")
        if not isinstance(proxy, dict) or not proxy.get("server"):
            continue
        nodes.append({
            "fp": n.get("fp") or common.fingerprint(proxy),
            "name": str(n.get("name") or proxy.get("name") or "node"),
            "proxy": proxy,
            "origin": origin,
            "final": bool(n.get("final")),
            "us_ok": bool(n.get("us_ok")),
            "src": str(n["src"]) if n.get("src") else None,
        })
    return nodes


def load_carryover(main_clash: str) -> list[dict]:
    """当前主资产（上一轮发布集）-> carryover 节点（滚动携带+自清洁）。"""
    if not os.path.exists(main_clash):
        return []
    try:
        with open(main_clash, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception as e:
        log(f"警告: 解析主资产失败: {e}")
        return []
    nodes = []
    for p in cfg.get("proxies", []) or []:
        if not isinstance(p, dict) or not p.get("server"):
            continue
        nodes.append({
            "fp": common.fingerprint(p),
            "name": str(p.get("name") or "node"),
            "proxy": dict(p),
            "origin": "carryover",
            # final 语义修正（2026-10-24 任务#96）：final = 本轮实测通过，
            # 由 main() 在拨测通过后统一置位。carryover 继承自上一轮发布集，
            # 上一轮通过≠本轮通过，此处不再硬编码 True（否则报告 nodes[] 里
            # 未复测/未通过的 carryover 节点会带着 final=True「带病上榜」，
            # 且 verified_rank 的双 vantage 判据被继承标记污染）。
            "final": False,
            "us_ok": False,  # 上一轮是美国视角，未知；仅作参考
        })
    return nodes


def load_slow_carryover(workdir: str, exclude_fps: set[str]) -> list[dict]:
    """第二资产（慢档）-> 回炉复测节点（2026-10-28 修复）。

    旧实现只从主资产加载 carryover：节点一旦降级慢档就永远退出测试集，
    即使下一轮已恢复也再无机会——「AI 慢档提级」设计因此空转（实证：
    6 个存活的 carryover 慢档节点滞留第二资产，其中含用户本地实测可用的
    节点）。此处从本地最新慢档资产加载，按 fingerprint 去重（与主资产
    carryover / 待测池重叠者跳过），origin 仍标 carryover。
    """
    cands: list[str] = []
    for pat in ("p_*_d.yaml", "verified_degraded_clash.yaml"):
        cands += glob.glob(os.path.join(workdir, pat))
    if not cands:
        return []
    path = max(cands, key=os.path.getmtime)  # 只取最新一份
    try:
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    except Exception as e:
        log(f"警告: 解析慢档资产失败: {e}")
        return []
    nodes = []
    for p in cfg.get("proxies", []) or []:
        if not isinstance(p, dict) or not p.get("server"):
            continue
        fp = common.fingerprint(p)
        if fp in exclude_fps:
            continue
        exclude_fps.add(fp)
        nodes.append({
            "fp": fp,
            "name": str(p.get("name") or "node"),
            "proxy": dict(p),
            "origin": "carryover",
            "final": False,
            "us_ok": False,
        })
    if nodes:
        log(f"慢档回炉: {len(nodes)} 个第二资产节点并入复测集（{os.path.basename(path)}）")
    return nodes


def _lib_path(workdir: str) -> str:
    return os.path.join(workdir, config.NODE_LIBRARY_FILE)


def _epoch_of(stamp) -> float:
    """ISO 时间串 -> epoch 秒；不可解析返回 0（视为最旧）。"""
    try:
        dt = datetime.datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


def save_node_library(nodes: list[dict], workdir: str, stamp: str) -> int:
    """把本轮通过/降级节点的**完整配置**存档（任务#117），供后续轮次跨源复测。

    动机：carryover 只从「上一轮主资产 + 上一轮第二资产」滚动。节点连续两轮
    没通过（晚高峰拥堵很常见）配置即彻底丢失——实测 cn_history 存着 781 个
    「历史通过过」的指纹、338 个「通过 ≥3 次」，本地却一个配置都找不回
    （clean_clash 仅 60 个）。没有节点库，订阅数量只能随源供给波动，
    这是「时多时少」的机制根源。

    只存通过/降级（有真实流量）的节点，不存从没通过的——避免库里沉淀垃圾。
    """
    path = _lib_path(workdir)
    lib: dict = {}
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                lib = (json.load(f) or {}).get("nodes") or {}
        except Exception:
            lib = {}
    now = time.time()
    added = 0
    for n in nodes:
        p = n.get("proxy")
        if not isinstance(p, dict) or not p.get("server"):
            continue
        rec = lib.get(n["fp"]) or {"passes": 0}
        rec["proxy"] = dict(p)
        rec["last_pass"] = stamp
        rec["last_probe_ts"] = int(now)
        rec["passes"] = int(rec.get("passes") or 0) + 1
        lib[n["fp"]] = rec
        added += 1
    cutoff = now - config.NODE_LIBRARY_MAX_AGE_D * 86400
    lib = {k: v for k, v in lib.items() if _epoch_of(v.get("last_pass")) >= cutoff}
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"nodes": lib}, f, ensure_ascii=False)
    except Exception as e:
        log(f"警告: 节点库写入失败: {e}")
        return 0
    return added


def load_node_library(workdir: str, exclude_fps: set[str], *,
                      limit: int | None = None) -> list[dict]:
    """从节点库挑「历史通过过、本轮尚未入池」的节点复测（任务#117）。

    按 passes 降序取前 N 个——通过次数是「这条链路长期可用」的最强证据
    （实证：历史 CN 通过率存活组 76% vs 死亡组 0%）。origin 标 carryover，
    使其在 cap_test_set 中不被裁剪。
    """
    path = _lib_path(workdir)
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            lib = (json.load(f) or {}).get("nodes") or {}
    except Exception:
        return []
    limit = config.NODE_LIBRARY_LOAD_LIMIT if limit is None else limit
    cands = []
    for fp, rec in lib.items():
        if fp in exclude_fps:
            continue
        p = rec.get("proxy")
        if not isinstance(p, dict) or not p.get("server"):
            continue
        cands.append((int(rec.get("passes") or 0), fp, p))
    cands.sort(key=lambda x: -x[0])
    out: list[dict] = []
    for passes, fp, p in cands[:limit]:
        exclude_fps.add(fp)
        out.append({
            "fp": fp,
            "name": str(p.get("name") or "node"),
            "proxy": dict(p),
            "origin": "carryover",
            "final": False,
            "us_ok": False,
        })
    if out:
        log(f"节点库: {len(out)} 个历史通过节点并入复测集"
            f"（库内共 {len(lib)} 个，取通过次数前 {limit}）")
    return out


def load_user_pool(workdir: str, tag: str, learning: dict | None) -> list[dict]:
    """用户实测验证常驻池（任务#119）。

    返回「用户本地判定 alive 且完整配置可恢复」的节点，每轮无条件并入主资产。
    设计依据（实证，勿删）：
      * 用户家宽与沙箱（腾讯云上海）是两条不同路径，8 个用户实测 alive 的
        节点在沙箱 0 通过，其中 6 个握手失败、2 个仅 38~40KB/s；用沙箱结果
        否决用户地面真相是系统性误杀。
      * 本轮 310 个候选中 294 个在 delay 初筛即被淘汰，根本不在 degraded 里，
        旧的 select_alive_keeps 对它们完全无感——这是「越测越少」的断点。
    因此池内节点不参与沙箱准入判定，沙箱结果只用于排序/标注。dead 仍硬否决，
    超时按 config.USER_POOL_MAX_AGE_S 退役（不搞「一周集体失忆」式一刀切）。
    """
    path = os.path.join(REPO_ROOT, config.USER_POOL_FILE)
    if not os.path.exists(path):
        alt = os.path.join(workdir, config.USER_POOL_FILE)
        if not os.path.exists(alt):
            gh_download(tag, config.USER_POOL_FILE, alt)
        if os.path.exists(alt):
            path = alt
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            recs = (json.load(f) or {}).get("nodes") or {}
    except Exception as e:
        log(f"警告: 用户验证池读取失败: {type(e).__name__}: {e}")
        return []
    now = time.time()
    out: list[dict] = []
    for i, (fp, rec) in enumerate(recs.items()):
        if str(rec.get("verdict") or "").lower() != "alive":
            continue
        p = rec.get("proxy")
        if not isinstance(p, dict) or not p.get("server"):
            continue
        ts = float(rec.get("ts") or 0)
        if ts and (now - ts) > config.USER_POOL_MAX_AGE_S:
            continue
        name = str(rec.get("name") or p.get("name") or "node")
        if user_verdict({"fp": fp, "name": name}, learning) == "dead":
            continue
        out.append({
            "fp": fp,
            "name": name,
            "proxy": dict(p),
            "origin": "user_pool",
            "final": False,
            "us_ok": False,
            "probe_name": f"userpool_{i}",
            "_user_verified": True,
            "_user_ts": ts,
            "_user_stale": bool(ts and (now - ts) > config.USER_POOL_STALE_S),
        })
    return out


def split_user_pool(pool: list[dict], *, same_vantage: bool) -> tuple[list[dict], list[dict]]:
    """把用户池节点分成「必须本轮复测」与「可豁免直发」两组（任务#122）。

    背景（2026-11-05 实证）：发布 15 个节点，用户本地 FlClash 6 超时 1 失败；
    现场复测发现**坏的 7 个恰好就是池里 7 个未复测节点，delay 阶段全灭**
    （证据年龄 7.3 天）。旧逻辑对池内节点一律免测、只在日志里写一句
    「建议复验」就把它们并进主资产——明知过期仍直发，是「测得准」的直接漏洞。

    新规则（两条，缺一不可）：
      * **同 vantage**（本机家宽跑的家宽实测）→ 全部必须复测：
        原豁免理由是「沙箱路径 ≠ 用户家宽路径」，同一 vantage 下这个理由不存在；
      * **证据过期**（超过 USER_POOL_STALE_S）→ 无论哪个 vantage 都必须复测：
        过期证据等于没有证据。

    返回 (require, exempt)；纯函数，便于回归。
    """
    require: list[dict] = []
    exempt: list[dict] = []
    for n in pool:
        if same_vantage or n.get("_user_stale"):
            require.append(n)
        else:
            exempt.append(n)
    return require, exempt


def _pool_unrecoverable(workdir: str) -> list[str]:
    """池里没找回配置的用户 alive 节点名（如实留痕，供用户补录，绝不编造）。"""
    for path in (os.path.join(REPO_ROOT, config.USER_POOL_FILE),
                 os.path.join(workdir, config.USER_POOL_FILE)):
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    return list((json.load(f) or {}).get("unrecoverable") or [])
            except Exception:
                return []
    return []


def dedup_nodes(groups: list[tuple[str, list[dict]]]) -> list[dict]:
    """按 (origin 优先级, 出现顺序) 去重；探测名保证全局唯一（mihomo 硬性要求）。

    2026-10-16 修复：旧实现用 `used_names[name] += 1` 计数生成 `name#n`，
    但当原始名本身已带 `#2` 后缀时（订阅源常见），会与计数生成的 `#2` 撞名，
    导致 mihomo 启动即报 "is the duplicate name" 并退出，cn_probe 熔断（exit 3），
    实测集永远发不出来。改用「全局已用名集合 + 冲突时递增加后缀直到不重复」，
    无论原始名长什么样都保证唯一。
    """
    seen_fp: dict[str, dict] = {}
    for _origin, nodes in groups:
        for n in nodes:
            seen_fp.setdefault(n["fp"], n)
    out: list[dict] = []
    used: set[str] = set()
    for n in seen_fp.values():
        base = n["name"]
        name = base
        if name in used:
            i = 2
            while f"{base}#{i}" in used:
                i += 1
            name = f"{base}#{i}"
        used.add(name)
        n["probe_name"] = name
        out.append(n)
    return out


# ---------------------------------------------------------------- mihomo
def mihomo_asset(plat: str | None = None) -> tuple[str, str]:
    """返回 (Release 资产名, 解包后二进制文件名)。

    平台差异（任务#121）：
      * Linux 沙箱：`mihomo-linux-amd64-vX.gz`（原样，不改沙箱行为）；
      * Windows 本机：`mihomo-windows-amd64-compatible-vX.zip`——
        选 `compatible` 而非 amd64-v3，因为 v3 需要 AVX2，老 CPU（Ivy Bridge
        级别的 i7-3770）跑 v3 会直接 illegal instruction；compatible 是官方
        提供的最大兼容构建，性能足够拨测。

    `plat` 显式传入时按该平台返回（测试用），默认按当前系统判断。
    """
    ver = MIHOMO_VERSION
    if plat is None:
        plat = "nt" if os.name == "nt" else "posix"
    if plat == "nt":
        arch = platform.machine().lower()
        if arch in ("arm64", "aarch64"):
            return f"mihomo-windows-arm64-{ver}.zip", "mihomo.exe"
        if arch in ("x86", "i386", "i686"):
            return f"mihomo-windows-386-{ver}.zip", "mihomo.exe"
        return f"mihomo-windows-amd64-compatible-{ver}.zip", "mihomo.exe"
    return f"mihomo-linux-amd64-{ver}.gz", "mihomo"


def _extract_mihomo(archive: str, dest: str, asset_name: str) -> bool:
    """解包 mihomo（zip 或 gz）。用标准库而非外部 `gunzip`/`unzip`：

    Windows 上没有 `gunzip`，原实现（curl + gunzip）在那边必然失败；
    标准库两条路都能走，沙箱行为不变。
    """
    try:
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                cand = [n for n in zf.namelist()
                        if os.path.basename(n).lower().startswith("mihomo")]
                if not cand:
                    return False
                with zf.open(cand[0]) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)
        else:
            with gzip.open(archive, "rb") as src, open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
        return os.path.exists(dest) and os.path.getsize(dest) > 0
    except (OSError, zipfile.BadZipFile, EOFError):
        return False


def ensure_mihomo(workdir: str) -> str | None:
    """找到或下载可用的 mihomo，返回可执行文件路径（失败返回 None）。"""
    _, exe = mihomo_asset()
    for local in ("/usr/local/bin/mihomo", os.path.join(workdir, exe)):
        if os.path.exists(local):
            v = run([local, "-v"])
            if (v.returncode == 0
                    and MIHOMO_VERSION.lstrip("v") in (v.stdout or "") + (v.stderr or "")):
                return local
    dest = os.path.join(workdir, exe)
    asset, _ = mihomo_asset()
    url = (f"https://github.com/MetaCubeX/mihomo/releases/download/"
           f"{MIHOMO_VERSION}/{asset}")
    archive = f"{dest}.dl"
    for i in range(3):
        # 下载交给 gh_compat.download_url：直连优先、失败走镜像。
        # 家宽直连 GitHub 资产常被挂住，没有镜像层这一步本机永远拿不到 mihomo。
        ok = gh_compat.download_url(url, archive, max_time=420)
        if ok and _extract_mihomo(archive, dest, asset):
            if os.name != "nt":
                os.chmod(dest, 0o755)
            try:
                os.unlink(archive)
            except OSError:
                pass
            return dest
        time.sleep(3 * (i + 1))
    return None


def free_port(start: int) -> int:
    for p in range(start, start + 20):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return start


def wait_controller(port: int, timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/version", timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def api_get(port: int, path: str, timeout: int = 10) -> dict | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def api_put(port: int, path: str, body: dict) -> bool:
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
            method="PUT", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status == 204
    except Exception:
        return False


def delay_test(port: int, name: str) -> dict:
    """单节点延迟测试：HTTPS generate_204，失败重试一次。"""
    quoted = urllib.parse.quote(name, safe="")
    for attempt, timeout in enumerate((DELAY_TIMEOUT_MS, 8000)):
        data = api_get(port, f"/proxies/{quoted}/delay"
                             f"?url={urllib.parse.quote(GENERATE_204, safe='')}"
                             f"&timeout={timeout}", timeout=timeout / 1000 + 5)
        if data and isinstance(data.get("delay"), (int, float)):
            return {"ok": True, "latency_ms": int(data["delay"])}
        if attempt == 0:
            continue
    return {"ok": False, "latency_ms": None}


def _timed_download(proxy: str, url: str, budget: int, min_bytes: int) -> int:
    """预算内硬超时下载：返回累计下载字节；超时或不足 min_bytes 均返回实际值。

    用独立线程 + join(timeout) 实现「整体硬超时」——urllib 的 socket timeout
    是每次 recv 超时而非整体超时，龟速节点会持续以几 KB/s 流入而整体远超预算
    （曾观测到单节点下载耗时 324s），故必须线程级强制截断。
    """
    import concurrent.futures
    def _dl() -> int:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        buf = 0
        try:
            # 关键：socket 超时 = budget，使慢节点首次 recv 即超时失败，
            # 避免「单次 read 阻塞超时」绕过 while 的预算检查（曾致龟速节点误判可用）。
            with opener.open(req, timeout=budget) as r:
                t0 = time.time()
                while time.time() - t0 < budget:
                    chunk = r.read(16384)
                    if not chunk:
                        break
                    buf += len(chunk)
                    if buf >= min_bytes:
                        break
        except Exception:
            pass
        return buf
    with concurrent.futures.ThreadPoolExecutor(1) as ex:
        fut = ex.submit(_dl)
        try:
            return fut.result(timeout=budget + 4)
        except Exception:
            return 0


def _curl_speed(proxy: str, url: str, budget: int) -> dict:
    """单源测速（curl 引擎）：返回 {bytes, bps, code}；任何异常返回 0。

    用 curl 而非 urllib：实证 urllib 经代理下载大体量数据频繁抛
    "TLS/SSL connection has been closed (EOF)" 直接计 0，同时刻 curl 却能
    拿到真实速率——引擎缺陷会把好节点误判为死节点。curl 的 --max-time 是
    整体硬超时，%{speed_download} 即平均速率（B/s）。
    """
    try:
        # 用 os.devnull 而不是硬编码 "/dev/null"（任务#121）：Windows 上没有
        # /dev/null，curl 打不开输出文件会以写错误码退出、size_download 恒为 0
        # ——实测第一轮本机 dry-run 因此把 29 个初筛通过节点全判死（0/29），
        # 而它们在家宽上其实是通的。这类"平台差异伪装成节点死亡"的坑，
        # 只有在用户真实网络上跑一遍才会暴露。
        r = run(["curl", "-s", "-o", os.devnull,
                 "-w", "%{size_download}|%{speed_download}|%{http_code}",
                 "--proxy", proxy, "--max-time", str(budget), url],
                timeout=budget + 6)
    except subprocess.TimeoutExpired:
        return {"bytes": 0, "bps": 0, "code": None}
    if r.returncode != 0 and not (r.stdout or "").strip():
        return {"bytes": 0, "bps": 0, "code": None}
    try:
        parts = (r.stdout or "").strip().split("|")
        size = int(float(parts[0] or 0))
        bps = int(float(parts[1] or 0))
        code = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
    except Exception:
        return {"bytes": 0, "bps": 0, "code": None}
    return {"bytes": size, "bps": bps, "code": code}


def _speed_once(proxy: str, source: tuple[str, str], budget: int) -> dict:
    """单源单次采样：判定该源是否达标（速率 + 实际下载量双条件）。"""
    name, url = source
    res = _curl_speed(proxy, url, budget)
    # 403/429/503 等：目标站限流或风控，该源本次不可信，不计通过也不计失败
    if res["code"] in (403, 429, 503, 451):
        return {"source": name, "ok": False, "blocked": True, **res}
    ok = (res["bps"] >= REAL_MIN_BYTES_PER_SEC
          and res["bytes"] >= REAL_MIN_BYTES)
    return {"source": name, "ok": ok, "blocked": False, **res}


def judge_speed_round(details: list[dict]) -> bool:
    """单轮测速判据（任务#117 双档判据，纯函数便于回归）。

    背景：三个测速源经免费节点代理后的固有带宽差异极大（本轮实测中位：
    阿里云 72KB/s、OVH 61KB/s、CF 0KB/s），而沙箱直连时三者分别有
    15716/3126/6356KB/s。用统一的 128KB/s 并列卡每个源，等于要求最慢的
    源也达标——本轮 4 个「阿里云 306~1054KB/s、OVH 仅 64~109KB/s」的
    好节点全被判死，是「节点越来越少」的直接成因。

    新判据（二者其一 + 流量源计数）：
      - strong：单源 ≥128KB/s 且下载 ≥768KB —— 1 个即证明链路真有带宽；
      - weak  ：单源 ≥48KB/s 且下载 ≥256KB —— 2 个互证（免费节点常态）。
    另要求「有真实流量的源（≥256KB）」≥2 个，挡掉单源偶发放行；
    可用源 ≤1 时（目标站集体 429），退化为单源强达标判决。
    """
    usable = [d for d in details if not d["blocked"]]
    strong = [d for d in usable
              if d["bps"] >= REAL_MIN_BYTES_PER_SEC and d["bytes"] >= REAL_MIN_BYTES]
    weak = [d for d in usable
            if d["bps"] >= WEAK_MIN_BPS and d["bytes"] >= WEAK_MIN_BYTES]
    flowing = [d for d in usable if d["bytes"] >= FLOW_MIN_BYTES]
    if len(usable) <= 1:
        # 目标站集体风控/限流：可用源不足以交叉，退化单源强达标判决
        return len(strong) >= 1
    # 弱档路径不能再用「单源 ≥768KB」卡——两源各 400KB 合起来已近 1MB，
    # 却没有任何单源达到 768KB。改用「总真实流量 ≥768KB」保证不是凑数。
    total_flow = sum(d["bytes"] for d in flowing)
    return (len(flowing) >= SPEED_MIN_SOURCES_OK
            and (len(strong) >= 1
                 or (len(weak) >= 2 and total_flow >= REAL_MIN_BYTES)))


def real_traffic_test(api_port: int, mixed_port: int, name: str) -> dict:
    """真实流量闸门（2026-10-26 全面重写，多源交叉 + 稳定性采样）。

    历史教训链：
    - 2026-10-16 前：只取 robots.txt/trace 几行字，403 兜底放行 → 伪可用。
    - 2026-10-17：改为单源硬超时下载（speed.cloudflare.com 1MB/8s）。
    - 2026-10-24：250KB→768KB 收紧。
    - 2026-10-26：用户实测「8 个节点无一有效」复盘发现单源测速存在三类
      系统性假象——机场对已知测速域名 QoS 白名单（先快后断）、目标站对代理
      出口 IP 限流（实测 HTTP 429）、节点对单一 CDN 路由差而对另一 CDN 正常
      （实测 SG14 在 CF 96KB/s、阿里云 787KB/s）。同时 786432 字节在多节点
      完全一致，是「刚好凑够门槛就断」的典型特征，而非真实测速。

    新判据（三层）：
    1. **多源交叉**：3 个互不相关基建（CF / OVH / 阿里云）各自测速，
       至少 SPEED_MIN_SOURCES_OK(2) 个源达标才通过；被限流的源不计入分母。
    2. **速率而非总量**：要求平均速率 ≥128KB/s 且下载量 ≥768KB，
       杜绝「慢慢凑够字节数」。
    3. **稳定性采样**：间隔 SPEED_STABLE_GAP_S 再测一次，两轮都通过才算
       稳定通过——直接剔除「先快后断」的节点（这是用户本地无一可用的主因）。

    返回 ok=True 仅当两轮均满足多源交叉；degraded=True 表示有真实流量但
    未达快档（进第二资产 p_*_d.yaml），由 AI 提级路径决定是否回升主资产。
    """
    if not api_put(api_port, "/proxies/PROBE", {"name": name}):
        return {"ok": False}
    proxy = f"http://127.0.0.1:{mixed_port}"

    def _round() -> tuple[bool, int, list[dict]]:
        """跑一遍全部源，返回 (是否通过, 最优速率, 各源明细)。"""
        details = []
        for src in SPEED_SOURCES:
            details.append(_speed_once(proxy, src, SPEED_TEST_TIMEOUT_S))
        usable = [d for d in details if not d["blocked"]]
        best_bps = max((d["bps"] for d in details), default=0)
        # 判据抽为纯函数 judge_speed_round（任务#117）：各源经代理后的固有
        # 带宽差异极大，统一门槛会系统性误杀阿里云快、OVH 慢的好节点。
        ok = judge_speed_round(details)
        return ok, best_bps, details

    ok1, bps1, det1 = _round()
    if not ok1:
        best_bytes = max((d["bytes"] for d in det1), default=0)
        best_bps = max((d["bps"] for d in det1), default=0)
        # 慢档：有真实流量但未达快档 → 第二资产
        if best_bytes >= REAL_SLOW_MIN_BYTES:
            return {"ok": False, "degraded": True, "bytes": best_bytes,
                    "bps": best_bps, "sources": det1, "rounds": 1}
        return {"ok": False, "bytes": best_bytes, "bps": best_bps,
                "sources": det1, "rounds": 1}

    # 第二轮稳定性采样：换序避免总是同一个源先建立连接
    time.sleep(SPEED_STABLE_GAP_S)
    ok2, bps2, det2 = _round()
    best_bytes = max([d["bytes"] for d in det1 + det2], default=0)
    if ok2:
        return {"ok": True, "bytes": best_bytes, "bps": min(bps1, bps2),
                "min_bps": min(bps1, bps2), "sources": det1 + det2,
                "rounds": 2, "stable": True}
    # 首轮达标、复测不达标 = 典型的「先快后断」——判 degraded 而非通过
    return {"ok": False, "degraded": True, "bytes": best_bytes,
            "bps": bps2, "sources": det1 + det2, "rounds": 2,
            "stable": False, "unstable": True}


def _geo_evidence_via_proxy(url: str, proxy: str, timeout: int) -> dict:
    """经代理取 GEO 站点响应并解析出口证据；任何异常吞掉返回 {}。

    与 `_http_status_via_proxy` 同一模式（异常绝不向上抛）：证据收集不构成
    闸门，单源失败由其余源兜底。⚠️ P0-1 教训（2026-10-15）：GEO 请求
    **必须**经 mihomo mixed-port 代理再发出——裸 urlopen 直连拿到的恒为
    沙箱自身出口（exit_ip 恒为沙箱 IP），该字段对「节点真实落地」毫无
    判别力。整体硬超时见 `_hard_timeout_call`。回归防线见
    tests/test_cn_probe.py 的 node_evidence 代理断言。
    """
    def _req():
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with opener.open(req, timeout=timeout) as r:
                text = r.read().decode("utf-8", "replace")
            return _parse_geo(text)
        except Exception:
            return {}
    out = _hard_timeout_call(_req, timeout)
    return out if out is not None else {}


def _parse_geo(text: str) -> dict:
    ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
    loc = re.search(r"(?:地址|来自于|来自|country)\s*[:：]\s*([^\n]{2,60})", text)
    ev: dict = {}
    if ip:
        ev["exit_ip"] = ip.group(1)
    if loc:
        ev["exit_loc"] = loc.group(1).strip()
    return ev if ev.get("exit_ip") else {}


def _hard_timeout_call(fn, timeout: float):
    """线程级硬超时执行 fn()；超时/异常返回 None。

    为什么必须线程级强制截断（2026-10-21 实测复踩 2026-10-17 教训）：
    urllib 的 socket timeout 是**每次 recv 超时**而非整体超时——龟速节点
    上的滴流响应（实测 gemini.google.com 302 重定向链经慢节点耗时 24.31s，
    而 socket timeout 只有 8s）会把单次证据请求拖到数倍预算，8 路并行下单
    节点成本失控（合并循环实测均摊 10.5s/节点，120s 预算只覆盖 13/28）。
    与 `_timed_download` 同一教训：整体硬超时，超时按「无数据」处理。

    实现要点：用 **daemon 线程 + join(timeout+2)**，不用
    `ThreadPoolExecutor` 的 `with` 块——后者退出时 shutdown(wait=True)
    会把已超时的线程重新等满（首版即此 bug：测试实测截断失效，控制权
    仍被拖住 5s）。daemon 线程不阻塞解释器退出。
    """
    box: dict = {}

    def _run():
        try:
            box["r"] = fn()
        except BaseException as e:  # 证据收集不构成闸门：任何失败按无数据处理
            box["err"] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout + 2)
    return None if t.is_alive() else box.get("r")


def _http_status_via_proxy(url: str, proxy: str, timeout: int) -> int | None:
    """经代理取 URL 的 HTTP 状态码；任何响应（含 4xx/5xx）都算「有响应」。

    不用 curl -f，也不用 urllib 抛异常判失败：403/401/302 都是有效响应，
    正是 AI 可达性判据要区分的状态（v1 诊断用 curl -f 把它们吞成失败，
    导致「13/29 节点完全不通 AI」的真实盲区被误判为方法学噪声）。
    整体硬超时见 `_hard_timeout_call`。
    """
    def _req():
        try:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=timeout) as r:
                return int(r.status)
        except urllib.error.HTTPError as e:
            return int(e.code)  # 401/403/404 等：有响应，返回真实状态码
        except Exception:
            return None          # 超时/连接失败/DNS：无响应
    return _hard_timeout_call(_req, timeout)


def classify_ai(codes: dict) -> dict:
    """把各 AI 域 HTTP 状态码归并为 ai_reachable / ai_api 判据（纯函数）。

    判据（2026-10-20 沙箱诊断确立）：
      - 任何 HTTP 响应（含 403/302/401）= 可达；None/超时/连接失败 = 不可达；
      - ai_api = openai_api 返回非 403 状态码——401（无密钥的正常响应）
        说明 API 层未被区域封锁，是「真 AI 可用」的最强信号；
      - chatgpt 403 只说明 Cloudflare 拒绝了该出口的网页端访问，与 API
        可用性是两回事，两者分开记录、不可互推。
    """
    reach = [k for k, v in codes.items() if v]
    oai = codes.get("openai_api")
    return {
        "codes": codes,
        "reach": reach,
        "ai_reachable": bool(reach),
        "ai_api": bool(oai and oai != 403),
    }


def node_evidence(api_port: int, mixed_port: int, name: str) -> dict:
    """单次切组，并行收集出口证据 + AI 可达性证据（2026-10-21 合并，任务#91）。

    原实现是两个顺序循环：`exit_evidence`（逐节点切组 + GEO 3 源**顺序**
    回退，最坏 24s/节点）与 `ai_probe`（再逐节点切组 + 5 域并行，8s/节点），
    各自 120s 预算——36 节点实测每循环各覆盖 18 个，**一半通过节点没有
    AI 数据**（排序时按「未知」沉底，有效节点被埋）。两者共用同一个
    PROBE 选择器与 mixed-port，合并为一次切组 + 8 路并行（GEO 3 + AI 5）
    后，单节点耗时从 ≈24s+8s 降为 ≈max(8s)，同预算内可全覆盖。

    返回 `{"geo": {...} or {}, "ai": classify_ai(codes)}`；切组失败
    （API 故障）返回 `{}`——调用方按「无数据」处理，不影响发布。
    """
    if not api_put(api_port, "/proxies/PROBE", {"name": name}):
        return {}
    proxy = f"http://127.0.0.1:{mixed_port}"
    # 8 路并行：GEO 3 源 + AI 5 域。各任务内部吞异常（_geo_evidence_via_proxy
    # 返回 {}、_http_status_via_proxy 返回 None），result() 不会抛。
    with ThreadPoolExecutor(max_workers=EVIDENCE_CONCURRENCY) as ex:
        geo_futs = [ex.submit(_geo_evidence_via_proxy, u, proxy, GEO_TIMEOUT_S)
                    for u in GEO_URLS]
        ai_futs = [ex.submit(_http_status_via_proxy, u, proxy, AI_TIMEOUT_S)
                   for u in AI_TARGETS.values()]
        geo_results = [f.result() for f in geo_futs]
        ai_codes = dict(zip(AI_TARGETS, (f.result() for f in ai_futs)))
    geo_ev: dict = {}
    for url, ev in zip(GEO_URLS, geo_results):
        if ev:
            ev["via"] = url
            geo_ev = ev
            break
    return {"geo": geo_ev, "ai": classify_ai(ai_codes)}


def load_learning() -> dict:
    """加载历史实测数据（survival.json + cn_history.json + user_probe.json）。

    2026-10-28 任务#111：池侧（拨测样本选择）早已用 survival.streak 排序，
    但发布侧一直没接——16 轮长命节点与 1 轮新面孔在主资产同权。
    2026-10-29 任务#113：接入用户本地实测回灌（user_probe.json）——用户
    家宽的成败才是最终事实，沙箱只是「上海这一跳」。
    文件缺失/损坏时返回空结构（学习静默降级为无历史模式）。
    """
    learning: dict = {"survival": {}, "cn_hist": {}, "user": {}}
    for key, path in (("survival", config.SURVIVAL_FILE),
                      ("cn_hist", config.CN_HISTORY_FILE),
                      ("user", config.USER_PROBE_FILE)):
        try:
            with open(path, encoding="utf-8") as f:
                learning[key] = json.load(f) or {}
        except Exception:
            learning[key] = {}
    return learning


def user_verdict(n: dict, learning: dict | None) -> str | None:
    """用户本地实测结论（2026-10-29 任务#113）：'alive' / 'dead' / None。

    回灌文件格式（用户侧客户端测速结果导出）：
        {"nodes": {"<节点名或指纹>": {"result": "alive|dead",
                                      "ts": 1780000000, "latency_ms": 220}}}
    有效期分设（任务#116）：alive 7 天、dead 14 天——alive 证据是「保活」依据，
    取久一点可稳定订阅数量；dead 是硬否决，也要记得久（封禁极少自动恢复）。
    """
    if not learning:
        return None
    up = learning.get("user") or {}
    rec = up.get("nodes") if isinstance(up.get("nodes"), dict) else up
    if not isinstance(rec, dict):
        return None
    fp = n.get("fp")
    name = n.get("name")
    item = None
    for key in (fp, name):
        if key and key in rec:
            item = rec[key]
            break
    if not isinstance(item, dict):
        return None
    r = str(item.get("result") or "").lower()
    if r not in ("alive", "dead"):
        return None
    try:
        ts = float(item.get("ts") or 0)
    except Exception:
        ts = 0
    ttl = (config.USER_PROBE_ALIVE_MAX_AGE_S if r == "alive"
           else config.USER_PROBE_DEAD_MAX_AGE_S)
    if ts and (time.time() - ts) > ttl:
        return None
    return r


def longevity_tier(n: dict, learning: dict | None) -> int:
    """长寿档（#111；2026-10-29 按用户实测数据校准）：历史 CN 通过率主导。

    **校准依据**（用户本地实测 12 节点 vs 沙箱数据）：
      - 历史 CN 通过率：存活组中位 76%，死亡组中位 0%  ← 唯一强预测信号
      - survival.streak：存活组中位 2 vs 死亡组 3        ← 无区分度（甚至反相关）
        原因：streak 只记「在源里出现过几天」，不记「实测可用」——US LA 04
        streak=5 但历史 0/14 全败，照样被排到前面。
      - 沙箱实测速度：存活组中位 65KB/s vs 死亡组 545KB/s ← **反向**，
        「先快后断」节点在临死前会出现速率尖峰。

    档位：
      0 = 铁证可用：cn_pass/cn_runs ≥ LONGEVITY_CN_PASS_RATE（样本 ≥5）
      1 = 中等证据：carryover 复测存活，或历史通过率一般但有过通过
      2 = 新面孔：无历史实证（单轮数据不可信）
    """
    if not learning:
        return 1 if n.get("origin") == "carryover" else 2
    fp = n.get("fp")
    c = learning.get("cn_hist", {}).get(fp, {}) if fp else {}
    runs = int(c.get("cn_runs") or 0)
    passed = int(c.get("cn_pass") or 0)
    if runs >= 5 and passed / runs >= config.LONGEVITY_CN_PASS_RATE:
        return 0
    s = learning.get("survival", {}).get(fp, {}) if fp else {}
    streak = int(s.get("streak") or 0)
    if streak >= config.LONGEVITY_STREAK_MIN and runs >= 5 and passed > 0:
        return 0        # streak 仅作辅助，且要求历史至少通过过一次
    if n.get("origin") == "carryover":
        return 1
    if runs >= 5 and passed > 0:
        return 1        # 有过通过记录但比率一般
    return 2


def select_alive_keeps(degraded: list[dict], results: dict,
                       learning: dict | None, cap: int | None = None) -> list[dict]:
    """用户实测 alive 的长效保活筛选（纯函数，任务#116）。

    只收「延迟仍达标」的节点：延迟测不出说明链路已死，不能因一周前的
    alive 记录误保。速度落慢档不算否决——用户实测是地面真相，沙箱测速
    只代表「腾讯云上海这一跳」，速度抖动不足以判定「不能用」。
    """
    if not config.USER_PROBE_ALIVE_KEEP:
        return []
    if cap is None:
        cap = CN_MAX_PUBLISH_LATENCY_MS
    out: list[dict] = []
    for n in degraded:
        if user_verdict(n, learning) != "alive":
            continue
        lat = results.get(n["probe_name"], {}).get("latency_ms") or 99999
        if lat <= cap:
            out.append(n)
    return out


def mark_final_flags(nodes: list[dict], passed: list[dict]) -> int:
    """把报告里 nodes[].final 严格对齐「本轮实测通过」（任务#118）。

    旧实现只置 True 不置 False，从 CI pending_probe.json 继承来的 final=True
    原样带进报告。实证本轮 311 条记录里 88 个「未测节点」被标 final=True，
    而真正通过的 4 个是 final=False——字段语义整个反了，任何按 final 做的
    统计都会把死节点算成可用节点。

    返回被置为 final=True 的节点数。
    """
    for n in nodes:
        n["final"] = False
    cnt = 0
    for n in passed:
        n["final"] = True
        cnt += 1
    return cnt


def select_ai_promotions(degraded: list[dict], results: dict,
                         cap: int | None = None) -> tuple[list[dict], int]:
    """从降级集中挑出可提级的「AI 干净」节点（纯函数，任务#116）。

    两个必要条件，缺一不可：
      1. **强信号** ai_reachable 且 ai_api。ai_reachable 只要有任何 HTTP 响应
         （含 403 / Cloudflare 拦截）即为真——2026-11-04 实证 14 个发布节点
         chatgpt/claude 全 403 却都判「AI 可用」；ai_api（openai_api != 403，
         即 401/200）才说明 Cloudflare 放行到 API 层、IP 干净。
      2. **延迟线取严** ≤ min(AI_PROMOTE_MAX_LATENCY_MS, CN_MAX_PUBLISH_LATENCY_MS)。
         旧实现提级用 3500ms、主闸门用 2500ms，导致 6.05 降级的节点被 6.6
         提回，同轮自相矛盾；取严后提级无法突破主资产延迟线。

    返回 (可提级节点, 因延迟超限被拒数)。
    """
    if cap is None:
        cap = min(config.AI_PROMOTE_MAX_LATENCY_MS, CN_MAX_PUBLISH_LATENCY_MS)
    promoted: list[dict] = []
    rejected = 0
    for n in degraded:
        ai = results.get(n["probe_name"], {}).get("ai") or {}
        if not (ai.get("ai_reachable") and ai.get("ai_api")):
            continue
        lat = results.get(n["probe_name"], {}).get("latency_ms") or 99999
        if lat > cap:
            rejected += 1
            continue
        # 速度底线（任务#117）：实证本轮 5 个提级节点里 3 个只有 37~50KB/s
        # （AI 干净、延迟达标，但打开网页都费劲）。AI 干净≠能用，提级必须
        # 至少达到弱档速率（48KB/s），否则宁可留在第二资产。
        rt = results.get(n["probe_name"], {}).get("real_traffic") or {}
        if (rt.get("bps") or 0) < WEAK_MIN_BPS:
            rejected += 1
            continue
        promoted.append(n)
    return promoted, rejected


def verified_rank(n: dict, results: dict, learning: dict | None = None) -> tuple:
    """验证集排序键：AI 可用性 > 长寿实证 > 用户实测 > vantage > 速度惩罚 > 延迟。

    2026-10-20 起 AI 可达性占首位——订阅顺序即用户可见性顺序，用户核心
    诉求是「可用于 AI 连接的纯净节点」；非 AI 节点不设硬闸门、仅沉底。
    2026-10-28 #111：次级判据升级为长寿档（历史实测反哺）。
    2026-10-29 #113/#114：接入用户本地实测回灌（最高权重），并把「沙箱实测
    速度」从正向加分改为**超高速惩罚**——实测证据显示沙箱速度与本地存活反向。
    """
    if learning is None:
        learning = load_learning()
    r = results.get(n["probe_name"], {})
    ai = r.get("ai") or {}
    if ai.get("ai_api"):
        ai_tier = 0        # API 层未被封锁：配密钥即可用
    elif ai.get("ai_reachable"):
        ai_tier = 1        # 至少一个 AI 域有响应
    else:
        ai_tier = 2        # 未探测到或无响应（含探测超预算无数据）
    uv = user_verdict(n, learning)
    uv_tier = 0 if uv == "alive" else (1 if uv == "dead" else 2)
    lon = longevity_tier(n, learning)
    kbps = (r.get("real_traffic", {}).get("bytes") or 0) / 8 / 1024
    if kbps >= config.SPEED_PENALTY_START_KBPS:
        span = max(1.0, config.SPEED_PENALTY_MAX_KBPS - config.SPEED_PENALTY_START_KBPS)
        speed_pen = int(min(1.0, (kbps - config.SPEED_PENALTY_START_KBPS) / span) * 100)
    else:
        speed_pen = 0
    return (ai_tier,
            lon,
            uv_tier,
            # 再次级判据（2026-10-24 任务#96）：双 vantage 强者 >
            # carryover 复测存活 > 仅本轮新通过。
            # 注意 final 此时已被 main() 在通过后统一置 True，不再区分。
            0 if (n["us_ok"] and n["final"])
            else (1 if n.get("origin") == "carryover" else 2),
            speed_pen,
            # 同档位内仍以实测速度降序（用户反馈缺失时的次优代理）：
            -(r.get("real_traffic", {}).get("bytes") or 0),
            r.get("latency_ms") if r.get("latency_ms") is not None else 99999)


# ---------------------------------------------------------------- 输出构建
def _truthy(v) -> bool:
    return str(v).lower() in ("1", "true", "yes", "on")


def _unique_names(proxies: list[dict]) -> list[str]:
    """给节点列表分配全局唯一 name（mihomo/clash 硬性要求），返回与 proxies 对齐的名称。

    订阅源常见同名节点（尤其带 `#2` 后缀者），直接写入会让客户端/拨测端报
    duplicate name 整体拒绝加载（2026-10-16 教训）。用「已用名集合 + 递增加后缀」
    保证唯一，不改节点身份。
    """
    used: set[str] = set()
    out: list[str] = []
    for p in proxies:
        base = str(p.get("name") or "node")
        name = base
        if name in used:
            i = 2
            while f"{base}#{i}" in used:
                i += 1
            name = f"{base}#{i}"
        used.add(name)
        out.append(name)
    return out


def build_verified_config(nodes: list[dict], results: dict | None = None) -> dict:
    """验证集 clash 配置：合规节点进自动/地区组，Insecure 独立隔离组。

    results（2026-10-24 新增）：本轮拨测结果；有 AI 可达证据的节点进
    「🤖 AI 可用」组并置于节点选择首位——用户客户端一键切换 AI 通道
    （任务#96 后 AI 证据全覆盖，该组在纯快照轮亦可靠）。
    """
    proxies = [dict(n["proxy"]) for n in nodes]
    names = _unique_names(proxies)  # 先统一分配唯一名，再回填 proxy.name 供分组引用
    for p, nm in zip(proxies, names):
        p["name"] = nm
    compliant = [p for p in proxies if not _truthy(p.get("skip-cert-verify"))]
    insecure = [p for p in proxies if _truthy(p.get("skip-cert-verify"))]
    compliant_names = [p["name"] for p in compliant]
    insecure_names = [p["name"] for p in insecure]
    # AI 可达名单（与 compliant_names 同序对齐）
    ai_names = []
    if results:
        for n, nm in zip(nodes, names):
            r = results.get(n.get("probe_name", ""), {})
            if (r.get("ai") or {}).get("ai_reachable"):
                ai_names.append(nm)
    groups = [
        {"name": "🚀 节点选择", "type": "select",
         "proxies": ["♻️ 自动选择", "DIRECT"] + compliant_names},
        {"name": "♻️ 自动选择", "type": "url-test", "proxies": compliant_names,
         "url": config.PROBE_URL, "interval": 300, "tolerance": 50},
    ]
    if ai_names:
        # AI 组置顶（插在「节点选择」引用的首位），url-test 自动选最快 AI 节点
        groups.append({"name": "🤖 AI 可用", "type": "url-test",
                       "proxies": ai_names, "url": config.PROBE_URL,
                       "interval": 300, "tolerance": 50})
        groups[0]["proxies"].insert(0, "🤖 AI 可用")
    # 任务#119：用户家宽实测验证过的节点单独成组并置顶。它们与沙箱实测节点
    # 证据来源不同（沙箱 0 通过 ≠ 本地不可用），混在自动组里用户无从分辨。
    uv_names = [nm for n, nm in zip(nodes, names) if n.get("_user_verified")]
    if uv_names:
        groups.append({"name": "✅ 本地实测", "type": "url-test",
                       "proxies": uv_names, "url": config.PROBE_URL,
                       "interval": 300, "tolerance": 50})
        groups[0]["proxies"].insert(0, "✅ 本地实测")
    if classify_proxy is not None:
        regions: dict[str, list[str]] = {}
        for p in compliant:
            regions.setdefault(classify_proxy(str(p.get("name", ""))), []).append(p["name"])
        for region, rnames in regions.items():
            if len(rnames) >= 2:
                groups.append({"name": region, "type": "url-test", "proxies": rnames,
                               "url": config.PROBE_URL, "interval": 300})
                groups[0]["proxies"].append(region)
    if insecure_names:
        groups.append({"name": config.INSECURE_GROUP, "type": "select",
                       "proxies": insecure_names})
        groups[0]["proxies"].append(config.INSECURE_GROUP)
    return {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"],
    }


def write_verified_outputs(nodes: list[dict], workdir: str,
                           results: dict | None = None) -> dict[str, str]:
    paths = {}
    cfg = build_verified_config(nodes, results)
    clash_path = os.path.join(workdir, VERIFIED_FILE["clash"])
    with open(clash_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)
    paths["clash"] = clash_path
    if write_outputs is not None:
        proxies = [dict(n["proxy"]) for n in nodes]
        write_outputs(proxies, namer=lambda b: os.path.join(
            workdir, VERIFIED_FILE[ASSET_FORMAT_REV.get(b, b)]))
        for fmt, fname in VERIFIED_FILE.items():
            if fmt != "clash":
                paths[fmt] = os.path.join(workdir, fname)
    return paths


# ---------------------------------------------------------------- 主流程
def default_workdir() -> str:
    """工作目录默认值（任务#121 跨平台）。

    沙箱沿用 /tmp/cn_probe（历史日志、检查点、节点库都在那儿，不能改）；
    Windows 本机没有 /tmp，改用系统临时目录，避免在盘根写 D:/tmp 这种
    半吊子路径。两处都可用 CN_PROBE_WORKDIR 覆盖。
    """
    env = os.environ.get("CN_PROBE_WORKDIR")
    if env:
        return env
    if os.name == "nt":
        return os.path.join(tempfile.gettempdir(), "cn_probe")
    return "/tmp/cn_probe"


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="中国出口节点实测（沙箱侧 / 本机家宽侧）")
    ap.add_argument("--tag", default=default_tag())
    ap.add_argument("--workdir", default=default_workdir())
    ap.add_argument("--max-wait", type=int, default=PENDING_POLL_WINDOW_MIN,
                    help="轮次闸门最长等待分钟（受任务 1800s 超时约束，默认 20）")
    ap.add_argument("--budget", type=int, default=TASK_BUDGET_S,
                    help="总时间预算秒数（默认 1800，对齐定时任务超时；"
                         "手动跑大可放宽，测试集按剩余预算裁剪）")
    ap.add_argument("--dry-run", action="store_true", help="不发布，仅本地验证")
    return ap


def main() -> int:
    args = build_parser().parse_args()

    tag = args.tag
    workdir = args.workdir
    os.makedirs(workdir, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc)
    round_id = stamp.strftime("%Y%m%dT%H%MZ")
    t0 = time.time()  # 预算起点：轮询/拨测/发布全程计时

    # 0) 单实例锁：任务重试/调度重叠时防止两个探针并发发布
    # 锁文件用 "a+" 打开——绝不能用 "w"：那会在取锁失败前先截断文件，把正在
    # 持锁那个进程的身份信息冲掉，事后无从回答「谁在持锁」。
    lock_path = os.path.join(workdir, "cn_probe.lock")
    lock_fd = open(lock_path, "a+", encoding="utf-8")
    if not xlock.supported():  # pragma: no cover - 极简环境
        log("警告: 本平台无可用文件锁，单实例保护失效（不会并发发布，但请勿并发启动）")
    elif not xlock.acquire(lock_fd):
        holder = ""
        try:
            lock_fd.seek(0)
            holder = lock_fd.read().strip()
        except (OSError, ValueError):
            pass
        log("另一实例正在运行（单实例锁），退出"
            + (f"；持锁者: {holder}" if holder else "；锁文件无持有者信息"))
        return 0
    # 持锁者身份落盘（任务#120）：守护与排障需要回答「谁在持锁、哪一轮、何时
    # 开始」。此前锁文件恒空，只能靠 pgrep 猜——而 pgrep -f 既会自匹配调用方
    # 命令行，也把沙箱冻结（SIGSTOP）的进程算作「在跑」，两种误判都发生过。
    try:
        lock_fd.seek(0)
        lock_fd.truncate()
        lock_fd.write(f"pid={os.getpid()} round={round_id} "
                      f"started={stamp.strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        lock_fd.flush()
    except (OSError, ValueError):
        pass

    # 0.5) 鉴权自检（grok 2.3）：GH_TOKEN 失效则立即退出，避免空转 20 分钟
    if not auth_selfcheck(required=not args.dry_run):
        return 3

    # 1) 自检：沙箱自身网络
    if not sandbox_selfcheck():
        log("熔断: 沙箱自身网络不可用（直连探测失败），中止——避免把自身故障"
            "误判为节点全失效")
        return 2
    log("自检通过: 沙箱直连可用")

    # 2) 交接文档 + 轮次闸门
    pend_path = os.path.join(workdir, config.PENDING_PROBE_FILE)
    rescue_path = os.path.join(workdir, config.PENDING_RESCUE_FILE)
    # 上轮报告 -> 已测轮次。首轮/报告缺失时 last_round=None：任何现有
    # 文档都算新轮次（修掉早期「首轮文档陈旧即空转」的死角）。
    last_round = None
    prev_report = os.path.join(workdir, "prev_verification_report.json")
    if gh_download(tag, config.VERIFICATION_REPORT_FILE, prev_report):
        try:
            with open(prev_report, encoding="utf-8") as f:
                last_round = json.load(f).get("tested_round") or None
        except Exception:
            last_round = None
    else:
        log("未找到上轮 verification_report.json（首轮或 CI 未发布）")

    fresh = False
    doc_round = doc_round_id(pend_path) if gh_download(
        tag, config.PENDING_PROBE_FILE, pend_path) else None
    if gate_decision(doc_round, last_round) == "test":
        fresh = True
    else:
        why = "交接文档缺失" if doc_round is None else f"轮次 {doc_round} 已测过"
        log(f"{why}，轮询等待 CI 新轮次至多 {args.max_wait} 分钟…")
        deadline = time.time() + args.max_wait * 60
        waited = 0
        while time.time() < deadline:
            time.sleep(60)
            waited += 1
            if gh_download(tag, config.PENDING_PROBE_FILE, pend_path):
                doc_round = doc_round_id(pend_path)
                if gate_decision(doc_round, last_round) == "test":
                    fresh = True
                    break
            if waited % 5 == 0:
                log(f"仍在等待 CI 新轮次交接文档"
                    f"（已等 {waited}/{args.max_wait} 分钟）")
    if fresh:
        if gh_download(tag, config.PENDING_RESCUE_FILE, rescue_path):
            log(f"交接文档轮次 {doc_round} 待测，进入实测")
        else:
            log(f"警告: 交接文档轮次 {doc_round} 已检出，但 rescue 文档下载失败，"
                "本轮仅测 pending + carryover（rescue 顺延至下次实测）")
    else:
        # 任务#106（2026-10-24）：轮次闸门挡的是「同一 round_id 文档二次整测」，
        # 不代表池里没有未测节点——上轮 cap_test_set 裁剪后尾部大量节点从未
        # 进过实测（如 09:05 轮 815 个 pending 只测了样本）。下载当前/残留
        # 交接文档补测未测尾部（dedup 中 carryover 优先，已发布节点不受影响），
        # 避免把 pass_rate=1.0 的零信息轮写进源级与协议级实证。
        got = gh_download(tag, config.PENDING_PROBE_FILE, pend_path)
        if got:
            gh_download(tag, config.PENDING_RESCUE_FILE, rescue_path)
            log("无新轮次（同 round_id 已消费）：本轮 = carryover + 当前交接文档未测尾部")
        else:
            log("无新轮次且交接文档下载失败：本轮仅测 carryover")

    # 3) 测试集 = carryover ∪ pending ∪ rescue
    assets = release_assets(tag)
    if not assets:
        # 兜底（任务#121）：匿名 API 限流（60 次/小时，共享出口 IP 实测打满）
        # 或 gh 挂起时，资产列表会拿到空——carryover 随之全丢，只能测候选集，
        # 发布集立刻塌成个位数。上一轮报告里本来就记着发布过的资产名
        # （main_assets / degraded_asset），据此反推即可，无需再打一次 API。
        assets = _assets_from_prev_report(prev_report)
        if assets:
            log(f"警告: release 资产列表获取失败，改用上轮报告的 main_assets "
                f"反推（{len(assets)} 个资产名），carryover 不受影响")
    main_clash = next((a["name"] for a in assets if ASSET_RE.match(a.get("name", ""))
                       and a["name"].endswith("_c.yaml")), None)
    carry = load_carryover(os.path.join(workdir, "main_clash.yaml")) if (
        main_clash and gh_download(tag, main_clash, os.path.join(workdir, "main_clash.yaml"))
    ) else []
    # 慢档回炉（2026-10-28）：第二资产节点并入复测集，给「AI 慢档提级」
    # 供给证据（此前降级即沉没，永远无 AI 数据）。fingerprint 去重防重复测。
    carry += load_slow_carryover(
        workdir, exclude_fps={n["fp"] for n in carry})
    # 节点库复测（任务#117）：把「历史通过过、但已滑出最近两轮资产」的节点
    # 捞回复测集。这是打破「通过少 → carryover 少 → 下轮更少」恶性循环的关键。
    # 任务#119：节点库持久化。原实现只写 /tmp/cn_probe，沙箱重启或目录清理
    # 即全部失忆，#117 建的跨轮节点库等于没有持久化。本地缺失时先从
    # release 恢复，发布后再回传（见 8.6）。
    if (config.NODE_LIBRARY_PERSIST
            and not os.path.exists(_lib_path(workdir))
            and gh_download(tag, config.NODE_LIBRARY_FILE, _lib_path(workdir))):
        log("节点库: 从 release 恢复（本地缺失）")
    carry += load_node_library(
        workdir, exclude_fps={n["fp"] for n in carry})
    # 任务#106：非 fresh 轮也加载交接文档（当前/残留）——闸门只挡「同轮
    # 二次整测」的 fresh 标记，未测尾部照常并入（dedup 保 carryover 优先）。
    # 下载失败的 fresh 轮 pend_path 不存在，加载自然为空，与原行为一致。
    pend = load_doc_nodes(pend_path, "pending") if (
        fresh or os.path.exists(pend_path)) else []
    resc = load_doc_nodes(rescue_path, "rescue") if (
        fresh or os.path.exists(rescue_path)) else []
    # 用户池复测（任务#122）：同 vantage 或证据过期的池节点，必须走本轮实测，
    # 不再「免测直发」。learning 提前加载（原本在 6) 合并段才读，纯文件读取，
    # 提前一次即可，避免二次读盘）。
    learning = load_learning()
    pool_all = load_user_pool(workdir, tag, learning)
    _same_vantage = VANTAGE_LABEL.startswith("cn-home")
    pool_require, pool_exempt = split_user_pool(pool_all, same_vantage=_same_vantage)
    if pool_require:
        log(f"用户池: {len(pool_require)} 个需本轮复测"
            f"（{'同 vantage' if _same_vantage else '证据过期'}），"
            f"{len(pool_exempt)} 个可豁免直发")
    # 去重优先级（2026-10-24 任务#99）：carryover 最先——上一轮已发布节点若
    # 与本轮 pending 重复，必须保留 carryover 身份（cap_test_set 中不裁剪、
    # 永远进测试集）。旧顺序 pending 在前，会把已发布节点改标成 pending，
    # 一旦时间预算吃紧被裁剪，好节点就「静默消失」（2026-10-24 实测：
    # 上一轮 50 个发布节点仅 37 个以 carryover 身份进入测试集）。
    # 代价：这批节点的 src 归属让位给滚动保障（分源统计少计十余条，可接受）。
    nodes = dedup_nodes([("carryover", carry), ("user_pool", pool_require),
                         ("pending", pend), ("rescue", resc)])
    if not nodes:
        log("无任何可测节点（无待测文档且主资产为空），退出")
        return 4
    # 3.5) 截止时间感知上限：轮询等待已耗时，按剩余预算裁剪，
    # 保证 TASK_BUDGET_S 内完成发布（裁剪序：rescue→pending，
    # carryover 不裁；未测节点由 CI 下轮文档自然再现，不丢失）。
    budget = args.budget - PUBLISH_RESERVE_S - (time.time() - t0)
    nodes, dropped = cap_test_set(nodes, budget)
    if dropped:
        log(f"时间预算约束：裁剪 {dropped} 个节点"
            f"（剩余预算 {int(budget)}s，~{int(budget / PER_NODE_S)} 个名额），"
            f"未测节点顺延至 CI 后续轮次，不丢失")
    n_pend = sum(1 for n in nodes if n.get("origin") == "pending")
    n_resc = sum(1 for n in nodes if n.get("origin") == "rescue")
    n_carry = sum(1 for n in nodes if n.get("origin") == "carryover")
    n_pool = sum(1 for n in nodes if n.get("origin") == "user_pool")
    log(f"测试集: {len(nodes)}（pending {n_pend} / rescue {n_resc} / "
        f"carryover {n_carry} / 用户池复测 {n_pool}）")

    # 4) mihomo 拨测
    ckpt: ProbeCheckpoint | None = None  # 断点续跑检查点（任务#120），见 4.0
    mihomo = ensure_mihomo(workdir)
    if not mihomo:
        log("熔断: mihomo 不可用，不发布")
        return 3
    mixed_port, api_port = free_port(7897), free_port(9097)
    probe_names = [n["probe_name"] for n in nodes]
    cfg = {
        "mixed-port": mixed_port,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{api_port}",
        "proxies": [dict(n["proxy"], name=n["probe_name"]) for n in nodes],
        "proxy-groups": [{"name": "PROBE", "type": "select",
                          "proxies": probe_names + ["DIRECT"]}],
        "rules": ["MATCH,PROBE"],
    }
    cfg_path = os.path.join(workdir, "probe_config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, sort_keys=False)
    # mihomo 日志落盘（不再吞 stderr）：控制器未就绪时可读尾部定位真正原因
    # （常见为配置非法，如节点名重复），而不是黑盒"控制器未就绪"。
    mihomo_log = os.path.join(workdir, "mihomo.log")
    with open(mihomo_log, "w", encoding="utf-8") as mlog:
        proc = subprocess.Popen([mihomo, "-d", workdir, "-f", cfg_path],
                                stdout=mlog, stderr=subprocess.STDOUT)
    try:
        if not wait_controller(api_port):
            try:
                with open(mihomo_log, encoding="utf-8") as f:
                    tail = "".join(list(f)[-25:])
            except Exception:
                tail = "(日志读取失败)"
            log("熔断: mihomo 控制器未就绪，不发布。mihomo 尾部日志:\n" + tail)
            return 3
        log(f"mihomo 就绪（mixed {mixed_port} / api {api_port}），开始拨测 "
            f"{len(nodes)} 个节点…")
        try:
            t0 = time.time()
            results: dict[str, dict] = {}
            # 4.0) 断点续跑（任务#120）：被休眠打断的轮次，重启后复用已测结论。
            # 签名只由测试集节点名集合决定——同一批节点才复用；重跑时 mihomo
            # 端口是新分配的，故复用的是「判定结论」而非连接，没有脏状态风险。
            ckpt = ProbeCheckpoint(workdir, checkpoint_signature(probe_names), round_id)
            ck_delay, ck_real, ck_results = ckpt.load()
            if ck_results:
                results.update(ck_results)
                log(f"断点续跑: 复用上轮已测 {len(ck_delay)} 个节点的初筛结论"
                    f"（其中 {len(ck_real)} 个已出终筛结论），本轮只补测剩余节点")
            # 4.1) 初筛：mihomo delay API（快速排除完全不可达节点）
            todo_delay = [n for n in nodes if n["probe_name"] not in ck_delay]
            if todo_delay:
                with ThreadPoolExecutor(max_workers=DELAY_CONCURRENCY) as ex:
                    futs = {ex.submit(delay_test, api_port, n["probe_name"]):
                            n["probe_name"] for n in todo_delay}
                    for fut in futs:
                        name = futs[fut]
                        try:
                            res = fut.result()
                        except Exception:
                            res = {"ok": False, "latency_ms": None}
                        results[name] = res
                        # 初筛是耗时大头，逐节点落盘——被杀的轮次下次直接跳过
                        ckpt.mark_delay(name, res)
            ckpt.flush(force=True)
            delay_passed = [n for n in nodes if results.get(n["probe_name"], {}).get("ok")]
            log(f"delay 初筛通过: {len(delay_passed)}/{len(nodes)}（{time.time() - t0:.0f}s）")

            # 4.2) 终筛：真实流量测试（经 mixed-port 访问海外被封锁目标）
            if delay_passed:
                t1 = time.time()
                todo_real = [n for n in delay_passed if n["probe_name"] not in ck_real]
                if todo_real:
                    with ThreadPoolExecutor(max_workers=REAL_TRAFFIC_CONCURRENCY) as ex:
                        futs = {ex.submit(real_traffic_test, api_port, mixed_port,
                                          n["probe_name"]): n["probe_name"]
                                for n in todo_real}
                        for fut in futs:
                            name = futs[fut]
                            try:
                                rt = fut.result()
                            except Exception:
                                rt = {"ok": False}
                            # 真实流量失败则把该节点最终标记为不通过
                            if not rt.get("ok"):
                                results[name]["ok"] = False
                            results[name]["real_traffic"] = rt
                            ckpt.mark_real(name, results[name])
                    ckpt.flush(force=True)
                if len(todo_real) < len(delay_passed):
                    log(f"断点续跑: 终筛复用 {len(delay_passed) - len(todo_real)} 个结论，"
                        f"补测 {len(todo_real)} 个")
                real_passed = [n for n in delay_passed
                               if results.get(n["probe_name"], {}).get("ok")]
                log(f"真实流量终筛通过: {len(real_passed)}/{len(delay_passed)}"
                    f"（{time.time() - t1:.0f}s）")
                # 不稳定计数（2026-10-26）：首轮达标、复测不达标的「先快后断」
                # 节点——它们正是「沙箱测着像活的、用户用着全死」的主因，
                # 单独计数便于每轮审计这道闸门是否在起作用。
                n_unstable = sum(
                    1 for n in delay_passed
                    if (results.get(n["probe_name"], {}).get("real_traffic") or {})
                    .get("unstable"))
                if n_unstable:
                    log(f"稳定性剔除: {n_unstable} 个节点首轮达标但复测不达标"
                        f"（先快后断），降级第二资产")
            # 慢档收集（任务#97）：快档不足但有真实流量的节点 → 第二资产
            degraded = [n for n in delay_passed
                        if results.get(n["probe_name"], {}).get("real_traffic", {})
                        .get("degraded")]
            log(f"拨测完成: 最终通过 {sum(1 for r in results.values() if r['ok'])}/{len(nodes)}"
                f"（{time.time() - t0:.0f}s）")

            # 5) 证据收集（出口 IP/地区 + AI 可达性，单次切组 8 路并行，
            #    2026-10-21 任务#91 合并）。仅通过节点；限量 + 限时，
            #    证据仅留痕、不构成闸门。
            passed = [n for n in nodes if results.get(n["probe_name"], {}).get("ok")]
            # final 置位（2026-10-24 任务#96）：实测通过才算 final=True。
            # 继承自 CI 文档/上一轮发布集的 final 标记在进入本轮后一律作废，
            # 报告 nodes[].final 从此严格等于「本轮实测通过」。
            #
            # 修复（2026-11-04 任务#118）：上方注释是承诺，实现却没兑现——
            # 只置 True 不置 False，从 CI pending_probe.json 继承来的 final=True
            # 原样带进报告。实证本轮 311 条记录里 88 个「未测节点」
            # （cn={"ok":false,"latency_ms":null}）被标 final=True，而真正通过
            # 的 4 个是 final=False——报告字段语义整个反了，任何按 final 做的
            # 统计（含 dashboard、历史复盘）都会把死节点算成可用节点。
            mark_final_flags(nodes, passed)
            # 动态证据预算（2026-10-24 任务#98）：旧固定 120s 在通过节点较多时
            # 只能覆盖一半（本轮 30 个只探到 17 个），无 AI 证据的节点在排序中
            # 被「未知」沉底——有效节点被埋。单节点 ≈8s，按通过数给足预算
            # （下限 120s 兜底，上限 300s 防极端），保证全覆盖。
            ev_budget = min(300, max(EVIDENCE_BUDGET_S, len(passed) * 12))
            ev_deadline = time.time() + ev_budget
            # 证据收集范围（2026-10-28 修复）：旧实现仅覆盖快档通过者，
            # degraded 节点永远没有 AI 证据 → 6.6「AI 慢档提级」空转
            # （实证：6 个存活的 carryover 慢档节点无一被 AI 探测，AI 可用
            # 节点滞留第二资产）。现追加慢档节点（carryover 优先），共用时间
            # 预算；出口证据（geo）仍只统计快档通过者，口径不变。
            _deg_ev = sorted(
                degraded,
                key=lambda n: 0 if n.get("origin") == "carryover" else 1)
            ev_nodes = passed[:GEO_MAX_NODES] + _deg_ev
            n_geo = 0
            for i, n in enumerate(ev_nodes):
                if time.time() > ev_deadline:
                    log(f"证据收集达到时间预算 {ev_budget}s，跳过剩余 "
                        f"{len(ev_nodes) - i} 个节点（证据仅留痕，不构成闸门）")
                    break
                try:
                    ev = node_evidence(api_port, mixed_port, n["probe_name"])
                except Exception as e:
                    log(f"证据收集异常（节点 {n['probe_name']}，已跳过）："
                        f"{type(e).__name__}: {e}")
                    ev = {}
                if ev.get("geo"):
                    results[n["probe_name"]].update(ev["geo"])
                    n_geo += 1
                if ev.get("ai"):
                    results[n["probe_name"]]["ai"] = ev["ai"]
            n_ai = sum(1 for n in passed
                       if results[n["probe_name"]].get("ai", {}).get("ai_reachable"))
            n_api = sum(1 for n in passed
                        if results[n["probe_name"]].get("ai", {}).get("ai_api"))
            log(f"证据收集完成: 出口证据 {n_geo}/{len(passed)}，"
                f"AI 任一可达 {n_ai}/{len(passed)}，API 层可用 {n_api}/{len(passed)}"
                f"（{ev_budget - max(0, ev_deadline - time.time()):.0f}s）")
            if _deg_ev:
                _d_ai = sum(1 for n in _deg_ev
                            if results[n["probe_name"]].get("ai", {}).get("ai_reachable"))
                _d_api = sum(1 for n in _deg_ev
                             if results[n["probe_name"]].get("ai", {}).get("ai_api"))
                log(f"慢档证据: 探测 {len(_deg_ev)}，AI 可达 {_d_ai}，"
                    f"API 层可用 {_d_api}（可达者将由 AI 慢档提级升入主资产）")
        except Exception as e:
            log(f"熔断: 拨测过程异常（{type(e).__name__}: {e}），不发布")
            return 3
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    # 6) 合并：通过即留、败即汰（自清洁）；AI 可用优先 + 长寿实证 + 双 vantage
    # learning 已在 3) 测试集段加载（任务#122 提前，供池节点判定使用）
    verified = sorted(passed, key=lambda n: verified_rank(n, results, learning))

    # 6.05) 高延迟降级（2026-10-24）：初筛 RTT 超上限的通过节点降级第二资产。
    # 沙箱「能通」≠ 本地可用——延迟 2.5s+ 的节点用户点开即弃。置于此处：
    # 早于波动带判定（降级者计入缺口）与 AI 慢档提级（AI 可达者仍可回升）。
    _slow = [n for n in verified
             if (results.get(n["probe_name"], {}).get("latency_ms") or 99999)
             > CN_MAX_PUBLISH_LATENCY_MS]
    if _slow:
        verified = [n for n in verified if n not in _slow]
        degraded = degraded + _slow
        log(f"高延迟降级: {len(_slow)} 个节点 RTT > "
            f"{CN_MAX_PUBLISH_LATENCY_MS}ms，降级第二资产（AI 可达者可提级回升）")

    # 6.5) 纯 carryover 轮次「保留已发布集」修复（2026-10-17，服务「固化闭环」）：
    # 当本轮没有新 CI 待测文档（n_pend==0 且 n_resc==0，测试集全为 carryover），
    # 且缺口在波动带内，则不触发「真实退化自清洁」，但主资产只发复测存活者。
    # 2026-10-24 改判：旧逻辑把重测已死的节点也整集保留（本轮实证 5/30 复测
    # 失败仍发布），用户本地实测「能用节点不到 3 个」的直接元凶。防侵蚀诉求
    # 改由「失败者降级第二资产保留身份，后续轮复测存活可回升」承接。
    if (n_pend == 0 and n_resc == 0 and n_carry > 0
            and len(verified) >= config.VERIFICATION_MIN_PASSED
            and (n_carry - len(verified)) <= CARRYOVER_FLUCTUATION_BAND):
        _failed_carry = [n for n in carry if n not in verified]
        if _failed_carry:
            degraded = degraded + _failed_carry
        log(f"纯 carryover 轮次：重测通过 {len(verified)}/{n_carry}，缺口 "
            f"{n_carry - len(verified)} ≤ 波动带 {CARRYOVER_FLUCTUATION_BAND}；"
            f"主资产只发复测存活者，{len(_failed_carry)} 个失败者降级第二资产"
            f"（不随单快照波动侵蚀身份，也不占主资产）")

    # 6.6) AI 慢档提级（2026-10-24，用户硬性诉求「无论如何保证 AI 可用节点」）：
    # 快档不足但 AI 可达的慢档节点升入主资产。依据：AI 聊天/API 流量极小
    # （单条消息几 KB），32KB/s（≈4KB/s 起步）远够 chatgpt/claude 网页与
    # API 使用——「下载速度」闸门对 AI 场景过严，导致 AI 可用节点被误汰。
    # 置于 6.5 之后：纯 carryover 轮的整集保留不冲掉提级结果。
    # 任务#112（2026-10-28）：提级须守延迟上限——本轮实证 6.9s 的节点靠 AI
    # 提级混进主资产，用户本地「点开即弃」。AI 可用 ≠ 本地能用：延迟超
    # AI_PROMOTE_MAX_LATENCY_MS 的节点留在第二资产，下轮回炉（慢档回炉机制）。
    # 任务#116（2026-11-04）两处收紧，皆有实证：
    # (a) 延迟线取严：提级上限必须 ≤ 主资产闸门，否则 6.05 降级→6.6 提回，
    #     同轮内自相矛盾（实测 4 个 2646~3030ms 节点因此发布，用户端全超时）。
    # (b) 信号取强：ai_reachable 只要有任何 HTTP 响应（含 403/Cloudflare 拦截）
    #     即为真，14 个发布节点 chatgpt/claude 全 403 却都被判「AI 可用」；
    #     改用 ai_api（openai_api != 403，即 401/200）——Cloudflare 放行到 API 层，
    #     才是「IP 干净、真能调 AI」的可靠判据。
    _promote_cap = min(config.AI_PROMOTE_MAX_LATENCY_MS, CN_MAX_PUBLISH_LATENCY_MS)
    ai_slow, _ai_slow_rejected = select_ai_promotions(degraded, results, _promote_cap)
    if ai_slow:
        log(f"AI 慢档提级: {len(ai_slow)} 个 AI 干净（openai_api 放行）的慢档节点并入主资产"
            + (f"（另有 {_ai_slow_rejected} 个超延迟上限 {_promote_cap}ms 留守第二资产）"
               if _ai_slow_rejected else ""))
        verified = sorted(verified + ai_slow,
                          key=lambda n: verified_rank(n, results, learning))
        degraded = [n for n in degraded if n not in ai_slow]

    # 6.7) 用户本地实测硬否决（2026-10-29 任务#113）：用户家宽的实测结论是
    # 最终事实——本地连不上的节点，沙箱再快也不该进主资产。置于 AI 提级之后，
    # 防止「AI 可达」把用户已判死的节点复活。
    if config.USER_PROBE_DEAD_BLOCK:
        _udead = [n for n in verified
                  if user_verdict(n, learning) == "dead"]
        if _udead:
            verified = [n for n in verified if n not in _udead]
            degraded = degraded + _udead
            log(f"用户实测否决: {len(_udead)} 个节点在用户本地实测失败，"
                f"已移出主资产（降级第二资产，下轮复测）")

    # 6.8) 用户实测 alive 长效保活（任务#116，2026-11-04）：用户验证过能用的节点，
    # 本轮测速落入慢档（速度抖动）但延迟仍达标时保留主资产。理由：
    #   - 用户本地实测是地面真相，沙箱测速只反映「腾讯云上海这一跳」；
    #   - 延迟达标 = 链路还活着，速度波动不足以判定「不能用」；
    #   - 48h 一刀切过期会让一周前验证的节点全部失忆，订阅数量忽多忽少。
    # 防误保：延迟测不出（真死）不保活，仍走第二资产/下轮复测淘汰路径。
    if config.USER_PROBE_ALIVE_KEEP:
        _ukeep = select_alive_keeps(degraded, results, learning)
        if _ukeep:
            verified = sorted(verified + _ukeep,
                              key=lambda n: verified_rank(n, results, learning))
            degraded = [n for n in degraded if n not in _ukeep]
            log(f"用户实测保活: {len(_ukeep)} 个用户验证可用的节点测速落慢档"
                f"但延迟达标（≤{CN_MAX_PUBLISH_LATENCY_MS}ms），保留主资产")

    # 6.9) 用户验证常驻池（任务#119，2026-11-04）：把「用户本地实测 alive 且
    # 完整配置已存档」的节点无条件并入主资产。与 6.8 的区别：6.8 只救得回
    # 本轮 delay 初筛通过、后续落慢档的节点；而实证本轮 310 个候选里 294 个
    # 在 delay 初筛就被淘汰（沙箱路径与家宽不等价），6.8 对它们完全无感。
    # 池内节点不参与沙箱准入判定，也不冒充「本轮实测通过」——报告里单独标注
    # via=user_verified，用户可自行区分两类证据。dead 硬否决与 30 天退役仍在。
    # 只有「豁免组」直接并入；需复测的池节点已随测试集跑完，通过者此刻就在
    # verified 里（origin=user_pool，final=True），不再重复并入。
    pool_nodes = pool_exempt
    _req_pass = [n for n in pool_require
                 if results.get(n["probe_name"], {}).get("ok")]
    if pool_require:
        log(f"用户池复测结果: {len(_req_pass)}/{len(pool_require)} 通过"
            f"（未通过者不发布——它们此前是靠免测特权留在订阅里的）")
    pool_add: list[dict] = []
    if pool_nodes:
        have = {n["fp"] for n in verified} | {n["fp"] for n in degraded}
        pool_add = [n for n in pool_nodes if n["fp"] not in have]
        if pool_add:
            verified = sorted(verified + pool_add,
                              key=lambda n: verified_rank(n, results, learning))
            stale = sum(1 for n in pool_add if n["_user_stale"])
            dup = len(pool_nodes) - len(pool_add)
            log(f"用户验证常驻池: {len(pool_add)} 个本地实测 alive 节点并入主资产"
                f"（不依赖沙箱复测）"
                + (f"，其中 {stale} 个证据已超 "
                   f"{config.USER_POOL_STALE_S // 86400} 天建议复验" if stale else "")
                + (f"；另有 {dup} 个已在本轮发布/降级集内，去重未重复计入" if dup else ""))
        else:
            log(f"用户验证常驻池: {len(pool_nodes)} 个节点均已在本轮发布集内")
    else:
        log("用户验证常驻池: 无可用记录")

    by_origin = {o: sum(1 for n in verified if n["origin"] == o)
                 for o in ("pending", "rescue", "carryover", "user_pool")}
    # 分源/分协议聚合（Phase 2.2）：tested/passed 双口径，供 CI 源级评分与门槛自学习
    # 分源仅统计带 src 的节点（carryover 等无源节点不归任何源，避免产生 "?" 伪源
    # 污染源级评分）；分协议仍覆盖全部节点。
    # 分源行带 AI 证据三口径（任务#92）：ai_tested/ai_reachable/ai_api，
    # 供 CI 侧计算分源 AI 效率（有效性反哺，见 _agg_source_ai）。
    src_nodes = [n for n in nodes if n.get("src")]
    src_verified = [n for n in verified if n.get("src")]
    by_source = _agg_source_ai(src_nodes, src_verified, results)
    # 分协议带置信区间（P2-a）：小样本协议（anytls/hysteria 等）的通过率必须配
    # 95% Wilson 区间与 sample_ok 标记，避免"看单轮数字就加权"（2026-10-15 教训）。
    by_protocol = _agg_two(nodes, verified,
                           key_fn=lambda n: str(n["proxy"].get("type", "?")),
                           with_ci=True)
    # AI 可达性统计（2026-10-20）：仅覆盖有 ai 数据的通过节点（探测受预算
    # 约束可能跳过尾部）；ai_reachable/ai_api 判据见 classify_ai。
    ai_probed = [n for n in passed if "ai" in results.get(n["probe_name"], {})]
    ai_reach = [n for n in ai_probed
                if results[n["probe_name"]]["ai"].get("ai_reachable")]
    ai_api_ok = [n for n in ai_probed
                 if results[n["probe_name"]]["ai"].get("ai_api")]
    ai_by_domain = {
        label: sum(1 for n in ai_probed
                   if (results[n["probe_name"]]["ai"].get("codes") or {}).get(label))
        for label in AI_TARGETS
    }
    log(f"验证集: {len(verified)} 个（pending {by_origin['pending']} / "
        f"rescue {by_origin['rescue']} / carryover {by_origin['carryover']} / "
        f"用户池 {by_origin['user_pool']}"
        f"（本轮复测通过 {len(_req_pass)} + 豁免直发 {len(pool_add)}））")
    if ai_probed:
        log(f"AI 可达性: 探测 {len(ai_probed)} 个，任一可达 {len(ai_reach)}，"
            f"API 层可用 {len(ai_api_ok)}（分域名: "
            + ", ".join(f"{k}={v}" for k, v in ai_by_domain.items()) + "）")

    report = {
        "round_id": round_id,
        "tested_round": resolve_tested_round(doc_round if fresh else None,
                                             last_round),
        "generated_at": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "vantage": VANTAGE_LABEL,
        "exit_ip": _sandbox_ip(),
        # 语义说明（口径修正，2026-10-15）：us_ok 与 cn.ok 是**两次不同测量**，
        # 不可当同一维度的重复观测。二者的探测目标/超时/判定标准均不同：
        #   us_ok  —— CI 美西 Runner 侧 mihomo 完整 HTTPS 拨测，回答「对美西出口
        #             是否可达」；False 不代表节点已死（可能是该方向被墙/QoS）。
        #   cn.ok  —— 本沙箱（中国）侧 mihomo 延迟测试，回答「国内路径是否可用」。
        # 报告观测到的差异（如 us_ok=False 且 cn.ok=True）是**正常现象**，
        # 反映的是路径差异而非数据矛盾。下游判读务必分开使用。
        "dimensions": {
            "us_ok": "美西拨测可达性（CI Runner，完整 HTTPS；False≠节点死亡）",
            "cn_ok": "中国实测可用性（本沙箱，延迟测试）",
            "ai": "AI 服务可达性（本沙箱经节点探测 chatgpt/claude/gemini/"
                  "copilot/openai_api；证据+排序信号，不构成闸门）",
            "user_pool": "用户本地实测 alive 且配置已存档的节点；沙箱与家宽"
                         "路径不等价，故不参与沙箱准入判定，单独标注不改 final 语义",
            "note": "两维度探测目标/判定标准不同，不可互相替代或合并统计；"
                    "counts.passed 为发布集总数（含用户实测保活），"
                    "counts.sandbox_passed 才是本轮沙箱实测通过数",
        },
        "counts": {
            "tested": len(nodes),
            "passed": len(verified),
            # 任务#119：发布集含两类证据，分开计数，避免把「用户实测保活」
            # 误读成「本轮沙箱新测通过」（nodes[].final 只标后者）。
            "sandbox_passed": len(passed),
            "published_sandbox": len(verified) - len(pool_add),
            # 任务#122：池节点拆两口径——本轮实测通过 vs 免测直发。
            # 旧字段 user_pool_kept 保留（CI/dashboard 在读），但语义收窄为
            # 「免测直发数」，另加 retested 供核对「多少是真验过的」。
            "user_pool_kept": len(pool_add),
            "user_pool_retested": len(_req_pass),
            # 慢档统计（任务#97）：快档不足但有真实流量的节点数，仅留痕
            "degraded": len(degraded) + len(ai_slow),
            # AI 慢档提级数（6.6）：已并入主资产
            "ai_slow_promoted": len(ai_slow),
            "by_origin": {"pending": n_pend, "rescue": n_resc,
                          "carryover": n_carry},
            "passed_by_origin": by_origin,
            "by_source": by_source,
            "by_protocol": by_protocol,
            "ai": {
                "probed": len(ai_probed),
                "reachable": len(ai_reach),
                "api_ok": len(ai_api_ok),
                "by_domain": ai_by_domain,
            },
        },
        "nodes": [{
            "fp": n["fp"], "name": n["name"], "origin": n["origin"],
            "final": n["final"], "us_ok": n["us_ok"], "src": n.get("src"),
            "cn": results.get(n["probe_name"], {}),
            "ai": results.get(n["probe_name"], {}).get("ai"),
        } for n in nodes],
        # 任务#119：发布集逐节点列出证据来源，用户可直接核对「哪些是本地
        # 实测验证过的、哪些是沙箱本轮新测的」，不再混在一个数字里。
        "published_nodes": [{
            "name": n["name"],
            "fp": n["fp"],
            "type": n["proxy"].get("type"),
            # 任务#122：池节点分两种证据强度——「本轮刚复测通过」与「7 天前
            # 的用户旧证据免测直发」。旧实现两者都写 user_verified + 旧年龄，
            # 用户核对时无法区分「验过的」和「靠特权留下的」。
            "via": ("user_pool_retested"
                    if (n.get("_user_verified") and n.get("final"))
                    else "user_verified" if n.get("_user_verified")
                    else "sandbox_pass"),
            "evidence_age_d": (0.0 if (n.get("_user_verified") and n.get("final"))
                               else round((time.time() - n["_user_ts"]) / 86400, 1)
                               if n.get("_user_ts") else None),
        } for n in verified],
        "user_pool": {
            "total": len(pool_nodes),
            "kept": len(pool_add),
            "stale": sum(1 for n in pool_add if n["_user_stale"]),
            "unrecoverable": _pool_unrecoverable(workdir),
        },
        "published": False,
    }
    # 继承主资产归属信号（2026-10-17 修复）：从 release 现有 report 读取最近
    # 一次有效发布的时间/通过数。本轮通过数不足时，只要该信号仍新鲜，就保留
    # "实测集在场"信号，避免 CI 误判为"沙箱未产出"而兜底覆盖实测集。
    prev_report = _load_release_report(tag, workdir)
    mp_at = prev_report.get("main_asset_published_at") if prev_report else None
    mp_passed = int((prev_report or {}).get("main_asset_passed", 0) or 0)
    report["main_asset_published_at"] = mp_at
    report["main_asset_passed"] = mp_passed
    report_path = os.path.join(workdir, config.VERIFICATION_REPORT_FILE)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)

    # 7) 熔断：空集才不碰主资产（保留上轮验证集/CI 兜底）。
    # 任务#116：原用 VERIFICATION_MIN_PASSED(8) 作闸门，逼着系统靠 AI 提级
    # 凑数（实证 4 个 2646~3030ms 废节点因此进主资产）；改为 ≥1 即发布——
    # 宁发 1 个真能用，不发 12 个凑数，也不保留上一轮的坏节点。
    if len(verified) < config.PUBLISH_MIN_PASSED:
        # 关键修复（2026-10-17）：本轮通过数不足 ≠ "沙箱从未有效产出"。
        # 若 release 上最近有效发布（main_asset_passed≥15）仍新鲜，则保留
        # published=True 信号，CI 据此不兜底，实测集不被候选集覆盖。
        report["published"] = bool(
            prev_report and prev_report.get("published")
            and mp_at and mp_passed >= config.PUBLISH_MIN_PASSED
            and _within_window(mp_at, config.VERIFICATION_MAX_AGE_S))
        log(f"熔断: 通过数 {len(verified)} < 下限 {config.VERIFICATION_MIN_PASSED}，"
            f"不发布主资产（保留上一轮验证集）；继承主资产信号 published="
            f"{report['published']}")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=1)
        if not args.dry_run:
            _upload_report(tag, report_path)
        return 0

    # 8) 发布验证集到主资产（p_* 随机名，订阅永久地址不变）
    paths = write_verified_outputs(verified, workdir, results)
    asset_by_fmt = {}
    for a in assets:
        m = ASSET_RE.match(a.get("name", ""))
        if m:
            asset_by_fmt[ASSET_FORMAT[m.group(1)]] = a["name"]
    log("验证集输出: " + ", ".join(f"{k}={os.path.basename(v)}"
                                    for k, v in paths.items()))
    if args.dry_run:
        log("dry-run: 跳过发布。产物在 " + workdir)
        return 0
    uploaded = []
    for fmt, path in paths.items():
        target = asset_by_fmt.get(fmt)
        if not target:
            log(f"警告: 未找到 {fmt} 对应的主资产名，跳过")
            continue
        # gh release upload 的资产名只能取文件基名（'#' 后缀是显示标签而非
        # 改名），故先复制成目标资产名再传，保证永久订阅地址内容被原地刷新。
        staged = os.path.join(workdir, target)
        shutil.copyfile(path, staged)
        ok, err = upload_asset_with_retry(tag, staged)
        if ok:
            uploaded.append(target)
        else:
            log(f"警告: 上传 {target} 失败（已重试）: {err}")
    # 8.5) 第二资产（2026-10-24 任务#97）：慢档节点（能连但慢）单独发布，
    # 不稀释主资产——主资产口径不变（全部快档通过），慢档按延迟排序上限
    # 50 个，供用户「主资产连不上时备选」。资产名沿用主资产随机前缀 _d.yaml。
    if degraded:
        deg_sorted = sorted(
            degraded,
            key=lambda n: (results.get(n["probe_name"], {}).get("latency_ms")
                           if results.get(n["probe_name"], {}).get("latency_ms")
                           is not None else 99999))[:50]
        deg_cfg = build_verified_config(deg_sorted, results)
        deg_path = os.path.join(
            workdir, VERIFIED_FILE["clash"].replace(
                "verified_clash", "verified_degraded_clash"))
        with open(deg_path, "w", encoding="utf-8") as f:
            yaml.dump(deg_cfg, f, allow_unicode=True, sort_keys=False)
        m_main = asset_by_fmt.get("clash")
        mm = re.match(r"^(p_[0-9a-f]+)_", m_main) if m_main else None
        deg_name = (mm.group(1) + "_d.yaml") if mm else "verified_degraded_clash.yaml"
        staged = os.path.join(workdir, deg_name)
        shutil.copyfile(deg_path, staged)
        ok, err = upload_asset_with_retry(tag, staged)
        if ok:
            log(f"第二资产已发布: {deg_name}（慢档 {len(deg_sorted)} 个）")
            report["degraded_asset"] = deg_name
            report["degraded_count"] = len(deg_sorted)
        else:
            log(f"警告: 第二资产上传失败（已重试）: {err}")
    _upload_report(tag, report_path)
    report["published"] = bool(uploaded)
    report["main_assets"] = uploaded
    # 任务#116：记录上传失败的格式，便于排查「各格式内容不一致」
    # （实证 clash 502 后停留在上一轮 12 个旧节点，其余格式已是新的 2 个）。
    _want = [asset_by_fmt[f] for f in paths if asset_by_fmt.get(f)]
    report["main_assets_missing"] = [a for a in _want if a not in uploaded]
    report["main_asset_published_at"] = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    report["main_asset_passed"] = len(verified)
    # 节点库存档（任务#117）：把本轮通过 + 慢档的完整配置写进库，供后续轮次
    # 跨源复测。没有这层，节点滑出最近两轮资产后配置即永久丢失（实测 781 个
    # 历史通过节点全部失联），订阅数量只能随源波动。
    try:
        _lib_n = save_node_library(verified + degraded, workdir,
                                   stamp.strftime("%Y-%m-%dT%H:%M:%SZ"))
        log(f"节点库存档: 本轮 {_lib_n} 个节点（通过 {len(verified)} + "
            f"慢档 {len(degraded)}）")
        # 任务#119：回传 release，避免沙箱重启后失忆；同时把用户验证池一并
        # 持久化，保证换沙箱也能读回地面真相。
        if config.NODE_LIBRARY_PERSIST and not args.dry_run:
            _pushed = []
            for _f in (_lib_path(workdir),
                       os.path.join(REPO_ROOT, config.USER_POOL_FILE)):
                if os.path.exists(_f):
                    ok, err = upload_asset_with_retry(tag, _f)
                    if ok:
                        _pushed.append(os.path.basename(_f))
                    else:
                        log(f"警告: 持久化 {os.path.basename(_f)} 失败: {err}")
            if _pushed:
                log(f"持久化到 release: {', '.join(_pushed)}")
    except Exception as e:
        log(f"警告: 节点库存档失败（不影响发布）: {e}")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    _upload_report(tag, report_path)
    # 轮转：保留本轮消费的待测文档一个世代（pending_probe.prev.json）
    if fresh and os.path.exists(pend_path):
        prev_path = os.path.join(workdir, "pending_probe.prev.json")
        shutil.copyfile(pend_path, prev_path)
        _ok, _err = gh_compat.upload_asset(
            tag, prev_path, name="pending_probe.prev.json")
        if not _ok:
            log(f"警告: 上传 pending_probe.prev.json 失败: {_err}")
    # 学习回写（任务#117）：沙箱每轮实测结果**立即**折回进化数据，不再只依赖
    # CI 的 daily-update。实证：source_scores.json 里 26 个源的 cn_last 中有
    # 16 个停在 10-19~10-28（超 CN_DECISION_MAX_AGE_S=48h），cn_fetch_tilt 全部
    # 返回 None → 配额倾斜失效 → 零产源（311 测 0 通过）继续占据 76% 测试预算。
    # 沙箱一天跑 6 轮、CI 一天只跑 1~2 次，学习速率被 CI 频率卡死。
    try:
        import evolution
        _ev = evolution.run_evolution(report, REPO_ROOT, _official_url_map())
        log(f"学习回写: cn_history={_ev['cn_history_nodes']} 节点 / "
            f"源评分带cn={_ev['source_scores_with_cn']} / "
            f"带ai={_ev['source_scores_with_ai']} 源")
    except Exception as e:  # 学习回写失败绝不能影响已完成的发布
        log(f"警告: 学习回写失败（不影响本轮发布）: {type(e).__name__}: {e}")

    # 任务#119：旧日志「主资产 4 个」实际是 4 个格式文件，被反复误读成
    # 「只有 4 个节点」，直接触发「怎么越来越少」的误判。口径写全。
    # 注意用「发布集内沙箱来源数」而非 len(passed)：后者是本轮拨测通过数，
    # 其中若干已因高延迟/稳定性降级到第二资产，与保活数相加会超过发布集
    # 总数（本轮实证 6+6≠11），又是一个假数字。
    # 断点续跑检查点清理（任务#120）：本轮已走完发布流程，检查点使命结束。
    # 必须清掉——否则下一轮若测试集签名恰好相同（如纯 carryover 轮），
    # 就会复用上一轮的判定结论，而项目口径是「活性由实时拨测决定」。
    if ckpt is not None:
        ckpt.clear()
    _pub_sandbox = len(verified) - len(pool_add)
    log(f"发布完成: {len(verified)} 个节点（发布集内沙箱来源 {_pub_sandbox} + "
        f"用户实测保活 {len(pool_add)}；本轮沙箱拨测通过 {len(passed)}），"
        f"已刷新 {len(uploaded)}/{len(paths)} 个格式资产 + "
        f"{config.VERIFICATION_REPORT_FILE}（round {round_id}）")
    return 0


def _sandbox_ip() -> str:
    for url in ("https://cip.cc", "https://myip.ipip.net"):
        try:
            with _DIRECT_OPENER.open(urllib.request.Request(
                    url, headers={"User-Agent": "curl/8"}), timeout=8) as r:
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})",
                              r.read().decode("utf-8", "replace"))
                if m:
                    return m.group(1)
        except Exception:
            continue
    return ""


def _load_release_report(tag: str, workdir: str) -> dict:
    """下载 release 上现有 verification_report（用于继承主资产归属信号）。"""
    path = os.path.join(workdir, "prev_verification_report.json")
    if gh_download(tag, config.VERIFICATION_REPORT_FILE, path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _within_window(ts: str | None, max_age_s: int) -> bool:
    """时间戳是否落在 [0, max_age_s) 窗口内（用于主资产归属信号新鲜度）。"""
    if not ts:
        return False
    try:
        gen = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if gen.tzinfo is None:
            gen = gen.replace(tzinfo=datetime.timezone.utc)
        age = (datetime.datetime.now(datetime.timezone.utc) - gen).total_seconds()
        return 0 <= age < max_age_s
    except Exception:
        return False


if __name__ == "__main__":
    sys.exit(main())
