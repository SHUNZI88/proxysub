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
import fcntl
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

# 已知持久化 PAT 路径（沙箱内）；环境变量为空时自动兜底载入。
# 绝不可因环境变量为空就断言"没有 token"——见仓库根目录 AGENTS.md。
PERSISTED_PAT_PATH = os.environ.get("PERSISTED_PAT_PATH", "/root/.github_pat")

import common  # noqa: E402
import config  # noqa: E402
import yaml  # noqa: E402

try:
    from output import write_outputs  # noqa: E402
    from score import classify_proxy  # noqa: E402
except Exception:  # 仓库模块缺失时明确失败（脚本与仓库同版本发布）
    write_outputs = None
    classify_proxy = None

GENERATE_204 = "https://www.google.com/robots.txt"
# 真实流量测试：必须是中国大陆被封锁、只有经代理才能访问的海外地址。
# 早期用 robots.txt / cdn-cgi/trace「几行字」+ 403/非空 body 兜底作判据，放行大量
# 「能握手但下载龟速」的伪可用节点（用户本地实测即暴露无效）。2026-10-17 改为
# 「硬超时真实下载速度」闸门（见 real_traffic_test / _timed_download）。
REAL_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=1000000"  # 1MB
REAL_MIN_BYTES = 250 * 1024   # 预算内至少下载 250KB（≈31KB/s）才算真能应用
# 慢档阈值（2026-10-24 任务#97）：8s 内有真实流量但不足快档——「能连但慢」。
# 这类节点不进主资产（快档标准不放松），但进第二资产 p_*_d.yaml 供用户备选。
# 依据：用户本地测速只要求「有延迟反应」，32KB（≈4KB/s）即有明显体感；
# 旧口径一刀切淘汰了大批「能连但慢」节点，是 326 节点源 0 通过的成因之一。
REAL_SLOW_MIN_BYTES = 32 * 1024
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
DELAY_TIMEOUT_MS = 5000
DELAY_CONCURRENCY = 12
REAL_TRAFFIC_TIMEOUT_S = 8    # 真实下载硬超时预算（秒）
REAL_TRAFFIC_CONCURRENCY = 12
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
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    repo = os.environ.get("PROXYSUB_REPO", "SHUNZI88/proxysub")
    url = f"https://github.com/{repo}/releases/download/{tag}/{pattern}"
    last_err = "未执行"
    for attempt in range(retries + 1):
        # 1) 优先 gh（超时/失败均交由 curl 兜底）
        try:
            r = run(["gh", "release", "download", tag, "-p", pattern, "-O", dest, "--clobber"],
                    timeout=60)
            if r.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 0:
                return True
        except subprocess.TimeoutExpired:
            last_err = "gh 超时"
            log(f"提示: gh 下载 {pattern} 超时，回退 curl")
        except Exception as e:
            last_err = f"gh 异常: {e!r}"
        # 2) 回退 curl（务必显式捕获超时，绝不向上抛出）
        try:
            cr = run(["curl", "-fsSL", "--connect-timeout", "10", "--max-time", "45",
                      "-H", f"Authorization: Bearer {token}", "-o", dest, url],
                     timeout=60)
            if cr.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 0:
                return True
            last_err = f"curl 返回码 {cr.returncode}"
        except subprocess.TimeoutExpired:
            last_err = "curl 超时"
            log(f"提示: curl 下载 {pattern} 超时")
        except Exception as e:
            last_err = f"curl 异常: {e!r}"
        if attempt < retries:
            log(f"下载 {pattern} 失败（{last_err}），8s 后重试（第 {attempt + 2}/{retries + 1} 次）")
            time.sleep(8)
    log(f"熔断: 下载 {pattern} 重试 {retries} 次仍失败（{last_err}）——将由调用方降级处理")
    return False


def auth_selfcheck() -> bool:
    """鉴权自检（grok 2.3）：GH_TOKEN 缺失或 gh 未登录则立即失败，避免空转。

    返回 True 表示可继续；False 表示应非 0 退出。

    注（2026-10-15 复盘）：本函数的失败信息必须给出「去哪找凭据」的指引，
    否则 AI 协作者容易把「环境变量为空」误判为「没有 token」——项目里有持久化
    PAT，路径见下方提示与仓库根目录 AGENTS.md。
    """
    # 自动兜底：环境变量缺失时，从已知持久化路径补充（避免误判"没有 token"）
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token and os.path.exists(PERSISTED_PAT_PATH):
        try:
            with open(PERSISTED_PAT_PATH, encoding="utf-8") as f:
                token = f.read().strip()
            if token:
                os.environ["GH_TOKEN"] = token
                log(f"提示: 环境变量无 token，已自动从 {PERSISTED_PAT_PATH} 载入持久化 PAT")
        except OSError:
            token = None
    if not token:
        log(
            "熔断: 环境变量 GH_TOKEN/GITHUB_TOKEN 均未设置，且持久化路径"
            f" {PERSISTED_PAT_PATH} 不存在——无法读写 Release，中止。\n"
            "  【给 AI 协作者】本仓库凭据存在多处，环境变量通常为空，"
            "绝不等于\"没有 token\"。断言前请依次检查：\n"
            f"    ① 持久化 PAT 文件: {PERSISTED_PAT_PATH}（chmod 600）\n"
            "    ② 项目文档: docs/cn_probe.md、scripts/cn_probe.py、monitor_1617_run.py\n"
            "    ③ 环境变量: GH_TOKEN / GITHUB_TOKEN\n"
            "  正确用法: export GH_TOKEN=\"$(cat /root/.github_pat)\"\n"
            "  完整规则见仓库根目录 AGENTS.md。"
        )
        return False
    # gh 自动从 GH_TOKEN 读取；auth status 验证 token 实际可用（含 401 检测）
    r = run(["gh", "auth", "status"], timeout=60)
    if r.returncode != 0:
        # 裁剪输出，避免把 token 细节打印到日志
        msg = (r.stderr or r.stdout).strip().splitlines()
        tail = "；".join(msg[-3:]) if msg else "gh auth status 异常"
        log(
            f"熔断: gh 鉴权失败（GH_TOKEN 可能失效/权限不足）——中止。{tail}\n"
            f"  【给 AI 协作者】token 可能已轮换，请核对 {PERSISTED_PAT_PATH} 是否为最新，"
            "并参考 AGENTS.md 的凭据规则。"
        )
        return False
    return True


def release_assets(tag: str) -> list[dict]:
    r = run(["gh", "release", "view", tag, "--json", "assets"])
    if r.returncode != 0:
        return []
    try:
        return json.loads(r.stdout).get("assets", [])
    except Exception:
        return []


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
    carry = [n for n in nodes if n.get("origin") == "carryover"]
    pend = [n for n in nodes if n.get("origin") == "pending"]
    resc = [n for n in nodes if n.get("origin") == "rescue"]
    kept: list[dict] = []
    for bucket in (carry, pend, resc):  # 优先级：carryover > pending > rescue
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
            with urllib.request.urlopen(req, timeout=10) as resp:
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
def ensure_mihomo(workdir: str) -> str | None:
    local = "/usr/local/bin/mihomo"
    if os.path.exists(local):
        v = run([local, "-v"])
        if v.returncode == 0 and MIHOMO_VERSION.lstrip("v") in v.stdout + v.stderr:
            return local
    dest = os.path.join(workdir, "mihomo")
    url = (f"https://github.com/MetaCubeX/mihomo/releases/download/"
           f"{MIHOMO_VERSION}/mihomo-linux-amd64-{MIHOMO_VERSION}.gz")
    for i in range(3):
        r = run(["curl", "-fsSL", "--retry", "2", "-o", f"{dest}.gz", url], timeout=180)
        if r.returncode == 0 and run(["gunzip", "-f", f"{dest}.gz"]).returncode == 0:
            os.chmod(dest, 0o755)
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


def real_traffic_test(api_port: int, mixed_port: int, name: str) -> dict:
    """真实流量闸门：硬超时真实下载，验证节点真能在中国网络下传输数据。

    这是 2026-10-16 升级后的第二道闸门，2026-10-17 收紧判据。早期版本只取
    google/robots.txt 与 cloudflare/cdn-cgi/trace「几行字」，且 403/非空 body
    兜底放行，导致「能握手但下载龟速」的伪可用节点被判通过、用户本地实测即
    暴露无效。现改为真实下载速度闸门：预算内下载量达 REAL_MIN_BYTES 才判可用，
    龟速/失败（下载 0 或不足阈值）一律剔除。
    """
    if not api_put(api_port, "/proxies/PROBE", {"name": name}):
        return {"ok": False}
    proxy = f"http://127.0.0.1:{mixed_port}"
    n = _timed_download(proxy, REAL_DOWNLOAD_URL, REAL_TRAFFIC_TIMEOUT_S, REAL_MIN_BYTES)
    if n >= REAL_MIN_BYTES:
        return {"ok": True, "bytes": n}
    # 双档闸门（2026-10-24 任务#97）：快档不足但达慢档——标记 degraded，
    # 不进主资产，由调用方汇入第二资产。ok 恒 False，闸门口径不放松。
    if n >= REAL_SLOW_MIN_BYTES:
        return {"ok": False, "degraded": True, "bytes": n}
    return {"ok": False, "bytes": n}


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


def verified_rank(n: dict, results: dict) -> tuple:
    """验证集排序键：AI 可用性 > 双 vantage 强者 > 低延迟。

    2026-10-20 起 AI 可达性占首位——订阅顺序即用户可见性顺序，用户核心
    诉求是「可用于 AI 连接的纯净节点」；非 AI 节点不设硬闸门、仅沉底。
    原「双 vantage 强者 + 延迟」序降为次级判据（保持不变）。
    """
    r = results.get(n["probe_name"], {})
    ai = r.get("ai") or {}
    if ai.get("ai_api"):
        ai_tier = 0        # API 层未被封锁：配密钥即可用
    elif ai.get("ai_reachable"):
        ai_tier = 1        # 至少一个 AI 域有响应
    else:
        ai_tier = 2        # 未探测到或无响应（含探测超预算无数据）
    return (ai_tier,
            # 次级判据（2026-10-24 任务#96）：双 vantage 强者 >
            # carryover 复测存活（长寿命实证，用户体感最好）> 仅本轮新通过。
            # 注意 final 此时已被 main() 在通过后统一置 True，不再区分。
            0 if (n["us_ok"] and n["final"])
            else (1 if n.get("origin") == "carryover" else 2),
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


def build_verified_config(nodes: list[dict]) -> dict:
    """验证集 clash 配置：合规节点进自动/地区组，Insecure 独立隔离组。"""
    proxies = [dict(n["proxy"]) for n in nodes]
    names = _unique_names(proxies)  # 先统一分配唯一名，再回填 proxy.name 供分组引用
    for p, nm in zip(proxies, names):
        p["name"] = nm
    compliant = [p for p in proxies if not _truthy(p.get("skip-cert-verify"))]
    insecure = [p for p in proxies if _truthy(p.get("skip-cert-verify"))]
    compliant_names = [p["name"] for p in compliant]
    insecure_names = [p["name"] for p in insecure]
    groups = [
        {"name": "🚀 节点选择", "type": "select",
         "proxies": ["♻️ 自动选择", "DIRECT"] + compliant_names},
        {"name": "♻️ 自动选择", "type": "url-test", "proxies": compliant_names,
         "url": config.PROBE_URL, "interval": 300, "tolerance": 50},
    ]
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


def write_verified_outputs(nodes: list[dict], workdir: str) -> dict[str, str]:
    paths = {}
    cfg = build_verified_config(nodes)
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
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="中国出口节点实测（沙箱侧）")
    ap.add_argument("--tag", default=default_tag())
    ap.add_argument("--workdir", default=os.environ.get("CN_PROBE_WORKDIR", "/tmp/cn_probe"))
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
    lock_fd = open(os.path.join(workdir, "cn_probe.lock"), "w")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        log("另一实例正在运行（单实例锁），退出")
        return 0

    # 0.5) 鉴权自检（grok 2.3）：GH_TOKEN 失效则立即退出，避免空转 20 分钟
    if not auth_selfcheck():
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
        log("无新轮次待测文档（CI 调度延迟或故障）：本轮仅测 carryover；"
            "未测轮次顺延至下一实测轮，不丢失")

    # 3) 测试集 = carryover ∪ pending ∪ rescue
    assets = release_assets(tag)
    main_clash = next((a["name"] for a in assets if ASSET_RE.match(a.get("name", ""))
                       and a["name"].endswith("_c.yaml")), None)
    carry = load_carryover(os.path.join(workdir, "main_clash.yaml")) if (
        main_clash and gh_download(tag, main_clash, os.path.join(workdir, "main_clash.yaml"))
    ) else []
    pend = load_doc_nodes(pend_path, "pending") if fresh else []
    resc = load_doc_nodes(rescue_path, "rescue") if fresh else []
    # 去重优先级（2026-10-24 任务#99）：carryover 最先——上一轮已发布节点若
    # 与本轮 pending 重复，必须保留 carryover 身份（cap_test_set 中不裁剪、
    # 永远进测试集）。旧顺序 pending 在前，会把已发布节点改标成 pending，
    # 一旦时间预算吃紧被裁剪，好节点就「静默消失」（2026-10-24 实测：
    # 上一轮 50 个发布节点仅 37 个以 carryover 身份进入测试集）。
    # 代价：这批节点的 src 归属让位给滚动保障（分源统计少计十余条，可接受）。
    nodes = dedup_nodes([("carryover", carry), ("pending", pend), ("rescue", resc)])
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
    log(f"测试集: {len(nodes)}（pending {n_pend} / rescue {n_resc} / "
        f"carryover {n_carry}）")

    # 4) mihomo 拨测
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
            # 4.1) 初筛：mihomo delay API（快速排除完全不可达节点）
            with ThreadPoolExecutor(max_workers=DELAY_CONCURRENCY) as ex:
                futs = {ex.submit(delay_test, api_port, n["probe_name"]): n["probe_name"]
                        for n in nodes}
                for fut in futs:
                    name = futs[fut]
                    try:
                        results[name] = fut.result()
                    except Exception:
                        results[name] = {"ok": False, "latency_ms": None}
            delay_passed = [n for n in nodes if results.get(n["probe_name"], {}).get("ok")]
            log(f"delay 初筛通过: {len(delay_passed)}/{len(nodes)}（{time.time() - t0:.0f}s）")

            # 4.2) 终筛：真实流量测试（经 mixed-port 访问海外被封锁目标）
            if delay_passed:
                t1 = time.time()
                with ThreadPoolExecutor(max_workers=REAL_TRAFFIC_CONCURRENCY) as ex:
                    futs = {ex.submit(real_traffic_test, api_port, mixed_port,
                                     n["probe_name"]): n["probe_name"]
                            for n in delay_passed}
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
                real_passed = [n for n in delay_passed
                               if results.get(n["probe_name"], {}).get("ok")]
                log(f"真实流量终筛通过: {len(real_passed)}/{len(delay_passed)}"
                    f"（{time.time() - t1:.0f}s）")
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
            for _n in passed:
                _n["final"] = True
            # 动态证据预算（2026-10-24 任务#98）：旧固定 120s 在通过节点较多时
            # 只能覆盖一半（本轮 30 个只探到 17 个），无 AI 证据的节点在排序中
            # 被「未知」沉底——有效节点被埋。单节点 ≈8s，按通过数给足预算
            # （下限 120s 兜底，上限 300s 防极端），保证全覆盖。
            ev_budget = min(300, max(EVIDENCE_BUDGET_S, len(passed) * 12))
            ev_deadline = time.time() + ev_budget
            ev_nodes = passed[:GEO_MAX_NODES]
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
        except Exception as e:
            log(f"熔断: 拨测过程异常（{type(e).__name__}: {e}），不发布")
            return 3
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    # 6) 合并：通过即留、败即汰（自清洁）；AI 可用优先 + 双 vantage 强者排前
    verified = sorted(passed, key=lambda n: verified_rank(n, results))

    # 6.5) 纯 carryover 轮次「保留已发布集」修复（2026-10-17，服务「固化闭环」）：
    # 当本轮没有新 CI 待测文档（n_pend==0 且 n_resc==0，测试集全为 carryover），
    # 且重测通过数相对已发布集的缺口 ≤ 波动带时，发布「完整 carryover 集」而非
    # 重测通过的子集。依据：carryover 加载的即上一轮已发布/已验证集合；单快照
    # 波动（用户自述约 6 个节点浮动）会让重测子集略小于已发布集，若据此发布更小
    # 集合将随轮次持续侵蚀已验证质量（39→37→…）。缺口在波动带内即视为健康，
    # 整体保留；缺口超带则归为真实退化，走正常自清洁。新 CI 轮次仍正常清洁。
    if (n_pend == 0 and n_resc == 0 and n_carry > 0
            and len(verified) >= config.VERIFICATION_MIN_PASSED
            and (n_carry - len(verified)) <= CARRYOVER_FLUCTUATION_BAND):
        log(f"纯 carryover 轮次：重测通过 {len(verified)}/{n_carry}，缺口 "
            f"{n_carry - len(verified)} ≤ 波动带 {CARRYOVER_FLUCTUATION_BAND}，"
            f"保留已发布集 {n_carry} 个（不随单快照波动侵蚀）")
        verified = list(carry)  # carry 即上一轮已发布集，直接整体保留

    by_origin = {o: sum(1 for n in verified if n["origin"] == o)
                 for o in ("pending", "rescue", "carryover")}
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
        f"rescue {by_origin['rescue']} / carryover {by_origin['carryover']}）")
    if ai_probed:
        log(f"AI 可达性: 探测 {len(ai_probed)} 个，任一可达 {len(ai_reach)}，"
            f"API 层可用 {len(ai_api_ok)}（分域名: "
            + ", ".join(f"{k}={v}" for k, v in ai_by_domain.items()) + "）")

    report = {
        "round_id": round_id,
        "tested_round": resolve_tested_round(doc_round if fresh else None,
                                             last_round),
        "generated_at": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "vantage": "cn-hn-sandbox",
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
            "note": "两维度探测目标/判定标准不同，不可互相替代或合并统计",
        },
        "counts": {
            "tested": len(nodes),
            "passed": len(verified),
            # 慢档统计（任务#97）：快档不足但有真实流量的节点数，仅留痕
            "degraded": len(degraded),
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

    # 7) 熔断：通过数不足 → 不碰主资产（保留上轮验证集/CI 兜底）
    if len(verified) < config.VERIFICATION_MIN_PASSED:
        # 关键修复（2026-10-17）：本轮通过数不足 ≠ "沙箱从未有效产出"。
        # 若 release 上最近有效发布（main_asset_passed≥15）仍新鲜，则保留
        # published=True 信号，CI 据此不兜底，实测集不被候选集覆盖。
        report["published"] = bool(
            prev_report and prev_report.get("published")
            and mp_at and mp_passed >= config.VERIFICATION_MIN_PASSED
            and _within_window(mp_at, config.VERIFICATION_MAX_AGE_S))
        log(f"熔断: 通过数 {len(verified)} < 下限 {config.VERIFICATION_MIN_PASSED}，"
            f"不发布主资产（保留上一轮验证集）；继承主资产信号 published="
            f"{report['published']}")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=1)
        if not args.dry_run:
            run(["gh", "release", "upload", tag, "--clobber", report_path])
        return 0

    # 8) 发布验证集到主资产（p_* 随机名，订阅永久地址不变）
    paths = write_verified_outputs(verified, workdir)
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
        r = run(["gh", "release", "upload", tag, "--clobber", staged])
        if r.returncode == 0:
            uploaded.append(target)
        else:
            log(f"警告: 上传 {target} 失败: {r.stderr.strip()[:200]}")
    # 8.5) 第二资产（2026-10-24 任务#97）：慢档节点（能连但慢）单独发布，
    # 不稀释主资产——主资产口径不变（全部快档通过），慢档按延迟排序上限
    # 50 个，供用户「主资产连不上时备选」。资产名沿用主资产随机前缀 _d.yaml。
    if degraded:
        deg_sorted = sorted(
            degraded,
            key=lambda n: (results.get(n["probe_name"], {}).get("latency_ms")
                           if results.get(n["probe_name"], {}).get("latency_ms")
                           is not None else 99999))[:50]
        deg_cfg = build_verified_config(deg_sorted)
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
        r = run(["gh", "release", "upload", tag, "--clobber", staged])
        if r.returncode == 0:
            log(f"第二资产已发布: {deg_name}（慢档 {len(deg_sorted)} 个）")
            report["degraded_asset"] = deg_name
            report["degraded_count"] = len(deg_sorted)
        else:
            log(f"警告: 第二资产上传失败: {r.stderr.strip()[:200]}")
    run(["gh", "release", "upload", tag, "--clobber", report_path])
    report["published"] = bool(uploaded)
    report["main_assets"] = uploaded
    report["main_asset_published_at"] = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    report["main_asset_passed"] = len(verified)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    run(["gh", "release", "upload", tag, "--clobber", report_path])
    # 轮转：保留本轮消费的待测文档一个世代（pending_probe.prev.json）
    if fresh and os.path.exists(pend_path):
        prev_path = os.path.join(workdir, "pending_probe.prev.json")
        shutil.copyfile(pend_path, prev_path)
        run(["gh", "release", "upload", tag, "--clobber",
             f"{prev_path}#pending_probe.prev.json"])
    log(f"发布完成: 主资产 {len(uploaded)} 个 + {config.VERIFICATION_REPORT_FILE}"
        f"（round {round_id}）")
    return 0


def _sandbox_ip() -> str:
    for url in ("https://cip.cc", "https://myip.ipip.net"):
        try:
            with urllib.request.urlopen(urllib.request.Request(
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
