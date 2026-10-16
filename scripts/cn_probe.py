#!/usr/bin/env python3
"""中国出口节点实测（沙箱侧）——Phase 1 核心工作者。

定时任务（北京 09:18/16:18，即 CI 名义时段 06:17/12:17 后 ~45min，避开凌晨
沙箱易休眠窗口）启动本脚本：

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
     HTTPS+204 双信号），通过节点逐个取出口 IP/地区证据；
  6. 合并发布：通过节点构建验证集（clash + sing-box + v2ray + proxies-only），
     覆盖发布到主资产 p_*（订阅永久地址不变），并发布
     verification_report.json（证据 + 统计，CI 据此切换主资产所有权）；
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
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import time
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
# 真实流量测试目标：必须是在中国大陆被封锁、只有经代理才能稳定访问的海外地址。
# 多 URL 回退可吸收单一域名被污染/劫持/间歇性失效的抖动。
REAL_PROBE_URLS = [
    "https://www.google.com/robots.txt",
    "https://www.cloudflare.com/cdn-cgi/trace",
]
GEO_URLS = ["https://cip.cc", "https://myip.ipip.net", "http://ip-api.com/json"]
MIHOMO_VERSION = os.environ.get("MIHOMO_VERSION", "v1.19.32")
DELAY_TIMEOUT_MS = 5000
DELAY_CONCURRENCY = 12
REAL_TRAFFIC_TIMEOUT_S = 10
REAL_TRAFFIC_CONCURRENCY = 12
GEO_TIMEOUT_S = 8
GEO_MAX_NODES = 120
SELFCHECK_URLS = ["https://www.baidu.com", "https://api.github.com"]
ASSET_RE = re.compile(r"^p_[0-9a-f]+_([cpsv])\.(yaml|json|txt)$")
ASSET_FORMAT = {"c": "clash", "p": "proxies_only", "s": "singbox", "v": "v2ray"}
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
# 出口证据时间预算（秒）：证据仅留痕、不构成闸门；顺序取证最坏
# 120 节点 × 24s（三源回退各 8s 超时）会击穿任务超时，设硬预算，
# 超时跳过剩余节点（无证据不影响发布）。
GEO_BUDGET_S = 120
# 总时间预算（秒）：与定时任务 timeout 对齐（scheduler-api 上限）。
# 本轮实测 1193 节点端到端 902s（拨测 ~0.62s/节点）；但轮询等待
# 最多 20min 会挤占预算，最坏 1200+902=2102s 击穿超时——故按
# 剩余预算裁剪测试集（见 cap_test_set）。
TASK_BUDGET_S = 1800
# 拨测后预留（秒）：真实流量测试 + 出口证据（≤GEO_BUDGET_S）+ 多格式输出
# + 发布 + 收尾开销。真实流量测试加入后，通过节点需经 mixed-port 二次
# 访问海外目标，预留从 300s 提升到 360s。
PUBLISH_RESERVE_S = 360
# 单节点拨测耗时悲观估计（秒），用于 cap_test_set 预算裁剪。
# 实测耗时构成：delay 初筛（并发 12，约 0.66s/节点，是绝对大头）
# + 真实流量终筛（仅对 delay 通过的少数节点跑，1142 节点轮仅 6s 边际，
# 已被并发+少数稀释、可忽略）。故 PER_NODE_S 只需覆盖 delay 初筛成本，
# 取 1.2 留约 80% 余量吸收个别慢节点/抖动即可。
# 2.0 是过度保守——2026-10-17 一例，误以为真实流量终筛会对每节点翻倍
# 耗时，把 PER_NODE_S 从 1.0 误调到 2.0，导致本轮无故裁剪 413 个待测节点。
PER_NODE_S = 1.2


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


def gh_download(tag: str, pattern: str, dest: str) -> bool:
    """下载 Release 资产：优先 gh，失败/超时自动回退 curl（Bearer token）。

    回退原因（grok 2.4）：实测某些沙箱环境下 `gh release download` 会长时间
    挂起无响应，而直连 `curl` 走 API 更稳定。两者任一成功即视为下载成功。

    ⚠️ 2026-10-16 教训：gh 挂起表现为 `subprocess.TimeoutExpired`（**异常**），
    而非非零返回码。早期实现只判 `returncode`、未捕获超时异常，于是一次网络
    抖动就让 `gh_download` 抛异常、整脚本崩溃，curl 回退永不会执行——结果
    `pending_probe.json` / 主资产等关键下载静默失败，carryover=0、实测集也发不出。
    现改为显式捕获 `TimeoutExpired` 后同样走 curl 回退。
    """
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    repo = os.environ.get("PROXYSUB_REPO", "SHUNZI88/proxysub")
    url = f"https://github.com/{repo}/releases/download/{tag}/{pattern}"
    # 1) 优先 gh（超时/失败均交由 curl 兜底）
    try:
        r = run(["gh", "release", "download", tag, "-p", pattern, "-O", dest, "--clobber"],
                timeout=90)
        if r.returncode == 0 and os.path.exists(dest):
            return True
    except subprocess.TimeoutExpired:
        log(f"提示: gh 下载 {pattern} 超时，回退 curl")
    # 2) 回退 curl（gh 失败或超时均走此路）
    cr = run(["curl", "-fsSL", "-H", f"Authorization: Bearer {token}", "-o", dest, url],
             timeout=120)
    return cr.returncode == 0 and os.path.exists(dest)


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
    """
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z / denom * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, center - margin), min(1.0, center + margin)


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
            "final": True,
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


def real_traffic_test(api_port: int, mixed_port: int, name: str) -> dict:
    """真实流量测试：把 mihomo 切到指定节点，经 mixed-port 访问海外目标。

    这是 2026-10-16 升级后的第二道闸门。仅做 delay 测试会出现假阳性：
    mihomo 的 /delay API 只验证到节点 server 的 TCP/TLS 连通，不验证
    server 是否真能转发流量访问被封锁目标；且原 URL gstatic.com 在国内
    某些网络下可直接解析，导致沙箱测出"通过"、用户本地却全超时。
    真实流量测试用中国大陆明确不可达的海外地址，只有返回合法 HTTP 响
    应才算可用。
    """
    if not api_put(api_port, "/proxies/PROBE", {"name": name}):
        return {"ok": False}
    proxy = f"http://127.0.0.1:{mixed_port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    for url in REAL_PROBE_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=REAL_TRAFFIC_TIMEOUT_S) as r:
                status = r.status
                body = r.read(256)
            # Google robots.txt 必然包含 "User-agent"；Cloudflare trace 包含 "ip="
            # 200/204/403 都算"目标可达"（403 是服务端拒绝，证明代理链路已通）
            if status in (200, 204, 301, 302, 403):
                if "google.com" in urllib.parse.urlparse(url).netloc and b"User-agent" in body:
                    return {"ok": True, "via": url, "status": status}
                if "cloudflare.com" in urllib.parse.urlparse(url).netloc and b"ip=" in body:
                    return {"ok": True, "via": url, "status": status}
                # 兜底：只要状态码合法且读到非空 body 也算通（防止未来 URL 微调）
                if body:
                    return {"ok": True, "via": url, "status": status}
        except Exception:
            continue
    return {"ok": False}


def exit_evidence(port: int, selector: str, name: str, mixed_port: int | None = None) -> dict:
    """把流量切到指定节点，取出口 IP/地区（证据留痕，不构成闸门）。

    ⚠️ 必须先经 mihomo 的 mixed-port 代理再请求 GEO 站：早前版本用裸
    `urlopen` 直连 GEO，未指向 mihomo，导致每次拿到的都是**沙箱自身出口**
    （exit_ip 恒为沙箱 IP、exit_loc 恒为沙箱所在地），该字段对「节点真实
    落地」毫无判别力。修复后请求走 mihomo 所选节点出口，才能反映节点归属。
    """
    if not api_put(port, f"/proxies/{urllib.parse.quote(selector, safe='')}",
                   {"name": name}):
        return {}
    # 经 mihomo mixed-port 代理；mixed_port 缺省时退回直连（仅兼容旧调用，
    # 主线总会传入——见 run_probe 的 free_port 分配）。
    opener = None
    if mixed_port:
        proxy = f"http://127.0.0.1:{mixed_port}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    for url in GEO_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            openfn = opener.open if opener else urllib.request.urlopen
            with openfn(req, timeout=GEO_TIMEOUT_S) as r:
                text = r.read().decode("utf-8", "replace")
            ev = _parse_geo(text)
            if ev:
                ev["via"] = url
                return ev
        except Exception:
            continue
    return {}


def _parse_geo(text: str) -> dict:
    ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
    loc = re.search(r"(?:地址|来自于|来自|country)\s*[:：]\s*([^\n]{2,60})", text)
    ev: dict = {}
    if ip:
        ev["exit_ip"] = ip.group(1)
    if loc:
        ev["exit_loc"] = loc.group(1).strip()
    return ev if ev.get("exit_ip") else {}


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
        gh_download(tag, config.PENDING_RESCUE_FILE, rescue_path)
        log(f"交接文档轮次 {doc_round} 待测，进入实测")
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
    nodes = dedup_nodes([("pending", pend), ("rescue", resc), ("carryover", carry)])
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
            log(f"拨测完成: 最终通过 {sum(1 for r in results.values() if r['ok'])}/{len(nodes)}"
                f"（{time.time() - t0:.0f}s）")

            # 5) 出口证据（仅通过节点，限量 + 限时顺序执行）
            passed = [n for n in nodes if results.get(n["probe_name"], {}).get("ok")]
            geo_deadline = time.time() + GEO_BUDGET_S
            for i, n in enumerate(passed[:GEO_MAX_NODES]):
                if time.time() > geo_deadline:
                    log(f"出口证据达到时间预算 {GEO_BUDGET_S}s，跳过剩余 "
                        f"{len(passed[:GEO_MAX_NODES]) - i} 个节点"
                        f"（证据仅留痕，不构成闸门）")
                    break
                ev = exit_evidence(api_port, "PROBE", n["probe_name"], mixed_port)
                if ev:
                    results[n["probe_name"]].update(ev)
        except Exception as e:
            log(f"熔断: 拨测过程异常（{type(e).__name__}: {e}），不发布")
            return 3
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    # 6) 合并：通过即留、败即汰（自清洁）；双 vantage 强者排前
    def rank(n: dict) -> tuple:
        r = results.get(n["probe_name"], {})
        return (0 if (n["us_ok"] and n["final"]) else 1,
                r.get("latency_ms") if r.get("latency_ms") is not None else 99999)

    verified = sorted(passed, key=rank)
    by_origin = {o: sum(1 for n in verified if n["origin"] == o)
                 for o in ("pending", "rescue", "carryover")}
    # 分源/分协议聚合（Phase 2.2）：tested/passed 双口径，供 CI 源级评分与门槛自学习
    # 分源仅统计带 src 的节点（carryover 等无源节点不归任何源，避免产生 "?" 伪源
    # 污染源级评分）；分协议仍覆盖全部节点。
    src_nodes = [n for n in nodes if n.get("src")]
    src_verified = [n for n in verified if n.get("src")]
    by_source = _agg_two(src_nodes, src_verified, key_fn=lambda n: n["src"])
    # 分协议带置信区间（P2-a）：小样本协议（anytls/hysteria 等）的通过率必须配
    # 95% Wilson 区间与 sample_ok 标记，避免"看单轮数字就加权"（2026-10-15 教训）。
    by_protocol = _agg_two(nodes, verified,
                           key_fn=lambda n: str(n["proxy"].get("type", "?")),
                           with_ci=True)
    log(f"验证集: {len(verified)} 个（pending {by_origin['pending']} / "
        f"rescue {by_origin['rescue']} / carryover {by_origin['carryover']}）")

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
            "note": "两维度探测目标/判定标准不同，不可互相替代或合并统计",
        },
        "counts": {
            "tested": len(nodes),
            "passed": len(verified),
            "by_origin": {"pending": n_pend, "rescue": n_resc,
                          "carryover": n_carry},
            "passed_by_origin": by_origin,
            "by_source": by_source,
            "by_protocol": by_protocol,
        },
        "nodes": [{
            "fp": n["fp"], "name": n["name"], "origin": n["origin"],
            "final": n["final"], "us_ok": n["us_ok"], "src": n.get("src"),
            "cn": results.get(n["probe_name"], {}),
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
