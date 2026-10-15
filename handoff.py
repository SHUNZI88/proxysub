"""CI → 沙箱交接文档：拟交中国出口实测的待测节点集与救援集（Phase 1）。

流水线每轮把「静态门槛 + TCP 存活 + 配额选择」后的节点集写成交接文档，
随 .publish/ 发布为滚动 Release 资产；沙箱侧定时任务下载后用中国出口
实测筛选，通过者覆盖发布为主资产（详见 docs/cn_probe.md）。

设计约束：
- 节点携带 clash 原生 proxies 条目：沙箱 mihomo 直接消费，完整保留
  skip-cert-verify / obfs / 端口等参数，不依赖分享 URI 解析假设；
- name 为跨格式匹配键（CI 命名阶段保证唯一，未入选节点用原始名）；
- fp 携带指纹：供 Phase 2 进化引擎关联存活历史/中国通过史；
- 交接走 Release 资产而非 git 提交：无提交竞态、无仓库膨胀、两侧解耦。
"""

from __future__ import annotations

import datetime
import json
import os
from collections import defaultdict

from common import src_key
from config import (HANDOFF_GENERATOR, PENDING_PROBE_FILE, PENDING_RESCUE_FILE,
                    RESCUE_PER_PROTO_MIN, RESCUE_QUOTA)


def round_stamp(now: datetime.datetime | None = None) -> tuple[str, str]:
    """生成 (round_id, generated_at)。

    round_id 形如 20261014T0017Z（UTC），作为本轮交接/实测/报告的关联键。
    """
    dt = now or datetime.datetime.now(datetime.timezone.utc)
    return dt.strftime("%Y%m%dT%H%MZ"), dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _by_protocol(nodes: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for n in nodes:
        counts[str(n["proxy"].get("type", "?"))] += 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def build_pending_doc(*, round_id: str, generated_at: str, sample_fps: list[str],
                      final_names: dict[str, str], unique: dict[str, dict],
                      real_ok: dict[str, dict], prov: dict[str, set] | None = None) -> dict:
    """待测集 = 拨测样本 ∪ 最终输出。

    最终输出必须并入：它是已发布的候选集，沙箱要能验证「已发布节点在
    中国是否可用」（双 vantage 差分的基准面）。入选节点携带最终发布名
    （跨格式匹配键）；未入选者携带原始名，仅供沙箱侧配置内标识。
    prov 提供 fp→源URL集合映射，写入 src 短键供 Phase 2 源级中国通过率聚合。
    """
    fps = list(dict.fromkeys([*sample_fps, *final_names]))
    nodes: list[dict] = []
    for fp in fps:
        proxy = unique.get(fp)
        if proxy is None:
            continue
        published = final_names.get(fp)
        src = None
        if prov and fp in prov and prov[fp]:
            src = src_key(sorted(prov[fp])[0])
        nodes.append({
            "fp": fp,
            "name": published or str(proxy.get("name", "node")),
            "final": published is not None,
            "us_ok": fp in real_ok,
            "src": src,
            "proxy": proxy,
        })
    return {
        "round_id": round_id,
        "generated_at": generated_at,
        "generator": HANDOFF_GENERATOR,
        "vantage": "cn-exit",
        "counts": {
            "nodes": len(nodes),
            "final": sum(1 for n in nodes if n["final"]),
            "us_ok": sum(1 for n in nodes if n["us_ok"]),
            "by_protocol": _by_protocol(nodes),
        },
        "nodes": nodes,
    }


def select_rescue(*, tcp_lat: dict[str, float], unique: dict[str, dict],
                  tampered: set[str], excluded: set[str], quota: int = RESCUE_QUOTA,
                  is_preferred, protocol_tier,
                  per_proto_min: int = RESCUE_PER_PROTO_MIN) -> list[str]:
    """救援集：TCP 存活、未篡改、未入待测集，按协议档位/延迟取前 quota 个。

    这是「美国不通、中国通」节点的 lost-and-found 池：拨测样本有配额上限，
    被挤出但静态可行的节点仍有中国可用可能，交沙箱复测。排序与主线评分
    同向——协议档位优先（hy2/reality 等 tier 0/1 对中国路径最友好），
    其次偏好特征，最后 TCP 延迟（UDP 协议的中性 9999 在同档内排最后）。

    **协议多样化（2026-10-15 修复）**：实测 rescue 池 100 个**全是 vless**，
    通过率仅 3.0%（与 pending 4.7% 同档），沦为低效配额。根因是 `protocol_tier`
    把非 reality 的 vless 也归 tier 1，而 vless 占存活节点 72%（824/1141），
    按档位排序取前 quota 时配额被单一低通过率协议占满；而中国实测通过率
    更高的小众协议（anytls 60%、hysteria2 7.7%）因数量稀少永远选不进。

    故引入「每协议保底配额」：少于 quota 的协议先各保底 `per_proto_min` 个
    （按档位/偏好/延迟排序取），余量再按原全局排序填充。保证小众高通过率
    协议有实测机会，不改变总量与其它池的边界。
    """
    pool = [fp for fp in tcp_lat
            if fp not in excluded and fp not in tampered and fp in unique]
    pool.sort(key=lambda fp: (protocol_tier(unique[fp]),
                              0 if is_preferred(unique[fp]) else 1,
                              tcp_lat[fp]))
    if not pool:
        return []
    # 1) 每协议保底：优先给「被全局排序挤在后面」的小众协议实测机会。
    by_proto: dict[str, list[str]] = defaultdict(list)
    for fp in pool:
        by_proto[str(unique[fp].get("type", "?"))].append(fp)
    reserved: list[str] = []
    chosen: set[str] = set()
    if per_proto_min > 0:
        # 协议按「全局最优代表的名次」排序——名次越靠后（越被挤掉）越优先保底。
        rank = {fp: i for i, fp in enumerate(pool)}
        order = sorted(by_proto.items(),
                       key=lambda kv: rank[kv[1][0]], reverse=True)
        for _p, fps in order:
            # 只对「数量少于配额、确有被挤出风险」的协议保底
            if len(fps) >= len(pool):
                continue
            for fp in fps[:per_proto_min]:
                if fp not in chosen:
                    reserved.append(fp)
                    chosen.add(fp)
        reserved = reserved[:quota]
    # 2) 余量按原全局排序填充
    out = list(reserved)
    for fp in pool:
        if len(out) >= quota:
            break
        if fp not in chosen:
            out.append(fp)
            chosen.add(fp)
    return out[:quota]


def build_rescue_doc(*, round_id: str, generated_at: str, rescue_fps: list[str],
                     unique: dict[str, dict], prov: dict[str, set] | None = None) -> dict:
    """救援集文档：未入样本节点，us_ok 恒 False（本轮未经美国出口拨测）。

    prov 提供源短键（src），与待测集同源级键体系，供 Phase 2 聚合。
    """
    nodes = [{"fp": fp, "name": str(unique[fp].get("name", "node")),
              "final": False, "us_ok": False,
              "src": src_key(sorted(prov[fp])[0]) if prov and fp in prov and prov[fp] else None,
              "proxy": unique[fp]}
             for fp in rescue_fps]
    return {
        "round_id": round_id,
        "generated_at": generated_at,
        "generator": HANDOFF_GENERATOR,
        "vantage": "cn-exit",
        "counts": {"nodes": len(nodes), "by_protocol": _by_protocol(nodes)},
        "nodes": nodes,
    }


def write_handoff_docs(publish_dir: str, pending: dict, rescue: dict) -> dict:
    """把两份交接文档写入 publish_dir（.publish/），返回各文档节点数。"""
    os.makedirs(publish_dir, exist_ok=True)
    stat: dict[str, int] = {}
    for doc, fname in ((pending, PENDING_PROBE_FILE), (rescue, PENDING_RESCUE_FILE)):
        path = os.path.join(publish_dir, fname)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))
        stat[fname] = len(doc["nodes"])
    return stat
