"""源生命周期阈值的契约（2026-11-21 「节点资源日渐枯竭」事故后锁定）。

事故链条（有数据支撑，不是推测）：
1. 全池真实通过率约 0.6%（本轮 47/1640）——这是 GFW + 免费节点质量的客观现实。
2. 旧淘汰判据：cn_tested >= 20 且「绝对通过数 = 0」连续 2 轮 → 淘汰。
   0.6% 通过率下，20 个样本的期望通过数是 0.12 个，**任何源都必然落在 0 通过**。
   这不是源的过错，是小样本的算术必然。
3. 结果：official 从 40 个被淘到 19 个，removed 堆了 41 个——其中
   peasoft/NoMoreWalls(0/123)、mahdibland/V2RayAggregator(0/98)、
   anaer/Sub(0/159)、yy1588133/proxy-pool(0/23)、clashfreenode(0/262)
   等业界主力源全部因「中国通过率为 0」被判死。
4. 后果：能抓到的候选变少 → 测试集变小 → 产出递减，正是用户说的
   「除非你把它们都删了，不可能会日渐枯竭」。
"""
import config
import sources_manager as sm


def test_demote_requires_large_sample():
    """淘汰源的样本门槛必须 ≥200：0.6% 基线需要 200 样本才算有统计意义。"""
    assert config.CN_MIN_SAMPLE >= 200, \
        "小样本判死是枯竭主因；0.6% 基线 + 20 样本 = 必然 0 通过"


def test_demote_requires_long_streak():
    """连续轮次要 ≥6：免费源两轮 0 通过完全可能是抖动。"""
    assert config.CN_DEMOTE_STREAK >= 6


def test_official_floor_is_generous():
    """保底源数 ≥30：旧值 6 等于允许系统把 40 个源砍到 6 个还算「健康」。"""
    assert config.MIN_OFFICIAL >= 30


def test_source_capacity_allows_broad_net():
    """源容量上限必须留足广撒网空间。"""
    assert sm.MAX_OFFICIAL >= 60


def test_repo_sources_json_keeps_broad_net():
    """实际源清单不能又被削薄：official 至少 40 个。"""
    import json
    src = json.load(open('sources.json', encoding='utf-8'))
    assert len(src['official']) >= 40, \
        f"official 只剩 {len(src['official'])} 个，广撒网前提被破坏"


def test_measurement_version_bumped_for_twitter_probe():
    """判据从 gstatic 换推特、并开 unified-delay 后，版本号必须 ≥3。

    否则旧判决不会失效，被误杀的源不会回来（项目自带的 rehab 机制
    依赖这个版本号）。
    """
    assert sm.MEASUREMENT_VERSION >= 3
