"""客户端下发配置的契约（2026-11-21 推倒重来后锁定）。

背景：用户「发布 8 个节点基本都不能用」。排查发现不是上游源枯竭（2278 候选），
而是本地这一侧的四个结构性缺陷，每一个都在把可用节点变相删掉或误判：

1. 未开 unified-delay → 服务端延迟读数比客户端虚高 2.5~12 倍（中位 5.58x），
   所有阈值决策建立在错误量纲上。
2. url-test 用 gstatic 测速 → 客户端把「Google 通、推特不通」的节点选成最快。
3. insecure 节点被隔离进 select 组 → 8 个发布节点里 4 个不在自动组中。
4. tolerance=50 → 跨境抖动导致出口乒乓，每次切换拆会话、IP 跳变。

本文件把这四条钉成契约。改任何一条都会让测试失败，必须先想清楚。
"""
import config
from scripts import cn_probe


def _sample_cfg():
    nodes = [
        {"proxy": {"name": "🇭🇰 香港 01", "type": "vless", "server": "a.example",
                   "port": 443, "uuid": "u1"}, "probe_name": "a"},
        {"proxy": {"name": "🇭🇰 香港 02", "type": "vless", "server": "b.example",
                   "port": 443, "uuid": "u2", "skip-cert-verify": True},
         "probe_name": "b"},
        {"proxy": {"name": "🇯🇵 日本 01", "type": "vless", "server": "c.example",
                   "port": 443, "uuid": "u3"}, "probe_name": "c"},
        {"proxy": {"name": "🇺🇸 美国 01", "type": "vless", "server": "d.example",
                   "port": 443, "uuid": "u4"}, "probe_name": "d"},
    ]
    return cn_probe.build_verified_config(nodes)


def test_published_config_enables_unified_delay():
    """unified-delay 必须开：否则客户端与服务端延迟不同量纲，对照全是错的。"""
    assert _sample_cfg().get("unified-delay") is True


def test_all_url_test_groups_use_twitter_probe():
    """所有 url-test 组必须用推特端点——与本地实测同源。

    这是「手机端超时」的直接原因之一：下发给客户端的组用 gstatic 测速，
    客户端就会把「Google 通、推特不通」的节点选成最快，用户开推特必超时。
    """
    cfg = _sample_cfg()
    tw = config.TWITTER_PROBE_URL
    uts = [g for g in cfg["proxy-groups"] if g.get("type") == "url-test"]
    assert uts, "必须有 url-test 组"
    for g in uts:
        assert g["url"] == tw, f"{g['name']} 用了 {g['url']}，应为推特端点"
        assert g.get("tolerance", 0) >= 100, f"{g['name']} tolerance 过小会出口乒乓"
        assert g.get("lazy") is True, f"{g['name']} 未开 lazy，空转探测耗资源"


def test_auto_group_contains_every_node_including_insecure():
    """⚡ 自动最快 必须包含全部节点，包括 skip-cert-verify 的。

    旧实现把 insecure 隔离进 select 组，导致 8 个节点里 4 个不在自动组中——
    用户挂「自动选择」时等于有一半节点被静默删除。
    """
    cfg = _sample_cfg()
    auto = next(g for g in cfg["proxy-groups"] if g["name"] == "⚡ 自动最快")
    all_names = [p["name"] for p in cfg["proxies"]]
    assert set(auto["proxies"]) == set(all_names)
    # insecure 节点确实在这批样本里，确保上面的断言不是空转
    assert any(p.get("skip-cert-verify") for p in cfg["proxies"])


def test_select_group_defaults_to_auto_and_lists_all_nodes():
    """节点选择默认走自动组，且手动可及全部节点（不能把默认出口锁死在子集）。"""
    cfg = _sample_cfg()
    sel = next(g for g in cfg["proxy-groups"] if g["name"] == "🚀 节点选择")
    assert sel["type"] == "select"
    assert sel["proxies"][0] == "⚡ 自动最快"
    for p in cfg["proxies"]:
        assert p["name"] in sel["proxies"]


def test_probe_mihomo_config_enables_unified_delay():
    """拨测/终验自建的 mihomo 配置也必须开 unified-delay（源码级断言）。

    这是量纲一致的根：测的时候不开，测完再拿结果去比 2500ms 上限，等于用假尺子。
    """
    import inspect
    src = inspect.getsource(cn_probe)
    assert src.count('"unified-delay": True') >= 4, \
        "主拨测/终验/预检/分片四处 mihomo 配置都要开 unified-delay"
