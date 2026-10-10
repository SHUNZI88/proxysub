"""地区识别正则边界回归测试。

验证 REGION_RULES 短代码匹配强制单词边界后：
- Russia（包含 "us"）不再被误判为美国；
- AUS / UKRAINE 等含子串的名称不再被误判；
- 真正的 US / USA / HK / JP / SG / TW / KR / UK 名称仍正确识别。
"""

import pytest

import filter_clash as fc


@pytest.mark.parametrize("name,expected", [
    # 短代码边界修复的核心场景：连续字符子串不得误判
    ("Russia-01", "🌐 其他"),
    ("Russia Moskva IEPL", "🌐 其他"),
    ("AUS Sydney 01", "🌐 其他"),          # AUS 不含独立的 US
    ("UKRAINE-Kiev", "🌐 其他"),           # UKRAINE 不含独立的 UK
    ("RUS-K", "🌐 其他"),
    ("Turkmenistan", "🌐 其他"),
    # 正确识别
    ("US-01", "🇺🇸 美国"),
    ("USA Los Angeles", "🇺🇸 美国"),
    ("美国 高速线路", "🇺🇸 美国"),
    ("America-02", "🇺🇸 美国"),
    ("United States West", "🇺🇸 美国"),
    ("香港 IEPL 01", "🇭🇰 香港"),
    ("HK-03", "🇭🇰 香港"),
    ("HongKong 99", "🇭🇰 香港"),
    ("日本 Tokyo 02", "🇯🇵 日本"),
    ("JP-Osaka-1", "🇯🇵 日本"),
    ("新加坡 SG-01", "🇸🇬 新加坡"),
    ("TW-Hinet-04", "🇹🇼 台湾"),
    ("KR-Seoul-02", "🇰🇷 韩国"),
    ("英国 London 01", "🇬🇧 英国"),
    ("UK-02", "🇬🇧 英国"),
])
def test_classify_region(name, expected):
    assert fc.classify_proxy(name) == expected


def test_russia_not_us_regression():
    """核心回归：旧实现会把 Russia 误判为美国（'us' 子串 + IGNORECASE）。"""
    assert fc.classify_proxy("Russia-高速-01") != "🇺🇸 美国"


def test_region_rules_all_short_codes_bounded():
    """所有规则中的英文短代码必须带单词边界，防止未来回退。"""
    import re
    # 提取 REGION_RULES 里每个交替分支，检查纯字母短代码是否被边界包裹
    for pattern in fc.REGION_RULES.values():
        # 逐分支检查：形如 US / USA / HK 的纯短代码分支
        for branch in re.split(r"\|", pattern.strip("()")):
            branch = branch.strip()
            if re.fullmatch(r"[A-Za-z]{2,4}", branch):
                assert re.fullmatch(r"\\b[A-Za-z]{2,4}\\b", branch), (
                    f"短代码 {branch} 缺少单词边界: {pattern}"
                )
