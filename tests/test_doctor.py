"""scripts/doctor.py 自检测试：配置正确性判定的各分支与退出码。

doctor 是产品化-上手助手的落点：fork 者首次运行前本地体检、
提 Issue 前附输出。测试用临时仓库覆盖全部分支，保证判据稳定。
"""
import json
import os

import pytest

from scripts import doctor

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

VALID_ANTI_CRAWL = {
    "enabled": True,
    "publish_release": True,
    "rotate_days": 3,
    "asset_names": {"clean_clash.yaml": "p_x_c.yaml"},
}
VALID_CHANNELS = {"enabled": True, "telegram": ["FreeNodes"], "web": [], "static_sources": []}
VALID_SOURCES = {"official": [{"url": "https://example.com/clash.yaml"}], "removed": [], "deny_repos": []}


def _mk_repo(tmp_path, files=None, workflows=True):
    (tmp_path / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    if workflows:
        (tmp_path / ".github" / "workflows" / "daily-update.yml").write_text("name: x\njobs: {}\n")
    for name, content in (files or {}).items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content))
    return tmp_path


def _levels(checks):
    return {c.level for c in checks}


def _find(checks, name):
    return next(c for c in checks if c.name.startswith(name))


@pytest.fixture(autouse=True)
def _no_mihomo(monkeypatch):
    """mihomo 发现与否不应影响配置判据测试——统一置为未发现（警告级）。"""
    monkeypatch.delenv("MIHOMO_BIN", raising=False)
    monkeypatch.setattr(doctor.shutil, "which", lambda _n: None)


# ---------------------------------------------------------------- 通过路径
def test_valid_minimal_repo_passes(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    checks = doctor.run_checks(root)
    assert not [c for c in checks if c.level == doctor.ERROR]
    # mihomo 未发现是唯一预期警告（fixture 置位）
    warns = [c for c in checks if c.level == doctor.WARN]
    assert len(warns) == 1 and "mihomo" in warns[0].name


def test_main_exit_zero_and_quiet_suppresses_ok(tmp_path, capsys):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    assert doctor.main(["--repo-root", str(root)]) == 0
    out = capsys.readouterr().out
    assert "✅" in out and "小结" in out
    assert doctor.main(["--repo-root", str(root), "--quiet"]) == 0
    quiet_out = capsys.readouterr().out
    assert "✅" not in quiet_out and "⚠️" in quiet_out  # 仅剩 mihomo 警告


def test_bad_repo_root_returns_2(tmp_path, capsys):
    assert doctor.main(["--repo-root", str(tmp_path / "nope")]) == 2
    assert "不存在" in capsys.readouterr().err


# ---------------------------------------------------------------- 错误路径
def test_corrupt_json_is_error(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": "{broken json",
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    checks = doctor.run_checks(root)
    assert _find(checks, "配置文件 channels.json").level == doctor.ERROR
    assert doctor.main(["--repo-root", str(root)]) == 1


def test_anti_crawl_enabled_without_asset_names_is_error(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": {"enabled": True, "publish_release": True, "asset_names": {}},
    })
    c = _find(doctor.run_checks(root), "反爬配置")
    assert c.level == doctor.ERROR
    assert "asset_names" in c.detail


def test_channels_wrong_shape_is_error(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": {"enabled": True, "telegram": "FreeNodes"},
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    assert _find(doctor.run_checks(root), "多渠道配置").level == doctor.ERROR


def test_channels_enabled_not_bool_is_error(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": {"enabled": "yes", "telegram": []},
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    assert _find(doctor.run_checks(root), "多渠道配置").level == doctor.ERROR


def test_sources_official_bad_url_is_error(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": {"official": [{"url": "ftp://x"}]},
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    c = _find(doctor.run_checks(root), "正式源列表")
    assert c.level == doctor.ERROR and "url" in c.detail


def test_broken_workflow_yaml_is_error(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    (root / ".github" / "workflows" / "tests.yml").write_text("name: [unclosed")
    checks = doctor.run_checks(root)
    assert _find(checks, "工作流 tests.yml").level == doctor.ERROR


def test_missing_workflows_dir_is_error(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
    }, workflows=False)
    assert _find(doctor.run_checks(root), "工作流").level == doctor.ERROR


# ---------------------------------------------------------------- 警告路径
def test_anti_crawl_rotation_mode_warns(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": {**VALID_ANTI_CRAWL, "publish_release": False, "rotate_days": 3},
    })
    levels = _levels(doctor.run_checks(root))
    assert doctor.ERROR not in levels
    c = next(c for c in doctor.run_checks(root) if "轮换" in c.detail)
    assert c.level == doctor.WARN


def test_anti_crawl_disabled_warns(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": {"enabled": False},
    })
    c = _find(doctor.run_checks(root), "反爬配置")
    assert c.level == doctor.WARN


def test_channels_enabled_but_empty_warns(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": {"enabled": True, "telegram": [], "web": [], "static_sources": []},
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    c = _find(doctor.run_checks(root), "多渠道配置")
    assert c.level == doctor.WARN and "GitHub 搜索" in c.detail


def test_channels_disabled_ok(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": {"enabled": False},
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    c = _find(doctor.run_checks(root), "多渠道配置")
    assert c.level == doctor.OK


def test_empty_official_warns(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": {"official": []},
        "anti_crawl.json": VALID_ANTI_CRAWL,
    })
    c = _find(doctor.run_checks(root), "正式源列表")
    assert c.level == doctor.WARN and "手工源" in c.detail


def test_missing_configs_warn_not_error(tmp_path):
    """全新 fork：除工作流外什么都没有——应全部降级为警告而非错误。"""
    root = _mk_repo(tmp_path)
    checks = doctor.run_checks(root)
    assert not [c for c in checks if c.level == doctor.ERROR]
    names = {c.name for c in checks if c.level == doctor.WARN}
    assert any("多渠道配置" in n for n in names)
    assert any("正式源列表" in n for n in names)
    assert any("反爬配置" in n for n in names)


def test_corrupt_backup_warns(tmp_path):
    root = _mk_repo(tmp_path, {
        "channels.json": VALID_CHANNELS,
        "sources.json": VALID_SOURCES,
        "anti_crawl.json": VALID_ANTI_CRAWL,
        "survival.json.corrupt": "garbage",
    })
    c = _find(doctor.run_checks(root), "损坏备份")
    assert c.level == doctor.WARN and "survival.json.corrupt" in c.detail


# ---------------------------------------------------------------- 版本下限解析
def test_floor_tuple_parsing():
    assert doctor._floor_tuple("requests>=2.32,<3") == (2, 32)
    assert doctor._floor_tuple("PyYAML>=6.0.1,<7") == (6, 0, 1)
    assert doctor._floor_tuple("pytest>=8.0") == (8, 0)
    assert doctor._floor_tuple("pytest") is None
    assert doctor._floor_tuple("# comment") is None


# ---------------------------------------------------------------- 真实仓库集成
def test_real_repo_passes():
    """仓库自身配置必须通过自检（防配置腐化——如反爬开了却没配资产名）。"""
    checks = doctor.run_checks(REPO_ROOT)
    errors = [c for c in checks if c.level == doctor.ERROR]
    assert not errors, f"真实仓库自检出错: {[(c.name, c.detail) for c in errors]}"
