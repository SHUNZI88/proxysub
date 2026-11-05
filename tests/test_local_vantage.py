"""本机家宽实测（任务#121）支撑件测试。

覆盖三块「搬到 Windows 家宽」时新增/改写的能力：
  * mihomo 按平台选产物 + 标准库解包（不依赖 gunzip/unzip）；
  * 资产名兜底：Release API 限流时从上一轮报告的 main_assets 反推；
  * 跨平台文件锁（xlock）：单实例与存活探测不再依赖 flock。
"""

import gzip
import os
import zipfile

import pytest

from scripts import cn_probe, round_guard, xlock


# ------------------------------------------------------------------ mihomo
def test_mihomo_asset_windows_compatible():
    """Windows 必须选 compatible 构建：v3 需要 AVX2，老 CPU 直接崩。"""
    name, exe = cn_probe.mihomo_asset("nt")
    assert name.startswith("mihomo-windows-amd64-compatible-")
    assert name.endswith(".zip")
    assert exe == "mihomo.exe"


def test_mihomo_asset_posix_unchanged():
    """沙箱路径必须完全没有变化（否则等于把线上实测改坏）。"""
    name, exe = cn_probe.mihomo_asset("posix")
    assert name == f"mihomo-linux-amd64-{cn_probe.MIHOMO_VERSION}.gz"
    assert exe == "mihomo"


def test_extract_from_zip(tmp_path):
    src = tmp_path / "a.zip"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("mihomo.exe", b"BINARY")
    dest = tmp_path / "mihomo.exe"
    assert cn_probe._extract_mihomo(str(src), str(dest), "x.zip") is True
    assert dest.read_bytes() == b"BINARY"


def test_extract_from_gz(tmp_path):
    src = tmp_path / "a.gz"
    with gzip.open(src, "wb") as f:
        f.write(b"ELF")
    dest = tmp_path / "mihomo"
    assert cn_probe._extract_mihomo(str(src), str(dest), "x.gz") is True
    assert dest.read_bytes() == b"ELF"


def test_extract_bad_archive_returns_false(tmp_path):
    bad = tmp_path / "a.zip"
    bad.write_bytes(b"not a zip")
    assert cn_probe._extract_mihomo(str(bad), str(tmp_path / "o"), "a.zip") is False


# ------------------------------------------------------------------ 资产兜底
def test_assets_from_prev_report(tmp_path):
    import json
    p = tmp_path / "r.json"
    p.write_text(json.dumps({
        "main_assets": ["p_abcd_c.yaml", "p_abcd_p.yaml"],
        "degraded_asset": "p_abcd_d.yaml",
    }), encoding="utf-8")
    names = [a["name"] for a in cn_probe._assets_from_prev_report(str(p))]
    assert names == ["p_abcd_c.yaml", "p_abcd_p.yaml", "p_abcd_d.yaml"]


def test_assets_from_prev_report_missing_is_empty(tmp_path):
    assert cn_probe._assets_from_prev_report(str(tmp_path / "nope.json")) == []


def test_assets_from_prev_report_bad_json(tmp_path):
    p = tmp_path / "r.json"
    p.write_text("{broken", encoding="utf-8")
    assert cn_probe._assets_from_prev_report(str(p)) == []


def test_workdir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("CN_PROBE_WORKDIR", str(tmp_path))
    assert cn_probe.default_workdir() == str(tmp_path)


def test_workdir_default_per_platform(monkeypatch):
    monkeypatch.delenv("CN_PROBE_WORKDIR", raising=False)
    wd = cn_probe.default_workdir()
    if os.name == "nt":
        assert wd.replace("\\", "/").endswith("cn_probe")
        assert not wd.startswith("/tmp")
    else:
        assert wd == "/tmp/cn_probe"


# ------------------------------------------------------------------ 跨平台锁
def test_xlock_supported_on_known_platforms():
    assert xlock.supported() is True


def test_xlock_acquire_and_release(tmp_path):
    p = tmp_path / "l"
    fh = open(p, "a+", encoding="utf-8")
    try:
        assert xlock.acquire(fh) is True
        assert xlock.is_locked(str(p)) is True      # 自己持锁时不可再取
        xlock.release(fh)
        assert xlock.is_locked(str(p)) is False
    finally:
        fh.close()


def test_xlock_is_locked_false_when_missing(tmp_path):
    assert xlock.is_locked(str(tmp_path / "absent")) is False


def test_round_guard_detects_held_lock(tmp_path):
    """round_guard 的存活探测必须能区分「持锁/空闲」——Windows 上也要成立。

    这是本机守护能自动补跑的前提：此前 fcntl-only 实现让它在 Windows 恒返回
    unknown，decide() 保守判「不跑」，守护形同虚设。
    """
    p = tmp_path / round_guard.LOCK_FILE
    fh = open(p, "a+", encoding="utf-8")
    try:
        assert xlock.acquire(fh) is True
        fh.seek(0)
        fh.truncate()
        fh.write("pid=1234 round=R1\n")
        fh.flush()
        state = round_guard.probe_lock_state(str(tmp_path))
        assert state["state"] == "running"
        # Windows 的字节锁会拒绝他人读该文件，持锁者信息读不到是预期行为；
        # POSIX 下则应能报出是谁在持锁（排障关键）。
        if os.name != "nt":
            assert "pid=1234" in state["holder"]
    finally:
        xlock.release(fh)
        fh.close()
    assert round_guard.probe_lock_state(str(tmp_path))["state"] == "idle"


@pytest.mark.parametrize("streak,expect", [(0, 10), (1, 10), (2, 20), (5, 120)])
def test_backoff_still_sane(streak, expect):
    assert round_guard.backoff_min(streak, base_min=10, max_min=120) == expect


# ------------------------------------------------------------------ 平台差异坑
def test_curl_speed_uses_platform_devnull(monkeypatch):
    """回归：`-o /dev/null` 在 Windows 上会让 curl 以写错误退出，size_download
    恒为 0——本机第一次 dry-run 因此把 29 个初筛通过节点全判死（0/29）。

    实测证据（curl 8.21.0 Windows，system32）：`-o /dev/null` → rc=23、
    size_download=0；`-o nul` → rc=0、size_download=200000。
    """
    seen = {}

    class _R:
        returncode = 0
        stdout = "12345|678|200"
        stderr = ""

    def fake_run(cmd, timeout=120, **kw):
        seen["cmd"] = cmd
        return _R()

    monkeypatch.setattr(cn_probe, "run", fake_run)
    out = cn_probe._curl_speed("http://127.0.0.1:7897", "https://x/y", 5)
    assert out["bytes"] == 12345
    assert os.devnull in seen["cmd"]
    assert "/dev/null" not in seen["cmd"]


def test_no_hardcoded_devnull_in_production_code():
    """同类问题举一反三：生产代码里不得再出现硬编码 /dev/null。"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(cn_probe.__file__)))
    bad = []
    for dirpath, _dirs, files in os.walk(root):
        if os.sep + "tests" in dirpath or ".git" in dirpath:
            continue
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(dirpath, f)
            try:
                text = open(path, encoding="utf-8").read()
            except OSError:
                continue
            # 只看可执行代码：注释里提到旧写法是允许的（那是修复记录）
            code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
            if '"/dev/null"' in code or "'/dev/null'" in code:
                bad.append(os.path.relpath(path, root))
    assert not bad, f"仍有硬编码 /dev/null: {bad}"
