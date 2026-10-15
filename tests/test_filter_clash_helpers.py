"""filter_clash 辅助函数单测（P1-1d 覆盖率补齐）。

覆盖 gh CLI 报告下载、进化引擎入口与 JSON 安全加载三处纯边界逻辑——
它们此前的未覆盖行集中在 subprocess/tempfile/json 异常路径。
"""

import json

import common
import evolution
import pytest

import filter_clash as fc


@pytest.fixture
def clean_report_file():
    """清理 _verification_report.json 固定名临时文件（测试前后）。"""
    import os
    import tempfile
    path = os.path.join(tempfile.gettempdir(), "_verification_report.json")
    if os.path.exists(path):
        os.remove(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


def _gh_download_mock(content):
    """模拟 gh release download：把 content 写入 -O 指定路径后返回 rc=0。

    _download_verification_report 先删除旧文件再调 gh，因此 mock 必须
    真正落盘才能走通成功路径（与生产行为一致）。
    """
    def _run(cmd, *a, **k):
        out = cmd[cmd.index("-O") + 1]
        with open(out, "w", encoding="utf-8") as f:
            f.write(content)
        return type("R", (), {"returncode": 0})()
    return _run


class TestDownloadVerificationReport:
    def test_success(self, clean_report_file, monkeypatch):
        monkeypatch.setattr(fc.subprocess, "run",
                            _gh_download_mock(json.dumps({"round": "r1"})))
        assert fc._download_verification_report("/repo") == {"round": "r1"}

    def test_gh_failure_returns_none(self, clean_report_file, monkeypatch):
        monkeypatch.setattr(
            fc.subprocess, "run",
            lambda *a, **k: type("R", (), {"returncode": 1})())
        assert fc._download_verification_report("/repo") is None

    def test_corrupt_json_returns_none(self, clean_report_file, monkeypatch):
        monkeypatch.setattr(fc.subprocess, "run",
                            _gh_download_mock("{not json"))
        assert fc._download_verification_report("/repo") is None


class TestLoadEvolutionInputs:
    def test_report_present_runs_evolution(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fc, "_download_verification_report",
                            lambda root: {"round": "r1"})
        seen = {}

        def _fake_run(report, root, url_by_src=None):
            seen["url_by_src"] = url_by_src
            return {"cn_history_nodes": 3, "source_scores_with_cn": 2,
                    "learned": {"k": 1}}

        monkeypatch.setattr(evolution, "run_evolution", _fake_run)
        # 状态文件存在时被读入
        (tmp_path / fc.CN_HISTORY_FILE).write_text(
            json.dumps({"fp1": [1, 1]}), encoding="utf-8")
        (tmp_path / fc.SOURCE_SCORES_FILE).write_text(
            json.dumps({"src1": 0.9}), encoding="utf-8")
        # 传入 official 源，验证 src_key(url) -> url 映射被构造并透传
        url = "https://example.com/Au1rxx/sub.txt"
        sources = {"official": [{"url": url}]}
        cn_hist, learned, src_scores = fc.load_evolution_inputs(str(tmp_path), sources)
        assert cn_hist == {"fp1": [1, 1]}
        assert src_scores == {"src1": 0.9}
        assert learned == {"k": 1}
        assert seen["url_by_src"] == {common.src_key(url): url}

    def test_report_missing_returns_safe_defaults(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fc, "_download_verification_report", lambda root: None)
        cn_hist, learned, src_scores = fc.load_evolution_inputs(str(tmp_path))
        assert cn_hist == {} and src_scores == {}
        # 自学习参数回退到各参数默认值（不信任历史）
        assert learned == {k: v["default"]
                           for k, v in evolution.LEARNED_PARAMS.items()}


class TestLoadJsonSafe:
    def test_missing_file_returns_default(self, tmp_path):
        assert fc._load_json_safe(str(tmp_path / "nope.json"), {"d": 1}) == {"d": 1}

    def test_corrupt_file_returns_default(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{oops", encoding="utf-8")
        assert fc._load_json_safe(str(p), "fallback") == "fallback"

    def test_valid_file_loaded(self, tmp_path):
        p = tmp_path / "ok.json"
        p.write_text(json.dumps({"a": 1}), encoding="utf-8")
        assert fc._load_json_safe(str(p), None) == {"a": 1}
