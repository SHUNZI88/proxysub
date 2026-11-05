"""GitHub Release 适配层（任务#121）回归测试。

锁定的承诺：
  * 有 gh 用 gh、没有走 REST，两条路语义一致（clobber = 先删同名再传）；
  * 公开资产下载直连失败时按镜像回退；API 与带 token 的请求绝不走镜像；
  * 上传必须有 token，缺 token 时给出可读原因而不是静默失败。
"""

import json
import os

from scripts import gh_compat as gc


# ------------------------------------------------------------------ 凭据
def test_token_env_precedence(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "  envtoken  ")
    monkeypatch.setenv("GITHUB_TOKEN", "other")
    assert gc.token() == "envtoken"


def test_token_falls_back_to_persisted_file(tmp_path, monkeypatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    p = tmp_path / "pat"
    p.write_text("  filedtoken\n", encoding="utf-8")
    monkeypatch.setattr(gc, "PERSISTED_PAT_PATH", str(p))
    monkeypatch.setattr(gc, "HOME_PAT_PATH", str(tmp_path / "nope"))
    assert gc.token() == "filedtoken"


def test_token_empty_when_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(gc, "_gh_token", lambda: "")   # 与本机 gh 授权状态隔离
    monkeypatch.setattr(gc, "PERSISTED_PAT_PATH", str(tmp_path / "missing"))
    monkeypatch.setattr(gc, "HOME_PAT_PATH", str(tmp_path / "missing_home"))
    assert gc.token() == ""


def test_auth_fails_without_token(tmp_path, monkeypatch):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(gc, "_gh_token", lambda: "")
    monkeypatch.setattr(gc, "PERSISTED_PAT_PATH", str(tmp_path / "missing"))
    monkeypatch.setattr(gc, "HOME_PAT_PATH", str(tmp_path / "missing_home"))
    ok, why = gc.auth_ok()
    assert ok is False and "无 token" in why


def test_auth_uses_rest_when_gh_absent(monkeypatch):
    """没有 gh 时必须走 REST /user，否则 Windows 本机无法自检 token。"""
    monkeypatch.setattr(gc, "token", lambda: "t")
    monkeypatch.setattr(gc, "has_gh", lambda: False)

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return json.dumps({"login": "SHUNZI88"}).encode()

    monkeypatch.setattr(gc, "_req", lambda *a, **k: _Resp())
    ok, why = gc.auth_ok()
    assert ok is True and "SHUNZI88" in why


# ------------------------------------------------------------------ 镜像
def test_mirrors_default(monkeypatch):
    monkeypatch.delenv(gc.MIRRORS_ENV, raising=False)
    assert gc.mirrors() == list(gc.DEFAULT_MIRRORS)


def test_mirrors_env_override_and_disable(monkeypatch):
    monkeypatch.setenv(gc.MIRRORS_ENV, "https://a.example/, https://b.example")
    assert gc.mirrors() == ["https://a.example/", "https://b.example/"]
    for off in ("", "none", "off", "0"):
        monkeypatch.setenv(gc.MIRRORS_ENV, off)
        assert gc.mirrors() == []


def test_download_url_tries_direct_then_mirrors(monkeypatch):
    tried = []

    def fake_curl(url, dest, max_time=300):
        tried.append(url)
        return len(tried) >= 3          # 前两个（直连、镜像1）失败，镜像2 成功

    monkeypatch.setattr(gc, "_curl_download", fake_curl)
    monkeypatch.setenv(gc.MIRRORS_ENV, "https://m1/,https://m2/")
    url = "https://github.com/o/r/releases/download/t/a.zip"
    assert gc.download_url(url, "/tmp/x") is True
    assert tried == [url, "https://m1/" + url, "https://m2/" + url]


def test_download_url_no_mirror_for_non_github(monkeypatch):
    tried = []
    monkeypatch.setattr(gc, "_curl_download",
                        lambda u, d, max_time=300: (tried.append(u), True)[1])
    monkeypatch.setenv(gc.MIRRORS_ENV, "https://m1/")
    assert gc.download_url("https://example.com/a.zip", "/tmp/x") is True
    assert tried == ["https://example.com/a.zip"]


def test_api_requests_never_go_through_mirrors(monkeypatch):
    """API 调用携带 Authorization，走镜像等于把 PAT 交给第三方——必须是直连。"""
    src = (gc.__file__)
    text = open(src, encoding="utf-8").read()
    # _req / _json 的 URL 只允许 api.github.com / uploads.github.com
    assert "mirrors()" in text
    for fn in ("def _req", "def _json", "def _release_id"):
        seg = text.split(fn, 1)[1][:900]
        assert "mirrors()" not in seg, f"{fn} 里出现镜像，token 会泄漏给第三方"


# ------------------------------------------------------------------ 上传
def test_upload_requires_token(tmp_path, monkeypatch):
    f = tmp_path / "a.yaml"
    f.write_text("x", encoding="utf-8")
    monkeypatch.setattr(gc, "token", lambda: "")
    ok, err = gc.upload_asset("sub", str(f))
    assert ok is False and "token" in err


def test_upload_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "token", lambda: "t")
    ok, err = gc.upload_asset("sub", str(tmp_path / "nope.yaml"))
    assert ok is False and "不存在" in err


def test_upload_rest_deletes_then_posts(tmp_path, monkeypatch):
    f = tmp_path / "a.yaml"
    f.write_text("payload", encoding="utf-8")
    calls = []

    monkeypatch.setattr(gc, "token", lambda: "t")
    monkeypatch.setattr(gc, "has_gh", lambda: False)
    monkeypatch.setattr(gc, "_release_id", lambda tag, timeout=60: 42)
    monkeypatch.setattr(
        gc, "_json",
        lambda url, timeout=60: [{"name": "a.yaml", "id": 7},
                                 {"name": "other", "id": 8}])

    class _Resp:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_req(url, *, method="GET", data=None, headers=None, timeout=60):
        calls.append((method, url, data))
        return _Resp()

    monkeypatch.setattr(gc, "_req", fake_req)
    ok, err = gc.upload_asset("sub", str(f))
    assert ok is True, err
    methods = [(m, u.rsplit("/", 1)[-1]) for m, u, _ in calls]
    assert methods[0] == ("DELETE", "7")          # 先删同名旧资产
    assert methods[1][0] == "POST"
    assert calls[1][2] == b"payload"


def test_upload_rest_http_error_is_reported(tmp_path, monkeypatch):
    import urllib.error
    f = tmp_path / "a.yaml"
    f.write_text("x", encoding="utf-8")
    monkeypatch.setattr(gc, "token", lambda: "t")
    monkeypatch.setattr(gc, "has_gh", lambda: False)
    monkeypatch.setattr(gc, "_release_id", lambda tag, timeout=60: 42)
    monkeypatch.setattr(gc, "_json", lambda url, timeout=60: [])

    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 422, "unprocessable", {}, None)

    monkeypatch.setattr(gc, "_req", boom)
    ok, err = gc.upload_asset("sub", str(f))
    assert ok is False and "422" in err


# ------------------------------------------------------------------ 列资产
def test_release_assets_rest_shape(monkeypatch):
    monkeypatch.setattr(gc, "has_gh", lambda: False)
    monkeypatch.setattr(gc, "_json",
                        lambda url, timeout=60: {"assets": [{"name": "p_ab_c.yaml"}]})
    assert gc.release_assets("sub") == [{"name": "p_ab_c.yaml"}]


def test_release_assets_empty_on_error(monkeypatch):
    monkeypatch.setattr(gc, "has_gh", lambda: False)
    monkeypatch.setattr(gc, "_json", lambda url, timeout=60: None)
    assert gc.release_assets("sub") == []


def test_token_falls_back_to_gh_auth_token(monkeypatch, tmp_path):
    """gh 授权后无需再写 PAT 文件——直接取 `gh auth token`。

    这是本机的首选路径：用户在浏览器点一次授权即可，且 `gh auth logout`
    就是撤销方式，不必维护明文 token 文件。
    """
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(gc, "PERSISTED_PAT_PATH", str(tmp_path / "no1"))
    monkeypatch.setattr(gc, "HOME_PAT_PATH", str(tmp_path / "no2"))
    monkeypatch.setattr(gc, "gh_bin", lambda: "gh.exe")

    class R:
        returncode = 0
        stdout = "gho_fromOAuth\n"

    monkeypatch.setattr(gc.subprocess, "run", lambda *a, **k: R())
    assert gc.token() == "gho_fromOAuth"


def test_gh_token_empty_when_not_logged_in(monkeypatch):
    monkeypatch.setattr(gc, "gh_bin", lambda: "gh.exe")

    class R:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(gc.subprocess, "run", lambda *a, **k: R())
    assert gc._gh_token() == ""


def test_gh_bin_prefers_explicit_env(tmp_path, monkeypatch):
    fake = tmp_path / "gh.exe"
    fake.write_text("x", encoding="utf-8")
    monkeypatch.setenv("PROXYSUB_GH_BIN", str(fake))
    assert gc.gh_bin() == str(fake)


def test_gh_bin_none_when_nothing(monkeypatch):
    monkeypatch.delenv("PROXYSUB_GH_BIN", raising=False)
    monkeypatch.setattr(gc.shutil, "which", lambda _n: None)
    assert gc.gh_bin() is None


# ------------------------------------------------------------------ 代理
def test_gh_proxy_reads_explicit_env_only(monkeypatch):
    """只认 PROXYSUB_GH_PROXY，不偷吃 HTTPS_PROXY。

    理由：测量流量必须直连（家宽机器常驻 Clash），若 GitHub 客户端悄悄沿用
    系统里的代理，排障时无法区分「直连不通」与「代理配错」。
    """
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    monkeypatch.delenv(gc.PROXY_ENV, raising=False)
    assert gc.gh_proxy() == ""
    monkeypatch.setenv(gc.PROXY_ENV, " http://127.0.0.1:7890 ")
    assert gc.gh_proxy() == "http://127.0.0.1:7890"


def test_gh_env_injects_proxy_for_subprocess(monkeypatch):
    monkeypatch.setenv(gc.PROXY_ENV, "http://127.0.0.1:7890")
    env = gc._gh_env()
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:7890"
    assert env["HTTP_PROXY"] == "http://127.0.0.1:7890"


def test_gh_env_empty_without_proxy(monkeypatch):
    monkeypatch.delenv(gc.PROXY_ENV, raising=False)
    env = gc._gh_env()
    assert "HTTPS_PROXY" not in env or env["HTTPS_PROXY"] == os.environ.get("HTTPS_PROXY")


def test_curl_download_passes_proxy(monkeypatch, tmp_path):
    monkeypatch.setenv(gc.PROXY_ENV, "http://127.0.0.1:7890")
    seen = {}

    class R:
        returncode = 0

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        dest = cmd[cmd.index("-o") + 1]
        with open(dest, "w", encoding="utf-8") as f:
            f.write("x")
        return R()

    monkeypatch.setattr(gc.shutil, "which", lambda _n: "curl")
    monkeypatch.setattr(gc.subprocess, "run", fake_run)
    assert gc._curl_download("https://github.com/a/b.zip", str(tmp_path / "f")) is True
    cmd = seen["cmd"]
    assert cmd[cmd.index("--proxy") + 1] == "http://127.0.0.1:7890"


def test_curl_download_without_proxy_has_no_flag(monkeypatch, tmp_path):
    monkeypatch.delenv(gc.PROXY_ENV, raising=False)
    seen = {}

    class R:
        returncode = 0

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        dest = cmd[cmd.index("-o") + 1]
        with open(dest, "w", encoding="utf-8") as f:
            f.write("x")
        return R()

    monkeypatch.setattr(gc.shutil, "which", lambda _n: "curl")
    monkeypatch.setattr(gc.subprocess, "run", fake_run)
    gc._curl_download("https://github.com/a/b.zip", str(tmp_path / "f"))
    assert "--proxy" not in seen["cmd"]
