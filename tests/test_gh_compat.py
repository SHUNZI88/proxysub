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


def test_upload_asset_stages_before_replacing_live(tmp_path, monkeypatch):
    """非破坏性上传（任务#135）：先传 <name>.staging，再替换正式名。

    事故背景：`--clobber` 是「先删旧、再传新」，那次 POST 失败后线上主资产
    直接消失，订阅地址 404，而轮次仍报「已刷新 3/4」。
    """
    f = tmp_path / "a.yaml"
    f.write_text("payload", encoding="utf-8")
    order: list[str] = []
    monkeypatch.setattr(gc, "token", lambda: "t")
    monkeypatch.setattr(gc, "_upload_once",
                        lambda tag, path, name, timeout: (order.append(name), (True, ""))[1])
    monkeypatch.setattr(gc, "_asset_size", lambda tag, name: 7)
    monkeypatch.setattr(gc, "_delete_asset", lambda tag, name: True)
    ok, err = gc.upload_asset("sub", str(f))
    assert ok is True, err
    assert order == ["a.yaml.staging", "a.yaml"]      # 顺序即契约


def test_upload_asset_never_touches_live_when_staging_fails(tmp_path, monkeypatch):
    """暂存失败时**绝不**触碰正式名：宁可不更新，也不能把线上打空。"""
    f = tmp_path / "a.yaml"
    f.write_text("payload", encoding="utf-8")
    order: list[str] = []
    monkeypatch.setattr(gc, "token", lambda: "t")

    def fake_upload(tag, path, name, timeout):
        order.append(name)
        return (False, "HTTP 502")

    monkeypatch.setattr(gc, "_upload_once", fake_upload)
    ok, err = gc.upload_asset("sub", str(f))
    assert ok is False and "502" in err
    # 暂存会重试（任务#138：api.github.com 会 unexpected EOF），但**正式名一次都不能碰**
    assert set(order) == {"a.yaml.staging"}
    assert "a.yaml" not in order


def test_upload_asset_rejects_empty_or_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(gc, "token", lambda: "t")
    assert gc.upload_asset("sub", str(tmp_path / "nope.yaml"))[0] is False
    empty = tmp_path / "e.yaml"
    empty.write_text("", encoding="utf-8")
    ok, err = gc.upload_asset("sub", str(empty))
    assert ok is False and "空" in err


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
    monkeypatch.setattr(gc, "_proxy_reachable", lambda p, timeout=0.6: True)
    monkeypatch.setattr(gc, "_proxy_reachable", lambda p, timeout=0.6: True)
    env = gc._gh_env()
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:7890"
    assert env["HTTP_PROXY"] == "http://127.0.0.1:7890"


def test_gh_env_empty_without_proxy(monkeypatch):
    monkeypatch.delenv(gc.PROXY_ENV, raising=False)
    env = gc._gh_env()
    assert "HTTPS_PROXY" not in env or env["HTTPS_PROXY"] == os.environ.get("HTTPS_PROXY")


def test_curl_download_passes_proxy(monkeypatch, tmp_path):
    monkeypatch.setenv(gc.PROXY_ENV, "http://127.0.0.1:7890")
    monkeypatch.setattr(gc, "_proxy_reachable", lambda p, timeout=0.6: True)
    monkeypatch.setattr(gc, "_proxy_reachable", lambda p, timeout=0.6: True)
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


def test_token_source_reports_where_it_came_from(tmp_path, monkeypatch):
    """来源必须如实：日志曾一律写「持久化 PAT」，实际来自 gh 授权，排障白找文件。"""
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(gc, "PERSISTED_PAT_PATH", str(tmp_path / "n1"))
    monkeypatch.setattr(gc, "HOME_PAT_PATH", str(tmp_path / "n2"))
    monkeypatch.setattr(gc, "_gh_token", lambda: "")
    assert gc.token_source() == ""

    f = tmp_path / "pat"
    f.write_text("x", encoding="utf-8")
    monkeypatch.setattr(gc, "PERSISTED_PAT_PATH", str(f))
    assert gc.token_source().startswith("文件 ")

    monkeypatch.setattr(gc, "PERSISTED_PAT_PATH", str(tmp_path / "n1"))
    monkeypatch.setattr(gc, "_gh_token", lambda: "t")
    assert "gh" in gc.token_source()

    monkeypatch.setenv("GH_TOKEN", "e")
    assert gc.token_source() == "环境变量"


def test_dead_proxy_falls_back_to_direct(monkeypatch):
    """代理连不通必须自动直连（任务#134）。

    实证：用户级变量 PROXYSUB_GH_PROXY 指向的本地代理退出后，`gh auth status`
    把网络错误报成「The token in keyring is invalid」——订阅因此停更 10 小时，
    而 token 一直是好的。判据必须落在「端口能不能连」上，不能信 gh 的措辞。
    """
    monkeypatch.setenv(gc.PROXY_ENV, "http://127.0.0.1:65001")
    monkeypatch.setattr(gc, "_proxy_reachable", lambda p, timeout=0.6: False)
    assert gc.gh_proxy() == "http://127.0.0.1:65001"      # 配置原样保留
    assert gc.effective_proxy() == ""                      # 但不生效
    env = gc._gh_env()
    assert "HTTPS_PROXY" not in env or env["HTTPS_PROXY"] != "http://127.0.0.1:65001"


def test_alive_proxy_is_used(monkeypatch):
    monkeypatch.setenv(gc.PROXY_ENV, "http://127.0.0.1:65002")
    monkeypatch.setattr(gc, "_proxy_reachable", lambda p, timeout=0.6: True)
    assert gc.effective_proxy() == "http://127.0.0.1:65002"


def test_dead_proxy_falls_back_to_direct(monkeypatch):
    """代理连不通必须自动直连（任务#134）。

    实证：用户级变量 PROXYSUB_GH_PROXY 指向的本地代理退出后，`gh auth status`
    把网络错误报成「The token in keyring is invalid」——订阅因此停更 10 小时，
    而 token 一直是好的。判据必须落在「端口能不能连」上，不能信 gh 的措辞。
    """
    monkeypatch.setenv(gc.PROXY_ENV, "http://127.0.0.1:65001")
    monkeypatch.setattr(gc, "_proxy_reachable", lambda p, timeout=0.6: False)
    assert gc.gh_proxy() == "http://127.0.0.1:65001"      # 配置原样保留
    assert gc.effective_proxy() == ""                      # 但不生效
    env = gc._gh_env()
    assert "HTTPS_PROXY" not in env or env["HTTPS_PROXY"] != "http://127.0.0.1:65001"


def test_alive_proxy_is_used(monkeypatch):
    monkeypatch.setenv(gc.PROXY_ENV, "http://127.0.0.1:65002")
    monkeypatch.setattr(gc, "_proxy_reachable", lambda p, timeout=0.6: True)
    assert gc.effective_proxy() == "http://127.0.0.1:65002"


def test_asset_size_settled_polls_until_match(monkeypatch):
    """上传刚完成时 assets 列表可能是旧快照，必须轮询到期望值（任务#138）。

    事故：4 个格式资产上传成功，但校验立刻读到上一次的 4553B，判「暂存校验
    不符」→ 整轮不发布，远端仍是 7 小时前的文件。
    """
    seq = iter([4553, 4553, 7])
    monkeypatch.setattr(gc, "_asset_size", lambda tag, name: next(seq, 7))
    monkeypatch.setattr(gc.time, "sleep", lambda s: None)
    assert gc._asset_size_settled("sub", "a.yaml", 7) == 7


def test_asset_size_settled_returns_last_reading_on_persistent_mismatch(monkeypatch):
    monkeypatch.setattr(gc, "_asset_size", lambda tag, name: 4553)
    monkeypatch.setattr(gc.time, "sleep", lambda s: None)
    assert gc._asset_size_settled("sub", "a.yaml", 7) == 4553


def test_download_asset_records_each_channel_error(monkeypatch, tmp_path):
    """三条通道全失败时，必须把**每条通道各自的**原因收集进 errs。

    动机：轮次内连续 4 次下载 pool.json.gz 失败，日志只有「gh 与直链均失败」，
    无法判断是资产不存在、还是 gh 的 git 上下文问题、还是 objects 被 RST——
    三者解法完全不同，报不出原因的失败等于没报。
    """
    import subprocess as sp

    class R:
        def __init__(self, rc=1, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    monkeypatch.setattr(gc, "has_gh", lambda: True)
    monkeypatch.setattr(gc, "gh_bin", lambda: "gh")
    monkeypatch.setattr(gc, "_gh_env", lambda: {})
    monkeypatch.setattr(gc, "repo", lambda: "o/r")

    def fake_run(cmd, **kw):
        # 通道一先查 id，通道二再拉实体：都失败
        if "tags/" in " ".join(cmd):
            return R(0, out="")                    # 没查到资产 id
        return R(1, err="fatal: not a git repository")

    monkeypatch.setattr(gc.subprocess, "run", fake_run)
    monkeypatch.setattr(gc, "download_url", lambda url, dest, **kw: False)

    errs = []
    assert gc.download_asset("pool", "pool.json.gz", str(tmp_path / "p.gz"), errs=errs) is False
    joined = " | ".join(errs)
    assert "api查id" in joined
    assert "gh release rc=1" in joined and "not a git repository" in joined
    assert "直链+镜像失败" in joined


def test_download_asset_errs_is_optional(monkeypatch, tmp_path):
    """不传 errs 也不能炸（老调用方兼容）。"""
    monkeypatch.setattr(gc, "has_gh", lambda: False)
    monkeypatch.setattr(gc, "download_url", lambda url, dest, **kw: False)
    assert gc.download_asset("pool", "x.gz", str(tmp_path / "x.gz")) is False


# ------------------------------------------------ 成败看产物，不看退出码（2026-11-20）
def _noisy(n=4000) -> bytes:
    """不可压缩的近随机字节：保证 gz 体积足够大，截断一定是真截断。

    教训：用 `b"0," * 5000` 这类高重复载荷，gz 只有 66 字节，`raw[:200]`
    根本没截断，测试反而"通过"了一个假前提。
    """
    import hashlib
    return b"".join(hashlib.sha256(str(i).encode()).digest() for i in range(n))


def _write_gz(path, payload=b'{"nodes":[1,2,3]}'):
    import gzip as _gz
    with _gz.open(path, "wb") as f:
        f.write(payload)


def test_artifact_ok_accepts_complete_gz(tmp_path):
    p = tmp_path / "pool.json.gz"
    _write_gz(p)
    assert gc.artifact_ok(str(p)) is True


def test_artifact_ok_rejects_truncated_gz(tmp_path):
    """截断的 gz 必须判失败——否则解压时才炸，白烧一轮。"""
    p = tmp_path / "pool.json.gz"
    _write_gz(p, _noisy())
    raw = p.read_bytes()
    assert len(raw) > 1000, "载荷必须足够大，否则截断无意义"
    p.write_bytes(raw[: len(raw) // 2])
    assert gc.artifact_ok(str(p)) is False


def test_artifact_ok_rejects_empty_and_corrupt_json(tmp_path):
    empty = tmp_path / "a.json.gz"
    empty.write_bytes(b"")
    assert gc.artifact_ok(str(empty)) is False
    bad = tmp_path / "b.json"
    bad.write_text("{not json", encoding="utf-8")
    assert gc.artifact_ok(str(bad)) is False
    assert gc.artifact_ok(str(tmp_path / "missing.gz")) is False


def test_curl_download_success_despite_nonzero_rc(monkeypatch, tmp_path):
    """事故复现：镜像把完整 body 送完后连接被 RST，curl 退出码非 0，但文件是好的。

    2026-11-20 14:35 家宽实测：轮次内 pool.json.gz 连续 4 次「下载失败」→ 降级
    本机自抓；而工作目录里那份文件完整可解（988 个节点、CI 4 分钟前构建）。
    判据错误导致整轮白跑，故改为按产物判定。
    """
    dest = str(tmp_path / "pool.json.gz")

    class R:
        returncode = 56          # curl: recv failure
        stdout = stderr = ""

    def fake_run(cmd, **kw):
        _write_gz(dest)          # 文件其实下完了
        return R()

    monkeypatch.setattr(gc.shutil, "which", lambda n: "/usr/bin/curl")
    monkeypatch.setattr(gc.subprocess, "run", fake_run)
    gc._LAST_VIA.clear()
    assert gc._curl_download("https://example.invalid/x.gz", dest) is True
    assert any("产物完整" in v for v in gc._LAST_VIA)


def test_curl_download_rejects_partial_file(monkeypatch, tmp_path):
    """rc==0 但只写了一半（被截断）也要判失败。"""
    dest = str(tmp_path / "pool.json.gz")

    class R:
        returncode = 0
        stdout = stderr = ""

    def fake_run(cmd, **kw):
        _write_gz(dest, _noisy())
        raw = open(dest, "rb").read()
        open(dest, "wb").write(raw[: len(raw) // 2])
        return R()

    monkeypatch.setattr(gc.shutil, "which", lambda n: "/usr/bin/curl")
    monkeypatch.setattr(gc.subprocess, "run", fake_run)
    monkeypatch.setattr(gc.urllib.request, "urlopen",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("no net")))
    assert gc._curl_download("https://example.invalid/x.gz", dest) is False


def test_dispatch_workflow_requires_token(monkeypatch):
    """没有 token 时不许空转调用 gh——直接给出可读原因。"""
    monkeypatch.setattr(gc, "token", lambda: "")
    ok, why = gc.dispatch_workflow("pool-refresh.yml")
    assert ok is False and "token" in why


def test_dispatch_workflow_reports_failure_without_raising(monkeypatch):
    monkeypatch.setattr(gc, "token", lambda: "x" * 40)
    monkeypatch.setattr(gc, "has_gh", lambda: True)
    monkeypatch.setattr(gc, "gh_bin", lambda: "gh")
    monkeypatch.setattr(gc, "_gh_env", lambda: {})

    class R:
        returncode = 1
        stdout = ""
        stderr = "HTTP 422: Workflow does not have 'workflow_dispatch' trigger"

    monkeypatch.setattr(gc.subprocess, "run", lambda *a, **k: R())
    ok, why = gc.dispatch_workflow("pool-refresh.yml")
    assert ok is False and "workflow_dispatch" in why
