#!/usr/bin/env python3
"""GitHub Release 读写适配层（任务#121，2026-11-05）。

## 为什么要有这一层

`cn_probe.py` 原先把「下载/上传/鉴权/列资产」全部绑在 `gh` CLI 上，带来两个
实际问题：

1. **本机无法实测**。要把实测从沙箱搬到家宽（家宽才是用户真实网络环境，
   沙箱"测着活、本地用着死"的老问题根源就在这里），就必须让同一份代码在
   Windows 上跑——而那里通常没有 `gh`。
2. **`gh` 自身不稳定**。项目文档记录过多起 `gh release download` 长时间挂起
   （2026-10-17、grok 2.4），只能靠 curl 兜底；上传也没有兜底路径。

因此把 Release 操作抽到本模块：**有 `gh` 就用 `gh`，没有就走 REST**。
两条路径语义一致（`--clobber` = 先删同名资产再传），调用方不需要关心。

## 凭据

沿用项目既有约定：环境变量 `GH_TOKEN` / `GITHUB_TOKEN` 优先，其次读持久化
文件（`PERSISTED_PAT_PATH`，沙箱为 `/root/.github_pat`）。公开仓库的**读取**
可不带 token；**上传/删除**必须有 token。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request

API = "https://api.github.com"
UPLOAD = "https://uploads.github.com"
DEFAULT_REPO = "SHUNZI88/proxysub"
# 持久化 PAT 位置（任务#121 扩展为多候选）：
#   * PERSISTED_PAT_PATH（环境变量可覆盖，沙箱为 /root/.github_pat）；
#   * 家目录 ~/.proxysub_pat —— 本机（Windows 家宽）的标准位置。
# 多候选而不是改写单一常量：沙箱与家宽各自的凭据互不影响，换机器只需放文件。
PERSISTED_PAT_PATH = os.environ.get("PERSISTED_PAT_PATH", "/root/.github_pat")
HOME_PAT_PATH = os.path.join(os.path.expanduser("~"), ".proxysub_pat")

# Release 资产下载的镜像回退（任务#121）。
# 实况（2026-11-05 本机实测）：`github.com/.../releases/download/...` 直连在国内
# 家宽上**完全拉不动**（20s 内 0 字节），而 ghfast.top 有 ~197KB/s、
# gh-proxy.com ~94KB/s。没有这层回退，本机连候选集与 mihomo 二进制都拿不到，
# 「实测搬到家宽」无从谈起。
# 生效范围仅限**公开资产下载**：API 调用与携带 token 的请求绝不走镜像
# （镜像能看到 Authorization 头，等于把 PAT 交出去）。
MIRRORS_ENV = "PROXYSUB_GH_MIRRORS"
DEFAULT_MIRRORS = ("https://ghfast.top/", "https://gh-proxy.com/")


def mirrors() -> list[str]:
    """镜像前缀列表。环境变量显式设为空/`none` 可关闭（如沙箱环境直连正常）。"""
    raw = os.environ.get(MIRRORS_ENV)
    if raw is None:
        return list(DEFAULT_MIRRORS)
    if raw.strip().lower() in ("", "none", "off", "0"):
        return []
    return [m.strip().rstrip("/") + "/" for m in raw.split(",") if m.strip()]


def _curl_download(url: str, dest: str, *, max_time: int = 300) -> bool:
    """用 curl 下载单个 URL，带「低速即中止」保护。

    `--speed-time 20 --speed-limit 10240`（连续 20s 低于 10KB/s 即放弃）是关键：
    被墙的连接不会立刻报错，而是**挂住不动**，没有这个参数只能靠 --max-time
    硬等满 300s——三个候选地址就是 15 分钟。
    """
    if shutil.which("curl"):
        cmd = ["curl", "-fsSL", "--connect-timeout", "8",
               "--speed-time", "20", "--speed-limit", "10240",
               "--max-time", str(max_time), "-o", dest, url]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=max_time + 15)
            if r.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 0:
                return True
        except (subprocess.SubprocessError, OSError):
            pass
    try:
        # ⚠️ 这里**不能**复用 `_req`：它会带上 Authorization，而本函数可能正在
        # 访问第三方镜像——等于把 PAT 交给镜像方。资产下载一律匿名直连。
        req = urllib.request.Request(url, headers={"User-Agent": "proxysub-cn-probe"})
        with urllib.request.urlopen(req, timeout=max_time) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
        return os.path.exists(dest) and os.path.getsize(dest) > 0
    except (urllib.error.URLError, OSError, ValueError):
        return False


def download_url(url: str, dest: str, *, max_time: int = 300) -> bool:
    """下载公开 URL：直连优先，失败按镜像列表回退。"""
    candidates = [url]
    if "github.com/" in url:
        candidates += [m + url for m in mirrors()]
    for cand in candidates:
        if _curl_download(cand, dest, max_time=max_time):
            return True
    return False


def pat_paths() -> list[str]:
    """持久化 PAT 的候选路径（按优先级）。"""
    out = [PERSISTED_PAT_PATH]
    if HOME_PAT_PATH not in out:
        out.append(HOME_PAT_PATH)
    return out


def token() -> str:
    """当前可用 token（空串 = 匿名，只够读取公开仓库）。"""
    t = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if t:
        return t.strip()
    for path in pat_paths():
        try:
            with open(path, encoding="utf-8") as f:
                value = f.read().strip()
            if value:
                return value
        except OSError:
            continue
    # 最后一条：gh 已完成授权时直接取它保管的 token。
    # 好处是用户只需在浏览器点一次授权，不必手抄任何字符串；
    # `gh auth logout` 即刻失效，撤销路径也是一条命令。
    return _gh_token()


def _gh_token() -> str:
    """从 `gh auth token` 取 token（未授权返回空串）。绝不打印其内容。"""
    exe = gh_bin()
    if not exe:
        return ""
    try:
        r = subprocess.run([exe, "auth", "token"], capture_output=True,
                           text=True, timeout=20)
    except (subprocess.SubprocessError, OSError):
        return ""
    return (r.stdout or "").strip() if r.returncode == 0 else ""


def repo() -> str:
    return os.environ.get("PROXYSUB_REPO", DEFAULT_REPO)


def gh_bin() -> str | None:
    """gh 可执行文件路径。

    优先 PATH；其次 `PROXYSUB_GH_BIN`——本机用便携版 gh（不装系统、不要管理员），
    路径由用户级环境变量给出，仓库里不写死任何设备路径。
    """
    explicit = os.environ.get("PROXYSUB_GH_BIN")
    if explicit and os.path.exists(explicit):
        return explicit
    return shutil.which("gh")


def has_gh() -> bool:
    return gh_bin() is not None


def _req(url: str, *, method: str = "GET", data: bytes | None = None,
         headers: dict | None = None, timeout: int = 60):
    hdrs = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "proxysub-cn-probe",
    }
    t = token()
    if t:
        hdrs["Authorization"] = f"Bearer {t}"
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    return urllib.request.urlopen(req, timeout=timeout)


def _json(url: str, *, timeout: int = 60) -> dict | list | None:
    try:
        with _req(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


# ------------------------------------------------------------------ 鉴权
def auth_ok() -> tuple[bool, str]:
    """token 是否可用。有 gh 时沿用 `gh auth status`（项目既有口径），
    否则打一次 REST `/user`——空 token 打 `/repos/{repo}` 也能验证公开可达。"""
    if not token():
        return False, "无 token（环境变量与持久化文件均缺失）"
    if has_gh():
        r = subprocess.run([gh_bin(), "auth", "status"], capture_output=True, text=True,
                           timeout=60)
        if r.returncode == 0:
            return True, "gh auth status OK"
        tail = ((r.stderr or r.stdout) or "").strip().splitlines()
        return False, "；".join(tail[-3:]) or "gh auth status 异常"
    try:
        with _req(f"{API}/user", timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        login = data.get("login") if isinstance(data, dict) else None
        return True, f"REST /user OK（{login or '匿名'}）"
    except urllib.error.HTTPError as e:
        return False, f"REST /user HTTP {e.code}"
    except (urllib.error.URLError, OSError) as e:
        return False, f"REST /user 失败: {type(e).__name__}"


# ------------------------------------------------------------------ 读
def release_assets(tag: str) -> list[dict]:
    """列出某 tag 的资产（`[{"name":..., "size":..., "id":...}]`）。"""
    if has_gh():
        try:
            r = subprocess.run([gh_bin(), "release", "view", tag, "--json", "assets"],
                               capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                return json.loads(r.stdout).get("assets", []) or []
        except (subprocess.SubprocessError, ValueError):
            pass  # 落到 REST
    data = _json(f"{API}/repos/{repo()}/releases/tags/{tag}")
    if isinstance(data, dict):
        return data.get("assets", []) or []
    return []


def download_asset(tag: str, name: str, dest: str, *, timeout: int = 60) -> bool:
    """下载单个 Release 资产到 dest。gh 优先，失败回退 REST 直链。

    回退用 `releases/download` 直链而不是 API 资产接口：直链支持跟随重定向，
    且公开仓库**不需要 token**——本机匿名也能跑通完整的"下载候选/交接文档"。
    """
    url = f"https://github.com/{repo()}/releases/download/{tag}/{name}"
    if has_gh():
        try:
            r = subprocess.run(
                [gh_bin(), "release", "download", tag, "-p", name, "-O", dest,
                 "--clobber"],
                capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) > 0:
                return True
        except subprocess.SubprocessError:
            pass
    # 直连 + 镜像回退（沙箱直连正常时第一枪即中，家宽则自动落到镜像）
    return download_url(url, dest, max_time=max(timeout, 60))


# ------------------------------------------------------------------ 写
def upload_asset(tag: str, path: str, *, name: str | None = None,
                 timeout: int = 180) -> tuple[bool, str]:
    """上传资产并以 name 覆盖同名资产（等价 `gh release upload --clobber`）。

    `gh` 的 `--clobber` 语义是「覆盖同名资产」；REST 下没有原子覆盖，只能
    先 DELETE 旧资产再 POST 新的——顺序不可颠倒，否则同名冲突返回 422。
    """
    asset_name = name or os.path.basename(path)
    if not os.path.exists(path):
        return False, f"文件不存在: {path}"
    if not token():
        return False, "上传需要 token（GH_TOKEN / GITHUB_TOKEN / 持久化 PAT）"

    if has_gh():
        # gh 用 `文件名#资产名` 语法指定上传后的资产名
        arg = path if asset_name == os.path.basename(path) else f"{path}#{asset_name}"
        try:
            r = subprocess.run([gh_bin(), "release", "upload", tag, "--clobber", arg],
                               capture_output=True, text=True, timeout=timeout)
            if r.returncode == 0:
                return True, ""
            gh_err = (r.stderr or r.stdout or "").strip()[:200]
        except subprocess.SubprocessError as e:
            gh_err = f"gh 异常: {type(e).__name__}"
        # gh 失败不再直接返回：落到 REST 重试一次（上传偶发 5xx 属常态）
        ok, err = _upload_rest(tag, path, asset_name, timeout)
        return (True, "") if ok else (False, f"gh: {gh_err} | rest: {err}")
    return _upload_rest(tag, path, asset_name, timeout)


def _release_id(tag: str, timeout: int = 60) -> int | None:
    data = _json(f"{API}/repos/{repo()}/releases/tags/{tag}", timeout=timeout)
    if isinstance(data, dict) and isinstance(data.get("id"), int):
        return data["id"]
    return None


def _upload_rest(tag: str, path: str, name: str,
                 timeout: int = 180) -> tuple[bool, str]:
    rid = _release_id(tag, timeout=timeout)
    if rid is None:
        return False, f"取不到 release id（tag={tag}）"
    # 1) 删除同名旧资产（--clobber 语义）
    assets = _json(f"{API}/repos/{repo()}/releases/{rid}/assets?per_page=100",
                   timeout=timeout)
    if isinstance(assets, list):
        for a in assets:
            if isinstance(a, dict) and a.get("name") == name and a.get("id"):
                try:
                    resp = _req(f"{API}/repos/{repo()}/releases/assets/{a['id']}",
                                method="DELETE", timeout=timeout)
                    try:
                        resp.close()
                    except (AttributeError, OSError):
                        pass
                except (urllib.error.URLError, OSError):
                    pass
    # 2) 上传
    try:
        with open(path, "rb") as f:
            payload = f.read()
        url = f"{UPLOAD}/repos/{repo()}/releases/{rid}/assets?name={name}"
        with _req(url, method="POST", data=payload,
                  headers={"Content-Type": "application/octet-stream"},
                  timeout=timeout) as r:
            return r.status in (200, 201), f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", "replace")[:200]
        except Exception:  # noqa: BLE001
            pass
        return False, f"HTTP {e.code} {body}"
    except (urllib.error.URLError, OSError) as e:
        return False, f"{type(e).__name__}: {e}"
