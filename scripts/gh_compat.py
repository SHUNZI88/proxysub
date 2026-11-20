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

import gzip
import json
import os
import socket
import time
import shutil
import tempfile
import subprocess
import urllib.error
import urllib.parse
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
# 代理（任务#121）：GitHub 访问在部分家宽上必须走本地代理（实况：
# github.com 直连 TLS 握手超时，gh 作为 Go 程序**不读 Windows 系统代理**）。
# 与 MIRRORS 一样只作用于 GitHub 相关请求——测量流量必须直连，二者不可混。
PROXY_ENV = "PROXYSUB_GH_PROXY"

MIRRORS_ENV = "PROXYSUB_GH_MIRRORS"
DEFAULT_MIRRORS = ("https://ghfast.top/", "https://gh-proxy.com/")


def gh_proxy() -> str:
    """GitHub 访问所用代理（空串 = 直连）。只认显式配置，不吃隐式环境变量。

    刻意不读 HTTPS_PROXY：那会把"用户系统里恰好有的代理"偷偷用于发布，
    也让排障时无法区分"直连不通"与"代理不对"。要代理就显式配。
    """
    return (os.environ.get(PROXY_ENV) or "").strip()


_PROXY_ALIVE: dict[str, bool] = {}
_PROXY_WARNED: set[str] = set()
# 最近一次成功下载走的通道（纯诊断，给调用方日志用；不进任何判定）
_LAST_VIA: list[str] = []


def _proxy_reachable(proxy: str, timeout: float = 0.6) -> bool:
    """代理是否**真的能用**（TCP 通了还不算数，带缓存）。

    用途只有一个：**别把死代理当配置用**。实证 2026-11-07 19:14 起订阅停更
    10 小时——用户级环境变量 PROXYSUB_GH_PROXY 指向的本地代理已退出，而
    `gh auth status` 在代理连不通时会把网络错误报成
    「The token in keyring is invalid」，于是一轮轮全在鉴权处中止，
    看起来像 token 坏了，实际只是代理没了。

    2026-11-20 又踩到同一坑的**变体**：端口在监听（TCP 可连），但经它访问
    api.github.com 是 TLS 失败（实测 curl -x 返回 000/5s，直连 401/0.6s）。
    此时 gh 依旧报「token 无效」。只做 TCP 探活救不了这种情况，所以改成
    两段式：先 TCP（快、失败即返回），再做一次真正的 HTTPS 请求
    （401/403 也算通——那说明 TLS 与 HTTP 往返都完成了，只是没带凭据）。
    """
    if proxy in _PROXY_ALIVE:
        return _PROXY_ALIVE[proxy]
    ok = False
    try:
        u = urllib.parse.urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=timeout):
            ok = True
    except OSError:
        ok = False
    if ok:
        ok = _proxy_https_works(proxy)
    _PROXY_ALIVE[proxy] = ok
    return ok


def _proxy_https_works(proxy: str, timeout: float = 5.0) -> bool:
    """经代理访问一次 api.github.com，确认它不是「TCP 通但 TLS 不通」的残尸。"""
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    req = urllib.request.Request("https://api.github.com/",
                                 headers={"User-Agent": "proxysub-probe"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return 200 <= int(r.status) < 500
    except urllib.error.HTTPError as e:
        return 200 <= int(e.code) < 500
    except Exception:      # noqa: BLE001  - 任何异常都等于「这个代理不通」
        return False


def effective_proxy() -> str:
    """实际生效的代理：配置了但连不通 → 空串（直连），并只告警一次。"""
    p = gh_proxy()
    if not p:
        return ""
    if _proxy_reachable(p):
        return p
    if p not in _PROXY_WARNED:
        _PROXY_WARNED.add(p)
        print(f"警告: 配置的 GitHub 代理 {p} 不可用（端口可能仍在监听，但经它"
              f"访问 GitHub 失败），本轮改为直连——gh 在代理失效时会误报"
              f"「token 无效」，不要据此判断凭据坏了")
    return ""


def _proxy_env() -> dict:
    """给子进程（gh）用的代理环境变量（代理不可达时为空）。"""
    p = effective_proxy()
    if not p:
        return {}
    return {"HTTP_PROXY": p, "HTTPS_PROXY": p, "http_proxy": p, "https_proxy": p}


def mirrors() -> list[str]:
    """镜像前缀列表。环境变量显式设为空/`none` 可关闭（如沙箱环境直连正常）。"""
    raw = os.environ.get(MIRRORS_ENV)
    if raw is None:
        return list(DEFAULT_MIRRORS)
    if raw.strip().lower() in ("", "none", "off", "0"):
        return []
    return [m.strip().rstrip("/") + "/" for m in raw.split(",") if m.strip()]


def artifact_ok(dest: str) -> bool:
    """文件是否是**完整可用**的产物（而不是看命令的退出码）。

    事故（2026-11-20 14:35，家宽）：轮次内 `pool.json.gz` 连续 4 次报下载失败、
    整轮降级为本机自抓；而工作目录里那份文件其实**是完整的**——988 个节点，
    `generated_at` 正是 CI 4 分钟前那次构建。也就是说下载成功了，只是命令
    退出码非 0（镜像在把完整 body 送完后被 RST、或 curl 收尾时触到
    `--speed-limit`），`rc == 0` 的判定把它当成失败，白扔了一整轮。

    结论：成败只能由**产物**判定。gz 全量解压（截断必抛异常）、json 尝试
    `json.loads`，其余只要求非空。**任何一次写入后都按这个判定。**
    """
    try:
        if not os.path.exists(dest):
            return False
        size = os.path.getsize(dest)
        if size <= 0:
            return False
        low = dest.lower()
        if low.endswith(".gz"):
            # 必须用 gzip.decompress 一次性解到底：它校验 CRC32 与 ISIZE，
            # 截断/尾部缺失必抛 EOFError。流式 `read()` 在"刚好读完可见数据"
            # 时会安静地返回 b""，缺尾部也看不出来（实测漏判一半体量的 gz）。
            with open(dest, "rb") as f:
                gzip.decompress(f.read())
            return True
        if low.endswith(".json"):
            with open(dest, "r", encoding="utf-8") as f:
                json.load(f)
            return True
        return True
    except (OSError, EOFError, ValueError, gzip.BadGzipFile):
        return False


def _curl_download(url: str, dest: str, *, max_time: int = 300) -> bool:
    """用 curl 下载单个 URL，带「低速即中止」保护。

    `--speed-time 20 --speed-limit 10240`（连续 20s 低于 10KB/s 即放弃）是关键：
    被墙的连接不会立刻报错，而是**挂住不动**，没有这个参数只能靠 --max-time
    硬等满 300s——三个候选地址就是 15 分钟。

    成败判定见 `artifact_ok`：**不看 rc，看产物**。写之前先删干净，
    避免上一候选的残缺文件被下一次判定误认为成品。
    """
    try:
        if os.path.exists(dest):
            os.remove(dest)
    except OSError:
        pass
    if shutil.which("curl"):
        cmd = ["curl", "-fsSL", "--connect-timeout", "8",
               "--speed-time", "20", "--speed-limit", "10240",
               "--max-time", str(max_time), "-o", dest, url]
        if effective_proxy():
            cmd[-1:-1] = ["--proxy", effective_proxy()]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=max_time + 15)
            if artifact_ok(dest):
                if r.returncode != 0:
                    _LAST_VIA.append(f"curl rc={r.returncode} 但产物完整")
                return True
        except (subprocess.SubprocessError, OSError):
            pass
    try:
        # ⚠️ 这里**不能**复用 `_req`：它会带上 Authorization，而本函数可能正在
        # 访问第三方镜像——等于把 PAT 交给镜像方。资产下载一律匿名直连。
        req = urllib.request.Request(url, headers={"User-Agent": "proxysub-cn-probe"})
        with urllib.request.urlopen(req, timeout=max_time) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
        return artifact_ok(dest)
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


def token_source() -> str:
    """token 的来源描述（排障用，绝不含 token 本身）。

    实测坑：早期日志统一写「已载入持久化 PAT」，而实际可能来自 gh 授权
    （Windows 凭据管理器），排障时会白找文件。
    """
    if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        return "环境变量"
    for path in pat_paths():
        try:
            with open(path, encoding="utf-8") as f:
                if f.read().strip():
                    return f"文件 {path}"
        except OSError:
            continue
    if _gh_token():
        return "gh 授权（凭据管理器）"
    return ""


def _gh_token() -> str:
    """从 `gh auth token` 取 token（未授权返回空串）。绝不打印其内容。"""
    exe = gh_bin()
    if not exe:
        return ""
    try:
        r = subprocess.run([exe, "auth", "token"], capture_output=True,
                           text=True, timeout=20, env=_gh_env())
    except (subprocess.SubprocessError, OSError):
        return ""
    return (r.stdout or "").strip() if r.returncode == 0 else ""


def repo() -> str:
    return os.environ.get("PROXYSUB_REPO", DEFAULT_REPO)


def _gh_env() -> dict:
    """gh 子进程环境：叠加代理设置（其余继承）。

    任务#138（2026-11-20）：`gh_proxy()` 刻意只认显式配置，但这里
    `dict(os.environ)` 会把系统里的 HTTP(S)_PROXY **隐式**带进去——本机恰好
    有 `HTTPS_PROXY=127.0.0.1:44386`（客户端混合端口），于是发布流量走了
    一批不稳定的免费节点，表现为
    `Post "https://api.github.com/graphql": unexpected EOF` 与
    `net/http: TLS handshake timeout`，四个格式资产连续两轮传不上去。
    而同一时刻直连 curl api.github.com 是 200/0.4s。

    结论：未显式配置 GitHub 代理时，**主动剥离**代理变量，让发布走直连；
    需要代理时用 PROXYSUB_GH_PROXY 显式给出，行为可预期。
    """
    env = dict(os.environ)
    p = gh_proxy()
    if p:
        env.update(_proxy_env())
    else:
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
                  "ALL_PROXY", "all_proxy"):
            env.pop(k, None)
    return env


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
    p = effective_proxy()
    if p:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": p, "https": p}))
        return opener.open(req, timeout=timeout)
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
        r = subprocess.run([gh_bin(), "auth", "status"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=60, env=_gh_env())
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
def dispatch_workflow(workflow: str, ref: str = "main", timeout: int = 25) -> tuple[bool, str]:
    """触发一次 workflow_dispatch（用于补跑 CI 的计划任务）。不抛异常。

    背景（2026-11-20）：`pool-refresh.yml` 的 `schedule: 8,28,48 * * * *` 在本
    仓库**一次都没触发过**——`gh run list` 里全部记录都是 workflow_dispatch，
    连原有的定时工作流也一样。GitHub 的计划任务在高频 cron 下会被大量丢弃，
    把「池子新鲜度」全押在它身上，等于把架构建在不会响的闹钟上。
    所以本机侧自愈：池子龄期超阈值时自己拍一下 dispatch，下一轮就有新池子。
    """
    if not token():
        return False, "无 token，无法触发"
    if not has_gh():
        return False, "gh 不可用"
    try:
        r = subprocess.run([gh_bin(), "workflow", "run", workflow, "--ref", ref],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, env=_gh_env())
        if r.returncode == 0:
            return True, "已触发"
        tail = ((r.stderr or r.stdout) or "").strip().splitlines()
        return False, (tail[-1][:160] if tail else f"rc={r.returncode}")
    except (subprocess.SubprocessError, OSError) as e:
        return False, type(e).__name__


def release_assets(tag: str) -> list[dict]:
    """列出某 tag 的资产（`[{"name":..., "size":..., "id":...}]`）。"""
    if has_gh():
        try:
            r = subprocess.run([gh_bin(), "release", "view", tag, "--json", "assets"],
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
                               env=_gh_env())
            if r.returncode == 0:
                return json.loads(r.stdout).get("assets", []) or []
        except (subprocess.SubprocessError, ValueError):
            pass  # 落到 REST
    data = _json(f"{API}/repos/{repo()}/releases/tags/{tag}")
    if isinstance(data, dict):
        return data.get("assets", []) or []
    return []


def download_asset(tag: str, name: str, dest: str, *, timeout: int = 60,
                   errs: list[str] | None = None) -> bool:
    """下载单个 Release 资产到 dest。三条通道按**实测成功率**排序。

    实测 2026-11-20（家宽）：
      * `gh release download`：依赖「当前目录是个 git 仓库且有 remote」，
        从非仓库目录调用直接 `failed to run git`；且它最终从
        objects.githubusercontent.com 取实体，该域名在国内常被 RST。
        轮次内实测连续 4 次 ×9s 全失败，而同一函数在仓库根目录手跑成功。
      * `gh api releases/assets/<id>`（Accept: octet-stream）：纯 api.github.com
        往返，同一文件 8~10s 稳定成功——**成功率最高，故排第一**。
      * 直链 + 镜像：公开仓库免 token，家宽下快但受 objects 域名影响。

    任何一条成功即返回；全部失败返回 False（绝不抛异常）。
    """
    url = f"https://github.com/{repo()}/releases/download/{tag}/{name}"
    if errs is None:
        errs = []
    _LAST_VIA.clear()

    def _note(msg: str) -> None:
        try:
            errs.append(msg)
        except Exception:  # noqa: BLE001 - 记录失败绝不影响主流程
            pass

    if has_gh():
        # 通道一：资产接口（不依赖 git 上下文，也不走 objects 域名）
        try:
            r = subprocess.run(
                [gh_bin(), "api", f"repos/{repo()}/releases/tags/{tag}",
                 "--jq", f'.assets[]|select(.name=="{name}").id'],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=20, env=_gh_env())
            aid = (r.stdout or "").strip()
            if aid.isdigit():
                r2 = subprocess.run(
                    [gh_bin(), "api", f"repos/{repo()}/releases/assets/{aid}",
                     "-H", "Accept: application/octet-stream"],
                    capture_output=True, timeout=max(timeout, 120), env=_gh_env())
                if r2.returncode == 0 and r2.stdout:
                    with open(dest, "wb") as f:
                        f.write(r2.stdout)
                    if artifact_ok(dest):
                        _LAST_VIA.append("api资产")
                        return True
                    _note("api资产 写入后校验不通过")
                else:
                    tail = ((r2.stderr or b"").decode("utf-8", "replace")).strip().splitlines()
                    _note(f"api资产 rc={r2.returncode} {(tail[-1] if tail else '空响应')[:120]}")
            else:
                tail = ((r.stderr or "").strip().splitlines())
                _note(f"api查id rc={r.returncode} 未取到 id{(('：' + tail[-1][:100]) if tail else '')}")
        except (subprocess.SubprocessError, OSError) as e:
            _note(f"api资产 {type(e).__name__}")
        # 通道二：gh release download（显式 -R，摆脱 git 上下文依赖）
        try:
            r = subprocess.run(
                [gh_bin(), "release", "download", tag, "-R", repo(),
                 "-p", name, "-O", dest, "--clobber"],
                capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout, env=_gh_env())
            if artifact_ok(dest):
                _LAST_VIA.append("gh release")
                return True
            tail = ((r.stderr or "").strip().splitlines())
            _note(f"gh release rc={r.returncode} {(tail[-1] if tail else '无输出')[:120]}")
        except subprocess.SubprocessError as e:
            _note(f"gh release {type(e).__name__}")
    else:
        _note("gh 不可用")
    # 通道三：直连 + 镜像回退（沙箱直连正常时第一枪即中，家宽则落到镜像）
    ok = download_url(url, dest, max_time=max(timeout, 60))
    if not ok:
        _note("直链+镜像失败")
    else:
        _LAST_VIA.append("直链+镜像")
    return ok


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

    return upload_asset_safe(tag, path, asset_name, timeout=timeout)


def _upload_once(tag: str, path: str, asset_name: str, timeout: int) -> tuple[bool, str]:
    """单次上传（会覆盖同名资产）。成功返回 (True, "")。

    任务#140：**不再用 `path#name` 语法**。实测在 Windows + 便携版 gh 上，
    它会写错资产名——把内容写进别的 `p_*` 资产，导致订阅主资产
    `p_58dd290962_c.yaml` 变成 3318B 的无效配置（本应 5594B）。
    改为先把文件复制成目标文件名，再上传，让 gh 按文件名落资产。
    """
    if has_gh():
        tmpdir = None
        try:
            if asset_name == os.path.basename(path):
                target = path
            else:
                tmpdir = tempfile.mkdtemp(prefix="ghup_")
                target = os.path.join(tmpdir, asset_name)
                shutil.copyfile(path, target)
            r = subprocess.run([gh_bin(), "release", "upload", tag, "--clobber", target],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=timeout, env=_gh_env())
            if r.returncode == 0:
                return True, ""
            gh_err = (r.stderr or r.stdout or "").strip()[:200]
        except subprocess.SubprocessError as e:
            gh_err = f"gh 异常: {type(e).__name__}"
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)
        ok, err = _upload_rest(tag, path, asset_name, timeout)
        return (True, "") if ok else (False, f"gh: {gh_err} | rest: {err}")
    return _upload_rest(tag, path, asset_name, timeout)


def _asset_size(tag: str, name: str) -> int | None:
    """现网资产大小（不存在返回 None）。只用列表接口，不做下载。"""
    for a in release_assets(tag) or []:
        if a.get("name") == name:
            try:
                return int(a.get("size") or 0)
            except (TypeError, ValueError):
                return 0
    return None


def _asset_size_settled(tag: str, name: str, want: int,
                        tries: int = 4, wait: float = 2.0) -> int | None:
    """轮询资产大小直到等于期望值（失败则返回最后一次读数）。

    为什么必须轮询（任务#138，2026-11-20）：GitHub 的 release assets 列表在
    上传成功后并不立即可见，实测刚传完就查会读到**上一次的大小**，于是
    upload_asset_safe 判「暂存校验不符」并放弃——本轮 4 个格式资产全部因此
    未更新（远端仍是 7 小时前的 9049B），而代码报告「已刷新 0/4」。
    上传本身是成功的，坏在校验读到了陈旧快照。
    """
    got = None
    for i in range(max(1, tries)):
        got = _asset_size(tag, name)
        if got == want:
            return got
        if i < tries - 1:
            time.sleep(wait * (i + 1))
    return got


def upload_asset_safe(tag: str, path: str, asset_name: str, *,
                      timeout: int = 180, attempts: int = 3) -> tuple[bool, str]:
    """**非破坏性**上传：先暂存并校验，再替换正式名（任务#135）。

    事故（2026-11-19）：客户端刷新订阅报「无内容」——线上主资产
    `p_*_c.yaml` 整个消失，只剩 `_d/_p/_s/_v`。根因是 `--clobber` 的语义
    「先 DELETE 旧资产、再 POST 新的」：那次 POST 失败后，旧文件已被删除，
    于是**订阅地址 404**，而轮次仍按「已刷新 3/4」报成功。

    新顺序把内容先送上服务器，再动现网名字：
      1) 传 `<name>.staging`（同名先清，不影响订阅地址）；
      2) 校验 staging 大小 == 本地大小；
      3) 删正式名并上传（失败重试 attempts 次）；
      4) 校验正式名大小。
    staging 上传失败时**绝不触碰**正式名——宁可不更新，也不能把线上打空。
    """
    if not os.path.exists(path):
        return False, f"文件不存在: {path}"
    try:
        local_size = os.path.getsize(path)
    except OSError as e:
        return False, f"读取失败: {e}"
    if local_size <= 0:
        return False, "本地文件为空，拒绝上传"

    staging = f"{asset_name}.staging"
    # 显式删除旧的 staging（任务#138）：docstring 写了「同名先清」，但代码一直
    # 依赖 `gh release upload --clobber` 的隐式覆盖。实测该覆盖对**上一轮遗留
    # 的 staging 资产**不生效——gh 退出码 0、远端内容却是旧文件，于是
    # `_asset_size_settled` 读到旧的 15435B 并判「暂存校验不符」，四个格式资产
    # 连续两轮发不出去。删一次再传，语义就明确了。
    try:
        if _asset_size(tag, staging) is not None:
            _delete_asset(tag, staging)
    except Exception:
        pass
    # staging 上传本身要重试（任务#138）：实测 api.github.com 会返回
    # `Post "https://api.github.com/graphql": unexpected EOF`，与 raw 通道
    # 同源——家宽到 GitHub 的连接整体不稳。单次失败就放弃，等于整轮白跑。
    st_err = ""
    for i in range(max(1, attempts)):
        ok, err = _upload_once(tag, path, staging, timeout)
        if ok:
            st_err = ""
            break
        st_err = err
        if i < attempts - 1:
            time.sleep(3 * (i + 1))
    if st_err:
        return False, f"暂存失败（现网资产未受影响）: {st_err}"
    got = _asset_size_settled(tag, staging, local_size)
    if got is not None and got != local_size:
        return False, f"暂存校验不符（远端 {got}B ≠ 本地 {local_size}B）"

    last = ""
    for i in range(max(1, attempts)):
        ok, err = _upload_once(tag, path, asset_name, timeout)
        if ok:
            got = _asset_size_settled(tag, asset_name, local_size)
            if got is None or got == local_size:
                try:
                    _delete_asset(tag, staging)
                except Exception:
                    pass
                return True, ""
            last = f"正式名校验不符（远端 {got}B ≠ 本地 {local_size}B）"
        else:
            last = err
        time.sleep(2 * (i + 1))
    return False, (f"替换正式名失败（内容已安全暂存在 {staging}，"
                   f"可用 gh release upload 手工恢复）: {last}")


def _delete_asset(tag: str, name: str) -> bool:
    """删除指定资产（不存在视为成功）。REST 需要资产 id，故先列一遍。

    任务#140：优先走 gh api --method DELETE。实测自写的 REST DELETE
    在这台机器上**静默失败**（返回 False，但无异常信息），导致遗留的
    `.staging` 资产始终删不掉；而 `gh api --method DELETE` 一次就成功。
    结果是 upload_asset_safe 每次都读到上一轮遗留的 staging 大小，
    判「暂存校验不符」，四个格式资产连续多轮发不出去。
    """
    for a in release_assets(tag) or []:
        if a.get("name") == name and a.get("id"):
            if has_gh():
                try:
                    r = subprocess.run(
                        [gh_bin(), "api", "--method", "DELETE",
                         f"repos/{repo()}/releases/assets/{a['id']}"],
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=60, env=_gh_env())
                    if r.returncode == 0:
                        return True
                except subprocess.SubprocessError:
                    pass
            try:
                _req(f"{API}/repos/{repo()}/releases/assets/{a['id']}",
                     method="DELETE", timeout=30).close()
                return True
            except (urllib.error.URLError, OSError):
                return False
    return True


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
