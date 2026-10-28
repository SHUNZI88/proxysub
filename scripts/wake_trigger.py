#!/usr/bin/env python3
"""proxysub 唤醒触发端点（2026-10-28）

用途：从沙箱外部（GitHub Actions 定时 workflow 等）访问，把「沙箱被唤醒」
变成可控事件。端点只做两件事：
  GET /          -> 返回状态（资产龄期、是否有实测在跑）
  GET /trigger   -> 资产超龄则后台触发一轮实测，返回是否已触发

安全：绑定 0.0.0.0（平台要求），凭 token 校验（环境变量 PROXYSUB_TRIGGER_TOKEN）。
沙箱 URL 本身是随机 space key，但仍在 URL 上加 token 防误触发。
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

REPO = "/root/.codebuddy/artifact/proxysub"
WD = "/tmp/cn_probe"
REPORT = os.path.join(WD, "verification_report.json")
MARK = os.path.join(WD, ".last_round_start")
TOKEN = os.environ.get("PROXYSUB_TRIGGER_TOKEN", "")
STALE_H = int(os.environ.get("PROXYSUB_STALE_H", "3"))
COOLDOWN_H = int(os.environ.get("PROXYSUB_COOLDOWN_H", "2"))
PORT = int(os.environ.get("PROXYSUB_TRIGGER_PORT", "8080"))


def asset_age_h() -> int:
    try:
        with open(REPORT, encoding="utf-8") as f:
            r = json.load(f)
        ts = r.get("main_asset_published_at") or r.get("generated_at")
        if not ts:
            return 999
        t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
        return int((datetime.datetime.now(datetime.timezone.utc) - t).total_seconds() // 3600)
    except Exception:
        return 999


def running() -> bool:
    r = subprocess.run(["pgrep", "-f", "scripts/cn_probe.py"],
                       capture_output=True, text=True)
    return r.returncode == 0


def since_last_min() -> int:
    try:
        return int((datetime.datetime.now().timestamp() - os.stat(MARK).st_mtime) // 60)
    except Exception:
        return 99999


def trigger() -> tuple[bool, str]:
    age = asset_age_h()
    if running():
        return False, f"already running (asset_age={age}h)"
    if age < STALE_H:
        return False, f"fresh (asset_age={age}h < {STALE_H}h)"
    gap = since_last_min()
    if gap < COOLDOWN_H * 60:
        return False, f"cooldown ({gap}min < {COOLDOWN_H}h)"
    open(MARK, "w").close()
    env = dict(os.environ)
    env["GITHUB_TOKEN"] = open("/root/.github_pat").read().strip()
    env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    log = open(os.path.join(WD, "wakeup_run.log"), "a")
    subprocess.Popen(
        ["/root/.pyenv/shims/python3.11", "-u", f"{REPO}/scripts/cn_probe.py"],
        cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True)
    return True, f"triggered (asset_age={age}h)"


class Handler(BaseHTTPRequestHandler):
    server_version = "proxysub-trigger/1.0"

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if TOKEN and q.get("token", [""])[0] != TOKEN:
            return self._json(403, {"ok": False, "error": "bad token"})
        if u.path == "/trigger":
            ok, msg = trigger()
            return self._json(200 if ok else 200,
                              {"ok": ok, "msg": msg, "asset_age_h": asset_age_h(),
                               "running": running()})
        if u.path in ("/", "/status"):
            return self._json(200, {"ok": True, "asset_age_h": asset_age_h(),
                                    "running": running(),
                                    "since_last_min": since_last_min()})
        self._json(404, {"ok": False, "error": "not found"})

    def log_message(self, fmt: str, *a) -> None:
        sys.stderr.write("%s %s\n" % (datetime.datetime.now().strftime("%F %T"), fmt % a))


if __name__ == "__main__":
    if not TOKEN:
        TOKEN = "proxysub"
    os.makedirs(WD, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
