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
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

REPO = "/root/.codebuddy/artifact/proxysub"
WD = "/tmp/cn_probe"
TOKEN = os.environ.get("PROXYSUB_TRIGGER_TOKEN", "")
PORT = int(os.environ.get("PROXYSUB_TRIGGER_PORT", "8080"))
STALE_H = int(os.environ.get("PROXYSUB_STALE_H", "3"))

# 决策逻辑统一由 round_guard 提供（任务#120，2026-11-05）：
# 此前本模块自己实现了一遍「pgrep 判存活 + .last_round_start 判冷却」，
# 与 cron_supervisor.sh 各写一套，且两套都错在同一个地方——把「开跑」
# 当成了「完成」。策略只留一份，三个入口（supervisor / watchdog / 本端点）
# 才不会再次分叉。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import round_guard  # noqa: E402


def asset_age_h() -> int:
    return int(round_guard.asset_age_h(WD))


def running() -> bool:
    """是否已有实例持锁。判锁不判进程名：pgrep -f 会自匹配，且把冻结进程
    算作在跑（沙箱休眠是冻结而非 kill），两种误判都会让补跑永远不触发。"""
    return round_guard.probe_lock_state(WD)["state"] == "running"


def trigger() -> tuple[bool, str]:
    ok, why = round_guard.decide(WD, stale_h=STALE_H)
    age = asset_age_h()
    if not ok:
        return False, f"{why} (asset_age={age}h)"
    round_guard.note_attempt(WD)
    env = dict(os.environ)
    env["GITHUB_TOKEN"] = open("/root/.github_pat").read().strip()
    env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    log = open(os.path.join(WD, "wakeup_run.log"), "a")
    proc = subprocess.Popen(
        ["/root/.pyenv/shims/python3.11", "-u", f"{REPO}/scripts/cn_probe.py"],
        cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True)
    # 后台进程无人等待退出码，用守护线程回收结果：成败按「资产是否刷新」
    # 判定（note_result 内部比对发布戳），而不是看 rc——cn_probe 在
    # 「另一实例持锁」等路径上同样以 0 退出。
    def _reap() -> None:
        rc = proc.wait()
        try:
            round_guard.note_result(WD, rc)
        except Exception:  # noqa: BLE001 - 状态记录失败不影响端点存活
            pass

    threading.Thread(target=_reap, daemon=True).start()
    return True, f"triggered (asset_age={age}h; {why})"



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
            # `since_last_min` 已废弃（任务#120）：它度量的是「距上次开跑」，
            # 正是把失败尝试当成冷却依据的那个错误口径。改报退避状态。
            decide_ok, decide_why = round_guard.decide(WD, stale_h=STALE_H)
            state = round_guard.load_state(WD)
            return self._json(200, {
                "ok": True,
                "asset_age_h": asset_age_h(),
                "running": running(),
                "would_trigger": decide_ok,
                "reason": decide_why,
                "fail_streak": state.get("fail_streak") or 0,
                "backoff_min": round_guard.backoff_min(
                    int(state.get("fail_streak") or 0)),
                "last_result_refreshed": state.get("last_result_refreshed"),
            })
        self._json(404, {"ok": False, "error": "not found"})

    def log_message(self, fmt: str, *a) -> None:
        sys.stderr.write("%s %s\n" % (datetime.datetime.now().strftime("%F %T"), fmt % a))


if __name__ == "__main__":
    if not TOKEN:
        TOKEN = "proxysub"
    os.makedirs(WD, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
