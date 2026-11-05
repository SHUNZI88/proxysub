#!/usr/bin/env python3
"""跨平台非阻塞文件锁（任务#121）。

## 为什么需要单独一个模块

`cn_probe.py` 的单实例锁与 `round_guard.py` 的「是否已有实例在跑」原本只用
`fcntl.flock`（POSIX）。实测搬到 Windows 家宽后这条路径整段失效：

* `cn_probe` 拿不到锁 → 可以并发起两个探针，两个进程同时发布同一批资产；
* `round_guard.probe_lock_state` 返回 `unknown` → `decide()` 保守判「不跑」，
  于是**本机的自动补跑永远不会触发**（比没有守护更糟：它看起来在工作）。

Windows 的等价物是 `msvcrt.locking(LK_NBLCK)`（字节区间锁，进程退出/句柄关闭
即释放，与 flock 语义接近）。两边统一到本模块，调用方不再关心平台。

约定：锁文件第 0 字节。取锁前必须 `seek(0)`；写入持锁者信息后若再取锁判断，
须重新 seek（msvcrt 以当前文件位置为锁起点）。
"""

from __future__ import annotations

import os

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - 非 POSIX
    fcntl = None

try:  # Windows
    import msvcrt
except ImportError:  # pragma: no cover - 非 Windows
    msvcrt = None


def supported() -> bool:
    return fcntl is not None or msvcrt is not None


def acquire(fh) -> bool:
    """非阻塞取排他锁。成功 True；已被他人持有返回 False（绝不抛异常）。"""
    if fcntl is not None:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False
    if msvcrt is not None:
        try:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    return False


def release(fh) -> None:
    """释放锁。失败静默（进程退出时 OS 也会释放）。"""
    if fcntl is not None:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        return
    if msvcrt is not None:
        try:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass


def is_locked(path: str) -> bool:
    """探测 path 是否被别的进程持锁。文件不存在视为未锁。

    以「能否取到锁」判定，而不是猜进程名——`pgrep -f` 会自匹配、也会把
    被冻结（SIGSTOP）的进程当成在跑，两种误判都真实发生过（任务#120）。
    """
    if not os.path.exists(path):
        return False
    try:
        fh = open(path, "a+", encoding="utf-8")
    except OSError:
        return True  # 打开都失败：按「有锁」处理，保守
    try:
        if acquire(fh):
            release(fh)
            return False
        return True
    finally:
        try:
            fh.close()
        except OSError:
            pass
