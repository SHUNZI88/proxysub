#!/usr/bin/env python3
"""Safe JSON persistence for proxysub.

目标：sources.json / survival.json / source_stats.json 等状态文件在频繁读写时
绝不能因为进程中断而损坏（截断 / 半截 JSON / 空文件）。

机制：
  1. 原子写入：先写同目录临时文件，flush + fsync 落盘，再 os.replace() 原子替换。
     os.replace 在同一卷上是原子的：读者要么看到旧文件，要么看到完整新文件，
     不存在"写了一半"的中间状态。
  2. 进程间互斥：filelock 对每个目标文件加锁（<path>.lock），防止并发运行时
     多个进程同时读-改-写造成丢失更新。
  3. 损坏自愈：load_json 遇到无法解析的内容时，把损坏文件改名为 <path>.corrupt
     备份并返回默认值，避免整条流水线因一个坏文件反复崩溃。
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

try:
    from filelock import FileLock
except ImportError:  # pragma: no cover - 兜底：未安装 filelock 时退化为无锁
    FileLock = None

LOCK_TIMEOUT = 30


def _lock_for(path: str):
    if FileLock is None:
        return None
    return FileLock(path + ".lock", timeout=LOCK_TIMEOUT)


def load_json(path: str, default: Any) -> Any:
    """读取 JSON；文件不存在返回 default；损坏时备份为 .corrupt 并返回 default。"""
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        # 文件损坏（例如上次写入被中断导致截断）：备份后用默认值重启，不让流水线崩溃
        try:
            os.replace(path, path + ".corrupt")
        except OSError:
            pass
        return default
    except Exception:
        return default


def save_json(path: str, data: Any) -> None:
    """原子化写入 JSON：临时文件 + fsync + os.replace，全程持文件锁。"""
    lock = _lock_for(path)
    if lock is not None:
        with lock:
            _atomic_write(path, data)
    else:  # pragma: no cover
        _atomic_write(path, data)


def _atomic_write(path: str, data: Any) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        # os.replace 成功后 tmp 已不存在；失败时清理残留临时文件
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


__all__ = ["load_json", "save_json"]
