"""进程内的最小状态：限流窗口 + 最近一次结果。

真正常态路径（判定通行证）**不碰**这里 —— 无状态签名就够了。
单进程部署直接可用；多实例时这一层可以直接去掉，代价只是限流退化成单点。
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class MemoryStore:
    def __init__(self, max_keys: int = 50000):
        self._lock = threading.Lock()
        self._rate: dict[str, deque] = defaultdict(deque)
        self._max = max_keys
        self.last_result: dict = {"at": 0.0, "ok": None, "reason": "", "site": ""}

    def rate_ok(self, key: str, limit: int, window: float = 1.0) -> bool:
        if not key:
            return True
        now = time.time()
        with self._lock:
            if len(self._rate) > self._max:
                self._rate.clear()
            q = self._rate[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= max(1, limit):
                return False
            q.append(now)
            return True

    def record(self, ok: bool, reason: str, site: str = "") -> None:
        self.last_result = {"at": time.time(), "ok": ok, "reason": reason,
                            "site": site}
