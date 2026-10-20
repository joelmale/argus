import threading
import time
from collections import deque

from slowapi import Limiter
from slowapi.util import get_remote_address

# Per-peer limits. Browser traffic arrives via the Next.js proxy, so every browser
# shares the frontend container's address: keep these loose (flood protection only).
# Next forwards a client-supplied X-Forwarded-For untouched, so it can't be trusted.
limiter = Limiter(key_func=get_remote_address)


class FailureThrottle:
    """Sliding-window failure counter keyed by account (username or email).

    Brute-force protection that doesn't depend on client addresses: after
    `max_failures` failures within `window_s`, the key is blocked until the oldest
    failure ages out. In-process state; Argus runs a single API worker.
    """

    def __init__(self, max_failures: int, window_s: float):
        self.max_failures, self.window_s = max_failures, window_s
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        entries = self._failures.setdefault(key, deque())
        while entries and now - entries[0] > self.window_s:
            entries.popleft()
        return entries

    def retry_after(self, key: str, now: float | None = None) -> int:
        """Seconds until `key` may try again (0 if not blocked)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            entries = self._prune(key.lower(), now)
            if len(entries) < self.max_failures:
                return 0
            return max(1, int(self.window_s - (now - entries[0])) + 1)

    def record_failure(self, key: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            self._prune(key.lower(), now).append(now)
            if len(self._failures) > 10_000:  # bound memory under a username-spraying flood
                self._failures = {k: v for k, v in self._failures.items() if v}

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._failures.clear()
            else:
                self._failures.pop(key.lower(), None)


login_failures = FailureThrottle(max_failures=10, window_s=300)
reset_requests = FailureThrottle(max_failures=3, window_s=900)
