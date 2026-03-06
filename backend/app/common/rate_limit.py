"""
In-memory sliding window rate limiter.

Uses a simple dict-based approach for single-instance deployments.
For clustered deployments (K8s), swap to Redis-backed implementation.
"""

import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException, Request, status

# Store: { key: [timestamp, timestamp, ...] }
_windows: dict[str, list[float]] = defaultdict(list)
_lock = Lock()


def _cleanup_window(key: str, window_seconds: int) -> None:
    """Remove timestamps older than the window."""
    cutoff = time.monotonic() - window_seconds
    _windows[key] = [t for t in _windows[key] if t > cutoff]
    if not _windows[key]:
        del _windows[key]


def check_rate_limit(
    key: str,
    max_requests: int = 10,
    window_seconds: int = 300,
) -> None:
    """Raise 429 if the key has exceeded max_requests in the window.

    Args:
        key: Identifier (e.g., IP address, "login:{ip}")
        max_requests: Maximum allowed requests in the window
        window_seconds: Window size in seconds (default 5 minutes)
    """
    with _lock:
        _cleanup_window(key, window_seconds)
        if len(_windows[key]) >= max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
            )
        _windows[key].append(time.monotonic())


def rate_limit_login(request: Request) -> None:
    """Rate limit login attempts by IP address."""
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"login:{ip}", max_requests=10, window_seconds=300)


def rate_limit_2fa(request: Request) -> None:
    """Rate limit 2FA verification attempts by IP address."""
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"2fa:{ip}", max_requests=5, window_seconds=300)


def reset_rate_limit(key: str) -> None:
    """Reset rate limit for a key (e.g., after successful login)."""
    with _lock:
        _windows.pop(key, None)


def reset_login_rate_limit(request: Request) -> None:
    """Clear login rate limit for an IP after successful authentication."""
    ip = request.client.host if request.client else "unknown"
    reset_rate_limit(f"login:{ip}")
