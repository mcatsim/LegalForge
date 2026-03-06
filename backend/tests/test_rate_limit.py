"""Tests for rate limiting on auth endpoints."""

import pytest

from app.common.rate_limit import _windows


@pytest.fixture(autouse=True)
def clear_rate_limit_state():
    """Reset rate limit state between tests."""
    _windows.clear()
    yield
    _windows.clear()


class TestLoginRateLimit:
    @pytest.mark.asyncio
    async def test_login_rate_limited_after_threshold(self, client):
        """After 10 failed login attempts from same IP, requests should be rate-limited."""
        for i in range(10):
            await client.post(
                "/api/auth/login",
                json={
                    "email": "nonexistent@example.com",
                    "password": "WrongPassword123!",
                },
            )

        # 11th attempt should be rate-limited
        resp = await client.post(
            "/api/auth/login",
            json={
                "email": "nonexistent@example.com",
                "password": "WrongPassword123!",
            },
        )
        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_successful_login_not_rate_limited(self, client, admin_user):
        """Successful logins should work normally."""
        resp = await client.post(
            "/api/auth/login",
            json={
                "email": "admin@lexnebulis-test.com",
                "password": "AdminPass123!",
            },
        )
        assert resp.status_code == 200
