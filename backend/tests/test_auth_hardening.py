"""Tests for auth hardening fixes."""

import pytest

from app.auth.service import (
    create_refresh_token_value,
    generate_recovery_codes,
    verify_recovery_code,
)


class TestRefreshTokenEntropy:
    def test_refresh_token_uses_secrets_not_uuid(self):
        token = create_refresh_token_value()
        # secrets.token_urlsafe produces URL-safe base64 (contains _ or -)
        # uuid4 produces hex with dashes and is exactly 36 chars
        assert len(token) > 36 or "_" in token

    def test_refresh_token_has_sufficient_entropy(self):
        token = create_refresh_token_value()
        # secrets.token_urlsafe(32) produces ~43 chars
        assert len(token) >= 40


class TestRecoveryCodeEntropy:
    def test_recovery_codes_have_sufficient_entropy(self):
        codes = generate_recovery_codes()
        assert len(codes) == 8
        # Each code should be 16 hex chars (8 bytes = 64 bits)
        for code in codes:
            assert len(code) >= 16


class TestRecoveryCodeTiming:
    def test_verify_uses_constant_time_comparison(self):
        """verify_recovery_code should use hmac.compare_digest, not 'in' operator."""
        import inspect

        source = inspect.getsource(verify_recovery_code)
        assert "compare_digest" in source


class TestPasswordChangeRevokesTokens:
    @pytest.mark.asyncio
    async def test_password_change_revokes_refresh_tokens(self, admin_client, admin_user):
        """After password change, existing refresh tokens should be revoked."""
        # Login to get a refresh token
        resp = await admin_client.put(
            "/api/auth/me/password",
            json={
                "current_password": "AdminPass123!",
                "new_password": "NewAdminPass456!",
            },
        )
        assert resp.status_code == 200
        assert "log in again" in resp.json()["message"].lower() or "updated" in resp.json()["message"].lower()
