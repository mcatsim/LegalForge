"""Tests for SSO JWT signature verification."""

import jwt
import pytest

from app.sso.service import _decode_id_token


class TestDecodeIdToken:
    @pytest.mark.asyncio
    async def test_rejects_token_without_jwks_uri(self):
        """If no JWKS URI is available, id_token cannot be verified."""
        fake_token = jwt.encode(
            {"sub": "user1", "email": "user@example.com"},
            "some-key",
            algorithm="HS256",
        )
        with pytest.raises(ValueError, match="JWKS"):
            await _decode_id_token(fake_token, jwks_uri=None, client_id="test-client")

    @pytest.mark.asyncio
    async def test_rejects_unsigned_token(self):
        """Tokens without valid signatures must be rejected."""
        fake_token = jwt.encode(
            {"sub": "attacker", "email": "evil@example.com"},
            "wrong-key",
            algorithm="HS256",
        )
        # Even with a JWKS URI, the token can't be verified against it
        with pytest.raises(ValueError, match="signature"):
            await _decode_id_token(
                fake_token,
                jwks_uri="https://example.com/.well-known/jwks.json",
                client_id="test-client",
            )
