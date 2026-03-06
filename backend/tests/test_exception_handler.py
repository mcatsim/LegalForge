"""Tests for global exception handler."""

import pytest


class TestGlobalExceptionHandler:
    @pytest.mark.asyncio
    async def test_unhandled_exception_returns_500_without_stacktrace(self, client):
        """Internal errors should return 500 with a generic message, no stack trace."""
        resp = await client.get("/api/health/crash-test")
        assert resp.status_code == 500
        body = resp.json()
        assert "detail" in body
        assert "traceback" not in body.get("detail", "").lower()
        assert "Traceback" not in resp.text
        assert "File " not in resp.text

    @pytest.mark.asyncio
    async def test_404_still_works(self, client):
        resp = await client.get("/api/nonexistent-endpoint-xyz")
        assert resp.status_code in (404, 405)

    @pytest.mark.asyncio
    async def test_health_endpoint_still_works(self, client):
        resp = await client.get("/api/health")
        assert resp.status_code == 200
