"""Tests for SSO state parameter consumption."""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select

from app.sso.models import SSOProvider, SSOProviderType, SSOSession
from app.sso.service import _consume_sso_state
from tests.conftest import TestSession


@pytest_asyncio.fixture
async def sso_provider():
    """Create a minimal SSO provider for FK constraint."""
    provider = SSOProvider(
        name="Test Provider",
        provider_type=SSOProviderType.oidc,
        is_active=True,
    )
    async with TestSession() as db:
        db.add(provider)
        await db.commit()
        await db.refresh(provider)
        provider_id = provider.id
    return provider_id


@pytest_asyncio.fixture
async def sso_session(sso_provider):
    """Create an SSO session in the test database."""
    session_obj = SSOSession(
        provider_id=sso_provider,
        state="test-state-token-123",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    async with TestSession() as db:
        db.add(session_obj)
        await db.commit()
    return session_obj


class TestSSOStateConsumption:
    @pytest.mark.asyncio
    async def test_state_deleted_after_use(self, sso_session):
        """After callback processes a state, it must be deleted from the DB."""
        async with TestSession() as db:
            # Verify state exists before
            result = await db.execute(select(SSOSession).where(SSOSession.state == "test-state-token-123"))
            assert result.scalar_one_or_none() is not None

            # Consume the state
            session = await _consume_sso_state(db, "test-state-token-123")
            assert session is not None
            await db.commit()

            # Verify state is deleted
            result2 = await db.execute(select(SSOSession).where(SSOSession.state == "test-state-token-123"))
            assert result2.scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_replayed_state_rejected(self, sso_session):
        """A state token used twice must be rejected on the second attempt."""
        async with TestSession() as db:
            # First use succeeds
            session = await _consume_sso_state(db, "test-state-token-123")
            assert session is not None
            await db.commit()

        async with TestSession() as db:
            # Second use fails
            with pytest.raises(ValueError, match="Invalid or expired"):
                await _consume_sso_state(db, "test-state-token-123")
