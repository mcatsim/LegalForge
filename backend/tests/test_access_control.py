"""Tests for resource-level access control."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.auth.models import UserRole
from app.main import app
from tests.conftest import _auth_header, _create_test_user


@pytest_asyncio.fixture
async def second_attorney():
    return await _create_test_user(
        email="attorney2@lexnebulis-test.com",
        password="AttorneyPass123!",
        role=UserRole.attorney,
        first_name="John",
        last_name="SecondAttorney",
    )


@pytest_asyncio.fixture
async def second_attorney_client(second_attorney):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        ac.headers.update(_auth_header(second_attorney))
        yield ac


class TestMatterAccessControl:
    @pytest.mark.asyncio
    async def test_admin_can_access_any_matter(self, admin_client, sample_matter):
        resp = await admin_client.get(f"/api/matters/{sample_matter['id']}")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_assigned_attorney_can_access_matter(self, attorney_client, sample_matter):
        resp = await attorney_client.get(f"/api/matters/{sample_matter['id']}")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_unassigned_attorney_cannot_access_matter(self, second_attorney_client, sample_matter):
        resp = await second_attorney_client.get(f"/api/matters/{sample_matter['id']}")
        assert resp.status_code == 403
