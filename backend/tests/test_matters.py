"""
Tests for the matter CRUD endpoints.

Covers create, list with filters, get by ID, update,
and matter-contact linking.
"""

import uuid

from httpx import AsyncClient

from app.auth.models import User

# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


class TestCreateMatter:
    """POST /api/matters"""

    async def test_create_matter_linked_to_client(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
        attorney_user: User,
    ):
        data = {
            "title": "Smith v. Jones",
            "client_id": sample_client["id"],
            "litigation_type": "civil",
            "description": "Contract dispute",
            "assigned_attorney_id": str(attorney_user.id),
        }
        resp = await admin_client.post("/api/matters", json=data)
        assert resp.status_code == 201
        body = resp.json()
        assert body["title"] == "Smith v. Jones"
        assert body["client_id"] == sample_client["id"]
        assert body["status"] == "open"
        assert body["litigation_type"] == "civil"
        assert "matter_number" in body

    async def test_create_matter_with_defaults(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
    ):
        data = {"title": "Default Matter", "client_id": sample_client["id"]}
        resp = await admin_client.post("/api/matters", json=data)
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "open"
        assert body["litigation_type"] == "other"

    async def test_create_matter_requires_auth(self, sample_client: dict):
        from httpx import ASGITransport, AsyncClient

        from app.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as unauthed:
            data = {"title": "No Auth", "client_id": sample_client["id"]}
            resp = await unauthed.post("/api/matters", json=data)
            assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# List with filters
# ---------------------------------------------------------------------------


class TestListMatters:
    """GET /api/matters"""

    async def test_list_matters_returns_paginated(
        self,
        admin_client: AsyncClient,
        sample_matter: dict,
    ):
        resp = await admin_client.get("/api/matters")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1
        assert "items" in body

    async def test_filter_by_status(
        self,
        admin_client: AsyncClient,
        sample_matter: dict,
    ):
        resp = await admin_client.get("/api/matters", params={"status": "open"})
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert item["status"] == "open"

    async def test_filter_by_client_id(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
        sample_matter: dict,
    ):
        resp = await admin_client.get("/api/matters", params={"client_id": sample_client["id"]})
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1
        for item in body["items"]:
            assert item["client_id"] == sample_client["id"]

    async def test_filter_by_attorney_id(
        self,
        admin_client: AsyncClient,
        attorney_user: User,
        sample_matter: dict,
    ):
        resp = await admin_client.get(
            "/api/matters",
            params={"attorney_id": str(attorney_user.id)},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] >= 1

    async def test_filter_by_litigation_type(
        self,
        admin_client: AsyncClient,
        sample_matter: dict,
    ):
        resp = await admin_client.get("/api/matters", params={"litigation_type": "civil"})
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert item["litigation_type"] == "civil"


# ---------------------------------------------------------------------------
# Get by ID
# ---------------------------------------------------------------------------


class TestGetMatter:
    """GET /api/matters/{matter_id}"""

    async def test_get_matter_by_id(
        self,
        admin_client: AsyncClient,
        sample_matter: dict,
    ):
        resp = await admin_client.get(f"/api/matters/{sample_matter['id']}")
        assert resp.status_code == 200
        assert resp.json()["id"] == sample_matter["id"]

    async def test_get_nonexistent_matter(self, admin_client: AsyncClient):
        resp = await admin_client.get(f"/api/matters/{uuid.uuid4()}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------


class TestUpdateMatter:
    """PUT /api/matters/{matter_id}"""

    async def test_update_matter_title(
        self,
        admin_client: AsyncClient,
        sample_matter: dict,
    ):
        resp = await admin_client.put(
            f"/api/matters/{sample_matter['id']}",
            json={"title": "Revised Title"},
        )
        assert resp.status_code == 200
        assert resp.json()["title"] == "Revised Title"

    async def test_update_matter_status(
        self,
        admin_client: AsyncClient,
        sample_matter: dict,
    ):
        resp = await admin_client.put(
            f"/api/matters/{sample_matter['id']}",
            json={"status": "closed", "date_closed": "2025-12-31"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "closed"


# ---------------------------------------------------------------------------
# Matter Contacts
# ---------------------------------------------------------------------------


class TestMatterContacts:
    """POST/DELETE /api/matters/{matter_id}/contacts"""

    async def _create_contact(self, admin_client: AsyncClient) -> dict:
        """Helper to create a contact via the API."""
        data = {
            "first_name": "Witness",
            "last_name": "McWitness",
            "role": "witness",
        }
        resp = await admin_client.post("/api/contacts", json=data)
        assert resp.status_code == 201
        return resp.json()

    async def test_add_contact_to_matter(
        self,
        admin_client: AsyncClient,
        sample_matter: dict,
    ):
        contact = await self._create_contact(admin_client)
        resp = await admin_client.post(
            f"/api/matters/{sample_matter['id']}/contacts",
            json={"contact_id": contact["id"], "relationship_type": "witness"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["contact_id"] == contact["id"]
        assert body["relationship_type"] == "witness"

    async def test_remove_contact_from_matter(
        self,
        admin_client: AsyncClient,
        sample_matter: dict,
    ):
        contact = await self._create_contact(admin_client)
        add_resp = await admin_client.post(
            f"/api/matters/{sample_matter['id']}/contacts",
            json={"contact_id": contact["id"], "relationship_type": "expert"},
        )
        mc_id = add_resp.json()["id"]

        del_resp = await admin_client.delete(
            f"/api/matters/{sample_matter['id']}/contacts/{mc_id}",
        )
        assert del_resp.status_code == 204
