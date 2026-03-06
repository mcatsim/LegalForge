"""
Tests for the authentication and user-management endpoints.

Covers login, token refresh, account lockout, /me, password change,
and admin-only user CRUD.
"""

from httpx import AsyncClient

from app.auth.models import UserRole
from tests.conftest import UserFactory, _create_test_user

# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------


class TestLogin:
    """POST /api/auth/login"""

    async def test_login_valid_credentials(self, client: AsyncClient):
        """Successful login returns access + refresh tokens."""
        user = await _create_test_user(
            email="login-ok@test.com",
            password="GoodPassword1!",
            role=UserRole.attorney,
        )
        resp = await client.post(
            "/api/auth/login",
            json={
                "email": "login-ok@test.com",
                "password": "GoodPassword1!",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert "refresh_token" in body
        assert body["token_type"] == "bearer"

    async def test_login_wrong_password(self, client: AsyncClient):
        """Wrong password returns 401."""
        await _create_test_user(
            email="login-bad@test.com",
            password="CorrectPassword1!",
            role=UserRole.attorney,
        )
        resp = await client.post(
            "/api/auth/login",
            json={
                "email": "login-bad@test.com",
                "password": "WrongPassword1!",
            },
        )
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid credentials"

    async def test_login_nonexistent_user(self, client: AsyncClient):
        """Nonexistent email returns 401."""
        resp = await client.post(
            "/api/auth/login",
            json={
                "email": "nobody@test.com",
                "password": "Whatever123!",
            },
        )
        assert resp.status_code == 401

    async def test_account_lockout_after_failed_attempts(self, client: AsyncClient):
        """Account locks after max_login_attempts (5) consecutive failures."""
        await _create_test_user(
            email="lockout@test.com",
            password="RealPassword1!",
            role=UserRole.attorney,
        )
        for _ in range(5):
            resp = await client.post(
                "/api/auth/login",
                json={
                    "email": "lockout@test.com",
                    "password": "BadGuess12345",
                },
            )
            assert resp.status_code == 401

        # After lockout, even the correct password should fail
        resp = await client.post(
            "/api/auth/login",
            json={
                "email": "lockout@test.com",
                "password": "RealPassword1!",
            },
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------


class TestTokenRefresh:
    """POST /api/auth/refresh"""

    async def test_refresh_valid_token(self, client: AsyncClient):
        """A valid refresh token returns new tokens."""
        await _create_test_user(
            email="refresh-ok@test.com",
            password="RefreshPass1!",
            role=UserRole.attorney,
        )
        login = await client.post(
            "/api/auth/login",
            json={
                "email": "refresh-ok@test.com",
                "password": "RefreshPass1!",
            },
        )
        refresh_token = login.json()["refresh_token"]

        resp = await client.post(
            "/api/auth/refresh",
            json={
                "refresh_token": refresh_token,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert "refresh_token" in body
        # The old refresh token should be rotated (different value)
        assert body["refresh_token"] != refresh_token

    async def test_refresh_invalid_token(self, client: AsyncClient):
        """An invalid refresh token returns 401."""
        resp = await client.post(
            "/api/auth/refresh",
            json={
                "refresh_token": "bogus-token-value",
            },
        )
        assert resp.status_code == 401

    async def test_refresh_token_cannot_be_reused(self, client: AsyncClient):
        """After rotation, the old refresh token is revoked."""
        await _create_test_user(
            email="refresh-reuse@test.com",
            password="ReusePass123!",
            role=UserRole.attorney,
        )
        login = await client.post(
            "/api/auth/login",
            json={
                "email": "refresh-reuse@test.com",
                "password": "ReusePass123!",
            },
        )
        old_refresh = login.json()["refresh_token"]

        # First rotation succeeds
        await client.post("/api/auth/refresh", json={"refresh_token": old_refresh})

        # Re-using the same token should fail
        resp = await client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# GET /me
# ---------------------------------------------------------------------------


class TestGetMe:
    """GET /api/auth/me"""

    async def test_get_me_authenticated(self, client: AsyncClient, admin_headers):
        """Authenticated user can read their own profile."""
        resp = await client.get("/api/auth/me", headers=admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == "admin@lexnebulis-test.com"
        assert body["role"] == "admin"

    async def test_get_me_unauthenticated(self, client: AsyncClient):
        """Unauthenticated request returns 401/403."""
        resp = await client.get("/api/auth/me")
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------


class TestPasswordChange:
    """PUT /api/auth/me/password"""

    async def test_change_password_success(self, client: AsyncClient):
        """User can change their own password."""
        await _create_test_user(
            email="chpw@test.com",
            password="OldPassword1!",
            role=UserRole.attorney,
        )
        login = await client.post(
            "/api/auth/login",
            json={
                "email": "chpw@test.com",
                "password": "OldPassword1!",
            },
        )
        token = login.json()["access_token"]

        resp = await client.put(
            "/api/auth/me/password",
            json={"current_password": "OldPassword1!", "new_password": "NewPassword2!"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "Password updated" in resp.json()["message"]

        # Old password should no longer work
        resp2 = await client.post(
            "/api/auth/login",
            json={
                "email": "chpw@test.com",
                "password": "OldPassword1!",
            },
        )
        assert resp2.status_code == 401

        # New password should work
        resp3 = await client.post(
            "/api/auth/login",
            json={
                "email": "chpw@test.com",
                "password": "NewPassword2!",
            },
        )
        assert resp3.status_code == 200

    async def test_change_password_wrong_current(self, client: AsyncClient, admin_headers):
        """Providing the wrong current password returns 400."""
        resp = await client.put(
            "/api/auth/me/password",
            json={"current_password": "WrongOld123!", "new_password": "NewPassword2!"},
            headers=admin_headers,
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Admin user management
# ---------------------------------------------------------------------------


class TestAdminUserCRUD:
    """Admin-only endpoints: GET/POST/PUT /api/auth/users"""

    async def test_admin_can_list_users(self, admin_client: AsyncClient):
        resp = await admin_client.get("/api/auth/users")
        assert resp.status_code == 200
        body = resp.json()
        assert "items" in body
        assert "total" in body
        assert body["total"] >= 1  # at least the admin itself

    async def test_non_admin_cannot_list_users(self, attorney_client: AsyncClient):
        resp = await attorney_client.get("/api/auth/users")
        assert resp.status_code == 403

    async def test_admin_can_create_user(self, admin_client: AsyncClient):
        payload = UserFactory()
        resp = await admin_client.post("/api/auth/users", json=payload)
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == payload["email"]
        assert body["role"] == "attorney"

    async def test_create_duplicate_email_returns_409(self, admin_client: AsyncClient):
        payload = UserFactory(email="dup@test.com")
        resp1 = await admin_client.post("/api/auth/users", json=payload)
        assert resp1.status_code == 201

        resp2 = await admin_client.post("/api/auth/users", json=payload)
        assert resp2.status_code == 409

    async def test_admin_can_update_user(self, admin_client: AsyncClient):
        # Create a user first
        payload = UserFactory()
        create_resp = await admin_client.post("/api/auth/users", json=payload)
        user_id = create_resp.json()["id"]

        # Update the user
        resp = await admin_client.put(
            f"/api/auth/users/{user_id}",
            json={
                "first_name": "Updated",
                "last_name": "Name",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["first_name"] == "Updated"
        assert resp.json()["last_name"] == "Name"

    async def test_admin_can_deactivate_user(self, admin_client: AsyncClient):
        payload = UserFactory()
        create_resp = await admin_client.post("/api/auth/users", json=payload)
        user_id = create_resp.json()["id"]

        resp = await admin_client.put(
            f"/api/auth/users/{user_id}",
            json={
                "is_active": False,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False
