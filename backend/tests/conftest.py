"""
Shared test fixtures for the LexNebulis backend test suite.

Sets up an async SQLite in-memory database, overrides FastAPI dependencies,
and provides pre-authenticated HTTP clients for admin, attorney, and
billing_clerk roles.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import factory
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---- Environment overrides MUST come before any app imports ----
os.environ["DATABASE_URL"] = "sqlite+aiosqlite://"
os.environ["SECRET_KEY"] = "test-secret-key-for-unit-tests"
os.environ["FIELD_ENCRYPTION_KEY"] = "test-encryption-key-for-unit-tests"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"
os.environ["FIRST_ADMIN_EMAIL"] = "admin@test.com"
os.environ["FIRST_ADMIN_PASSWORD"] = "AdminPass123!"
os.environ["ENVIRONMENT"] = "test"

from app.auth.models import User, UserRole  # noqa: E402
from app.auth.service import create_access_token, hash_password  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402

# ---------------------------------------------------------------------------
# Async engine & session factory for the test database
# ---------------------------------------------------------------------------
TEST_DATABASE_URL = "sqlite+aiosqlite://"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSession = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


# SQLite does not enforce FK constraints by default — enable them.
@event.listens_for(test_engine.sync_engine, "connect")
def _enable_sqlite_fk(dbapi_conn, _connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# ---------------------------------------------------------------------------
# Session-scoped event loop
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Database lifecycle
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture(autouse=True)
async def setup_database():
    """Create all tables before each test, drop them afterward."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


# ---------------------------------------------------------------------------
# DB session fixture
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    """Provide a transactional DB session for direct service-layer tests."""
    async with TestSession() as session:
        yield session


# ---------------------------------------------------------------------------
# Dependency override
# ---------------------------------------------------------------------------
async def _override_get_db():
    async with TestSession() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


app.dependency_overrides[get_db] = _override_get_db


# ---------------------------------------------------------------------------
# Rate limit state cleanup (prevent cross-test contamination)
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _clear_rate_limits():
    """Clear in-memory rate limit windows between every test."""
    from app.common.rate_limit import _windows

    _windows.clear()
    yield
    _windows.clear()


# ---------------------------------------------------------------------------
# HTTP client fixture
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def client() -> AsyncClient:
    """Unauthenticated httpx async client wired to the FastAPI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helper: create a user directly in the database
# ---------------------------------------------------------------------------
async def _create_test_user(
    email: str,
    password: str,
    role: UserRole,
    first_name: str = "Test",
    last_name: str = "User",
) -> User:
    """Insert a user into the test database and return it."""
    user = User(
        id=uuid.uuid4(),
        email=email,
        password_hash=hash_password(password),
        first_name=first_name,
        last_name=last_name,
        role=role,
        is_active=True,
        failed_login_attempts=0,
    )
    async with TestSession() as session:
        session.add(user)
        await session.commit()
        await session.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Authenticated client helpers
# ---------------------------------------------------------------------------
def _auth_header(user: User) -> dict[str, str]:
    token = create_access_token(str(user.id), user.role.value)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def admin_user() -> User:
    return await _create_test_user(
        email="admin@lexnebulis-test.com",
        password="AdminPass123!",
        role=UserRole.admin,
        first_name="Admin",
        last_name="Tester",
    )


@pytest_asyncio.fixture
async def attorney_user() -> User:
    return await _create_test_user(
        email="attorney@lexnebulis-test.com",
        password="AttorneyPass123!",
        role=UserRole.attorney,
        first_name="Jane",
        last_name="Attorney",
    )


@pytest_asyncio.fixture
async def billing_user() -> User:
    return await _create_test_user(
        email="billing@lexnebulis-test.com",
        password="BillingPass123!",
        role=UserRole.billing_clerk,
        first_name="Bill",
        last_name="Clerk",
    )


@pytest_asyncio.fixture
async def admin_client(client: AsyncClient, admin_user: User) -> AsyncClient:
    """AsyncClient pre-authenticated as an admin."""
    client.headers.update(_auth_header(admin_user))
    return client


@pytest_asyncio.fixture
async def attorney_client(admin_user: User, attorney_user: User) -> AsyncClient:
    """AsyncClient pre-authenticated as an attorney (separate client instance)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        ac.headers.update(_auth_header(attorney_user))
        yield ac


@pytest_asyncio.fixture
async def billing_client(billing_user: User) -> AsyncClient:
    """AsyncClient pre-authenticated as a billing clerk."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        ac.headers.update(_auth_header(billing_user))
        yield ac


# ---------------------------------------------------------------------------
# Auth headers (dict) fixtures — useful when you already have a `client`
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def admin_headers(admin_user: User) -> dict[str, str]:
    return _auth_header(admin_user)


@pytest_asyncio.fixture
async def attorney_headers(attorney_user: User) -> dict[str, str]:
    return _auth_header(attorney_user)


@pytest_asyncio.fixture
async def billing_headers(billing_user: User) -> dict[str, str]:
    return _auth_header(billing_user)


# ---------------------------------------------------------------------------
# Factory Boy factories
# ---------------------------------------------------------------------------
class UserFactory(factory.Factory):
    class Meta:
        model = dict

    email = factory.LazyFunction(lambda: f"user-{uuid.uuid4().hex[:8]}@lexnebulis-test.com")
    password = "SecurePass123!"
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    role = "attorney"


class ClientFactory(factory.Factory):
    class Meta:
        model = dict

    client_type = "individual"
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    email = factory.LazyFunction(lambda: f"client-{uuid.uuid4().hex[:8]}@example.com")
    phone = factory.Faker("phone_number")
    status = "active"


class OrganizationClientFactory(factory.Factory):
    class Meta:
        model = dict

    client_type = "organization"
    organization_name = factory.Faker("company")
    email = factory.LazyFunction(lambda: f"org-{uuid.uuid4().hex[:8]}@example.com")
    phone = factory.Faker("phone_number")
    status = "active"


# ---------------------------------------------------------------------------
# Convenience fixture: a client record already in the DB
# ---------------------------------------------------------------------------
@pytest_asyncio.fixture
async def sample_client(admin_client: AsyncClient) -> dict:
    """Create and return a sample individual client via the API."""
    data = ClientFactory()
    resp = await admin_client.post("/api/clients", json=data)
    assert resp.status_code == 201
    return resp.json()


@pytest_asyncio.fixture
async def sample_matter(admin_client: AsyncClient, sample_client: dict, attorney_user: User) -> dict:
    """Create and return a sample matter linked to the sample client."""
    data = {
        "title": "Test Matter v. Defendant",
        "client_id": sample_client["id"],
        "status": "open",
        "litigation_type": "civil",
        "description": "A test matter for unit tests",
        "assigned_attorney_id": str(attorney_user.id),
    }
    resp = await admin_client.post("/api/matters", json=data)
    assert resp.status_code == 201
    return resp.json()
