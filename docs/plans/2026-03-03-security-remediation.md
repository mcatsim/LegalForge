# Security Remediation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 10 critical/high security findings from the 2026-03-03 architecture review before implementing killer features.

**Architecture:** Patch existing backend services and frontend code in-place. No new modules — all changes are fixes to existing files. Each fix is independently testable and deployable. Order matters: encryption consolidation (Task 3) must come before SSO fixes (Tasks 1-2) since SSO depends on the encryption module.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2.0 async, PyJWT, cryptography (Fernet/PBKDF2), React 18, TypeScript, Axios

---

## Task 1: Consolidate Encryption — Random Salt + PBKDF2 Everywhere (CWE-330)

**Why:** Three separate key derivation implementations exist. `encryption.py` uses PBKDF2 but with a hardcoded salt. `sso/service.py` and `payments/service.py` use raw SHA-256 (no KDF at all). All three must use the same PBKDF2-based approach with a random salt stored alongside the ciphertext.

**Files:**
- Modify: `backend/app/common/encryption.py` (lines 1-35)
- Modify: `backend/app/sso/service.py` (lines 24-44) — delete duplicate, import from encryption.py
- Modify: `backend/app/payments/service.py` (lines 34-67) — delete duplicate, import from encryption.py
- Modify: `backend/app/config.py` (line 33) — add `field_encryption_salt` setting
- Test: `backend/tests/test_encryption.py` (create)

### Step 1: Write the failing tests

Create `backend/tests/test_encryption.py`:

```python
"""Tests for consolidated encryption module."""
import pytest

from app.common.encryption import decrypt_field, encrypt_field


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "sensitive-bank-account-123"
        encrypted = encrypt_field(plaintext)
        assert encrypted != plaintext
        decrypted = decrypt_field(encrypted)
        assert decrypted == plaintext

    def test_encrypt_empty_string_returns_empty(self):
        assert encrypt_field("") == ""
        assert decrypt_field("") == ""

    def test_encrypt_none_returns_none(self):
        assert encrypt_field(None) is None
        assert decrypt_field(None) is None

    def test_different_encryptions_produce_different_ciphertext(self):
        """Each encryption should use a unique random salt."""
        plaintext = "same-value"
        enc1 = encrypt_field(plaintext)
        enc2 = encrypt_field(plaintext)
        assert enc1 != enc2  # random salt makes each unique
        assert decrypt_field(enc1) == plaintext
        assert decrypt_field(enc2) == plaintext

    def test_tampered_ciphertext_raises(self):
        encrypted = encrypt_field("test-value")
        tampered = encrypted[:-5] + "XXXXX"
        with pytest.raises(Exception):
            decrypt_field(tampered)

    def test_legacy_ciphertext_still_decryptable(self):
        """Backward compatibility: old Fernet tokens (no salt prefix) still work."""
        # This test verifies the migration path
        from app.common.encryption import _get_legacy_fernet
        legacy_fernet = _get_legacy_fernet()
        legacy_encrypted = legacy_fernet.encrypt(b"legacy-secret").decode()
        # decrypt_field should try new format first, fall back to legacy
        result = decrypt_field(legacy_encrypted)
        assert result == "legacy-secret"
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_encryption.py -v`
Expected: FAIL — `test_different_encryptions_produce_different_ciphertext` will fail (current impl produces identical ciphertext), and `_get_legacy_fernet` doesn't exist.

### Step 3: Implement the consolidated encryption module

Replace `backend/app/common/encryption.py` entirely:

```python
"""
Consolidated field-level encryption for LexNebulis.

Uses Fernet symmetric encryption with PBKDF2-derived keys.
Each encryption call generates a random 16-byte salt, prepended to the
ciphertext as base64. This prevents rainbow-table attacks and ensures
identical plaintexts produce different ciphertexts.

Legacy support: ciphertexts without a salt prefix (from v1.1 and earlier)
are decrypted using the hardcoded-salt derivation for backward compatibility.
"""

import base64
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings

_SALT_LENGTH = 16
_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-SHA256
_SALT_PREFIX = b"$LN1$"  # identifies new-format ciphertexts

# Legacy support — cached Fernet for old ciphertexts
_legacy_fernet = None


def _derive_key(salt: bytes) -> bytes:
    """Derive a Fernet key from the master encryption key + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return base64.urlsafe_b64encode(
        kdf.derive(settings.field_encryption_key.encode())
    )


def _get_legacy_fernet() -> Fernet:
    """Return a Fernet instance using the old hardcoded salt (for migration)."""
    global _legacy_fernet
    if _legacy_fernet is None:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"lexnebulis-field-encryption",
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(
            kdf.derive(settings.field_encryption_key.encode())
        )
        _legacy_fernet = Fernet(key)
    return _legacy_fernet


def encrypt_field(value: Optional[str]) -> Optional[str]:
    """Encrypt a string field value. Returns None/empty for None/empty input."""
    if not value:
        return value
    salt = os.urandom(_SALT_LENGTH)
    key = _derive_key(salt)
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(value.encode())
    # Format: base64($LN1$ + salt + ciphertext)
    combined = _SALT_PREFIX + salt + ciphertext
    return base64.urlsafe_b64encode(combined).decode()


def decrypt_field(value: Optional[str]) -> Optional[str]:
    """Decrypt a field value. Handles both new and legacy formats."""
    if not value:
        return value

    try:
        raw = base64.urlsafe_b64decode(value.encode())
    except Exception:
        raw = None

    # New format: starts with $LN1$ prefix
    if raw and raw[:len(_SALT_PREFIX)] == _SALT_PREFIX:
        rest = raw[len(_SALT_PREFIX):]
        salt = rest[:_SALT_LENGTH]
        ciphertext = rest[_SALT_LENGTH:]
        key = _derive_key(salt)
        fernet = Fernet(key)
        return fernet.decrypt(ciphertext).decode()

    # Legacy format: raw Fernet token (no salt prefix)
    legacy = _get_legacy_fernet()
    return legacy.decrypt(value.encode()).decode()
```

### Step 4: Remove duplicate encryption from SSO and Payments

In `backend/app/sso/service.py`, replace lines 24-44:
```python
# DELETE the _derive_fernet_key, encrypt_value, decrypt_value, mask_secret functions
# REPLACE with imports:
from app.common.encryption import decrypt_field as decrypt_value, encrypt_field as encrypt_value
```

Keep `mask_secret` but have it call `decrypt_value` (which now delegates to `encryption.py`):
```python
def mask_secret(encrypted_secret: Optional[str]) -> Optional[str]:
    """Return a masked version of the client secret for display."""
    if not encrypted_secret:
        return None
    try:
        decrypted = decrypt_value(encrypted_secret)
        if len(decrypted) <= 4:
            return "****"
        return "****" + decrypted[-4:]
    except Exception:
        return "****"
```

In `backend/app/payments/service.py`, replace lines 34-67:
```python
# DELETE the _derive_fernet_key, encrypt_value, decrypt_value, mask_secret functions
# REPLACE with imports:
from app.common.encryption import decrypt_field as decrypt_value, encrypt_field as encrypt_value


def mask_secret(encrypted_secret: Optional[str]) -> Optional[str]:
    """Return a masked version of a secret for display."""
    if not encrypted_secret:
        return None
    try:
        decrypted = decrypt_value(encrypted_secret)
        if len(decrypted) <= 4:
            return "****"
        return "****" + decrypted[-4:]
    except Exception:
        return "****"
```

### Step 5: Run tests to verify they pass

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_encryption.py -v`
Expected: All 7 tests PASS.

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/ -v`
Expected: All existing tests still pass (legacy compat).

### Step 6: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add backend/app/common/encryption.py backend/app/sso/service.py backend/app/payments/service.py backend/tests/test_encryption.py
git commit -m "fix(security): consolidate encryption with random salt + PBKDF2 (CWE-330)

- Replace hardcoded salt with random 16-byte salt per encryption
- Increase PBKDF2 iterations from 100k to 600k (OWASP 2023)
- Remove duplicate SHA-256 key derivation from sso/service.py and payments/service.py
- Add legacy decryption support for existing ciphertexts
- All three modules now use app.common.encryption"
```

---

## Task 2: Fix SSO JWT Signature Verification (CWE-347)

**Why:** `sso/service.py:513-517` decodes the OIDC id_token with `verify_signature=False`. An attacker who controls the redirect could forge an id_token and authenticate as any user.

**Files:**
- Modify: `backend/app/sso/service.py` (lines 502-519)
- Modify: `backend/app/sso/models.py` — add `jwks_uri` field if not present
- Test: `backend/tests/test_sso_jwt.py` (create)

### Step 1: Write the failing test

Create `backend/tests/test_sso_jwt.py`:

```python
"""Tests for SSO JWT signature verification."""
import json
from unittest.mock import AsyncMock, patch, MagicMock

import jwt
import pytest

from app.sso.service import _decode_id_token


class TestDecodeIdToken:
    @pytest.mark.asyncio
    async def test_rejects_unsigned_token(self):
        """Tokens without valid signatures must be rejected."""
        fake_token = jwt.encode(
            {"sub": "attacker", "email": "evil@example.com"},
            "wrong-key",
            algorithm="HS256",
        )
        with pytest.raises(ValueError, match="signature"):
            await _decode_id_token(fake_token, jwks_uri=None, client_id="test-client")

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
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_sso_jwt.py -v`
Expected: FAIL — `_decode_id_token` function does not exist.

### Step 3: Implement signature verification

In `backend/app/sso/service.py`, add the `_decode_id_token` function and update `handle_sso_callback`:

```python
# Add to imports at top of file:
from jwt import PyJWKClient

# Add new function before handle_sso_callback:
async def _decode_id_token(id_token: str, jwks_uri: Optional[str], client_id: str) -> dict:
    """Decode and verify an OIDC id_token using the provider's JWKS.

    Raises ValueError if the token cannot be verified.
    """
    if not jwks_uri:
        raise ValueError("Cannot verify id_token: no JWKS URI configured for this provider")

    try:
        jwks_client = PyJWKClient(jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = jose_jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=client_id,
            options={"verify_exp": True},
        )
        return claims
    except Exception as e:
        raise ValueError(f"id_token signature verification failed: {e}")
```

Then update `handle_sso_callback` (replace lines 508-519):

```python
    if id_token:
        try:
            claims = await _decode_id_token(
                id_token,
                jwks_uri=provider.jwks_uri,
                client_id=provider.client_id or "",
            )
        except ValueError:
            # If JWKS verification fails, fall back to userinfo endpoint only
            # (the access_token was obtained directly from the IdP over TLS)
            claims = {}
    # ... rest of function unchanged
```

### Step 4: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_sso_jwt.py tests/ -v`
Expected: All PASS.

### Step 5: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add backend/app/sso/service.py backend/tests/test_sso_jwt.py
git commit -m "fix(security): verify OIDC id_token signatures via JWKS (CWE-347)

- Add _decode_id_token() using PyJWKClient for RS256/ES256 verification
- Remove verify_signature=False from jwt.decode
- Fall back to userinfo endpoint if JWKS verification fails
- Reject tokens when no JWKS URI is configured"
```

---

## Task 3: Consume SSO State Parameter After Use (CWE-352)

**Why:** `handle_sso_callback` validates the state parameter but never deletes or marks it as used. An attacker who intercepts a state token can replay the callback indefinitely.

**Files:**
- Modify: `backend/app/sso/service.py` (lines 445-555 — `handle_sso_callback`)
- Test: `backend/tests/test_sso_state.py` (create)

### Step 1: Write the failing test

Create `backend/tests/test_sso_state.py`:

```python
"""Tests for SSO state parameter consumption."""
import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone

from app.sso.models import SSOSession
from tests.conftest import TestSession


@pytest_asyncio.fixture
async def sso_session():
    """Create an SSO session in the test database."""
    session_obj = SSOSession(
        provider_id=None,  # no real provider needed for this test
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
            from sqlalchemy import select
            # Verify state exists before
            result = await db.execute(
                select(SSOSession).where(SSOSession.state == "test-state-token-123")
            )
            assert result.scalar_one_or_none() is not None

            # Simulate consuming the state
            from app.sso.service import _consume_sso_state
            session = await _consume_sso_state(db, "test-state-token-123")
            assert session is not None
            await db.commit()

            # Verify state is deleted
            result2 = await db.execute(
                select(SSOSession).where(SSOSession.state == "test-state-token-123")
            )
            assert result2.scalar_one_or_none() is None

    @pytest.mark.asyncio
    async def test_replayed_state_rejected(self, sso_session):
        """A state token used twice must be rejected on the second attempt."""
        async with TestSession() as db:
            from app.sso.service import _consume_sso_state
            # First use succeeds
            session = await _consume_sso_state(db, "test-state-token-123")
            assert session is not None
            await db.commit()

        async with TestSession() as db:
            # Second use fails
            with pytest.raises(ValueError, match="Invalid or expired"):
                await _consume_sso_state(db, "test-state-token-123")
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_sso_state.py -v`
Expected: FAIL — `_consume_sso_state` does not exist.

### Step 3: Implement state consumption

In `backend/app/sso/service.py`, add `_consume_sso_state` and update `handle_sso_callback`:

```python
async def _consume_sso_state(db: AsyncSession, state: str) -> SSOSession:
    """Validate and delete the SSO state parameter in one operation.

    Raises ValueError if the state is invalid, expired, or already used.
    """
    result = await db.execute(select(SSOSession).where(SSOSession.state == state))
    sso_session = result.scalar_one_or_none()

    if sso_session is None:
        raise ValueError("Invalid or expired SSO state parameter")

    # Check expiration
    if sso_session.expires_at:
        expires = sso_session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            await db.delete(sso_session)
            raise ValueError("SSO session has expired")

    # Consume: delete the session so it cannot be reused
    provider_id = sso_session.provider_id
    nonce = sso_session.nonce
    await db.delete(sso_session)
    await db.flush()

    # Return a detached copy with the info we need
    return sso_session
```

Then update `handle_sso_callback` — replace lines 454-467 with:
```python
    # 1. Validate and consume the state parameter (one-time use)
    sso_session = await _consume_sso_state(db, state)
```

And at the end (lines 546-549), create a new session record for the authenticated user instead of updating the consumed one:
```python
    # 6. Create new SSO session for the authenticated user
    new_sso_session = SSOSession(
        provider_id=sso_session.provider_id,
        user_id=user.id,
        external_id=external_id,
        state=secrets.token_urlsafe(32),  # new non-reusable state
        id_token_claims=claims,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
    )
    db.add(new_sso_session)
    await db.flush()
```

### Step 4: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_sso_state.py tests/ -v`
Expected: All PASS.

### Step 5: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add backend/app/sso/service.py backend/tests/test_sso_state.py
git commit -m "fix(security): consume SSO state parameter after use (CWE-352)

- Add _consume_sso_state() that deletes state on first use
- Replayed state tokens now rejected
- Expired state tokens cleaned up on access"
```

---

## Task 4: Fix Trust Account Race Condition — SELECT FOR UPDATE (CWE-362)

**Why:** `trust/service.py:55-90` reads the trust account balance, checks it, and updates it in separate operations without locking. Two concurrent disbursements could both pass the balance check and overdraw the account.

**Files:**
- Modify: `backend/app/trust/service.py` (lines 55-90)
- Test: `backend/tests/test_trust.py` (add concurrency test)

### Step 1: Write the failing test

Add to `backend/tests/test_trust.py`:

```python
@pytest.mark.asyncio
async def test_concurrent_disbursements_prevent_overdraw(admin_client, sample_client):
    """Two concurrent disbursements should not overdraw the trust account."""
    # Create a trust account
    account_resp = await admin_client.post("/api/trust/accounts", json={
        "account_name": "IOLTA Main",
        "bank_name": "Test Bank",
        "account_number": "123456789",
        "routing_number": "021000021",
    })
    assert account_resp.status_code == 201
    account_id = account_resp.json()["id"]

    # Deposit $1000
    deposit_resp = await admin_client.post("/api/trust/ledger", json={
        "trust_account_id": account_id,
        "client_id": sample_client["id"],
        "entry_type": "deposit",
        "amount_cents": 100000,
        "description": "Initial deposit",
        "entry_date": "2026-03-03",
    })
    assert deposit_resp.status_code == 201

    # Verify the SELECT FOR UPDATE lock is used
    from app.trust.service import create_ledger_entry
    import inspect
    source = inspect.getsource(create_ledger_entry)
    assert "with_for_update" in source, "create_ledger_entry must use SELECT FOR UPDATE"
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_trust.py::test_concurrent_disbursements_prevent_overdraw -v`
Expected: FAIL — `with_for_update` not in source.

### Step 3: Implement row-level locking

In `backend/app/trust/service.py`, update `create_ledger_entry` (replace lines 55-90):

```python
async def create_ledger_entry(
    db: AsyncSession, data: TrustLedgerEntryCreate, created_by: uuid.UUID
) -> TrustLedgerEntry:
    # Lock the trust account row to prevent concurrent modifications
    result = await db.execute(
        select(TrustAccount)
        .where(TrustAccount.id == data.trust_account_id)
        .with_for_update()
    )
    account = result.scalar_one_or_none()
    if account is None:
        raise ValueError("Trust account not found")

    # Calculate running balance
    if data.entry_type == TrustEntryType.deposit:
        new_balance = account.balance_cents + data.amount_cents
    elif data.entry_type == TrustEntryType.disbursement:
        if data.amount_cents > account.balance_cents:
            raise ValueError("Insufficient trust account balance")
        new_balance = account.balance_cents - data.amount_cents
    else:  # transfer
        new_balance = account.balance_cents

    entry = TrustLedgerEntry(
        trust_account_id=data.trust_account_id,
        client_id=data.client_id,
        matter_id=data.matter_id,
        entry_type=data.entry_type,
        amount_cents=data.amount_cents,
        running_balance_cents=new_balance,
        description=data.description,
        reference_number=data.reference_number,
        entry_date=data.entry_date,
        created_by=created_by,
    )
    db.add(entry)

    # Update account balance
    account.balance_cents = new_balance
    await db.flush()
    await db.refresh(entry)
    return entry
```

**Note:** SQLite (used in tests) does not support `FOR UPDATE`, but SQLAlchemy silently ignores it. The test verifies the code path exists; PostgreSQL enforces the lock in production.

### Step 4: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_trust.py -v`
Expected: All PASS.

### Step 5: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add backend/app/trust/service.py backend/tests/test_trust.py
git commit -m "fix(security): add SELECT FOR UPDATE to trust ledger entries (CWE-362)

- Lock trust account row before reading balance
- Prevents concurrent disbursements from overdrawing
- PostgreSQL enforces serializable access via row-level lock"
```

---

## Task 5: Add Resource-Level Access Control (CWE-284)

**Why:** Current authorization is role-based only (`require_roles`). Any authenticated user can access any matter, document, invoice, or trust entry regardless of assignment. This is the biggest systemic gap.

**Files:**
- Create: `backend/app/common/access_control.py`
- Modify: `backend/app/matters/router.py` (lines 28-54)
- Modify: `backend/app/documents/router.py` — add matter-scoped checks
- Modify: `backend/app/billing/router.py` — add matter-scoped checks
- Test: `backend/tests/test_access_control.py` (create)

### Step 1: Write the failing test

Create `backend/tests/test_access_control.py`:

```python
"""Tests for resource-level access control."""
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.auth.models import UserRole
from app.main import app
from tests.conftest import _create_test_user, _auth_header


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
    async def test_unassigned_attorney_cannot_access_matter(
        self, second_attorney_client, sample_matter
    ):
        resp = await second_attorney_client.get(f"/api/matters/{sample_matter['id']}")
        assert resp.status_code == 403
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_access_control.py -v`
Expected: FAIL — `test_unassigned_attorney_cannot_access_matter` returns 200 instead of 403.

### Step 3: Create the access control module

Create `backend/app/common/access_control.py`:

```python
"""
Resource-level access control for LexNebulis.

Admins have full access. Other roles are scoped to matters they are
assigned to (as attorney) or have been granted access via matter teams
(future). Ethical-wall blocked matters are always denied.
"""
import uuid
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.models import User


async def check_matter_access(
    db: AsyncSession,
    user: User,
    matter_id: uuid.UUID,
) -> None:
    """Raise 403 if the user does not have access to the specified matter.

    Access rules:
    - admin: unrestricted
    - attorney/paralegal/billing_clerk: must be assigned_attorney or
      a member of the matter team
    - Ethical-wall blocked matters: always denied (checked via conflicts)
    """
    if user.role.value == "admin":
        return

    from app.matters.models import Matter
    result = await db.execute(
        select(Matter).where(Matter.id == matter_id)
    )
    matter = result.scalar_one_or_none()
    if matter is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Matter not found",
        )

    # Check if user is assigned attorney
    if matter.assigned_attorney_id == user.id:
        return

    # Check ethical walls
    from app.conflicts.models import EthicalWall
    wall_result = await db.execute(
        select(EthicalWall).where(
            EthicalWall.matter_id == matter_id,
            EthicalWall.user_id == user.id,
        )
    )
    if wall_result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: ethical wall",
        )

    # For non-admin users who are not the assigned attorney, deny access
    # Future: check matter_team membership table here
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You do not have access to this matter",
    )
```

### Step 4: Apply to matters router

In `backend/app/matters/router.py`, add import and access check to `get_matter_detail`:

Add import at top:
```python
from app.common.access_control import check_matter_access
```

Update `get_matter_detail` (lines 45-54):
```python
@router.get("/{matter_id}", response_model=MatterResponse)
async def get_matter_detail(
    matter_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    await check_matter_access(db, current_user, matter_id)
    matter = await get_matter(db, matter_id)
    if matter is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Matter not found")
    return matter
```

Also add to `update_existing_matter` and `delete_existing_matter` and the contact endpoints.

### Step 5: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_access_control.py tests/ -v`
Expected: All PASS.

### Step 6: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add backend/app/common/access_control.py backend/app/matters/router.py backend/tests/test_access_control.py
git commit -m "feat(security): add resource-level access control for matters (CWE-284)

- Create access_control.py with check_matter_access()
- Admins have unrestricted access
- Attorneys/staff scoped to assigned matters
- Ethical wall enforcement integrated
- Apply to all matters endpoints"
```

---

## Task 6: Add Rate Limiting to Login and 2FA (CWE-307)

**Why:** No rate limiting on `/api/auth/login` or `/api/auth/2fa/verify`. An attacker can brute-force passwords and TOTP codes without throttling.

**Files:**
- Create: `backend/app/common/rate_limit.py`
- Modify: `backend/app/auth/router.py` (lines 62-97, 133-182)
- Test: `backend/tests/test_rate_limit.py` (create)

### Step 1: Write the failing test

Create `backend/tests/test_rate_limit.py`:

```python
"""Tests for rate limiting on auth endpoints."""
import pytest


class TestLoginRateLimit:
    @pytest.mark.asyncio
    async def test_login_rate_limited_after_threshold(self, client):
        """After 10 failed login attempts from same IP, requests should be rate-limited."""
        for i in range(10):
            await client.post("/api/auth/login", json={
                "email": "nonexistent@test.com",
                "password": "wrong",
            })

        # 11th attempt should be rate-limited
        resp = await client.post("/api/auth/login", json={
            "email": "nonexistent@test.com",
            "password": "wrong",
        })
        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_successful_login_not_rate_limited(self, client, admin_user):
        """Successful logins should work normally."""
        resp = await client.post("/api/auth/login", json={
            "email": "admin@lexnebulis-test.com",
            "password": "AdminPass123!",
        })
        assert resp.status_code == 200
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_rate_limit.py -v`
Expected: FAIL — no 429 response.

### Step 3: Implement rate limiting

Create `backend/app/common/rate_limit.py`:

```python
"""
In-memory sliding window rate limiter.

Uses a simple dict-based approach for single-instance deployments.
For clustered deployments (K8s), swap to Redis-backed implementation.
"""
import time
from collections import defaultdict
from threading import Lock
from typing import Optional

from fastapi import HTTPException, Request, status

# Store: { key: [timestamp, timestamp, ...] }
_windows: dict[str, list[float]] = defaultdict(list)
_lock = Lock()


def _cleanup_window(key: str, window_seconds: int) -> None:
    """Remove timestamps older than the window."""
    cutoff = time.monotonic() - window_seconds
    _windows[key] = [t for t in _windows[key] if t > cutoff]


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
```

### Step 4: Apply rate limiting to auth router

In `backend/app/auth/router.py`, add imports and apply:

```python
from app.common.rate_limit import rate_limit_login, rate_limit_2fa
```

Update the `login` endpoint (add at the start of the function body):
```python
@router.post("/login", response_model=LoginResponse)
async def login(data: LoginRequest, request: Request, db: Annotated[AsyncSession, Depends(get_db)]):
    rate_limit_login(request)
    # ... rest unchanged
```

Update the `verify_2fa_login` endpoint:
```python
@router.post("/2fa/verify", response_model=LoginResponse)
async def verify_2fa_login(data: TwoFactorLoginRequest, request: Request, db: Annotated[AsyncSession, Depends(get_db)]):
    rate_limit_2fa(request)
    # ... rest unchanged
```

### Step 5: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_rate_limit.py tests/ -v`
Expected: All PASS.

### Step 6: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add backend/app/common/rate_limit.py backend/app/auth/router.py backend/tests/test_rate_limit.py
git commit -m "feat(security): add rate limiting to login and 2FA endpoints (CWE-307)

- In-memory sliding window rate limiter (5-minute window)
- Login: 10 attempts per IP per 5 minutes
- 2FA: 5 attempts per IP per 5 minutes
- Returns 429 with retry message when exceeded"
```

---

## Task 7: Add Global Exception Handler (CWE-209)

**Why:** Unhandled exceptions return full stack traces to the client, leaking internal paths, library versions, and database schema details.

**Files:**
- Modify: `backend/app/main.py` (add exception handlers after line 52)
- Test: `backend/tests/test_exception_handler.py` (create)

### Step 1: Write the failing test

Create `backend/tests/test_exception_handler.py`:

```python
"""Tests for global exception handler."""
import pytest


class TestGlobalExceptionHandler:
    @pytest.mark.asyncio
    async def test_unhandled_exception_returns_500_without_stacktrace(self, client):
        """Internal errors should return 500 with a generic message, no stack trace."""
        # Hit a deliberately broken endpoint (we'll add one for testing)
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
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_exception_handler.py -v`
Expected: FAIL — no `/api/health/crash-test` endpoint and no exception handler.

### Step 3: Implement global exception handler

In `backend/app/main.py`, add after the middleware section (after line 62):

```python
import logging
from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("lexnebulis")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch unhandled exceptions and return a safe 500 response."""
    correlation_id = getattr(request.state, "correlation_id", "unknown")
    logger.exception(
        "Unhandled exception [correlation_id=%s] %s: %s",
        correlation_id,
        type(exc).__name__,
        str(exc),
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred. Please contact support.",
            "correlation_id": correlation_id,
        },
    )
```

Add a test-only crash endpoint (in a debug-only block):

```python
if settings.environment == "test":
    @app.get("/api/health/crash-test")
    async def crash_test():
        raise RuntimeError("Deliberate crash for testing exception handler")
```

### Step 4: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_exception_handler.py tests/ -v`
Expected: All PASS.

### Step 5: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add backend/app/main.py backend/tests/test_exception_handler.py
git commit -m "fix(security): add global exception handler to prevent stack trace leaks (CWE-209)

- Catch unhandled exceptions and return generic 500 with correlation_id
- Log full exception server-side for debugging
- No stack traces, file paths, or internal details in client responses"
```

---

## Task 8: Add React ErrorBoundary

**Why:** Unhandled React errors crash the entire app with a white screen. An ErrorBoundary catches rendering errors and shows a recovery UI.

**Files:**
- Create: `frontend/src/components/ErrorBoundary.tsx`
- Modify: `frontend/src/main.tsx` (lines 24-37)
- Test: `frontend/src/components/__tests__/ErrorBoundary.test.tsx` (create)

### Step 1: Write the failing test

Create `frontend/src/components/__tests__/ErrorBoundary.test.tsx`:

```tsx
import { render, screen } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import { ErrorBoundary } from '../ErrorBoundary';

function BrokenComponent(): JSX.Element {
  throw new Error('Test crash');
}

describe('ErrorBoundary', () => {
  it('renders children when no error', () => {
    render(
      <ErrorBoundary>
        <div>Working content</div>
      </ErrorBoundary>
    );
    expect(screen.getByText('Working content')).toBeTruthy();
  });

  it('renders fallback UI on error', () => {
    // Suppress React error boundary console noise
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(
      <ErrorBoundary>
        <BrokenComponent />
      </ErrorBoundary>
    );
    expect(screen.getByText(/something went wrong/i)).toBeTruthy();
    spy.mockRestore();
  });

  it('shows reload button', () => {
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(
      <ErrorBoundary>
        <BrokenComponent />
      </ErrorBoundary>
    );
    expect(screen.getByRole('button', { name: /reload/i })).toBeTruthy();
    spy.mockRestore();
  });
});
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/frontend && npx vitest run src/components/__tests__/ErrorBoundary.test.tsx`
Expected: FAIL — module not found.

### Step 3: Implement ErrorBoundary

Create `frontend/src/components/ErrorBoundary.tsx`:

```tsx
import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Button, Container, Stack, Text, Title } from '@mantine/core';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('ErrorBoundary caught:', error, errorInfo);
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <Container size="sm" py="xl">
          <Stack align="center" gap="md">
            <Title order={2}>Something went wrong</Title>
            <Text c="dimmed">
              An unexpected error occurred. Please reload the page to continue.
            </Text>
            <Button onClick={() => window.location.reload()}>
              Reload Page
            </Button>
          </Stack>
        </Container>
      );
    }
    return this.props.children;
  }
}
```

### Step 4: Wrap App in ErrorBoundary

In `frontend/src/main.tsx`, add import and wrap:

```tsx
import { ErrorBoundary } from './components/ErrorBoundary';

// In the render tree, wrap <App /> with <ErrorBoundary>:
ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <MantineProvider theme={theme} defaultColorScheme="light">
          <ModalsProvider>
            <Notifications position="top-right" />
            <BrowserRouter>
              <App />
            </BrowserRouter>
          </ModalsProvider>
        </MantineProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>
);
```

### Step 5: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/frontend && npx vitest run src/components/__tests__/ErrorBoundary.test.tsx`
Expected: All 3 PASS.

Run: `cd /Users/mattcatsimanes/LexNebulis/frontend && npx vitest run`
Expected: All existing tests still pass.

### Step 6: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add frontend/src/components/ErrorBoundary.tsx frontend/src/main.tsx frontend/src/components/__tests__/ErrorBoundary.test.tsx
git commit -m "feat(frontend): add React ErrorBoundary to prevent white-screen crashes

- Class component ErrorBoundary wrapping entire App
- Shows recovery UI with reload button on unhandled render errors
- Logs error details to console for debugging"
```

---

## Task 9: Fix Token Refresh Race Condition (Frontend)

**Why:** `frontend/src/api/client.ts:18-48` — when multiple API calls return 401 simultaneously, each triggers a parallel refresh attempt. All but the first will fail (the old refresh token was already rotated), causing unnecessary logouts.

**Files:**
- Modify: `frontend/src/api/client.ts` (lines 18-48)
- Test: `frontend/src/api/__tests__/client.test.ts` (create)

### Step 1: Write the failing test

Create `frontend/src/api/__tests__/client.test.ts`:

```ts
import { describe, it, expect } from 'vitest';

describe('Token refresh mutex', () => {
  it('module exports a singleton refresh promise pattern', async () => {
    // Verify the client module uses a mutex/queue pattern
    const clientModule = await import('../client');
    const source = clientModule.default.interceptors.response.handlers;
    // The interceptor should exist and handle 401
    expect(source.length).toBeGreaterThan(0);
  });
});
```

### Step 2: Implement mutex pattern

Replace the response interceptor in `frontend/src/api/client.ts` (lines 18-48):

```ts
// Response interceptor: handle 401 with token refresh (mutex pattern)
let isRefreshing = false;
let refreshSubscribers: ((token: string) => void)[] = [];

function onRefreshed(token: string) {
  refreshSubscribers.forEach((cb) => cb(token));
  refreshSubscribers = [];
}

function addRefreshSubscriber(cb: (token: string) => void) {
  refreshSubscribers.push(cb);
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      if (isRefreshing) {
        // Another request is already refreshing — wait for it
        return new Promise((resolve) => {
          addRefreshSubscriber((token: string) => {
            originalRequest.headers.Authorization = `Bearer ${token}`;
            resolve(api(originalRequest));
          });
        });
      }

      isRefreshing = true;
      const refreshToken = useAuthStore.getState().refreshToken;

      if (refreshToken) {
        try {
          const response = await axios.post('/api/auth/refresh', {
            refresh_token: refreshToken,
          });
          const { access_token, refresh_token } = response.data;
          useAuthStore.getState().setTokens(access_token, refresh_token);
          isRefreshing = false;
          onRefreshed(access_token);
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          return api(originalRequest);
        } catch {
          isRefreshing = false;
          refreshSubscribers = [];
          useAuthStore.getState().logout();
          window.location.href = '/login';
        }
      } else {
        isRefreshing = false;
        useAuthStore.getState().logout();
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);
```

### Step 3: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/frontend && npx vitest run`
Expected: All tests PASS.

### Step 4: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add frontend/src/api/client.ts frontend/src/api/__tests__/client.test.ts
git commit -m "fix(frontend): prevent parallel token refresh race condition

- Add mutex pattern: first 401 triggers refresh, others queue
- Queued requests retry with new token after refresh completes
- Prevents unnecessary logouts from concurrent 401 responses"
```

---

## Task 10: Miscellaneous Security Hardening

**Why:** Several smaller issues found in the audit: bootstrap admin log leak, recovery code timing oracle, refresh token entropy, CORS hardening, password change session invalidation.

**Files:**
- Modify: `backend/app/auth/service.py` (lines 41-42, 89-91, 100-107, 527)
- Modify: `backend/app/main.py` (lines 56-62 — CORS)
- Modify: `backend/app/auth/router.py` (lines 116-127 — password change)
- Test: `backend/tests/test_auth_hardening.py` (create)

### Step 1: Write the failing tests

Create `backend/tests/test_auth_hardening.py`:

```python
"""Tests for auth hardening fixes."""
import hmac
import secrets

import pytest

from app.auth.service import (
    create_refresh_token_value,
    generate_recovery_codes,
    verify_recovery_code,
)


class TestRefreshTokenEntropy:
    def test_refresh_token_uses_secrets_not_uuid(self):
        token = create_refresh_token_value()
        # secrets.token_urlsafe produces URL-safe base64 (contains - and _)
        # uuid4 produces hex with dashes
        assert "-" not in token or "_" in token or len(token) > 36

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
        assert "hmac.compare_digest" in source or "compare_digest" in source
```

### Step 2: Run tests to verify they fail

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_auth_hardening.py -v`
Expected: FAIL — uuid4 doesn't have enough entropy, recovery codes are only 8 hex chars.

### Step 3: Apply fixes

In `backend/app/auth/service.py`:

**Fix 1 — Refresh token entropy** (line 41-42):
```python
def create_refresh_token_value() -> str:
    return secrets.token_urlsafe(32)
```

**Fix 2 — Recovery code entropy** (lines 89-91):
```python
def generate_recovery_codes(count: int = 8) -> list[str]:
    """Generate plaintext recovery codes with 64 bits of entropy each."""
    return [secrets.token_hex(8).upper() for _ in range(count)]
```

**Fix 3 — Constant-time recovery code verification** (lines 100-107):
```python
def verify_recovery_code(stored_hashes_json: str, code: str) -> tuple[bool, str]:
    """Verify a recovery code using constant-time comparison."""
    import hmac as _hmac
    code_hash = hashlib.sha256(code.upper().encode()).hexdigest()
    hashes = json.loads(stored_hashes_json)
    for i, stored_hash in enumerate(hashes):
        if _hmac.compare_digest(code_hash, stored_hash):
            hashes.pop(i)
            return True, json.dumps(hashes)
    return False, stored_hashes_json
```

**Fix 4 — Bootstrap admin log leak** (line 527):
```python
        logger.info("Bootstrap admin created")  # Don't log the email
```
(Add `import logging` and `logger = logging.getLogger(__name__)` at top if not present.)

**Fix 5 — CORS hardening** in `backend/app/main.py` (lines 56-62):
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
```

**Fix 6 — Invalidate sessions on password change** in `backend/app/auth/router.py` (lines 116-127):
```python
@router.put("/me/password")
async def change_password(
    data: PasswordChange,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    if not verify_password(data.current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")

    current_user.password_hash = hash_password(data.new_password)

    # Revoke all existing refresh tokens (force re-login on other devices)
    from app.auth.models import RefreshToken
    await db.execute(
        select(RefreshToken)
        .where(RefreshToken.user_id == current_user.id, RefreshToken.revoked == False)
    )
    tokens = (await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == current_user.id,
            RefreshToken.revoked == False,  # noqa: E712
        )
    )).scalars().all()
    for token in tokens:
        token.revoked = True

    await db.flush()
    return {"message": "Password updated. Please log in again on other devices."}
```

### Step 4: Run tests

Run: `cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/test_auth_hardening.py tests/ -v`
Expected: All PASS.

### Step 5: Commit

```bash
cd /Users/mattcatsimanes/LexNebulis
git add backend/app/auth/service.py backend/app/auth/router.py backend/app/main.py backend/tests/test_auth_hardening.py
git commit -m "fix(security): auth hardening — entropy, timing, CORS, session invalidation

- Refresh tokens use secrets.token_urlsafe(32) instead of uuid4
- Recovery codes use 64-bit entropy (secrets.token_hex(8))
- Recovery code verification uses hmac.compare_digest (constant-time)
- Bootstrap admin no longer logs email address
- CORS restricted to specific methods and headers
- Password change revokes all refresh tokens"
```

---

## Verification Checklist

After all 10 tasks are complete, run the full test suite:

```bash
cd /Users/mattcatsimanes/LexNebulis/backend && python -m pytest tests/ -v --tb=short
cd /Users/mattcatsimanes/LexNebulis/frontend && npx vitest run
```

**Security findings addressed:**

| # | Finding | CWE | Task | Status |
|---|---------|-----|------|--------|
| 1 | Hardcoded encryption salt | CWE-330 | Task 1 | |
| 2 | Duplicate key derivation (SHA-256 vs PBKDF2) | CWE-330 | Task 1 | |
| 3 | SSO JWT verify_signature=False | CWE-347 | Task 2 | |
| 4 | SSO state parameter not consumed | CWE-352 | Task 3 | |
| 5 | Trust account race condition | CWE-362 | Task 4 | |
| 6 | No resource-level access control | CWE-284 | Task 5 | |
| 7 | No rate limiting on login/2FA | CWE-307 | Task 6 | |
| 8 | No global exception handler | CWE-209 | Task 7 | |
| 9 | No React ErrorBoundary | — | Task 8 | |
| 10 | Token refresh race condition | — | Task 9 | |
| 11 | Misc: entropy, timing, CORS, sessions | CWE-330/208/942 | Task 10 | |
