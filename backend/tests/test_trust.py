"""
Tests for the trust/IOLTA accounting endpoints.

Covers trust account creation, deposit and disbursement ledger entries,
overdraft protection, running balance calculation, and reconciliation.
"""

from __future__ import annotations

from datetime import date

from httpx import AsyncClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_trust_account(client: AsyncClient) -> dict:
    data = {
        "account_name": "Main IOLTA Account",
        "bank_name": "First National Bank",
        "account_number": "1234567890",
        "routing_number": "021000021",
    }
    resp = await client.post("/api/trust/accounts", json=data)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _create_deposit(
    client: AsyncClient,
    account_id: str,
    client_id: str,
    amount_cents: int,
    matter_id: str | None = None,
) -> dict:
    data = {
        "trust_account_id": account_id,
        "client_id": client_id,
        "entry_type": "deposit",
        "amount_cents": amount_cents,
        "description": f"Deposit of {amount_cents} cents",
        "entry_date": str(date.today()),
    }
    if matter_id:
        data["matter_id"] = matter_id
    resp = await client.post("/api/trust/ledger", json=data)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Trust accounts
# ---------------------------------------------------------------------------


class TestTrustAccounts:
    """POST/GET /api/trust/accounts"""

    async def test_create_trust_account(self, admin_client: AsyncClient):
        body = await _create_trust_account(admin_client)
        assert body["account_name"] == "Main IOLTA Account"
        assert body["bank_name"] == "First National Bank"
        assert body["balance_cents"] == 0
        assert body["is_active"] is True

    async def test_list_trust_accounts(self, admin_client: AsyncClient):
        await _create_trust_account(admin_client)
        resp = await admin_client.get("/api/trust/accounts")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    async def test_billing_clerk_can_create_trust_account(
        self,
        billing_client: AsyncClient,
    ):
        body = await _create_trust_account(billing_client)
        assert body["account_name"] == "Main IOLTA Account"

    async def test_attorney_cannot_create_trust_account(
        self,
        attorney_client: AsyncClient,
    ):
        data = {
            "account_name": "Unauthorized",
            "bank_name": "SomeBank",
            "account_number": "111",
            "routing_number": "222",
        }
        resp = await attorney_client.post("/api/trust/accounts", json=data)
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Ledger entries — deposits
# ---------------------------------------------------------------------------


class TestDeposits:
    """POST /api/trust/ledger (entry_type=deposit)"""

    async def test_create_deposit(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
    ):
        account = await _create_trust_account(admin_client)
        entry = await _create_deposit(admin_client, account["id"], sample_client["id"], 500000)
        assert entry["entry_type"] == "deposit"
        assert entry["amount_cents"] == 500000
        assert entry["running_balance_cents"] == 500000

    async def test_multiple_deposits_accumulate(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
    ):
        account = await _create_trust_account(admin_client)
        e1 = await _create_deposit(admin_client, account["id"], sample_client["id"], 100000)
        assert e1["running_balance_cents"] == 100000

        e2 = await _create_deposit(admin_client, account["id"], sample_client["id"], 200000)
        assert e2["running_balance_cents"] == 300000


# ---------------------------------------------------------------------------
# Ledger entries — disbursements
# ---------------------------------------------------------------------------


class TestDisbursements:
    """POST /api/trust/ledger (entry_type=disbursement)"""

    async def test_create_disbursement(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
    ):
        account = await _create_trust_account(admin_client)
        await _create_deposit(admin_client, account["id"], sample_client["id"], 500000)

        data = {
            "trust_account_id": account["id"],
            "client_id": sample_client["id"],
            "entry_type": "disbursement",
            "amount_cents": 200000,
            "description": "Court filing fee",
            "entry_date": str(date.today()),
        }
        resp = await admin_client.post("/api/trust/ledger", json=data)
        assert resp.status_code == 201
        body = resp.json()
        assert body["entry_type"] == "disbursement"
        assert body["running_balance_cents"] == 300000  # 500000 - 200000

    async def test_overdraft_protection(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
    ):
        """Disbursement exceeding balance returns 400."""
        account = await _create_trust_account(admin_client)
        await _create_deposit(admin_client, account["id"], sample_client["id"], 50000)

        data = {
            "trust_account_id": account["id"],
            "client_id": sample_client["id"],
            "entry_type": "disbursement",
            "amount_cents": 100000,  # more than the 50000 balance
            "description": "Should fail",
            "entry_date": str(date.today()),
        }
        resp = await admin_client.post("/api/trust/ledger", json=data)
        assert resp.status_code == 400
        assert "Insufficient" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Running balance
# ---------------------------------------------------------------------------


class TestRunningBalance:
    """Verify that ledger entries track running balance correctly."""

    async def test_running_balance_across_operations(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
    ):
        account = await _create_trust_account(admin_client)

        # Deposit 1000.00
        e1 = await _create_deposit(admin_client, account["id"], sample_client["id"], 100000)
        assert e1["running_balance_cents"] == 100000

        # Deposit 500.00
        e2 = await _create_deposit(admin_client, account["id"], sample_client["id"], 50000)
        assert e2["running_balance_cents"] == 150000

        # Disburse 250.00
        resp = await admin_client.post(
            "/api/trust/ledger",
            json={
                "trust_account_id": account["id"],
                "client_id": sample_client["id"],
                "entry_type": "disbursement",
                "amount_cents": 25000,
                "description": "Partial disbursement",
                "entry_date": str(date.today()),
            },
        )
        assert resp.status_code == 201
        assert resp.json()["running_balance_cents"] == 125000

    async def test_ledger_entries_listed(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
    ):
        account = await _create_trust_account(admin_client)
        await _create_deposit(admin_client, account["id"], sample_client["id"], 100000)
        await _create_deposit(admin_client, account["id"], sample_client["id"], 200000)

        resp = await admin_client.get(f"/api/trust/accounts/{account['id']}/ledger")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


class TestReconciliation:
    """POST /api/trust/reconciliations"""

    async def test_create_reconciliation_balanced(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
    ):
        account = await _create_trust_account(admin_client)
        await _create_deposit(admin_client, account["id"], sample_client["id"], 100000)

        data = {
            "trust_account_id": account["id"],
            "reconciliation_date": str(date.today()),
            "statement_balance_cents": 100000,  # matches ledger
        }
        resp = await admin_client.post("/api/trust/reconciliations", json=data)
        assert resp.status_code == 201
        body = resp.json()
        assert body["is_balanced"] is True
        assert body["statement_balance_cents"] == 100000
        assert body["ledger_balance_cents"] == 100000

    async def test_create_reconciliation_unbalanced(
        self,
        admin_client: AsyncClient,
        sample_client: dict,
    ):
        account = await _create_trust_account(admin_client)
        await _create_deposit(admin_client, account["id"], sample_client["id"], 100000)

        data = {
            "trust_account_id": account["id"],
            "reconciliation_date": str(date.today()),
            "statement_balance_cents": 99000,  # does NOT match
            "notes": "Off by $10",
        }
        resp = await admin_client.post("/api/trust/reconciliations", json=data)
        assert resp.status_code == 201
        body = resp.json()
        assert body["is_balanced"] is False


# ---------------------------------------------------------------------------
# Race condition prevention
# ---------------------------------------------------------------------------


class TestRaceConditionPrevention:
    """Verify SELECT FOR UPDATE is used to prevent concurrent overdraw."""

    async def test_create_ledger_entry_uses_select_for_update(self):
        """create_ledger_entry must use SELECT FOR UPDATE to lock the row."""
        import inspect

        from app.trust.service import create_ledger_entry

        source = inspect.getsource(create_ledger_entry)
        assert "with_for_update" in source, (
            "create_ledger_entry must use SELECT FOR UPDATE to prevent "
            "concurrent disbursements from overdrawing the trust account"
        )
