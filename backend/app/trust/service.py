import uuid
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.encryption import encrypt_field
from app.trust.models import TrustAccount, TrustEntryType, TrustLedgerEntry, TrustReconciliation
from app.trust.schemas import TrustAccountCreate, TrustLedgerEntryCreate, TrustReconciliationCreate


async def get_trust_accounts(db: AsyncSession) -> list[TrustAccount]:
    result = await db.execute(select(TrustAccount).order_by(TrustAccount.account_name))
    return result.scalars().all()


async def get_trust_account(db: AsyncSession, account_id: uuid.UUID) -> Optional[TrustAccount]:
    result = await db.execute(select(TrustAccount).where(TrustAccount.id == account_id))
    return result.scalar_one_or_none()


async def create_trust_account(db: AsyncSession, data: TrustAccountCreate) -> TrustAccount:
    account = TrustAccount(
        account_name=data.account_name,
        bank_name=data.bank_name,
        account_number_encrypted=encrypt_field(data.account_number),
        routing_number_encrypted=encrypt_field(data.routing_number),
    )
    db.add(account)
    await db.flush()
    await db.refresh(account)
    return account


async def get_ledger_entries(
    db: AsyncSession,
    trust_account_id: uuid.UUID,
    page: int = 1,
    page_size: int = 50,
    client_id: Optional[uuid.UUID] = None,
) -> tuple[list[TrustLedgerEntry], int]:
    query = select(TrustLedgerEntry).where(TrustLedgerEntry.trust_account_id == trust_account_id)
    count_query = select(func.count(TrustLedgerEntry.id)).where(TrustLedgerEntry.trust_account_id == trust_account_id)

    if client_id:
        query = query.where(TrustLedgerEntry.client_id == client_id)
        count_query = count_query.where(TrustLedgerEntry.client_id == client_id)

    total = (await db.execute(count_query)).scalar_one()
    offset = (page - 1) * page_size
    result = await db.execute(query.order_by(TrustLedgerEntry.created_at.desc()).offset(offset).limit(page_size))
    return result.scalars().all(), total


async def create_ledger_entry(
    db: AsyncSession, data: TrustLedgerEntryCreate, created_by: uuid.UUID
) -> TrustLedgerEntry:
    # Lock the row to prevent concurrent balance reads (SELECT FOR UPDATE)
    result = await db.execute(select(TrustAccount).where(TrustAccount.id == data.trust_account_id).with_for_update())
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


async def create_reconciliation(
    db: AsyncSession, data: TrustReconciliationCreate, performed_by: uuid.UUID
) -> TrustReconciliation:
    account = await get_trust_account(db, data.trust_account_id)
    if account is None:
        raise ValueError("Trust account not found")

    recon = TrustReconciliation(
        trust_account_id=data.trust_account_id,
        reconciliation_date=data.reconciliation_date,
        statement_balance_cents=data.statement_balance_cents,
        ledger_balance_cents=account.balance_cents,
        is_balanced=data.statement_balance_cents == account.balance_cents,
        notes=data.notes,
        performed_by=performed_by,
    )
    db.add(recon)
    await db.flush()
    await db.refresh(recon)
    return recon
