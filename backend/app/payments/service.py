import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.billing.models import Invoice, InvoiceStatus, Payment, PaymentMethod
from app.config import settings
from app.payments.models import (
    PaymentLink,
    PaymentLinkStatus,
    PaymentProcessor,
    PaymentSettings,
    WebhookEvent,
)
from app.payments.schemas import (
    CompletePaymentRequest,
    CreatePaymentLinkRequest,
    PaymentLinkResponse,
    PaymentSettingsCreate,
    PaymentSettingsResponse,
    PaymentSummaryReport,
    ProcessorBreakdown,
    PublicPaymentInfo,
    SendPaymentLinkRequest,
    SendPaymentLinkResponse,
)

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


# ── Payment Settings CRUD ────────────────────────────────────────────


async def get_payment_settings(db: AsyncSession) -> Optional[PaymentSettings]:
    """Get the current payment settings (there should be at most one row)."""
    result = await db.execute(select(PaymentSettings).order_by(PaymentSettings.created_at.desc()).limit(1))
    return result.scalar_one_or_none()


async def create_or_update_payment_settings(
    db: AsyncSession,
    data: PaymentSettingsCreate,
    user_id: uuid.UUID,
) -> PaymentSettings:
    """Create or update payment settings."""
    existing = await get_payment_settings(db)

    if existing:
        # Update existing settings
        if data.processor is not None:
            existing.processor = data.processor
        existing.is_active = data.is_active
        if data.publishable_key is not None:
            existing.publishable_key = data.publishable_key
        if data.account_type is not None:
            existing.account_type = data.account_type
        existing.surcharge_enabled = data.surcharge_enabled
        existing.surcharge_rate = data.surcharge_rate

        # Encrypt sensitive fields if provided
        if data.api_key:
            existing.api_key_encrypted = encrypt_value(data.api_key)
        if data.webhook_secret:
            existing.webhook_secret_encrypted = encrypt_value(data.webhook_secret)

        await db.flush()
        await db.refresh(existing)
        return existing

    # Create new settings
    ps = PaymentSettings(
        processor=data.processor,
        is_active=data.is_active,
        publishable_key=data.publishable_key,
        account_type=data.account_type,
        surcharge_enabled=data.surcharge_enabled,
        surcharge_rate=data.surcharge_rate,
        created_by=user_id,
    )
    if data.api_key:
        ps.api_key_encrypted = encrypt_value(data.api_key)
    if data.webhook_secret:
        ps.webhook_secret_encrypted = encrypt_value(data.webhook_secret)

    db.add(ps)
    await db.flush()
    await db.refresh(ps)
    return ps


def build_settings_response(ps: PaymentSettings) -> PaymentSettingsResponse:
    """Build a settings response with masked secrets and webhook URL."""
    webhook_url = f"/api/payments/webhooks/{ps.processor.value}"
    return PaymentSettingsResponse(
        id=ps.id,
        processor=ps.processor,
        is_active=ps.is_active,
        api_key_masked=mask_secret(ps.api_key_encrypted),
        webhook_secret_masked=mask_secret(ps.webhook_secret_encrypted),
        publishable_key=ps.publishable_key,
        account_type=ps.account_type,
        surcharge_enabled=ps.surcharge_enabled,
        surcharge_rate=ps.surcharge_rate,
        webhook_url=webhook_url,
        created_by=ps.created_by,
        created_at=ps.created_at,
        updated_at=ps.updated_at,
    )


# ── Payment Links ───────────────────────────────────────────────────


async def create_payment_link(
    db: AsyncSession,
    data: CreatePaymentLinkRequest,
    user_id: uuid.UUID,
) -> PaymentLink:
    """Create a payment link for an invoice."""
    # Get the invoice
    result = await db.execute(select(Invoice).where(Invoice.id == data.invoice_id))
    invoice = result.scalar_one_or_none()
    if invoice is None:
        raise ValueError("Invoice not found")

    if invoice.status == InvoiceStatus.paid:
        raise ValueError("Invoice is already paid")

    if invoice.status == InvoiceStatus.void:
        raise ValueError("Cannot create payment link for a voided invoice")

    # Get active payment settings
    ps = await get_payment_settings(db)
    processor = PaymentProcessor.manual
    if ps and ps.is_active:
        processor = ps.processor

    # Calculate surcharge
    surcharge_cents = 0
    if ps and ps.surcharge_enabled and ps.surcharge_rate > 0:
        surcharge_cents = int(invoice.total_cents * ps.surcharge_rate)

    # Generate access token
    access_token = uuid.uuid4().hex

    # Set expiration
    expires_at = None
    if data.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=data.expires_in_days)

    link = PaymentLink(
        invoice_id=invoice.id,
        client_id=invoice.client_id,
        matter_id=invoice.matter_id,
        created_by=user_id,
        amount_cents=invoice.total_cents,
        description=data.description,
        access_token=access_token,
        processor=processor,
        expires_at=expires_at,
        surcharge_cents=surcharge_cents,
    )
    db.add(link)
    await db.flush()
    await db.refresh(link)
    return link


def build_payment_link_response(link: PaymentLink) -> PaymentLinkResponse:
    """Build a payment link response with the payment URL and enriched data."""
    payment_url = f"/pay/{link.access_token}"

    invoice_number = None
    client_name = None
    if link.invoice:
        invoice_number = link.invoice.invoice_number
    if link.client:
        client = link.client
        if hasattr(client, "organization_name") and client.organization_name:
            client_name = client.organization_name
        elif hasattr(client, "first_name"):
            client_name = f"{client.first_name or ''} {client.last_name or ''}".strip()

    return PaymentLinkResponse(
        id=link.id,
        invoice_id=link.invoice_id,
        client_id=link.client_id,
        matter_id=link.matter_id,
        created_by=link.created_by,
        amount_cents=link.amount_cents,
        description=link.description,
        status=link.status,
        access_token=link.access_token,
        processor=link.processor,
        processor_session_id=link.processor_session_id,
        expires_at=link.expires_at,
        paid_at=link.paid_at,
        paid_amount_cents=link.paid_amount_cents,
        surcharge_cents=link.surcharge_cents,
        processor_fee_cents=link.processor_fee_cents,
        payer_email=link.payer_email,
        payer_name=link.payer_name,
        processor_reference=link.processor_reference,
        payment_url=payment_url,
        invoice_number=invoice_number,
        client_name=client_name,
        created_at=link.created_at,
        updated_at=link.updated_at,
    )


async def get_payment_link(db: AsyncSession, link_id: uuid.UUID) -> Optional[PaymentLink]:
    """Get a payment link by ID."""
    result = await db.execute(select(PaymentLink).where(PaymentLink.id == link_id))
    return result.scalar_one_or_none()


async def get_payment_link_by_token(db: AsyncSession, access_token: str) -> Optional[PaymentLink]:
    """Get a payment link by its public access token."""
    result = await db.execute(select(PaymentLink).where(PaymentLink.access_token == access_token))
    return result.scalar_one_or_none()


async def list_payment_links(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 25,
    status: Optional[PaymentLinkStatus] = None,
    client_id: Optional[uuid.UUID] = None,
    invoice_id: Optional[uuid.UUID] = None,
) -> tuple[list[PaymentLink], int]:
    """List payment links with optional filters."""
    query = select(PaymentLink)
    count_query = select(func.count(PaymentLink.id))

    if status:
        query = query.where(PaymentLink.status == status)
        count_query = count_query.where(PaymentLink.status == status)
    if client_id:
        query = query.where(PaymentLink.client_id == client_id)
        count_query = count_query.where(PaymentLink.client_id == client_id)
    if invoice_id:
        query = query.where(PaymentLink.invoice_id == invoice_id)
        count_query = count_query.where(PaymentLink.invoice_id == invoice_id)

    total = (await db.execute(count_query)).scalar_one()
    offset = (page - 1) * page_size
    result = await db.execute(query.order_by(PaymentLink.created_at.desc()).offset(offset).limit(page_size))
    return list(result.scalars().all()), total


async def cancel_payment_link(db: AsyncSession, link: PaymentLink) -> PaymentLink:
    """Cancel a payment link."""
    if link.status != PaymentLinkStatus.active:
        raise ValueError(f"Cannot cancel a payment link with status '{link.status.value}'")
    link.status = PaymentLinkStatus.cancelled
    await db.flush()
    await db.refresh(link)
    return link


# ── Public Payment Info ──────────────────────────────────────────────


async def get_public_payment_info(db: AsyncSession, access_token: str) -> Optional[PublicPaymentInfo]:
    """Get public payment info for the payment page (no auth required)."""
    link = await get_payment_link_by_token(db, access_token)
    if link is None:
        return None

    # Check if expired
    if link.expires_at:
        now = datetime.now(timezone.utc)
        expires = link.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now and link.status == PaymentLinkStatus.active:
            link.status = PaymentLinkStatus.expired
            await db.flush()

    invoice_number = None
    client_name = None
    if link.invoice:
        invoice_number = link.invoice.invoice_number
    if link.client:
        client = link.client
        if hasattr(client, "organization_name") and client.organization_name:
            client_name = client.organization_name
        elif hasattr(client, "first_name"):
            client_name = f"{client.first_name or ''} {client.last_name or ''}".strip()

    total_cents = link.amount_cents + link.surcharge_cents

    return PublicPaymentInfo(
        invoice_number=invoice_number,
        amount_cents=link.amount_cents,
        surcharge_cents=link.surcharge_cents,
        total_cents=total_cents,
        description=link.description,
        client_name=client_name,
        firm_name=settings.app_name,
        processor=link.processor,
        status=link.status,
        expires_at=link.expires_at,
    )


# ── Mark Payment Link as Paid ────────────────────────────────────────


async def mark_payment_link_paid(
    db: AsyncSession,
    access_token: str,
    data: CompletePaymentRequest,
) -> PaymentLink:
    """Mark a payment link as paid and create a Payment record in billing."""
    link = await get_payment_link_by_token(db, access_token)
    if link is None:
        raise ValueError("Payment link not found")

    if link.status != PaymentLinkStatus.active:
        raise ValueError(f"Payment link is not active (status: {link.status.value})")

    # Check expiration
    if link.expires_at:
        now = datetime.now(timezone.utc)
        expires = link.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            link.status = PaymentLinkStatus.expired
            await db.flush()
            raise ValueError("Payment link has expired")

    # Update the payment link
    paid_amount = data.paid_amount_cents if data.paid_amount_cents else link.amount_cents + link.surcharge_cents
    link.status = PaymentLinkStatus.paid
    link.paid_at = datetime.now(timezone.utc)
    link.paid_amount_cents = paid_amount
    link.payer_email = data.payer_email
    link.payer_name = data.payer_name
    link.processor_reference = data.processor_reference

    # Map processor to payment method
    method_map = {
        PaymentProcessor.stripe: PaymentMethod.credit_card,
        PaymentProcessor.lawpay: PaymentMethod.credit_card,
        PaymentProcessor.manual: PaymentMethod.other,
    }
    method = method_map.get(link.processor, PaymentMethod.other)

    # Create a Payment record in billing
    payment = Payment(
        invoice_id=link.invoice_id,
        amount_cents=link.amount_cents,
        payment_date=date.today(),
        method=method,
        reference_number=data.processor_reference or f"PL-{link.access_token[:8]}",
        notes=f"Online payment via {link.processor.value}",
    )
    db.add(payment)

    # Update invoice status if fully paid
    invoice_result = await db.execute(select(Invoice).where(Invoice.id == link.invoice_id))
    invoice = invoice_result.scalar_one_or_none()
    if invoice:
        total_paid_result = await db.execute(
            select(func.coalesce(func.sum(Payment.amount_cents), 0)).where(Payment.invoice_id == invoice.id)
        )
        total_paid = total_paid_result.scalar_one() + link.amount_cents
        if total_paid >= invoice.total_cents:
            invoice.status = InvoiceStatus.paid

    await db.flush()
    await db.refresh(link)
    return link


# ── Webhook Processing ──────────────────────────────────────────────


async def process_webhook(
    db: AsyncSession,
    processor: PaymentProcessor,
    event_type: str,
    event_id: Optional[str],
    payload: Optional[dict],
) -> WebhookEvent:
    """Process an incoming webhook event. Dedup by event_id."""
    # Check for duplicate event
    if event_id:
        existing = await db.execute(
            select(WebhookEvent).where(WebhookEvent.event_id == event_id, WebhookEvent.processor == processor)
        )
        if existing.scalar_one_or_none():
            raise ValueError(f"Duplicate webhook event: {event_id}")

    event = WebhookEvent(
        processor=processor,
        event_type=event_type,
        event_id=event_id,
        payload=payload,
        processed=False,
    )
    db.add(event)

    # Process payment confirmation events
    payment_events = {
        "payment_intent.succeeded",
        "checkout.session.completed",
        "charge.succeeded",
        "transaction.completed",
    }
    if event_type in payment_events and payload:
        try:
            await _process_payment_webhook(db, processor, payload)
            event.processed = True
        except Exception as e:
            event.error_message = str(e)

    await db.flush()
    await db.refresh(event)
    return event


async def _process_payment_webhook(
    db: AsyncSession,
    processor: PaymentProcessor,
    payload: dict,
) -> None:
    """Process a payment webhook payload — find linked payment and mark as paid."""
    # Try to find the payment link by processor_session_id or metadata
    session_id = payload.get("id") or payload.get("session_id")
    if not session_id:
        return

    result = await db.execute(
        select(PaymentLink).where(
            PaymentLink.processor_session_id == session_id,
            PaymentLink.status == PaymentLinkStatus.active,
        )
    )
    link = result.scalar_one_or_none()
    if link is None:
        return

    complete_data = CompletePaymentRequest(
        processor_reference=session_id,
        payer_email=payload.get("customer_email"),
        payer_name=payload.get("customer_name"),
    )
    await mark_payment_link_paid(db, link.access_token, complete_data)


# ── Payment Summary Report ──────────────────────────────────────────


async def get_payment_summary(db: AsyncSession) -> PaymentSummaryReport:
    """Generate a payment summary report."""
    # Get all paid links
    result = await db.execute(select(PaymentLink).where(PaymentLink.status == PaymentLinkStatus.paid))
    paid_links = list(result.scalars().all())

    total_processed = 0
    total_fees = 0
    by_processor: dict[PaymentProcessor, ProcessorBreakdown] = {}

    for link in paid_links:
        amount = link.paid_amount_cents or link.amount_cents
        fees = link.processor_fee_cents or 0
        total_processed += amount
        total_fees += fees

        if link.processor not in by_processor:
            by_processor[link.processor] = ProcessorBreakdown(
                processor=link.processor,
                count=0,
                total_cents=0,
                fees_cents=0,
            )
        breakdown = by_processor[link.processor]
        breakdown.count += 1
        breakdown.total_cents += amount
        breakdown.fees_cents += fees

    return PaymentSummaryReport(
        total_processed_cents=total_processed,
        total_fees_cents=total_fees,
        count=len(paid_links),
        by_processor=list(by_processor.values()),
    )


# ── Send Payment Link Notification ──────────────────────────────────


async def send_payment_link_notification(
    db: AsyncSession,
    link: PaymentLink,
    data: SendPaymentLinkRequest,
) -> SendPaymentLinkResponse:
    """Record the intent to send a payment link notification.

    Actual email sending is deferred to a future Celery task.
    """
    # For now, just return success — the actual email will be sent via Celery
    recipient = data.recipient_email
    if not recipient and link.client:
        client = link.client
        if hasattr(client, "email"):
            recipient = client.email

    return SendPaymentLinkResponse(
        status="queued",
        message=f"Payment link notification queued for {recipient or 'client'}",
    )
