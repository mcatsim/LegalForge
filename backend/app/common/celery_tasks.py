import hashlib
import hmac
import json
import logging
import time
from typing import Optional

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.celery_app import celery
from app.common.audit import AuditEventJSON, audit_to_cef, audit_to_syslog

logger = logging.getLogger(__name__)


def _get_sync_session() -> Session:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.config import settings

    url = settings.database_url
    if url.startswith("postgresql+asyncpg"):
        url = url.replace("postgresql+asyncpg", "postgresql+psycopg2", 1)
    elif url.startswith("sqlite+aiosqlite"):
        url = url.replace("sqlite+aiosqlite", "sqlite", 1)

    engine = create_engine(url)
    session_factory = sessionmaker(bind=engine)
    return session_factory()


def _load_siem_config(session: Session):
    from app.admin.models import SiemConfig

    result = session.execute(select(SiemConfig).limit(1))
    return result.scalar_one_or_none()


def _audit_log_to_event_json(log) -> AuditEventJSON:
    return AuditEventJSON(
        timestamp=log.timestamp.isoformat(),
        event_id=str(log.id),
        event_type=f"{log.entity_type}.{log.action}",
        action=log.action,
        entity_type=log.entity_type,
        entity_id=log.entity_id,
        user_id=str(log.user_id) if log.user_id else None,
        user_email=log.user_email,
        ip_address=log.ip_address,
        user_agent=log.user_agent,
        changes=json.loads(log.changes_json) if log.changes_json else None,
        integrity_hash=log.integrity_hash,
        previous_hash=log.previous_hash,
        severity=log.severity,
        outcome=log.outcome,
    )


@celery.task(name="push_siem_event", bind=True, max_retries=3)
def push_siem_event(self, audit_log_id: str):
    import uuid

    from app.auth.models import AuditLog

    session = _get_sync_session()
    try:
        result = session.execute(select(AuditLog).where(AuditLog.id == uuid.UUID(audit_log_id)))
        log_entry = result.scalar_one_or_none()
        if log_entry is None:
            logger.warning("Audit log entry %s not found", audit_log_id)
            return

        config = _load_siem_config(session)
        if config is None:
            logger.debug("No SIEM config found, skipping push")
            return

        event = _audit_log_to_event_json(log_entry)

        # Format the message based on config
        fmt = config.realtime_format.value if hasattr(config.realtime_format, "value") else config.realtime_format
        if fmt == "cef":
            cef_event = audit_to_cef(event)
            formatted_message = cef_event.to_cef_string()
        elif fmt == "syslog":
            syslog_event = audit_to_syslog(event)
            formatted_message = syslog_event.to_syslog_string()
        else:
            formatted_message = json.dumps(event.model_dump())

        # Send via webhook if configured
        if config.webhook_url:
            from app.common.encryption import decrypt_field

            secret = ""
            if config.webhook_secret_encrypted:
                secret = decrypt_field(config.webhook_secret_encrypted)

            payload = event.model_dump()
            push_siem_webhook.delay(config.webhook_url, payload, secret)

        # Send via syslog if configured
        if config.syslog_host:
            protocol = (
                config.syslog_protocol.value if hasattr(config.syslog_protocol, "value") else config.syslog_protocol
            )
            push_siem_syslog.delay(
                config.syslog_host,
                config.syslog_port or 514,
                protocol,
                formatted_message,
                config.syslog_tls_ca_cert,
            )
    except Exception as exc:
        logger.error("Error pushing SIEM event: %s", exc)
        raise self.retry(exc=exc, countdown=2**self.request.retries)
    finally:
        session.close()


@celery.task(
    name="push_siem_webhook",
    bind=True,
    max_retries=3,
    default_retry_delay=5,
)
def push_siem_webhook(self, url: str, payload: dict, secret: str):
    try:
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        timestamp = str(int(time.time()))
        signature = ""
        if secret:
            sign_payload = timestamp.encode("utf-8") + b"." + payload_bytes
            signature = hmac.new(secret.encode("utf-8"), sign_payload, hashlib.sha256).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-LexNebulis-Timestamp": timestamp,
        }
        if signature:
            headers["X-LexNebulis-Signature"] = f"sha256={signature}"

        with httpx.Client(timeout=10) as client:
            resp = client.post(url, content=payload_bytes, headers=headers)
            resp.raise_for_status()

        logger.info("SIEM webhook sent to %s (status %d)", url, resp.status_code)
    except Exception as exc:
        logger.error("SIEM webhook error: %s", exc)
        raise self.retry(exc=exc, countdown=2**self.request.retries)


@celery.task(
    name="push_siem_syslog",
    bind=True,
    max_retries=3,
    default_retry_delay=5,
)
def push_siem_syslog(
    self,
    host: str,
    port: int,
    protocol: str,
    message: str,
    tls_ca_cert: Optional[str] = None,
):
    import asyncio

    try:
        from app.common.syslog_sender import send_syslog_message

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(send_syslog_message(host, port, protocol, message, tls_ca_cert))
        finally:
            loop.close()

        logger.info("SIEM syslog sent to %s:%d via %s", host, port, protocol)
    except Exception as exc:
        logger.error("SIEM syslog error: %s", exc)
        raise self.retry(exc=exc, countdown=2**self.request.retries)
