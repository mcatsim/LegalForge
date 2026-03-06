import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.models import SiemConfig, SiemFormat, SyslogProtocol
from app.admin.schemas import SiemConfigResponse, SiemConfigUpdate, SoarActionResponse
from app.auth.models import AuditLog, RefreshToken, SystemSetting, User
from app.auth.service import create_audit_log
from app.common.audit import AuditEventJSON, audit_to_cef, audit_to_syslog
from app.common.encryption import decrypt_field, encrypt_field
from app.common.pagination import PaginatedResponse
from app.database import get_db
from app.dependencies import require_roles
from app.scim import service as scim_service
from app.scim.schemas import ScimBearerTokenCreate, ScimBearerTokenCreateResponse, ScimBearerTokenResponse

router = APIRouter()


# --- Audit Log Viewer ---


@router.get("/audit-logs", response_model=PaginatedResponse)
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
    page: int = 1,
    page_size: int = 50,
    entity_type: Optional[str] = None,
    action: Optional[str] = None,
    user_id: Optional[uuid.UUID] = None,
    severity: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
):
    query = select(AuditLog)
    count_query = select(func.count(AuditLog.id))

    if entity_type:
        query = query.where(AuditLog.entity_type == entity_type)
        count_query = count_query.where(AuditLog.entity_type == entity_type)
    if action:
        query = query.where(AuditLog.action == action)
        count_query = count_query.where(AuditLog.action == action)
    if user_id:
        query = query.where(AuditLog.user_id == user_id)
        count_query = count_query.where(AuditLog.user_id == user_id)
    if severity:
        query = query.where(AuditLog.severity == severity)
        count_query = count_query.where(AuditLog.severity == severity)
    if start_date:
        query = query.where(AuditLog.timestamp >= start_date)
        count_query = count_query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)
        count_query = count_query.where(AuditLog.timestamp <= end_date)

    total = (await db.execute(count_query)).scalar_one()
    offset = (page - 1) * page_size
    result = await db.execute(query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(page_size))
    logs = result.scalars().all()

    items = [
        {
            "id": str(log.id),
            "user_id": str(log.user_id) if log.user_id else None,
            "user_email": log.user_email,
            "entity_type": log.entity_type,
            "entity_id": log.entity_id,
            "action": log.action,
            "changes_json": log.changes_json,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "outcome": log.outcome,
            "severity": log.severity,
            "integrity_hash": log.integrity_hash,
            "previous_hash": log.previous_hash,
            "timestamp": log.timestamp.isoformat(),
        }
        for log in logs
    ]
    return PaginatedResponse.create(items=items, total=total, page=page, page_size=page_size)


# --- Audit Log Integrity Verification ---


@router.get("/audit-logs/verify-chain")
async def verify_audit_chain(
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
    limit: int = Query(default=1000, ge=1, le=10000),
):
    """Verify the integrity hash chain of audit log entries.

    Checks that no entries have been tampered with by recomputing
    and comparing integrity hashes sequentially.
    """
    from app.common.audit import compute_integrity_hash

    result = await db.execute(select(AuditLog).order_by(AuditLog.timestamp.asc()).limit(limit))
    logs = result.scalars().all()

    if not logs:
        return {"status": "empty", "verified": 0, "errors": []}

    errors = []
    for i, log in enumerate(logs):
        expected_previous = logs[i - 1].integrity_hash if i > 0 else None

        if log.previous_hash != expected_previous:
            errors.append(
                {
                    "entry_id": str(log.id),
                    "position": i,
                    "error": "previous_hash mismatch",
                    "expected": expected_previous,
                    "actual": log.previous_hash,
                }
            )

        # Ensure timezone-aware timestamp for consistent hash (SQLite strips tzinfo)
        ts = log.timestamp
        if ts.tzinfo is None:
            from datetime import timezone

            ts = ts.replace(tzinfo=timezone.utc)
        recomputed = compute_integrity_hash(
            str(log.id),
            ts.isoformat(),
            str(log.user_id) if log.user_id else None,
            log.action,
            log.entity_type,
            log.entity_id,
            log.changes_json,
            log.previous_hash,
        )
        if recomputed != log.integrity_hash:
            errors.append(
                {
                    "entry_id": str(log.id),
                    "position": i,
                    "error": "integrity_hash mismatch (possible tampering)",
                    "expected": recomputed,
                    "actual": log.integrity_hash,
                }
            )

    return {
        "status": "valid" if not errors else "invalid",
        "verified": len(logs),
        "errors": errors,
    }


# --- SIEM/SOAR Export Endpoints ---


@router.get("/audit-logs/export/json")
async def export_audit_json(
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(default=1000, ge=1, le=10000),
):
    """Export audit logs as structured JSON for SIEM ingestion (Splunk, Elastic, etc.)."""
    query = select(AuditLog).order_by(AuditLog.timestamp.asc())
    if start_date:
        query = query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)
    query = query.limit(limit)

    result = await db.execute(query)
    logs = result.scalars().all()

    events = []
    for log in logs:
        event = AuditEventJSON(
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
        events.append(event.model_dump())

    await create_audit_log(
        db,
        admin.id,
        "audit_log",
        "export",
        "export",
        changes_json=json.dumps({"format": "json", "count": len(events)}),
        user_email=admin.email,
    )

    return {"format": "json", "count": len(events), "events": events}


@router.get("/audit-logs/export/cef")
async def export_audit_cef(
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(default=1000, ge=1, le=10000),
):
    """Export audit logs as CEF (Common Event Format) for ArcSight, QRadar, etc."""
    query = select(AuditLog).order_by(AuditLog.timestamp.asc())
    if start_date:
        query = query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)
    query = query.limit(limit)

    result = await db.execute(query)
    logs = result.scalars().all()

    lines = []
    for log in logs:
        event = AuditEventJSON(
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
        cef = audit_to_cef(event)
        lines.append(cef.to_cef_string())

    content = "\n".join(lines)
    await create_audit_log(
        db,
        admin.id,
        "audit_log",
        "export",
        "export",
        changes_json=json.dumps({"format": "cef", "count": len(lines)}),
        user_email=admin.email,
    )

    return StreamingResponse(
        iter([content]),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=lexnebulis-audit-cef.log"},
    )


@router.get("/audit-logs/export/syslog")
async def export_audit_syslog(
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(default=1000, ge=1, le=10000),
):
    """Export audit logs as RFC 5424 syslog for generic SIEM ingestion."""
    query = select(AuditLog).order_by(AuditLog.timestamp.asc())
    if start_date:
        query = query.where(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.where(AuditLog.timestamp <= end_date)
    query = query.limit(limit)

    result = await db.execute(query)
    logs = result.scalars().all()

    lines = []
    for log in logs:
        event = AuditEventJSON(
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
        syslog = audit_to_syslog(event)
        lines.append(syslog.to_syslog_string())

    content = "\n".join(lines)
    await create_audit_log(
        db,
        admin.id,
        "audit_log",
        "export",
        "export",
        changes_json=json.dumps({"format": "syslog", "count": len(lines)}),
        user_email=admin.email,
    )

    return StreamingResponse(
        iter([content]),
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=lexnebulis-audit-syslog.log"},
    )


# --- SOAR Webhook Configuration ---


@router.post("/audit-logs/webhook/test")
async def test_webhook(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    """Test the configured SIEM/SOAR webhook by sending a test event."""
    import httpx

    result = await db.execute(select(SystemSetting).where(SystemSetting.key == "siem_webhook_url"))
    setting = result.scalar_one_or_none()
    if not setting:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No webhook URL configured. Set 'siem_webhook_url' in system settings.",
        )

    test_event = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_id": "test-event",
        "event_type": "system.webhook_test",
        "action": "webhook_test",
        "entity_type": "system",
        "entity_id": "test",
        "user_id": str(admin.id),
        "user_email": admin.email,
        "severity": "info",
        "outcome": "success",
        "source": "lexnebulis",
        "message": "Webhook connectivity test from LexNebulis",
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(setting.value, json=test_event)
        return {"status": "sent", "response_status": resp.status_code}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# --- System Settings ---


@router.get("/settings")
async def list_settings(
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    result = await db.execute(select(SystemSetting).order_by(SystemSetting.key))
    settings = result.scalars().all()
    return [{"key": s.key, "value": s.value, "updated_at": s.updated_at.isoformat()} for s in settings]


@router.put("/settings/{key}")
async def update_setting(
    key: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    body = await request.json()
    value = body.get("value")
    if value is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Value is required")

    result = await db.execute(select(SystemSetting).where(SystemSetting.key == key))
    setting = result.scalar_one_or_none()

    old_value = setting.value if setting else None

    if setting:
        setting.value = str(value)
        setting.updated_by = admin.id
    else:
        setting = SystemSetting(key=key, value=str(value), updated_by=admin.id)
        db.add(setting)

    await create_audit_log(
        db,
        admin.id,
        "system_setting",
        key,
        "settings_change",
        changes_json=json.dumps({"old": old_value, "new": str(value)}),
        ip_address=request.client.host if request.client else None,
        user_email=admin.email,
    )
    await db.flush()
    return {"key": key, "value": str(value)}


# --- SIEM Config Endpoints ---


def _siem_config_to_response(config: SiemConfig) -> dict:
    secret_masked = None
    if config.webhook_secret_encrypted:
        try:
            plain = decrypt_field(config.webhook_secret_encrypted)
            if len(plain) > 4:
                secret_masked = "****" + plain[-4:]
            else:
                secret_masked = "****"
        except Exception:
            secret_masked = "****"

    return {
        "id": str(config.id),
        "webhook_url": config.webhook_url,
        "webhook_secret_masked": secret_masked,
        "syslog_host": config.syslog_host,
        "syslog_port": config.syslog_port,
        "syslog_protocol": (
            config.syslog_protocol.value if hasattr(config.syslog_protocol, "value") else config.syslog_protocol
        ),
        "syslog_tls_ca_cert": config.syslog_tls_ca_cert,
        "realtime_enabled": config.realtime_enabled,
        "realtime_format": (
            config.realtime_format.value if hasattr(config.realtime_format, "value") else config.realtime_format
        ),
        "created_at": config.created_at.isoformat() if config.created_at else None,
        "updated_at": config.updated_at.isoformat() if config.updated_at else None,
    }


@router.get("/siem/config", response_model=SiemConfigResponse)
async def get_siem_config(
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    result = await db.execute(select(SiemConfig).limit(1))
    config = result.scalar_one_or_none()
    if config is None:
        config = SiemConfig()
        db.add(config)
        await db.flush()
        await db.refresh(config)
    return _siem_config_to_response(config)


@router.put("/siem/config", response_model=SiemConfigResponse)
async def update_siem_config(
    data: SiemConfigUpdate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    result = await db.execute(select(SiemConfig).limit(1))
    config = result.scalar_one_or_none()
    if config is None:
        config = SiemConfig()
        db.add(config)
        await db.flush()
        await db.refresh(config)

    changes = {}
    if data.webhook_url is not None:
        changes["webhook_url"] = {"old": config.webhook_url, "new": data.webhook_url}
        config.webhook_url = data.webhook_url
    if data.webhook_secret is not None:
        changes["webhook_secret"] = "updated"
        config.webhook_secret_encrypted = encrypt_field(data.webhook_secret) if data.webhook_secret else None
    if data.syslog_host is not None:
        changes["syslog_host"] = {"old": config.syslog_host, "new": data.syslog_host}
        config.syslog_host = data.syslog_host
    if data.syslog_port is not None:
        changes["syslog_port"] = {"old": config.syslog_port, "new": data.syslog_port}
        config.syslog_port = data.syslog_port
    if data.syslog_protocol is not None:
        old_proto = config.syslog_protocol.value if hasattr(config.syslog_protocol, "value") else config.syslog_protocol
        changes["syslog_protocol"] = {"old": old_proto, "new": data.syslog_protocol}
        config.syslog_protocol = SyslogProtocol(data.syslog_protocol)
    if data.syslog_tls_ca_cert is not None:
        changes["syslog_tls_ca_cert"] = "updated"
        config.syslog_tls_ca_cert = data.syslog_tls_ca_cert
    if data.realtime_enabled is not None:
        changes["realtime_enabled"] = {"old": config.realtime_enabled, "new": data.realtime_enabled}
        config.realtime_enabled = data.realtime_enabled
    if data.realtime_format is not None:
        old_fmt = config.realtime_format.value if hasattr(config.realtime_format, "value") else config.realtime_format
        changes["realtime_format"] = {"old": old_fmt, "new": data.realtime_format}
        config.realtime_format = SiemFormat(data.realtime_format)

    await create_audit_log(
        db,
        admin.id,
        "siem_config",
        str(config.id),
        "settings_change",
        changes_json=json.dumps(changes),
        ip_address=request.client.host if request.client else None,
        user_email=admin.email,
    )
    await db.flush()
    await db.refresh(config)
    return _siem_config_to_response(config)


@router.post("/siem/test-webhook")
async def test_siem_webhook(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    import httpx as httpx_lib

    result = await db.execute(select(SiemConfig).limit(1))
    config = result.scalar_one_or_none()
    if config is None or not config.webhook_url:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No webhook URL configured in SIEM settings.",
        )

    test_event = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_id": "test-event",
        "event_type": "system.siem_webhook_test",
        "action": "siem_webhook_test",
        "entity_type": "system",
        "entity_id": "test",
        "user_id": str(admin.id),
        "user_email": admin.email,
        "severity": "info",
        "outcome": "success",
        "source": "lexnebulis",
        "message": "SIEM webhook connectivity test from LexNebulis",
    }

    payload_bytes = json.dumps(test_event, sort_keys=True).encode("utf-8")
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        "X-LexNebulis-Timestamp": timestamp,
    }

    if config.webhook_secret_encrypted:
        try:
            secret = decrypt_field(config.webhook_secret_encrypted)
            sign_payload = timestamp.encode("utf-8") + b"." + payload_bytes
            signature = hmac.new(secret.encode("utf-8"), sign_payload, hashlib.sha256).hexdigest()
            headers["X-LexNebulis-Signature"] = f"sha256={signature}"
        except Exception:
            pass

    try:
        async with httpx_lib.AsyncClient(timeout=10) as client:
            resp = await client.post(config.webhook_url, content=payload_bytes, headers=headers)
        return {"status": "sent", "response_status": resp.status_code}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@router.post("/siem/test-syslog")
async def test_siem_syslog(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    result = await db.execute(select(SiemConfig).limit(1))
    config = result.scalar_one_or_none()
    if config is None or not config.syslog_host:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No syslog host configured in SIEM settings.",
        )

    from app.common.syslog_sender import send_syslog_message

    test_message = (
        f"<134>1 {datetime.utcnow().isoformat()}Z lexnebulis lexnebulis - "
        f'SIEM-TEST [lexnebulis@0 test="true"] '
        f"Syslog connectivity test from LexNebulis by {admin.email}"
    )

    protocol = config.syslog_protocol.value if hasattr(config.syslog_protocol, "value") else config.syslog_protocol
    try:
        await send_syslog_message(
            config.syslog_host,
            config.syslog_port or 514,
            protocol,
            test_message,
            config.syslog_tls_ca_cert,
        )
        msg = f"Test message sent to {config.syslog_host}:{config.syslog_port} via {protocol}"
        return {"status": "sent", "message": msg}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


# --- SOAR Response Endpoints ---


@router.post("/security/disable-user/{user_id}", response_model=SoarActionResponse)
async def soar_disable_user(
    user_id: uuid.UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    result = await db.execute(select(User).where(User.id == user_id))
    target_user = result.scalar_one_or_none()
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target_user.is_active = False
    await db.flush()

    # Revoke all refresh tokens
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked == False)  # noqa: E712
        .values(revoked=True)
    )

    await create_audit_log(
        db,
        admin.id,
        "user",
        str(user_id),
        "soar_disable_user",
        changes_json=json.dumps({"is_active": False, "tokens_revoked": True}),
        ip_address=request.client.host if request.client else None,
        user_email=admin.email,
    )
    await db.flush()

    return SoarActionResponse(
        success=True,
        message=f"User {target_user.email} has been deactivated and all sessions revoked",
        action="disable_user",
    )


@router.post("/security/revoke-sessions/{user_id}", response_model=SoarActionResponse)
async def soar_revoke_sessions(
    user_id: uuid.UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    result = await db.execute(select(User).where(User.id == user_id))
    target_user = result.scalar_one_or_none()
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    result = await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked == False)  # noqa: E712
        .values(revoked=True)
    )

    await create_audit_log(
        db,
        admin.id,
        "user",
        str(user_id),
        "soar_revoke_sessions",
        changes_json=json.dumps({"tokens_revoked": True}),
        ip_address=request.client.host if request.client else None,
        user_email=admin.email,
    )
    await db.flush()

    return SoarActionResponse(
        success=True,
        message=f"All sessions revoked for user {target_user.email}",
        action="revoke_sessions",
    )


@router.post("/security/lock-matter/{matter_id}", response_model=SoarActionResponse)
async def soar_lock_matter(
    matter_id: uuid.UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    from app.conflicts.models import EthicalWall

    wall = EthicalWall(
        matter_id=matter_id,
        user_id=admin.id,
        reason="SOAR automated response: matter locked due to security incident",
        created_by=admin.id,
        is_active=True,
    )
    db.add(wall)
    await db.flush()

    await create_audit_log(
        db,
        admin.id,
        "matter",
        str(matter_id),
        "soar_lock_matter",
        changes_json=json.dumps({"ethical_wall_created": True, "wall_id": str(wall.id)}),
        ip_address=request.client.host if request.client else None,
        user_email=admin.email,
    )
    await db.flush()

    return SoarActionResponse(
        success=True,
        message=f"Ethical wall created for matter {matter_id} - all access blocked",
        action="lock_matter",
    )


@router.post("/security/force-logout-all", response_model=SoarActionResponse)
async def soar_force_logout_all(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.revoked == False)  # noqa: E712
        .values(revoked=True)
    )

    await create_audit_log(
        db,
        admin.id,
        "system",
        "all_users",
        "soar_force_logout_all",
        changes_json=json.dumps({"all_tokens_revoked": True}),
        ip_address=request.client.host if request.client else None,
        user_email=admin.email,
    )
    await db.flush()

    return SoarActionResponse(
        success=True,
        message="All active sessions across the system have been revoked",
        action="force_logout_all",
    )


# --- SCIM Token Management ---


@router.post("/scim/tokens", response_model=ScimBearerTokenCreateResponse)
async def create_scim_token(
    data: ScimBearerTokenCreate,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    token_record, plaintext_token = await scim_service.create_bearer_token(
        db, data.description, data.expires_in_days, admin.id
    )

    await create_audit_log(
        db,
        admin.id,
        "scim_token",
        str(token_record.id),
        "create",
        changes_json=json.dumps({"description": data.description}),
        ip_address=request.client.host if request.client else None,
        user_email=admin.email,
    )

    return ScimBearerTokenCreateResponse(
        id=str(token_record.id),
        description=token_record.description,
        created_at=token_record.created_at,
        expires_at=token_record.expires_at,
        last_used_at=token_record.last_used_at,
        is_active=token_record.is_active,
        token=plaintext_token,
    )


@router.get("/scim/tokens")
async def list_scim_tokens(
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    tokens = await scim_service.list_bearer_tokens(db)
    return [
        ScimBearerTokenResponse(
            id=str(t.id),
            description=t.description,
            created_at=t.created_at,
            expires_at=t.expires_at,
            last_used_at=t.last_used_at,
            is_active=t.is_active,
        ).model_dump()
        for t in tokens
    ]


@router.delete("/scim/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_scim_token(
    token_id: uuid.UUID,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    admin: Annotated[User, Depends(require_roles("admin"))],
):
    success = await scim_service.revoke_bearer_token(db, token_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")

    await create_audit_log(
        db,
        admin.id,
        "scim_token",
        str(token_id),
        "revoke",
        ip_address=request.client.host if request.client else None,
        user_email=admin.email,
    )
