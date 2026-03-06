import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, LargeBinary, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.base_models import GUID, TimestampMixin, UUIDBase


class UserRole(str, enum.Enum):
    admin = "admin"
    attorney = "attorney"
    paralegal = "paralegal"
    billing_clerk = "billing_clerk"


class User(UUIDBase, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), nullable=False, default=UserRole.attorney)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Two-Factor Authentication
    totp_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    recovery_codes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # WebAuthn / FIDO2
    webauthn_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")

    # SCIM
    scim_external_id: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # Relationships
    time_entries = relationship("TimeEntry", back_populates="user", lazy="selectin")
    webauthn_credentials = relationship("WebAuthnCredential", back_populates="user", lazy="selectin")
    calendar_events = relationship(
        "CalendarEvent", back_populates="assigned_user", foreign_keys="CalendarEvent.assigned_to", lazy="selectin"
    )

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


class RefreshToken(UUIDBase):
    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AuditLog(UUIDBase):
    """Immutable audit log with hash chain for nonrepudiation.

    Each entry includes a SHA-256 integrity hash computed from the event data
    and the previous entry's hash, creating a tamper-evident chain. Entries
    are append-only — no update or delete operations are exposed.
    """

    __tablename__ = "audit_log"

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), nullable=True, index=True)
    user_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    entity_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    entity_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    changes_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    previous_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )


class WebAuthnCredential(UUIDBase):
    __tablename__ = "webauthn_credentials"

    user_id: Mapped[uuid.UUID] = mapped_column(GUID(), ForeignKey("users.id"), nullable=False, index=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    transports: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    aaguid: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Relationships
    user = relationship("User", back_populates="webauthn_credentials")


class SystemSetting(UUIDBase):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_by: Mapped[Optional[uuid.UUID]] = mapped_column(GUID(), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
