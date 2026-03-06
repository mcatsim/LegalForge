import enum
from typing import Optional

from sqlalchemy import Boolean, Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.common.base_models import TimestampMixin, UUIDBase


class SyslogProtocol(str, enum.Enum):
    udp = "udp"
    tcp = "tcp"
    tls = "tls"


class SiemFormat(str, enum.Enum):
    json = "json"
    cef = "cef"
    syslog = "syslog"


class SiemConfig(UUIDBase, TimestampMixin):
    __tablename__ = "siem_config"

    webhook_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    webhook_secret_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    syslog_host: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    syslog_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, default=514)
    syslog_protocol: Mapped[SyslogProtocol] = mapped_column(
        Enum(SyslogProtocol), nullable=False, default=SyslogProtocol.udp
    )
    syslog_tls_ca_cert: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    realtime_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    realtime_format: Mapped[SiemFormat] = mapped_column(Enum(SiemFormat), nullable=False, default=SiemFormat.json)
