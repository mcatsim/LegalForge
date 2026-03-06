"""Add SIEM config table

Revision ID: 0017
Revises: 0016
Create Date: 2026-02-28
"""

from collections.abc import Sequence
from typing import Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "siem_config",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("webhook_url", sa.String(1000), nullable=True),
        sa.Column("webhook_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("syslog_host", sa.String(500), nullable=True),
        sa.Column("syslog_port", sa.Integer(), nullable=True, server_default="514"),
        sa.Column(
            "syslog_protocol",
            sa.Enum("udp", "tcp", "tls", name="syslogprotocol"),
            nullable=False,
            server_default="udp",
        ),
        sa.Column("syslog_tls_ca_cert", sa.Text(), nullable=True),
        sa.Column("realtime_enabled", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column(
            "realtime_format",
            sa.Enum("json", "cef", "syslog", name="siemformat"),
            nullable=False,
            server_default="json",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("siem_config")
    op.execute("DROP TYPE IF EXISTS syslogprotocol")
    op.execute("DROP TYPE IF EXISTS siemformat")
