import asyncio
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.celery_app import celery
from app.cloud_storage.models import CloudStorageConnection
from app.cloud_storage.providers import get_provider
from app.common.encryption import decrypt_field, encrypt_field

logger = logging.getLogger(__name__)


def _get_sync_session() -> Session:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.config import settings

    # Convert async URL to sync for Celery tasks
    sync_url = settings.database_url.replace("+asyncpg", "").replace("+aiosqlite", "")
    engine = create_engine(sync_url)
    session_factory = sessionmaker(bind=engine)
    return session_factory()


@celery.task(name="cloud_storage.refresh_cloud_tokens")
def refresh_cloud_tokens():
    session = _get_sync_session()
    try:
        # Find connections with tokens expiring within 1 hour
        threshold = datetime.now(timezone.utc) + timedelta(hours=1)
        result = session.execute(
            select(CloudStorageConnection).where(
                CloudStorageConnection.is_active,
                CloudStorageConnection.token_expires_at.isnot(None),
                CloudStorageConnection.token_expires_at < threshold,
                CloudStorageConnection.refresh_token_encrypted.isnot(None),
            )
        )
        connections = result.scalars().all()

        refreshed = 0
        for connection in connections:
            try:
                refresh_token = decrypt_field(connection.refresh_token_encrypted)
                provider_impl = get_provider(connection.provider)

                # Run async method synchronously
                loop = asyncio.new_event_loop()
                try:
                    token_data = loop.run_until_complete(provider_impl.refresh_access_token(refresh_token))
                finally:
                    loop.close()

                access_token = token_data.get("access_token", "")
                new_refresh_token = token_data.get("refresh_token")
                expires_in = token_data.get("expires_in")

                connection.access_token_encrypted = encrypt_field(access_token)
                if new_refresh_token:
                    connection.refresh_token_encrypted = encrypt_field(new_refresh_token)
                if expires_in:
                    connection.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

                refreshed += 1
                logger.info(
                    "Refreshed token for connection %s (%s)",
                    connection.id,
                    connection.provider,
                )
            except Exception:
                logger.exception(
                    "Failed to refresh token for connection %s (%s)",
                    connection.id,
                    connection.provider,
                )

        session.commit()
        return {"refreshed": refreshed, "total": len(connections)}

    except Exception:
        session.rollback()
        logger.exception("Error in refresh_cloud_tokens task")
        raise
    finally:
        session.close()


# Register periodic task
celery.conf.beat_schedule = getattr(celery.conf, "beat_schedule", {})
celery.conf.beat_schedule["refresh-cloud-tokens"] = {
    "task": "cloud_storage.refresh_cloud_tokens",
    "schedule": 1800.0,  # Every 30 minutes
}
