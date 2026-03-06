import uuid
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.cloud_storage.models import CloudStorageConnection, CloudStorageLink
from app.cloud_storage.providers import get_provider
from app.common.encryption import decrypt_field, encrypt_field
from app.config import settings
from app.documents.models import Document
from app.documents.service import get_minio_client


async def create_connection(
    provider: str,
    display_name: str,
    user_id: uuid.UUID,
    db: AsyncSession,
) -> CloudStorageConnection:
    connection = CloudStorageConnection(
        provider=provider,
        display_name=display_name,
        connected_by=user_id,
        is_active=True,
    )
    db.add(connection)
    await db.flush()
    await db.refresh(connection)
    return connection


async def complete_oauth(
    provider: str,
    code: str,
    connection_id: uuid.UUID,
    db: AsyncSession,
) -> CloudStorageConnection:
    result = await db.execute(select(CloudStorageConnection).where(CloudStorageConnection.id == connection_id))
    connection = result.scalar_one_or_none()
    if not connection:
        raise ValueError("Connection not found")

    provider_impl = get_provider(provider)
    token_data = await provider_impl.exchange_code(code)

    access_token = token_data.get("access_token", "")
    refresh_token = token_data.get("refresh_token", "")
    expires_in = token_data.get("expires_in")

    connection.access_token_encrypted = encrypt_field(access_token) if access_token else None
    connection.refresh_token_encrypted = encrypt_field(refresh_token) if refresh_token else None

    if expires_in:
        connection.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    # Fetch user info
    try:
        user_info = await provider_impl.get_user_info(access_token)
        connection.account_email = user_info.get("email")
    except Exception:
        pass

    await db.flush()
    await db.refresh(connection)
    return connection


async def list_connections(
    user_id: uuid.UUID,
    db: AsyncSession,
) -> list[CloudStorageConnection]:
    result = await db.execute(
        select(CloudStorageConnection)
        .where(
            CloudStorageConnection.connected_by == user_id,
            CloudStorageConnection.is_active,
        )
        .order_by(CloudStorageConnection.created_at.desc())
    )
    return list(result.scalars().all())


async def delete_connection(
    connection_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession,
) -> None:
    result = await db.execute(
        select(CloudStorageConnection).where(
            CloudStorageConnection.id == connection_id,
            CloudStorageConnection.connected_by == user_id,
        )
    )
    connection = result.scalar_one_or_none()
    if not connection:
        raise ValueError("Connection not found")

    connection.is_active = False
    connection.access_token_encrypted = None
    connection.refresh_token_encrypted = None
    await db.flush()


async def get_access_token(
    connection: CloudStorageConnection,
    db: AsyncSession,
) -> str:
    if not connection.access_token_encrypted:
        raise ValueError("No access token available")

    access_token = decrypt_field(connection.access_token_encrypted)

    # Check if token is expired or about to expire (within 5 minutes)
    if connection.token_expires_at and connection.token_expires_at < datetime.now(timezone.utc) + timedelta(minutes=5):
        if not connection.refresh_token_encrypted:
            raise ValueError("Token expired and no refresh token available")

        refresh_token = decrypt_field(connection.refresh_token_encrypted)
        provider_impl = get_provider(connection.provider)

        try:
            token_data = await provider_impl.refresh_access_token(refresh_token)
            access_token = token_data.get("access_token", "")
            new_refresh_token = token_data.get("refresh_token")
            expires_in = token_data.get("expires_in")

            connection.access_token_encrypted = encrypt_field(access_token)
            if new_refresh_token:
                connection.refresh_token_encrypted = encrypt_field(new_refresh_token)
            if expires_in:
                connection.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

            await db.flush()
        except Exception:
            raise ValueError("Failed to refresh access token")

    return access_token


async def browse_folder(
    connection_id: uuid.UUID,
    folder_id: Optional[str],
    user_id: uuid.UUID,
    db: AsyncSession,
) -> list:
    result = await db.execute(
        select(CloudStorageConnection).where(
            CloudStorageConnection.id == connection_id,
            CloudStorageConnection.connected_by == user_id,
            CloudStorageConnection.is_active,
        )
    )
    connection = result.scalar_one_or_none()
    if not connection:
        raise ValueError("Connection not found")

    access_token = await get_access_token(connection, db)
    provider_impl = get_provider(connection.provider)
    return await provider_impl.list_folder(access_token, folder_id)


async def create_link(
    matter_id: uuid.UUID,
    connection_id: uuid.UUID,
    cloud_file_id: str,
    cloud_file_name: str,
    user_id: uuid.UUID,
    db: AsyncSession,
    cloud_file_url: Optional[str] = None,
    cloud_mime_type: Optional[str] = None,
    cloud_size_bytes: Optional[int] = None,
    cloud_modified_at: Optional[datetime] = None,
    link_type: str = "link",
    document_id: Optional[uuid.UUID] = None,
) -> CloudStorageLink:
    link = CloudStorageLink(
        document_id=document_id,
        matter_id=matter_id,
        connection_id=connection_id,
        cloud_file_id=cloud_file_id,
        cloud_file_name=cloud_file_name,
        cloud_file_url=cloud_file_url,
        cloud_mime_type=cloud_mime_type,
        cloud_size_bytes=cloud_size_bytes,
        cloud_modified_at=cloud_modified_at,
        link_type=link_type,
        created_by=user_id,
    )
    db.add(link)
    await db.flush()
    await db.refresh(link)
    return link


async def list_links(
    matter_id: uuid.UUID,
    db: AsyncSession,
) -> list[CloudStorageLink]:
    result = await db.execute(
        select(CloudStorageLink)
        .where(CloudStorageLink.matter_id == matter_id)
        .order_by(CloudStorageLink.created_at.desc())
    )
    return list(result.scalars().all())


async def delete_link(
    link_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession,
) -> None:
    result = await db.execute(select(CloudStorageLink).where(CloudStorageLink.id == link_id))
    link = result.scalar_one_or_none()
    if not link:
        raise ValueError("Link not found")

    await db.delete(link)
    await db.flush()


async def import_file(
    connection_id: uuid.UUID,
    cloud_file_id: str,
    matter_id: uuid.UUID,
    description: Optional[str],
    user_id: uuid.UUID,
    db: AsyncSession,
) -> CloudStorageLink:
    result = await db.execute(
        select(CloudStorageConnection).where(
            CloudStorageConnection.id == connection_id,
            CloudStorageConnection.is_active,
        )
    )
    connection = result.scalar_one_or_none()
    if not connection:
        raise ValueError("Connection not found")

    access_token = await get_access_token(connection, db)
    provider_impl = get_provider(connection.provider)

    # Download from cloud
    content, filename, mime_type = await provider_impl.download_file(access_token, cloud_file_id)

    # Upload to MinIO (reuse pattern from documents service)
    storage_key = f"{matter_id}/{uuid.uuid4()}/{filename}"
    client = get_minio_client()
    client.put_object(
        settings.minio_bucket,
        storage_key,
        BytesIO(content),
        length=len(content),
        content_type=mime_type,
    )

    # Create Document record
    doc = Document(
        matter_id=matter_id,
        uploaded_by=user_id,
        filename=filename,
        storage_key=storage_key,
        mime_type=mime_type,
        size_bytes=len(content),
        version=1,
        description=description,
    )
    db.add(doc)
    await db.flush()
    await db.refresh(doc)

    # Get cloud file metadata
    try:
        file_meta = await provider_impl.get_file_metadata(access_token, cloud_file_id)
    except Exception:
        file_meta = {}

    # Create link
    link = await create_link(
        matter_id=matter_id,
        connection_id=connection_id,
        cloud_file_id=cloud_file_id,
        cloud_file_name=filename,
        user_id=user_id,
        db=db,
        cloud_file_url=file_meta.get("web_url"),
        cloud_mime_type=mime_type,
        cloud_size_bytes=len(content),
        cloud_modified_at=None,
        link_type="imported",
        document_id=doc.id,
    )

    return link


async def export_file(
    document_id: uuid.UUID,
    connection_id: uuid.UUID,
    folder_id: Optional[str],
    user_id: uuid.UUID,
    db: AsyncSession,
) -> CloudStorageLink:
    # Get document
    doc_result = await db.execute(select(Document).where(Document.id == document_id))
    doc = doc_result.scalar_one_or_none()
    if not doc:
        raise ValueError("Document not found")

    # Get connection
    conn_result = await db.execute(
        select(CloudStorageConnection).where(
            CloudStorageConnection.id == connection_id,
            CloudStorageConnection.is_active,
        )
    )
    connection = conn_result.scalar_one_or_none()
    if not connection:
        raise ValueError("Connection not found")

    access_token = await get_access_token(connection, db)
    provider_impl = get_provider(connection.provider)

    # Download from MinIO
    client = get_minio_client()
    response = client.get_object(settings.minio_bucket, doc.storage_key)
    content = response.read()
    response.close()
    response.release_conn()

    # Upload to cloud
    cloud_file = await provider_impl.upload_file(access_token, folder_id, doc.filename, content, doc.mime_type)

    # Create link
    link = await create_link(
        matter_id=doc.matter_id,
        connection_id=connection_id,
        cloud_file_id=cloud_file.get("id", ""),
        cloud_file_name=cloud_file.get("name", doc.filename),
        user_id=user_id,
        db=db,
        cloud_file_url=cloud_file.get("web_url"),
        cloud_mime_type=doc.mime_type,
        cloud_size_bytes=doc.size_bytes,
        cloud_modified_at=None,
        link_type="exported",
        document_id=doc.id,
    )

    return link
