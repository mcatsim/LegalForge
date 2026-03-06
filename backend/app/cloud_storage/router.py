import json
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.service import create_audit_log
from app.cloud_storage import service
from app.cloud_storage.providers import get_provider
from app.cloud_storage.schemas import (
    CloudExportRequest,
    CloudFileBrowserResponse,
    CloudFileItem,
    CloudImportRequest,
    CloudStorageConnectionCreate,
    CloudStorageConnectionResponse,
    CloudStorageLinkCreate,
    CloudStorageLinkResponse,
)
from app.database import get_db
from app.dependencies import get_current_user

router = APIRouter()


@router.get("/connections", response_model=list[CloudStorageConnectionResponse])
async def list_connections(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    connections = await service.list_connections(current_user.id, db)
    results = []
    for conn in connections:
        results.append(
            CloudStorageConnectionResponse(
                id=conn.id,
                provider=conn.provider,
                display_name=conn.display_name,
                account_email=conn.account_email,
                root_folder_id=conn.root_folder_id,
                root_folder_name=conn.root_folder_name,
                is_active=conn.is_active,
                connected_by=conn.connected_by,
                has_access_token=conn.access_token_encrypted is not None,
                has_refresh_token=conn.refresh_token_encrypted is not None,
                token_expires_at=conn.token_expires_at,
                created_at=conn.created_at,
                updated_at=conn.updated_at,
            )
        )
    return results


@router.post("/connections/{provider}/authorize")
async def authorize_connection(
    provider: str,
    body: CloudStorageConnectionCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    valid_providers = ["google_drive", "dropbox", "box", "onedrive"]
    if provider not in valid_providers:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {provider}")

    connection = await service.create_connection(
        provider=provider,
        display_name=body.display_name,
        user_id=current_user.id,
        db=db,
    )

    # Encode connection_id + provider in state param
    state = json.dumps({"connection_id": str(connection.id), "provider": provider})

    provider_impl = get_provider(provider)
    auth_url = provider_impl.get_authorization_url(state)

    await create_audit_log(
        db=db,
        user_id=current_user.id,
        entity_type="cloud_storage_connection",
        entity_id=str(connection.id),
        action="authorize_initiated",
    )

    return {"authorization_url": auth_url, "connection_id": str(connection.id)}


@router.get("/connections/callback")
async def oauth_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    try:
        state_data = json.loads(state)
        connection_id = uuid.UUID(state_data["connection_id"])
        provider = state_data["provider"]
    except (json.JSONDecodeError, KeyError, ValueError):
        return RedirectResponse(
            url="/cloud-storage/callback?error=invalid_state",
            status_code=302,
        )

    try:
        connection = await service.complete_oauth(
            provider=provider,
            code=code,
            connection_id=connection_id,
            db=db,
        )

        await create_audit_log(
            db=db,
            user_id=connection.connected_by,
            entity_type="cloud_storage_connection",
            entity_id=str(connection.id),
            action="oauth_completed",
        )

        return RedirectResponse(
            url=f"/cloud-storage/callback?success=true&provider={provider}",
            status_code=302,
        )
    except Exception as e:
        return RedirectResponse(
            url=f"/cloud-storage/callback?error={str(e)}",
            status_code=302,
        )


@router.delete("/connections/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect(
    connection_id: uuid.UUID,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        await service.delete_connection(connection_id, current_user.id, db)
        await create_audit_log(
            db=db,
            user_id=current_user.id,
            entity_type="cloud_storage_connection",
            entity_id=str(connection_id),
            action="disconnected",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/browse/{connection_id}", response_model=CloudFileBrowserResponse)
async def browse_folder(
    connection_id: uuid.UUID,
    folder_id: Optional[str] = Query(None),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        items = await service.browse_folder(connection_id, folder_id, current_user.id, db)
        file_items = [CloudFileItem(**item) for item in items]
        return CloudFileBrowserResponse(items=file_items, folder_id=folder_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/link", response_model=CloudStorageLinkResponse)
async def create_link(
    body: CloudStorageLinkCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    link = await service.create_link(
        matter_id=body.matter_id,
        connection_id=body.connection_id,
        cloud_file_id=body.cloud_file_id,
        cloud_file_name=body.cloud_file_name,
        user_id=current_user.id,
        db=db,
        cloud_file_url=body.cloud_file_url,
        cloud_mime_type=body.cloud_mime_type,
        cloud_size_bytes=body.cloud_size_bytes,
        cloud_modified_at=body.cloud_modified_at,
        link_type=body.link_type,
    )

    resp = CloudStorageLinkResponse(
        id=link.id,
        document_id=link.document_id,
        matter_id=link.matter_id,
        connection_id=link.connection_id,
        cloud_file_id=link.cloud_file_id,
        cloud_file_name=link.cloud_file_name,
        cloud_file_url=link.cloud_file_url,
        cloud_mime_type=link.cloud_mime_type,
        cloud_size_bytes=link.cloud_size_bytes,
        cloud_modified_at=link.cloud_modified_at,
        link_type=link.link_type,
        created_by=link.created_by,
        created_at=link.created_at,
        connection_provider=link.connection.provider if link.connection else None,
        connection_display_name=link.connection.display_name if link.connection else None,
    )

    await create_audit_log(
        db=db,
        user_id=current_user.id,
        entity_type="cloud_storage_link",
        entity_id=str(link.id),
        action="created",
    )

    return resp


@router.post("/import", response_model=CloudStorageLinkResponse)
async def import_cloud_file(
    body: CloudImportRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        link = await service.import_file(
            connection_id=body.connection_id,
            cloud_file_id=body.cloud_file_id,
            matter_id=body.matter_id,
            description=body.description,
            user_id=current_user.id,
            db=db,
        )

        resp = CloudStorageLinkResponse(
            id=link.id,
            document_id=link.document_id,
            matter_id=link.matter_id,
            connection_id=link.connection_id,
            cloud_file_id=link.cloud_file_id,
            cloud_file_name=link.cloud_file_name,
            cloud_file_url=link.cloud_file_url,
            cloud_mime_type=link.cloud_mime_type,
            cloud_size_bytes=link.cloud_size_bytes,
            cloud_modified_at=link.cloud_modified_at,
            link_type=link.link_type,
            created_by=link.created_by,
            created_at=link.created_at,
            connection_provider=link.connection.provider if link.connection else None,
            connection_display_name=link.connection.display_name if link.connection else None,
        )

        await create_audit_log(
            db=db,
            user_id=current_user.id,
            entity_type="cloud_storage_link",
            entity_id=str(link.id),
            action="imported",
        )

        return resp
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/export", response_model=CloudStorageLinkResponse)
async def export_document(
    body: CloudExportRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        link = await service.export_file(
            document_id=body.document_id,
            connection_id=body.connection_id,
            folder_id=body.folder_id,
            user_id=current_user.id,
            db=db,
        )

        resp = CloudStorageLinkResponse(
            id=link.id,
            document_id=link.document_id,
            matter_id=link.matter_id,
            connection_id=link.connection_id,
            cloud_file_id=link.cloud_file_id,
            cloud_file_name=link.cloud_file_name,
            cloud_file_url=link.cloud_file_url,
            cloud_mime_type=link.cloud_mime_type,
            cloud_size_bytes=link.cloud_size_bytes,
            cloud_modified_at=link.cloud_modified_at,
            link_type=link.link_type,
            created_by=link.created_by,
            created_at=link.created_at,
            connection_provider=link.connection.provider if link.connection else None,
            connection_display_name=link.connection.display_name if link.connection else None,
        )

        await create_audit_log(
            db=db,
            user_id=current_user.id,
            entity_type="cloud_storage_link",
            entity_id=str(link.id),
            action="exported",
        )

        return resp
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/links", response_model=list[CloudStorageLinkResponse])
async def list_links(
    matter_id: uuid.UUID = Query(...),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    links = await service.list_links(matter_id, db)
    results = []
    for link in links:
        results.append(
            CloudStorageLinkResponse(
                id=link.id,
                document_id=link.document_id,
                matter_id=link.matter_id,
                connection_id=link.connection_id,
                cloud_file_id=link.cloud_file_id,
                cloud_file_name=link.cloud_file_name,
                cloud_file_url=link.cloud_file_url,
                cloud_mime_type=link.cloud_mime_type,
                cloud_size_bytes=link.cloud_size_bytes,
                cloud_modified_at=link.cloud_modified_at,
                link_type=link.link_type,
                created_by=link.created_by,
                created_at=link.created_at,
                connection_provider=link.connection.provider if link.connection else None,
                connection_display_name=link.connection.display_name if link.connection else None,
            )
        )
    return results


@router.delete("/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_link(
    link_id: uuid.UUID,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        await service.delete_link(link_id, current_user.id, db)
        await create_audit_log(
            db=db,
            user_id=current_user.id,
            entity_type="cloud_storage_link",
            entity_id=str(link_id),
            action="deleted",
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
