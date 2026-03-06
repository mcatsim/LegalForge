import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class CloudStorageConnectionCreate(BaseModel):
    provider: str
    display_name: str


class CloudStorageConnectionResponse(BaseModel):
    id: uuid.UUID
    provider: str
    display_name: str
    account_email: Optional[str] = None
    root_folder_id: Optional[str] = None
    root_folder_name: Optional[str] = None
    is_active: bool
    connected_by: uuid.UUID
    has_access_token: bool
    has_refresh_token: bool
    token_expires_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CloudFileItem(BaseModel):
    id: str
    name: str
    mime_type: Optional[str] = None
    size: Optional[int] = None
    modified_at: Optional[datetime] = None
    is_folder: bool
    web_url: Optional[str] = None


class CloudFileBrowserResponse(BaseModel):
    items: list[CloudFileItem]
    folder_id: Optional[str] = None
    folder_name: Optional[str] = None


class CloudStorageLinkCreate(BaseModel):
    matter_id: uuid.UUID
    connection_id: uuid.UUID
    cloud_file_id: str
    cloud_file_name: str
    cloud_file_url: Optional[str] = None
    cloud_mime_type: Optional[str] = None
    cloud_size_bytes: Optional[int] = None
    cloud_modified_at: Optional[datetime] = None
    link_type: str = "link"


class CloudStorageLinkResponse(BaseModel):
    id: uuid.UUID
    document_id: Optional[uuid.UUID] = None
    matter_id: uuid.UUID
    connection_id: uuid.UUID
    cloud_file_id: str
    cloud_file_name: str
    cloud_file_url: Optional[str] = None
    cloud_mime_type: Optional[str] = None
    cloud_size_bytes: Optional[int] = None
    cloud_modified_at: Optional[datetime] = None
    link_type: str
    created_by: uuid.UUID
    created_at: datetime
    connection_provider: Optional[str] = None
    connection_display_name: Optional[str] = None

    model_config = {"from_attributes": True}


class CloudImportRequest(BaseModel):
    connection_id: uuid.UUID
    cloud_file_id: str
    matter_id: uuid.UUID
    description: Optional[str] = None


class CloudExportRequest(BaseModel):
    document_id: uuid.UUID
    connection_id: uuid.UUID
    folder_id: Optional[str] = None


class OAuthCallbackRequest(BaseModel):
    code: str
    state: str
    provider: str
