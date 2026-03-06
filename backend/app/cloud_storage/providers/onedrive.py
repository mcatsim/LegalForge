from typing import Optional
from urllib.parse import urlencode

import httpx

from app.config import settings

from .base import CloudStorageProvider

AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
API_BASE = "https://graph.microsoft.com/v1.0"
SCOPES = "Files.ReadWrite User.Read offline_access"


class OneDriveProvider(CloudStorageProvider):
    def get_authorization_url(self, state: str) -> str:
        params = {
            "client_id": settings.onedrive_client_id,
            "redirect_uri": settings.cloud_storage_oauth_redirect_uri,
            "response_type": "code",
            "scope": SCOPES,
            "state": state,
        }
        return f"{AUTH_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                TOKEN_URL,
                data={
                    "client_id": settings.onedrive_client_id,
                    "client_secret": settings.onedrive_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": settings.cloud_storage_oauth_redirect_uri,
                    "scope": SCOPES,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def refresh_access_token(self, refresh_token: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                TOKEN_URL,
                data={
                    "client_id": settings.onedrive_client_id,
                    "client_secret": settings.onedrive_client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                    "scope": SCOPES,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def list_folder(self, access_token: str, folder_id: Optional[str] = None) -> list:
        if folder_id:
            url = f"{API_BASE}/me/drive/items/{folder_id}/children"
        else:
            url = f"{API_BASE}/me/drive/root/children"

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                url,
                params={"$top": 100, "$select": "id,name,file,folder,size,lastModifiedDateTime,webUrl"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        items = []
        for entry in data.get("value", []):
            is_folder = "folder" in entry
            items.append(
                {
                    "id": entry["id"],
                    "name": entry["name"],
                    "mime_type": entry.get("file", {}).get("mimeType") if not is_folder else None,
                    "size": entry.get("size"),
                    "modified_at": entry.get("lastModifiedDateTime"),
                    "is_folder": is_folder,
                    "web_url": entry.get("webUrl"),
                }
            )
        return items

    async def get_file_metadata(self, access_token: str, file_id: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{API_BASE}/me/drive/items/{file_id}",
                params={"$select": "id,name,file,folder,size,lastModifiedDateTime,webUrl"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            entry = resp.json()

        is_folder = "folder" in entry
        return {
            "id": entry["id"],
            "name": entry["name"],
            "mime_type": entry.get("file", {}).get("mimeType") if not is_folder else None,
            "size": entry.get("size"),
            "modified_at": entry.get("lastModifiedDateTime"),
            "is_folder": is_folder,
            "web_url": entry.get("webUrl"),
        }

    async def download_file(self, access_token: str, file_id: str) -> tuple[bytes, str, str]:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            # Get metadata first
            meta_resp = await client.get(
                f"{API_BASE}/me/drive/items/{file_id}",
                params={"$select": "name,file"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            meta_resp.raise_for_status()
            meta = meta_resp.json()
            filename = meta["name"]
            mime_type = meta.get("file", {}).get("mimeType", "application/octet-stream")

            resp = await client.get(
                f"{API_BASE}/me/drive/items/{file_id}/content",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            return resp.content, filename, mime_type

    async def upload_file(
        self, access_token: str, folder_id: Optional[str], filename: str, content: bytes, mime_type: str
    ) -> dict:
        if folder_id:
            url = f"{API_BASE}/me/drive/items/{folder_id}:/{filename}:/content"
        else:
            url = f"{API_BASE}/me/drive/root:/{filename}:/content"

        async with httpx.AsyncClient() as client:
            resp = await client.put(
                url,
                content=content,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": mime_type,
                },
            )
            resp.raise_for_status()
            entry = resp.json()

        is_folder = "folder" in entry
        return {
            "id": entry["id"],
            "name": entry["name"],
            "mime_type": entry.get("file", {}).get("mimeType") if not is_folder else None,
            "size": entry.get("size"),
            "modified_at": entry.get("lastModifiedDateTime"),
            "web_url": entry.get("webUrl"),
        }

    async def get_user_info(self, access_token: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{API_BASE}/me",
                params={"$select": "mail,userPrincipalName,displayName"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        return {
            "email": data.get("mail") or data.get("userPrincipalName"),
            "name": data.get("displayName"),
        }
