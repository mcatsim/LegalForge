import json
from typing import Optional
from urllib.parse import urlencode

import httpx

from app.config import settings

from .base import CloudStorageProvider

AUTH_URL = "https://www.dropbox.com/oauth2/authorize"
TOKEN_URL = "https://api.dropboxapi.com/oauth2/token"
API_BASE = "https://api.dropboxapi.com/2"
CONTENT_BASE = "https://content.dropboxapi.com/2"


class DropboxProvider(CloudStorageProvider):
    def get_authorization_url(self, state: str) -> str:
        params = {
            "client_id": settings.dropbox_app_key,
            "redirect_uri": settings.cloud_storage_oauth_redirect_uri,
            "response_type": "code",
            "token_access_type": "offline",
            "state": state,
        }
        return f"{AUTH_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                TOKEN_URL,
                data={
                    "client_id": settings.dropbox_app_key,
                    "client_secret": settings.dropbox_app_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": settings.cloud_storage_oauth_redirect_uri,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def refresh_access_token(self, refresh_token: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                TOKEN_URL,
                data={
                    "client_id": settings.dropbox_app_key,
                    "client_secret": settings.dropbox_app_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def list_folder(self, access_token: str, folder_id: Optional[str] = None) -> list:
        path = folder_id or ""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{API_BASE}/files/list_folder",
                json={"path": path, "limit": 100, "include_mounted_folders": True},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        items = []
        for entry in data.get("entries", []):
            is_folder = entry[".tag"] == "folder"
            items.append(
                {
                    "id": entry.get("id", entry.get("path_lower", "")),
                    "name": entry["name"],
                    "mime_type": None if is_folder else "application/octet-stream",
                    "size": entry.get("size"),
                    "modified_at": entry.get("client_modified"),
                    "is_folder": is_folder,
                    "web_url": None,
                }
            )
        return items

    async def get_file_metadata(self, access_token: str, file_id: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{API_BASE}/files/get_metadata",
                json={"path": file_id},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            entry = resp.json()

        is_folder = entry[".tag"] == "folder"
        return {
            "id": entry.get("id", entry.get("path_lower", "")),
            "name": entry["name"],
            "mime_type": None if is_folder else "application/octet-stream",
            "size": entry.get("size"),
            "modified_at": entry.get("client_modified"),
            "is_folder": is_folder,
            "web_url": None,
        }

    async def download_file(self, access_token: str, file_id: str) -> tuple[bytes, str, str]:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{CONTENT_BASE}/files/download",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Dropbox-API-Arg": json.dumps({"path": file_id}),
                },
            )
            resp.raise_for_status()
            # Metadata is in the Dropbox-API-Result header
            result_header = resp.headers.get("Dropbox-API-Result", "{}")
            meta = json.loads(result_header)
            filename = meta.get("name", "download")
            mime_type = "application/octet-stream"
            return resp.content, filename, mime_type

    async def upload_file(
        self, access_token: str, folder_id: Optional[str], filename: str, content: bytes, mime_type: str
    ) -> dict:
        path = f"{folder_id}/{filename}" if folder_id else f"/{filename}"
        upload_arg = {"path": path, "mode": "add", "autorename": True}
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{CONTENT_BASE}/files/upload",
                content=content,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/octet-stream",
                    "Dropbox-API-Arg": json.dumps(upload_arg),
                },
            )
            resp.raise_for_status()
            entry = resp.json()

        return {
            "id": entry.get("id", entry.get("path_lower", "")),
            "name": entry["name"],
            "mime_type": mime_type,
            "size": entry.get("size"),
            "modified_at": entry.get("client_modified"),
            "web_url": None,
        }

    async def get_user_info(self, access_token: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{API_BASE}/users/get_current_account",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        return {
            "email": data.get("email"),
            "name": data.get("name", {}).get("display_name"),
        }
