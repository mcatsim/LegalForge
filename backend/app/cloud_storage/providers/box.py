from typing import Optional
from urllib.parse import urlencode

import httpx

from app.config import settings

from .base import CloudStorageProvider

AUTH_URL = "https://account.box.com/api/oauth2/authorize"
TOKEN_URL = "https://api.box.com/oauth2/token"
API_BASE = "https://api.box.com/2.0"
UPLOAD_URL = "https://upload.box.com/api/2.0/files/content"


class BoxProvider(CloudStorageProvider):
    def get_authorization_url(self, state: str) -> str:
        params = {
            "client_id": settings.box_client_id,
            "redirect_uri": settings.cloud_storage_oauth_redirect_uri,
            "response_type": "code",
            "state": state,
        }
        return f"{AUTH_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                TOKEN_URL,
                data={
                    "client_id": settings.box_client_id,
                    "client_secret": settings.box_client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def refresh_access_token(self, refresh_token: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                TOKEN_URL,
                data={
                    "client_id": settings.box_client_id,
                    "client_secret": settings.box_client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def list_folder(self, access_token: str, folder_id: Optional[str] = None) -> list:
        fid = folder_id or "0"
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{API_BASE}/folders/{fid}/items",
                params={"fields": "id,name,type,size,modified_at,shared_link", "limit": 100},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        items = []
        for entry in data.get("entries", []):
            is_folder = entry["type"] == "folder"
            items.append(
                {
                    "id": entry["id"],
                    "name": entry["name"],
                    "mime_type": None if is_folder else "application/octet-stream",
                    "size": entry.get("size"),
                    "modified_at": entry.get("modified_at"),
                    "is_folder": is_folder,
                    "web_url": entry.get("shared_link", {}).get("url") if entry.get("shared_link") else None,
                }
            )
        return items

    async def get_file_metadata(self, access_token: str, file_id: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{API_BASE}/files/{file_id}",
                params={"fields": "id,name,type,size,modified_at,shared_link"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            entry = resp.json()

        is_folder = entry["type"] == "folder"
        return {
            "id": entry["id"],
            "name": entry["name"],
            "mime_type": None if is_folder else "application/octet-stream",
            "size": entry.get("size"),
            "modified_at": entry.get("modified_at"),
            "is_folder": is_folder,
            "web_url": entry.get("shared_link", {}).get("url") if entry.get("shared_link") else None,
        }

    async def download_file(self, access_token: str, file_id: str) -> tuple[bytes, str, str]:
        async with httpx.AsyncClient(follow_redirects=True) as client:
            # Get metadata first
            meta_resp = await client.get(
                f"{API_BASE}/files/{file_id}",
                params={"fields": "name"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            meta_resp.raise_for_status()
            filename = meta_resp.json()["name"]

            resp = await client.get(
                f"{API_BASE}/files/{file_id}/content",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            return resp.content, filename, "application/octet-stream"

    async def upload_file(
        self, access_token: str, folder_id: Optional[str], filename: str, content: bytes, mime_type: str
    ) -> dict:
        parent_id = folder_id or "0"
        import json

        attributes = json.dumps({"name": filename, "parent": {"id": parent_id}})

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                UPLOAD_URL,
                files={
                    "attributes": (None, attributes, "application/json"),
                    "file": (filename, content, mime_type),
                },
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()
            entry = data.get("entries", [{}])[0]

        return {
            "id": entry.get("id"),
            "name": entry.get("name"),
            "mime_type": mime_type,
            "size": entry.get("size"),
            "modified_at": entry.get("modified_at"),
            "web_url": None,
        }

    async def get_user_info(self, access_token: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{API_BASE}/users/me",
                params={"fields": "login,name"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        return {
            "email": data.get("login"),
            "name": data.get("name"),
        }
