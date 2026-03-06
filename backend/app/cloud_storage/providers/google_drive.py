import json
from typing import Optional
from urllib.parse import urlencode

import httpx

from app.config import settings

from .base import CloudStorageProvider

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
API_BASE = "https://www.googleapis.com/drive/v3"
UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files"
SCOPES = "https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive.readonly"


class GoogleDriveProvider(CloudStorageProvider):
    def get_authorization_url(self, state: str) -> str:
        params = {
            "client_id": settings.google_drive_client_id,
            "redirect_uri": settings.cloud_storage_oauth_redirect_uri,
            "response_type": "code",
            "scope": SCOPES,
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
        return f"{AUTH_URL}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                TOKEN_URL,
                data={
                    "client_id": settings.google_drive_client_id,
                    "client_secret": settings.google_drive_client_secret,
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
                    "client_id": settings.google_drive_client_id,
                    "client_secret": settings.google_drive_client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def list_folder(self, access_token: str, folder_id: Optional[str] = None) -> list:
        parent = folder_id or "root"
        query = f"'{parent}' in parents and trashed = false"
        fields = "files(id,name,mimeType,size,modifiedTime,webViewLink)"
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{API_BASE}/files",
                params={"q": query, "fields": fields, "pageSize": 100, "orderBy": "folder,name"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()

        items = []
        for f in data.get("files", []):
            items.append(
                {
                    "id": f["id"],
                    "name": f["name"],
                    "mime_type": f.get("mimeType"),
                    "size": int(f["size"]) if f.get("size") else None,
                    "modified_at": f.get("modifiedTime"),
                    "is_folder": f.get("mimeType") == "application/vnd.google-apps.folder",
                    "web_url": f.get("webViewLink"),
                }
            )
        return items

    async def get_file_metadata(self, access_token: str, file_id: str) -> dict:
        fields = "id,name,mimeType,size,modifiedTime,webViewLink"
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{API_BASE}/files/{file_id}",
                params={"fields": fields},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            f = resp.json()

        return {
            "id": f["id"],
            "name": f["name"],
            "mime_type": f.get("mimeType"),
            "size": int(f["size"]) if f.get("size") else None,
            "modified_at": f.get("modifiedTime"),
            "is_folder": f.get("mimeType") == "application/vnd.google-apps.folder",
            "web_url": f.get("webViewLink"),
        }

    async def download_file(self, access_token: str, file_id: str) -> tuple[bytes, str, str]:
        async with httpx.AsyncClient() as client:
            # Get metadata first
            meta_resp = await client.get(
                f"{API_BASE}/files/{file_id}",
                params={"fields": "name,mimeType"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            meta_resp.raise_for_status()
            meta = meta_resp.json()
            filename = meta["name"]
            mime_type = meta.get("mimeType", "application/octet-stream")

            # Handle Google Docs export
            if mime_type.startswith("application/vnd.google-apps."):
                export_mime = "application/pdf"
                resp = await client.get(
                    f"{API_BASE}/files/{file_id}/export",
                    params={"mimeType": export_mime},
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                resp.raise_for_status()
                return resp.content, f"{filename}.pdf", export_mime

            # Download binary file
            resp = await client.get(
                f"{API_BASE}/files/{file_id}",
                params={"alt": "media"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            return resp.content, filename, mime_type

    async def upload_file(
        self, access_token: str, folder_id: Optional[str], filename: str, content: bytes, mime_type: str
    ) -> dict:
        metadata = {"name": filename}
        if folder_id:
            metadata["parents"] = [folder_id]

        boundary = "----LexNebulisBoundary"
        body = (
            (
                f"--{boundary}\r\n"
                f"Content-Type: application/json; charset=UTF-8\r\n\r\n"
                f"{json.dumps(metadata)}\r\n"
                f"--{boundary}\r\n"
                f"Content-Type: {mime_type}\r\n\r\n"
            ).encode()
            + content
            + f"\r\n--{boundary}--".encode()
        )

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{UPLOAD_URL}?uploadType=multipart&fields=id,name,mimeType,size,modifiedTime,webViewLink",
                content=body,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": f"multipart/related; boundary={boundary}",
                },
            )
            resp.raise_for_status()
            f = resp.json()

        return {
            "id": f["id"],
            "name": f["name"],
            "mime_type": f.get("mimeType"),
            "size": int(f["size"]) if f.get("size") else None,
            "modified_at": f.get("modifiedTime"),
            "web_url": f.get("webViewLink"),
        }

    async def get_user_info(self, access_token: str) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{API_BASE}/about",
                params={"fields": "user(displayName,emailAddress,photoLink)"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            data = resp.json()
            user = data.get("user", {})
        return {
            "email": user.get("emailAddress"),
            "name": user.get("displayName"),
        }
