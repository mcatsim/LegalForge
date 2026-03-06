from abc import ABC, abstractmethod
from typing import Optional


class CloudStorageProvider(ABC):
    @abstractmethod
    def get_authorization_url(self, state: str) -> str: ...

    @abstractmethod
    async def exchange_code(self, code: str) -> dict: ...

    @abstractmethod
    async def refresh_access_token(self, refresh_token: str) -> dict: ...

    @abstractmethod
    async def list_folder(self, access_token: str, folder_id: Optional[str] = None) -> list: ...

    @abstractmethod
    async def get_file_metadata(self, access_token: str, file_id: str) -> dict: ...

    @abstractmethod
    async def download_file(self, access_token: str, file_id: str) -> tuple[bytes, str, str]: ...

    @abstractmethod
    async def upload_file(
        self, access_token: str, folder_id: Optional[str], filename: str, content: bytes, mime_type: str
    ) -> dict: ...

    @abstractmethod
    async def get_user_info(self, access_token: str) -> dict: ...
