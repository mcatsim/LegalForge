from app.cloud_storage.providers.base import CloudStorageProvider
from app.cloud_storage.providers.box import BoxProvider
from app.cloud_storage.providers.dropbox import DropboxProvider
from app.cloud_storage.providers.google_drive import GoogleDriveProvider
from app.cloud_storage.providers.onedrive import OneDriveProvider


def get_provider(provider_name: str) -> CloudStorageProvider:
    providers = {
        "google_drive": GoogleDriveProvider,
        "dropbox": DropboxProvider,
        "box": BoxProvider,
        "onedrive": OneDriveProvider,
    }
    provider_class = providers.get(provider_name)
    if provider_class is None:
        raise ValueError(f"Unknown cloud storage provider: {provider_name}")
    return provider_class()
