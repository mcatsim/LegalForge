"""
Consolidated field-level encryption for LexNebulis.

Uses Fernet symmetric encryption with PBKDF2-derived keys.
Each encryption call generates a random 16-byte salt, prepended to the
ciphertext as base64. This prevents rainbow-table attacks and ensures
identical plaintexts produce different ciphertexts.

Legacy support: ciphertexts without a salt prefix (from v1.1 and earlier)
are decrypted using the hardcoded-salt derivation for backward compatibility.
"""

import base64
import os
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.config import settings

_SALT_LENGTH = 16
_ITERATIONS = 600_000  # OWASP 2023 recommendation for PBKDF2-SHA256
_SALT_PREFIX = b"$LN1$"  # identifies new-format ciphertexts

# Legacy support — cached Fernet for old ciphertexts
_legacy_fernet = None


def _derive_key(salt: bytes) -> bytes:
    """Derive a Fernet key from the master encryption key + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(settings.field_encryption_key.encode()))


def _get_legacy_fernet() -> Fernet:
    """Return a Fernet instance using the old hardcoded salt (for migration)."""
    global _legacy_fernet
    if _legacy_fernet is None:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"lexnebulis-field-encryption",
            iterations=100_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(settings.field_encryption_key.encode()))
        _legacy_fernet = Fernet(key)
    return _legacy_fernet


def encrypt_field(value: Optional[str]) -> Optional[str]:
    """Encrypt a string field value. Returns None/empty for None/empty input."""
    if not value:
        return value
    salt = os.urandom(_SALT_LENGTH)
    key = _derive_key(salt)
    fernet = Fernet(key)
    ciphertext = fernet.encrypt(value.encode())
    # Format: base64($LN1$ + salt + ciphertext)
    combined = _SALT_PREFIX + salt + ciphertext
    return base64.urlsafe_b64encode(combined).decode()


def decrypt_field(value: Optional[str]) -> Optional[str]:
    """Decrypt a field value. Handles both new and legacy formats."""
    if not value:
        return value

    try:
        raw = base64.urlsafe_b64decode(value.encode())
    except Exception:
        raw = None

    # New format: starts with $LN1$ prefix
    if raw and raw[: len(_SALT_PREFIX)] == _SALT_PREFIX:
        rest = raw[len(_SALT_PREFIX) :]
        salt = rest[:_SALT_LENGTH]
        ciphertext = rest[_SALT_LENGTH:]
        key = _derive_key(salt)
        fernet = Fernet(key)
        return fernet.decrypt(ciphertext).decode()

    # Legacy format: raw Fernet token (no salt prefix)
    legacy = _get_legacy_fernet()
    return legacy.decrypt(value.encode()).decode()
