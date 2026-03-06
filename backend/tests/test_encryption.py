"""Tests for consolidated encryption module."""

import pytest

from app.common.encryption import decrypt_field, encrypt_field


class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "sensitive-bank-account-123"
        encrypted = encrypt_field(plaintext)
        assert encrypted != plaintext
        decrypted = decrypt_field(encrypted)
        assert decrypted == plaintext

    def test_encrypt_empty_string_returns_empty(self):
        assert encrypt_field("") == ""
        assert decrypt_field("") == ""

    def test_encrypt_none_returns_none(self):
        assert encrypt_field(None) is None
        assert decrypt_field(None) is None

    def test_different_encryptions_produce_different_ciphertext(self):
        """Each encryption should use a unique random salt."""
        plaintext = "same-value"
        enc1 = encrypt_field(plaintext)
        enc2 = encrypt_field(plaintext)
        assert enc1 != enc2  # random salt makes each unique
        assert decrypt_field(enc1) == plaintext
        assert decrypt_field(enc2) == plaintext

    def test_tampered_ciphertext_raises(self):
        encrypted = encrypt_field("test-value")
        tampered = encrypted[:-5] + "XXXXX"
        with pytest.raises(Exception):
            decrypt_field(tampered)

    def test_legacy_ciphertext_still_decryptable(self):
        """Backward compatibility: old Fernet tokens (no salt prefix) still work."""
        from app.common.encryption import _get_legacy_fernet

        legacy_fernet = _get_legacy_fernet()
        legacy_encrypted = legacy_fernet.encrypt(b"legacy-secret").decode()
        # decrypt_field should try new format first, fall back to legacy
        result = decrypt_field(legacy_encrypted)
        assert result == "legacy-secret"
