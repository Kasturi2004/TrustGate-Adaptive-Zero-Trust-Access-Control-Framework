"""Authenticated encryption for TOTP secrets stored by TrustGate."""

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings, get_settings

_NONCE_SIZE = 12
_KEY_SIZE = 32
_CONFIGURATION_ERROR = "TOTP secret encryption is not configured correctly"
_DECRYPTION_ERROR = "Stored TOTP secret could not be decrypted"


def _cipher(settings: Settings) -> AESGCM:
    configured_key = settings.totp_secret_encryption_key
    if configured_key is None:
        raise RuntimeError(_CONFIGURATION_ERROR)
    try:
        encoded_key = configured_key.get_secret_value().encode("ascii")
        if len(encoded_key) != 44 or not encoded_key.endswith(b"="):
            raise ValueError
        key = base64.b64decode(encoded_key, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise RuntimeError(_CONFIGURATION_ERROR) from None
    if len(key) != _KEY_SIZE or base64.urlsafe_b64encode(key) != encoded_key:
        raise RuntimeError(_CONFIGURATION_ERROR)
    return AESGCM(key)


def encrypt_totp_secret(secret: str, *, settings: Settings | None = None) -> bytes:
    """Encrypt a TOTP seed into nonce-prefixed AES-256-GCM ciphertext."""
    if not secret:
        raise ValueError("TOTP secret must not be empty")
    cipher = _cipher(settings or get_settings())
    nonce = os.urandom(_NONCE_SIZE)
    try:
        plaintext = secret.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("TOTP secret must be valid UTF-8") from None
    return nonce + cipher.encrypt(nonce, plaintext, None)


def decrypt_totp_secret(ciphertext: bytes, *, settings: Settings | None = None) -> str:
    """Decrypt a stored TOTP seed without exposing cryptographic error details."""
    cipher = _cipher(settings or get_settings())
    if len(ciphertext) <= _NONCE_SIZE:
        raise RuntimeError(_DECRYPTION_ERROR)
    nonce, encrypted = ciphertext[:_NONCE_SIZE], ciphertext[_NONCE_SIZE:]
    try:
        return cipher.decrypt(nonce, encrypted, None).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError):
        raise RuntimeError(_DECRYPTION_ERROR) from None
