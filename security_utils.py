import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


def _load_fernet() -> Optional[Fernet]:
    """Create a Fernet instance from DATA_ENCRYPTION_KEY if provided."""
    key = os.environ.get("DATA_ENCRYPTION_KEY")
    if not key:
        logger.warning("DATA_ENCRYPTION_KEY not set; sensitive fields will be stored unencrypted")
        return None

    try:
        return Fernet(key)
    except Exception as exc:  # pragma: no cover - defensive log path
        logger.error("Invalid DATA_ENCRYPTION_KEY provided; encryption disabled", exc_info=exc)
        return None


_fernet = _load_fernet()


def encryption_enabled() -> bool:
    """Return True when a valid encryption key is available."""
    return _fernet is not None


def encrypt_str(value: Optional[str]) -> Optional[str]:
    """Encrypt a string value using Fernet; return original when encryption is unavailable."""
    if not value:
        return value
    if not _fernet:
        return value

    token = _fernet.encrypt(value.encode("utf-8"))
    return f"enc::{token.decode('utf-8')}"


def decrypt_str(value: Optional[str]) -> Optional[str]:
    """Decrypt a string value previously encrypted; transparently return plaintext when unencrypted."""
    if not value:
        return value
    if not _fernet:
        return value

    if not value.startswith("enc::"):
        return value

    token = value.replace("enc::", "", 1).encode("utf-8")
    try:
        return _fernet.decrypt(token).decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt value; token invalid")
        return None
    except Exception as exc:  # pragma: no cover - defensive log path
        logger.error("Unexpected error decrypting value", exc_info=exc)
        return None
