"""SHA-256 hex of a UTF-8 string, matching the reference core."""
import hashlib


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
