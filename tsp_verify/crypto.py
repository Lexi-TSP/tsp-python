"""Ed25519 verification via the `cryptography` package.

The single runtime dependency of this port: Python's standard library has no
Ed25519, so we pin one well-audited implementation rather than pretend
otherwise. Verification only -- this module holds no private keys.
"""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


def base64_to_bytes(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded)


def import_public_key_jwk(jwk: dict) -> Ed25519PublicKey:
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("public key JWK must be OKP/Ed25519")
    x = jwk.get("x")
    if not isinstance(x, str) or not x:
        raise ValueError("public key JWK is missing x")
    return Ed25519PublicKey.from_public_bytes(_b64url_decode(x))


def verify_ed25519(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    try:
        public_key.verify(signature, data)
        return True
    except InvalidSignature:
        return False
