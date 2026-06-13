"""verify_license() -- TSP License Artifact v1 offline verifier (ADR-0010).

Python port of the gateway's verify-license.js. Normative invariant: a license
MUST be verifiable WITHOUT contacting LexiCo -- this performs no network I/O.
Validates a tsp.license-bundle.v1 through the two-tier offline trust hierarchy
(license -> issuer -> pinned license-root), reusing the TSP crypto substrate.
Independent of verify_local() / the TrustEnvelope schema, which are untouched.

Returns {"ok": bool, "reason": str, "detail": str, ...} in a CLOSED vocabulary:
  ok True  -> "valid" | "valid_in_grace"
  ok False -> schema_invalid | unsupported_artifact | issuer_mismatch
            | license_signature_invalid | untrusted_root | issuer_credential_invalid
            | issuer_not_yet_valid | issuer_expired | license_not_yet_valid
            | license_expired | origin_mismatch | module_not_licensed
"""
from __future__ import annotations

from datetime import datetime

from .canonical import canonicalize
from .crypto import base64_to_bytes, import_public_key_jwk, verify_ed25519
from .license_domain import build_issuer_credential_signing_domain, build_license_signing_domain
from .license_schema import LICENSE_ARTIFACT_TYPE, validate_license_bundle_shape


def _fail(reason: str, detail: str) -> dict:
    return {"ok": False, "reason": reason, "detail": detail}


def _pass(reason: str, detail: str, **extra) -> dict:
    return {"ok": True, "reason": reason, "detail": detail, **extra}


def _to_epoch(value) -> float:
    """ISO-8601 string (or datetime) -> POSIX seconds. Raises on invalid input."""
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s).timestamp()


def _verify_canonical_ed25519(public_jwk: dict, signature_b64: str, body: dict) -> bool:
    public_key = import_public_key_jwk(public_jwk)
    sig = base64_to_bytes(signature_b64)
    return verify_ed25519(public_key, sig, canonicalize(body).encode("utf-8"))


def verify_license(bundle, config, now) -> dict:
    """Verify a tsp.license-bundle.v1 fully offline.

    config: {"origin": str, "trustedRootKeys": [{"rootKeyId": str, "publicKey": jwk}],
             "requiredModules": list[str] (optional)}
    now:    ISO-8601 string or datetime.
    """
    if not isinstance(config, dict):
        raise ValueError("verify_license: config must be a dict")
    origin = config.get("origin")
    if not isinstance(origin, str) or not origin:
        raise ValueError("verify_license: config['origin'] (configured trust-manifest origin) is required")
    roots = config.get("trustedRootKeys")
    if not isinstance(roots, list) or not roots:
        raise ValueError("verify_license: config['trustedRootKeys'] must be a non-empty pinned root set")
    now_s = _to_epoch(now)
    required_modules = config.get("requiredModules") or []

    errors = validate_license_bundle_shape(bundle)
    if errors:
        return _fail("schema_invalid", "; ".join(errors))

    license = bundle["license"]
    cred = bundle["issuerCredential"]["credential"]

    if license["artifact_type"] != LICENSE_ARTIFACT_TYPE:
        return _fail("unsupported_artifact", f"license.artifact_type {license['artifact_type']} is not supported")

    try:
        license_sig_ok = _verify_canonical_ed25519(
            cred["issuerPublicKey"], bundle["licenseSignature"]["signature"], build_license_signing_domain(license))
    except Exception as error:  # noqa: BLE001 - fail closed with the reason
        return _fail("license_signature_invalid", f"license signature could not be verified: {error}")
    if not license_sig_ok:
        return _fail("license_signature_invalid", "license signature does not verify against the bundled issuer key")

    root = next((r for r in roots if r.get("rootKeyId") == cred["rootKeyId"]), None)
    if root is None:
        return _fail("untrusted_root", f'issuer credential references root "{cred["rootKeyId"]}" which is not in the pinned root set')
    try:
        cred_sig_ok = _verify_canonical_ed25519(
            root["publicKey"], bundle["issuerCredential"]["rootSignature"]["signature"], build_issuer_credential_signing_domain(cred))
    except Exception as error:  # noqa: BLE001
        return _fail("issuer_credential_invalid", f"issuer credential signature could not be verified: {error}")
    if not cred_sig_ok:
        return _fail("issuer_credential_invalid", "issuer credential does not verify against the pinned license-root")

    if license["issuer_id"] != cred["issuer_id"]:
        return _fail("issuer_mismatch", f'license issuer_id "{license["issuer_id"]}" does not match credential issuer_id "{cred["issuer_id"]}"')

    if now_s < _to_epoch(cred["validFrom"]):
        return _fail("issuer_not_yet_valid", f"issuer credential not valid until {cred['validFrom']}")
    if now_s > _to_epoch(cred["validUntil"]):
        return _fail("issuer_expired", f"issuer credential expired at {cred['validUntil']}")

    if now_s < _to_epoch(license["validFrom"]):
        return _fail("license_not_yet_valid", f"license not valid until {license['validFrom']}")
    in_grace = False
    if now_s > _to_epoch(license["validUntil"]):
        grace_until = license.get("graceUntil")
        if grace_until is not None and now_s <= _to_epoch(grace_until):
            in_grace = True
        else:
            return _fail("license_expired", f"license expired at {license['validUntil']}")

    allowed = [license["subject"]["origin"], *license["subject"].get("allowedOrigins", [])]
    if origin not in allowed:
        return _fail("origin_mismatch", f'configured origin "{origin}" is not in license subject origin(s) {allowed}')

    missing = [m for m in required_modules if m not in license["modules"]]
    if missing:
        return _fail("module_not_licensed", f"required module(s) not licensed: {', '.join(missing)}")

    return _pass(
        "valid_in_grace" if in_grace else "valid",
        f"license valid (in signed grace until {license.get('graceUntil')})" if in_grace else "license verified offline",
        in_grace=in_grace,
        license={
            "license_id": license["license_id"],
            "issuer_id": license["issuer_id"],
            "edition": license["edition"],
            "origin": license["subject"]["origin"],
            "modules": license["modules"],
            "validUntil": license["validUntil"],
            "graceUntil": license.get("graceUntil"),
        },
    )
