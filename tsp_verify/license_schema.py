"""TSP License Artifact v1 structural/shape validation (ADR-0010).

Python port of the gateway's license-schema.js: a closed-allowlist validator
for tsp.license-bundle.v1 and its two signed bodies. Independent of
validate_trust_envelope_shape() -- never merge the two.
"""
from __future__ import annotations

import re

_LICENSE_ARTIFACT = "tsp.license.v1"
_ISSUER_CRED_ARTIFACT = "tsp.license-issuer-credential.v1"
_BUNDLE_ARTIFACT = "tsp.license-bundle.v1"

_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_EDITIONS = {"trial", "pro", "enterprise"}
_PRIVATE_JWK_PARAMS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


def _is_record(v) -> bool:
    return isinstance(v, dict)


def _is_string(v) -> bool:
    return isinstance(v, str)


def _has_only(value: dict, path: str, allowed, errors: list) -> None:
    allowed_set = set(allowed)
    for key in value:
        if key not in allowed_set:
            errors.append(f"{path}.{key} is not allowed")


def _record_at(parent: dict, key: str, path: str, errors: list):
    v = parent.get(key)
    if not _is_record(v):
        errors.append(f"{path}.{key} must be an object")
        return None
    return v


def _string_at(parent: dict, key: str, path: str, errors: list):
    v = parent.get(key)
    if not _is_string(v) or v == "":
        errors.append(f"{path}.{key} must be a non-empty string")
        return None
    return v


def _datetime_at(parent: dict, key: str, path: str, errors: list) -> None:
    v = _string_at(parent, key, path, errors)
    if v is not None and not _DATETIME_RE.match(v):
        errors.append(f"{path}.{key} must be an ISO-8601 date-time string")


def _optional_datetime_at(parent: dict, key: str, path: str, errors: list) -> None:
    if parent.get(key) is not None:
        _datetime_at(parent, key, path, errors)


def _string_array_at(parent: dict, key: str, path: str, errors: list, optional: bool = False) -> None:
    v = parent.get(key)
    if v is None and optional:
        return
    if not isinstance(v, list):
        errors.append(f"{path}.{key} must be an array")
        return
    for i, entry in enumerate(v):
        if not _is_string(entry):
            errors.append(f"{path}.{key}[{i}] must be a string")


def _ed25519_public_jwk_at(parent: dict, key: str, parent_path: str, errors: list) -> None:
    jwk = parent.get(key)
    if not _is_record(jwk):
        errors.append(f"{parent_path}.{key} must be an object")
        return
    path = f"{parent_path}.{key}"
    _has_only(jwk, path, ["kty", "crv", "x", "alg", "use", "kid", "ext", "key_ops"], errors)
    priv = [k for k in _PRIVATE_JWK_PARAMS if k in jwk]
    if priv:
        errors.append(f"{path} must not contain private JWK parameter(s): {', '.join(priv)}")
    if jwk.get("kty") != "OKP":
        errors.append(f"{path}.kty must be OKP for Ed25519 public keys")
    if jwk.get("crv") != "Ed25519":
        errors.append(f"{path}.crv must be Ed25519")
    x = jwk.get("x")
    if not _is_string(x) or x == "":
        errors.append(f"{path}.x must be a non-empty public key value")
    if jwk.get("alg") is not None and jwk.get("alg") not in ("Ed25519", "EdDSA"):
        errors.append(f"{path}.alg must be Ed25519 or EdDSA when present")


def _signature_block_at(parent: dict, key: str, parent_path: str, errors: list) -> None:
    block = _record_at(parent, key, parent_path, errors)
    if block is None:
        return
    path = f"{parent_path}.{key}"
    _has_only(block, path, ["algorithm", "signature"], errors)
    alg = _string_at(block, "algorithm", path, errors)
    if alg is not None and alg != "ed25519":
        errors.append(f"{path}.algorithm must be ed25519")
    _string_at(block, "signature", path, errors)


def _validate_license_body(license, errors: list) -> None:
    if not license:
        return
    _has_only(
        license, "license",
        ["artifact_type", "license_id", "issuer_id", "subject", "edition", "modules", "features", "issuedAt", "validFrom", "validUntil", "graceUntil"],
        errors,
    )
    at = _string_at(license, "artifact_type", "license", errors)
    if at is not None and at != _LICENSE_ARTIFACT:
        errors.append(f'license.artifact_type must be "{_LICENSE_ARTIFACT}"')
    _string_at(license, "license_id", "license", errors)
    _string_at(license, "issuer_id", "license", errors)
    subject = _record_at(license, "subject", "license", errors)
    if subject:
        _has_only(subject, "license.subject", ["origin", "allowedOrigins", "organization"], errors)
        _string_at(subject, "origin", "license.subject", errors)
        _string_at(subject, "organization", "license.subject", errors)
        _string_array_at(subject, "allowedOrigins", "license.subject", errors, optional=True)
    edition = _string_at(license, "edition", "license", errors)
    if edition is not None and edition not in _EDITIONS:
        errors.append("license.edition must be trial, pro, or enterprise")
    _string_array_at(license, "modules", "license", errors)
    _string_array_at(license, "features", "license", errors, optional=True)
    _datetime_at(license, "issuedAt", "license", errors)
    _datetime_at(license, "validFrom", "license", errors)
    _datetime_at(license, "validUntil", "license", errors)
    _optional_datetime_at(license, "graceUntil", "license", errors)


def _validate_issuer_credential(ic, errors: list) -> None:
    if not ic:
        return
    _has_only(ic, "issuerCredential", ["credential", "rootSignature"], errors)
    cred = _record_at(ic, "credential", "issuerCredential", errors)
    if cred:
        _has_only(cred, "issuerCredential.credential", ["artifact_type", "issuer_id", "issuerPublicKey", "validFrom", "validUntil", "rootKeyId"], errors)
        at = _string_at(cred, "artifact_type", "issuerCredential.credential", errors)
        if at is not None and at != _ISSUER_CRED_ARTIFACT:
            errors.append(f'issuerCredential.credential.artifact_type must be "{_ISSUER_CRED_ARTIFACT}"')
        _string_at(cred, "issuer_id", "issuerCredential.credential", errors)
        _ed25519_public_jwk_at(cred, "issuerPublicKey", "issuerCredential.credential", errors)
        _datetime_at(cred, "validFrom", "issuerCredential.credential", errors)
        _datetime_at(cred, "validUntil", "issuerCredential.credential", errors)
        _string_at(cred, "rootKeyId", "issuerCredential.credential", errors)
    _signature_block_at(ic, "rootSignature", "issuerCredential", errors)


def validate_license_bundle_shape(value) -> list:
    errors: list = []
    if not _is_record(value):
        return ["bundle must be an object"]
    _has_only(value, "bundle", ["artifact_type", "license", "licenseSignature", "issuerCredential"], errors)
    at = _string_at(value, "artifact_type", "bundle", errors)
    if at is not None and at != _BUNDLE_ARTIFACT:
        errors.append(f'bundle.artifact_type must be "{_BUNDLE_ARTIFACT}"')
    _validate_license_body(_record_at(value, "license", "bundle", errors), errors)
    _signature_block_at(value, "licenseSignature", "bundle", errors)
    _validate_issuer_credential(_record_at(value, "issuerCredential", "bundle", errors), errors)
    return errors


LICENSE_ARTIFACT_TYPE = _LICENSE_ARTIFACT
