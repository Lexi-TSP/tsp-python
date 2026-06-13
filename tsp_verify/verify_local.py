"""TSP v3.0 local verification -- Python port of the reference verifier core.

Same check vocabulary and granular profiles as the JS core; conformant
because it reproduces the spec fixture verdicts (run the conformance runner),
never because it is trusted. Local-only mode: signature.keyRef is carried but
NOT authenticated; key binding to a published manifest is an online-mode
property.
"""
from __future__ import annotations

from .canonical import canonicalize
from .crypto import base64_to_bytes, import_public_key_jwk, verify_ed25519
from .domains import build_ledger_domain, build_signature_domain
from .hash import sha256_hex
from .schema import validate_trust_envelope_shape


def _passed(detail):
    return {"status": "passed", "detail": detail}


def _failed(detail, evidence=None):
    out = {"status": "failed", "detail": detail}
    if evidence is not None:
        out["evidence"] = evidence
    return out


def _skipped(detail):
    return {"status": "skipped", "detail": detail}


def _initial_checks():
    return {
        "schema": _skipped("not yet checked"),
        "contentHash": _skipped("not yet checked"),
        "ledgerHash": _skipped("not yet checked"),
        "manifestFetch": _skipped("local-only mode: manifest fetch not performed"),
        "rootSignature": _skipped("local-only mode: root signature not verified"),
        "certChain": _skipped("local-only mode: cert chain not validated"),
        "certValidity": _skipped("local-only mode: cert validity not checked"),
        "revocation": _skipped("local-only mode: revocation not checked"),
        "tsa": _skipped("local-only mode: TSA token not verified"),
        "signatures": [],
    }


def verify_local(envelope, known_public_key) -> dict:
    checks = _initial_checks()
    warnings = []

    schema_errors = validate_trust_envelope_shape(envelope)
    if schema_errors:
        checks["schema"] = _failed("schema validation failed: " + "; ".join(schema_errors), schema_errors)
        return {"valid": False, "envelope": envelope, "checks": checks, "warnings": warnings}
    checks["schema"] = _passed("schema is well-formed")

    expected_content_hash = sha256_hex(canonicalize(envelope["content"]["value"]))
    if expected_content_hash == envelope["content"]["hash"]:
        checks["contentHash"] = _passed("content hash matches canonical(value)")
    else:
        checks["contentHash"] = _failed(
            f"content hash mismatch: claimed {envelope['content']['hash']}, computed {expected_content_hash}")

    expected_ledger_hash = sha256_hex(canonicalize(build_ledger_domain(envelope)))
    if expected_ledger_hash == envelope["ledger"]["hash"]:
        checks["ledgerHash"] = _passed("ledger hash matches canonical(envelope without ledger.hash)")
    else:
        checks["ledgerHash"] = _failed(
            f"ledger hash mismatch: claimed {envelope['ledger']['hash']}, computed {expected_ledger_hash}")

    for signature in envelope["signatures"]:
        if signature.get("algorithm") != "ed25519":
            checks["signatures"].append(_failed(f"unsupported algorithm: {signature.get('algorithm')}"))
            continue
        try:
            public_key = import_public_key_jwk(known_public_key)
        except Exception as error:  # noqa: BLE001 - fail closed with the reason
            checks["signatures"].append(_failed(f"could not import known public key: {error}"))
            continue
        try:
            signature_bytes = base64_to_bytes(signature["signature"])
        except Exception as error:  # noqa: BLE001
            checks["signatures"].append(_failed(f"signature is not valid base64: {error}"))
            continue
        ok = verify_ed25519(
            public_key, signature_bytes,
            canonicalize(build_signature_domain(envelope)).encode("utf-8"))
        if ok:
            checks["signatures"].append(_passed(
                f"signature valid (role={signature.get('role')}, algorithm={signature.get('algorithm')})"))
        else:
            checks["signatures"].append(_failed(
                f"signature invalid (role={signature.get('role')}, algorithm={signature.get('algorithm')})"))

    warnings.append("local-only verify: manifest, cert-chain, TSA, DANE, and revocation checks are not performed")
    warnings.append("local-only verify: signature.keyRef is carried but NOT authenticated -- key-ref binding is an online-mode property")

    required = [checks["schema"], checks["contentHash"], checks["ledgerHash"], *checks["signatures"]]
    valid = all(c["status"] == "passed" for c in required)
    return {"valid": valid, "envelope": envelope, "checks": checks, "warnings": warnings}
