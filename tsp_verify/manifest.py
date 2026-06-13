"""Trust manifest validation, ported with the reference error vocabulary.

Key-material rule: public manifests must never contain private JWK parameters
or symmetric key material -- presence alone is rejected, even when empty.
"""
from __future__ import annotations

import re
from datetime import datetime

_PRIVATE_JWK_PARAMETERS = ["d", "p", "q", "dp", "dq", "qi", "oth"]
_MANIFEST_FIELDS = ["tsp", "organization", "rootKey", "instances", "revoked", "sequence", "issuedAt", "acceptableAge", "rootSignatureOverManifest"]
_PUBLIC_JWK_FIELDS = ["kty", "crv", "x", "alg", "use", "kid", "ext", "key_ops"]
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")


def _is_record(v):
    return isinstance(v, dict)


def _is_string(v):
    return isinstance(v, str)


def _has_only(value, path, allowed, errors):
    for key in value:
        if key not in allowed:
            errors.append(f"{path}.{key} is not allowed")


def _require_record(parent, key, path, errors):
    v = parent.get(key)
    if not _is_record(v):
        errors.append(f"{path}.{key} must be an object")
        return None
    return v


def _require_string(parent, key, path, errors):
    v = parent.get(key)
    if not _is_string(v) or len(v) == 0:
        errors.append(f"{path}.{key} must be a non-empty string")
        return None
    return v


def _require_iso_datetime(parent, key, path, errors):
    v = _require_string(parent, key, path, errors)
    if v is not None:
        ok = bool(_ISO.match(v))
        if ok:
            try:
                datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                ok = False
        if not ok:
            errors.append(f"{path}.{key} must be an ISO-8601 date-time string")


def _validate_public_jwk(jwk, path, errors):
    if not _is_record(jwk):
        errors.append(f"{path} must be an object")
        return
    _has_only(jwk, path, _PUBLIC_JWK_FIELDS, errors)
    private = [p for p in _PRIVATE_JWK_PARAMETERS if p in jwk]
    if private:
        errors.append(f"{path} must not contain private JWK parameter(s): {', '.join(private)}")
    if jwk.get("kty") == "oct" or "k" in jwk:
        errors.append(f"{path} must not contain symmetric key material")
    if jwk.get("kty") != "OKP":
        errors.append(f"{path}.kty must be OKP for Ed25519 public keys")
    if jwk.get("crv") != "Ed25519":
        errors.append(f"{path}.crv must be Ed25519")
    x = jwk.get("x")
    if not _is_string(x) or len(x) == 0:
        errors.append(f"{path}.x must be a non-empty public key value")
    alg = jwk.get("alg")
    if alg is not None and alg not in ("Ed25519", "EdDSA"):
        errors.append(f"{path}.alg must be Ed25519 or EdDSA when present")


def validate_trust_manifest(manifest) -> dict:
    errors = []
    if not _is_record(manifest):
        return {"errors": ["manifest must be a JSON object"], "ok": False}

    _has_only(manifest, "manifest", _MANIFEST_FIELDS, errors)
    if manifest.get("tsp") != "3.0":
        errors.append('manifest.tsp must be "3.0"')

    org = _require_record(manifest, "organization", "manifest", errors)
    if org:
        _has_only(org, "manifest.organization", ["name", "domain"], errors)
        _require_string(org, "name", "manifest.organization", errors)
        _require_string(org, "domain", "manifest.organization", errors)

    _validate_public_jwk(manifest.get("rootKey"), "manifest.rootKey", errors)

    instances = manifest.get("instances")
    if not isinstance(instances, list) or len(instances) == 0:
        errors.append("manifest.instances must be a non-empty array")
    else:
        seen = set()
        for i, instance in enumerate(instances):
            path = f"manifest.instances[{i}]"
            if not _is_record(instance):
                errors.append(f"{path} must be an object")
                continue
            _has_only(instance, path, ["id", "publicKey", "validFrom", "validUntil", "rootSignature"], errors)
            _require_string(instance, "id", path, errors)
            _validate_public_jwk(instance.get("publicKey"), f"{path}.publicKey", errors)
            _require_iso_datetime(instance, "validFrom", path, errors)
            _require_iso_datetime(instance, "validUntil", path, errors)
            _require_string(instance, "rootSignature", path, errors)
            iid = instance.get("id")
            if _is_string(iid):
                if iid in seen:
                    errors.append(f'manifest.instances contains duplicate instance id "{iid}"')
                seen.add(iid)

    revoked = manifest.get("revoked")
    if not isinstance(revoked, list):
        errors.append("manifest.revoked must be an array")
    else:
        for i, entry in enumerate(revoked):
            path = f"manifest.revoked[{i}]"
            if not _is_record(entry):
                errors.append(f"{path} must be an object")
                continue
            _has_only(entry, path, ["id", "revokedAt", "reason"], errors)
            _require_string(entry, "id", path, errors)
            _require_iso_datetime(entry, "revokedAt", path, errors)
            _require_string(entry, "reason", path, errors)

    seq = manifest.get("sequence")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        errors.append("manifest.sequence must be a non-negative integer")

    _require_iso_datetime(manifest, "issuedAt", "manifest", errors)
    age = _require_record(manifest, "acceptableAge", "manifest", errors)
    if age:
        _has_only(age, "manifest.acceptableAge", ["seconds"], errors)
        seconds = age.get("seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds <= 0:
            errors.append("manifest.acceptableAge.seconds must be a positive number")
    _require_string(manifest, "rootSignatureOverManifest", "manifest", errors)

    return {"errors": errors, "ok": len(errors) == 0}
