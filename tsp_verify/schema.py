"""TrustEnvelope shape validation, ported with the reference error vocabulary.

Allowlist-only (unknown fields rejected); error strings match the JS core so
the conformance suite's errorContains vectors hold across both ports.
"""
from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlparse

TSP_V3_VERSION = "3.0"
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_DATETIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_LOWER_HEX = re.compile(r"^[a-f0-9]+$")
_SOURCE_TYPES = {"legal-database", "government-website", "official-document", "academic-paper", "verified-website", "model-knowledge", "user-input", "unknown"}
_CONTENT_TYPES = {"text", "document", "structured"}
_SEVERITIES = {"low", "med", "high"}
_SIGNATURE_ROLES = {"instance", "human-reviewer"}


def _is_record(v):
    return isinstance(v, dict)


def _is_string(v):
    return isinstance(v, str)


def _parseable_date(v: str) -> bool:
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _has_only(value, path, allowed, errors):
    for key in value:
        if key not in allowed:
            errors.append(f"{path}.{key} is not allowed")


def _record_at(parent, key, path, errors):
    v = parent.get(key)
    if not _is_record(v):
        errors.append(f"{path}.{key} must be an object")
        return None
    return v


def _array_at(parent, key, path, errors):
    v = parent.get(key)
    if not isinstance(v, list):
        errors.append(f"{path}.{key} must be an array")
        return None
    return v


def _string_at(parent, key, path, errors):
    v = parent.get(key)
    if not _is_string(v):
        errors.append(f"{path}.{key} must be a string")
        return None
    return v


def _optional_string_at(parent, key, path, errors):
    if key in parent and not _is_string(parent[key]):
        errors.append(f"{path}.{key} must be a string")


def _boolean_at(parent, key, path, errors):
    if not isinstance(parent.get(key), bool):
        errors.append(f"{path}.{key} must be a boolean")


def _number_at(parent, key, path, errors):
    v = parent.get(key)
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or v in (float("inf"), float("-inf")):
        errors.append(f"{path}.{key} must be a finite number")


def _integer_at(parent, key, path, errors):
    v = parent.get(key)
    if isinstance(v, bool) or not (isinstance(v, int) or (isinstance(v, float) and v.is_integer())):
        errors.append(f"{path}.{key} must be an integer")


def _sha256_at(parent, key, path, errors):
    v = _string_at(parent, key, path, errors)
    if v is not None and not _SHA256.match(v):
        errors.append(f"{path}.{key} must be a lowercase sha256 hex string")


def _datetime_at(parent, key, path, errors):
    v = _string_at(parent, key, path, errors)
    if v is not None and (not _DATETIME.match(v) or not _parseable_date(v)):
        errors.append(f"{path}.{key} must be an ISO-8601 date-time string")


def _lowercase_hex_at(parent, key, path, errors):
    v = _string_at(parent, key, path, errors)
    if v is not None and not _LOWER_HEX.match(v):
        errors.append(f"{path}.{key} must be lowercase hexadecimal")


def _uri_at(parent, key, path, errors):
    v = _string_at(parent, key, path, errors)
    if v is None:
        return
    parsed = urlparse(v)
    if not parsed.scheme:
        errors.append(f"{path}.{key} must be a URI")


def validate_trust_envelope_shape(value) -> list:
    errors = []
    if not _is_record(value):
        return ["envelope must be an object"]

    _has_only(value, "envelope", ["tsp", "content", "declaration", "process", "alignment", "timestamp", "ledger", "signatures", "executionProvenance"], errors)

    tsp = _string_at(value, "tsp", "envelope", errors)
    if tsp is not None and tsp != TSP_V3_VERSION:
        errors.append(f'envelope.tsp must be "{TSP_V3_VERSION}"')

    _validate_content(_record_at(value, "content", "envelope", errors), errors)
    _validate_declaration(_record_at(value, "declaration", "envelope", errors), errors)
    _validate_process(_record_at(value, "process", "envelope", errors), errors)
    _validate_alignment(_record_at(value, "alignment", "envelope", errors), errors)
    _validate_timestamp(_record_at(value, "timestamp", "envelope", errors), errors)
    _validate_ledger(_record_at(value, "ledger", "envelope", errors), errors)

    signatures = _array_at(value, "signatures", "envelope", errors)
    if signatures is not None:
        if len(signatures) == 0:
            errors.append("envelope.signatures must contain at least one entry")
        for i, entry in enumerate(signatures):
            _validate_signature(entry, f"envelope.signatures[{i}]", errors)

    if "executionProvenance" in value:
        _validate_execution_provenance(_record_at(value, "executionProvenance", "envelope", errors), errors)

    return errors


def _validate_content(value, errors):
    if not value:
        return
    _has_only(value, "content", ["type", "value", "hash"], errors)
    t = _string_at(value, "type", "content", errors)
    if t is not None and t not in _CONTENT_TYPES:
        errors.append("content.type must be text, document, or structured")
    _string_at(value, "value", "content", errors)
    _sha256_at(value, "hash", "content", errors)


def _validate_declaration(value, errors):
    if not value:
        return
    _has_only(value, "declaration", ["primarySource", "citations"], errors)
    ps = _record_at(value, "primarySource", "declaration", errors)
    if ps:
        _has_only(ps, "declaration.primarySource", ["type", "url", "title", "retrieved"], errors)
        t = _string_at(ps, "type", "declaration.primarySource", errors)
        if t is not None and t not in _SOURCE_TYPES:
            errors.append("declaration.primarySource.type is not a v3 source type")
        _optional_string_at(ps, "url", "declaration.primarySource", errors)
        _string_at(ps, "title", "declaration.primarySource", errors)
        if "retrieved" in ps:
            _datetime_at(ps, "retrieved", "declaration.primarySource", errors)
    citations = _array_at(value, "citations", "declaration", errors)
    if citations is not None:
        for i, entry in enumerate(citations):
            path = f"declaration.citations[{i}]"
            if not _is_record(entry):
                errors.append(f"{path} must be an object")
                continue
            _has_only(entry, path, ["url", "paragraph", "quote", "retrieved"], errors)
            _string_at(entry, "url", path, errors)
            _string_at(entry, "paragraph", path, errors)
            _string_at(entry, "quote", path, errors)
            _datetime_at(entry, "retrieved", path, errors)


def _validate_process(value, errors):
    if not value:
        return
    _has_only(value, "process", ["model", "systemPrompt", "pipeline"], errors)
    model = _record_at(value, "model", "process", errors)
    if model:
        _has_only(model, "process.model", ["provider", "name", "version", "temperature", "contextWindow"], errors)
        _string_at(model, "provider", "process.model", errors)
        _string_at(model, "name", "process.model", errors)
        _string_at(model, "version", "process.model", errors)
        _number_at(model, "temperature", "process.model", errors)
        _integer_at(model, "contextWindow", "process.model", errors)
        cw = model.get("contextWindow")
        if isinstance(cw, (int, float)) and not isinstance(cw, bool) and cw < 0:
            errors.append("process.model.contextWindow must be non-negative")
    _validate_system_prompt(_record_at(value, "systemPrompt", "process", errors), errors)


def _validate_system_prompt(value, errors):
    if not value:
        return
    _sha256_at(value, "hash", "process.systemPrompt", errors)
    if "text" in value:
        _has_only(value, "process.systemPrompt", ["hash", "text"], errors)
        _string_at(value, "text", "process.systemPrompt", errors)
        return
    _has_only(value, "process.systemPrompt", ["hash", "redacted", "reason"], errors)
    if value.get("redacted") is not True:
        errors.append("process.systemPrompt.redacted must be true")
    _string_at(value, "reason", "process.systemPrompt", errors)


def _validate_alignment(value, errors):
    if not value:
        return
    _has_only(value, "alignment", ["uncertainty", "flags", "humanReviewRequired", "policy", "refusal"], errors)
    uncertainty = _array_at(value, "uncertainty", "alignment", errors)
    if uncertainty is not None:
        for i, entry in enumerate(uncertainty):
            path = f"alignment.uncertainty[{i}]"
            if not _is_record(entry):
                errors.append(f"{path} must be an object")
                continue
            _has_only(entry, path, ["field", "reason", "severity"], errors)
            _string_at(entry, "field", path, errors)
            _string_at(entry, "reason", path, errors)
            sev = _string_at(entry, "severity", path, errors)
            if sev is not None and sev not in _SEVERITIES:
                errors.append(f"{path}.severity must be low, med, or high")
    _boolean_at(value, "humanReviewRequired", "alignment", errors)
    policy = _record_at(value, "policy", "alignment", errors)
    if policy:
        _has_only(policy, "alignment.policy", ["id", "version"], errors)
        _string_at(policy, "id", "alignment.policy", errors)
        _string_at(policy, "version", "alignment.policy", errors)


def _validate_timestamp(value, errors):
    if not value:
        return
    _has_only(value, "timestamp", ["claimed", "tsaToken", "tsaUrl"], errors)
    _datetime_at(value, "claimed", "timestamp", errors)
    _string_at(value, "tsaToken", "timestamp", errors)
    _uri_at(value, "tsaUrl", "timestamp", errors)


def _validate_ledger(value, errors):
    if not value:
        return
    _has_only(value, "ledger", ["id", "prevHash", "hash"], errors)
    _string_at(value, "id", "ledger", errors)
    _sha256_at(value, "prevHash", "ledger", errors)
    _sha256_at(value, "hash", "ledger", errors)


def _validate_signature(value, path, errors):
    if not _is_record(value):
        errors.append(f"{path} must be an object")
        return
    _has_only(value, path, ["role", "algorithm", "keyRef", "signature", "certChain"], errors)
    role = _string_at(value, "role", path, errors)
    if role is not None and role not in _SIGNATURE_ROLES:
        errors.append(f"{path}.role must be instance or human-reviewer")
    alg = _string_at(value, "algorithm", path, errors)
    if alg is not None and alg != "ed25519":
        errors.append(f"{path}.algorithm must be ed25519")
    _uri_at(value, "keyRef", path, errors)
    _string_at(value, "signature", path, errors)
    cert_chain = _array_at(value, "certChain", path, errors)
    if cert_chain is not None:
        for i, entry in enumerate(cert_chain):
            if not _is_string(entry):
                errors.append(f"{path}.certChain[{i}] must be a string")


def _validate_execution_provenance(value, errors):
    if not value:
        return
    _has_only(value, "executionProvenance", ["spatialBoundary", "temporalBoundary", "deterministicOutput"], errors)
    sb = _record_at(value, "spatialBoundary", "executionProvenance", errors)
    if sb:
        _has_only(sb, "executionProvenance.spatialBoundary", ["gateway", "toolsMounted", "toolsIsolated", "o1ConstraintMet"], errors)
        _string_at(sb, "gateway", "executionProvenance.spatialBoundary", errors)
        tools = _array_at(sb, "toolsMounted", "executionProvenance.spatialBoundary", errors)
        if tools is not None:
            for i, entry in enumerate(tools):
                if not _is_string(entry):
                    errors.append(f"executionProvenance.spatialBoundary.toolsMounted[{i}] must be a string")
        _boolean_at(sb, "toolsIsolated", "executionProvenance.spatialBoundary", errors)
        _boolean_at(sb, "o1ConstraintMet", "executionProvenance.spatialBoundary", errors)
    tb = _record_at(value, "temporalBoundary", "executionProvenance", errors)
    if tb:
        _has_only(tb, "executionProvenance.temporalBoundary", ["engine", "tier1AnchorHash", "totalContextTokens", "driftDetected"], errors)
        _string_at(tb, "engine", "executionProvenance.temporalBoundary", errors)
        _lowercase_hex_at(tb, "tier1AnchorHash", "executionProvenance.temporalBoundary", errors)
        _integer_at(tb, "totalContextTokens", "executionProvenance.temporalBoundary", errors)
        tct = tb.get("totalContextTokens")
        if isinstance(tct, (int, float)) and not isinstance(tct, bool) and tct < 0:
            errors.append("executionProvenance.temporalBoundary.totalContextTokens must be non-negative")
        _boolean_at(tb, "driftDetected", "executionProvenance.temporalBoundary", errors)
    det = _record_at(value, "deterministicOutput", "executionProvenance", errors)
    if det:
        _has_only(det, "executionProvenance.deterministicOutput", ["status", "payloadHash"], errors)
        _string_at(det, "status", "executionProvenance.deterministicOutput", errors)
        _lowercase_hex_at(det, "payloadHash", "executionProvenance.deterministicOutput", errors)
