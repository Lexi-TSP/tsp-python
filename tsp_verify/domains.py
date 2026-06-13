"""Canonical signing/ledger domain construction -- SINGLE SOURCE for this port.

The domain rule is a crypto invariant (ADR-0002): executionProvenance is bound
into both domains; optional envelope fields are included iff present.
Semantics pinned by the tsp-spec v3.0 fixture suite; normative authority is
tsp-spec per ADR-0008.
"""
from __future__ import annotations


def build_ledger_domain(envelope: dict) -> dict:
    domain = {
        "tsp": envelope["tsp"],
        "content": envelope["content"],
        "process": envelope["process"],
        "signatures": envelope["signatures"],
        "ledger": {"id": envelope["ledger"]["id"], "prevHash": envelope["ledger"]["prevHash"]},
    }
    for key in ("declaration", "alignment", "timestamp", "executionProvenance"):
        if key in envelope:
            domain[key] = envelope[key]
    return domain


def build_signature_domain(envelope: dict) -> dict:
    domain = {
        "tsp": envelope["tsp"],
        "content": envelope["content"],
        "process": envelope["process"],
        "ledger": {"id": envelope["ledger"]["id"], "prevHash": envelope["ledger"]["prevHash"]},
    }
    for key in ("declaration", "alignment"):
        if key in envelope:
            domain[key] = envelope[key]
    if "timestamp" in envelope:
        domain["timestamp"] = {
            "claimed": envelope["timestamp"].get("claimed"),
            "tsaUrl": envelope["timestamp"].get("tsaUrl"),
        }
    if "executionProvenance" in envelope:
        domain["executionProvenance"] = envelope["executionProvenance"]
    return domain
