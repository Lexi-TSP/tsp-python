"""TSP License Artifact v1 signing-domain construction -- SINGLE SOURCE.

Python port of the gateway's license-domain.js (ADR-0010). A license is a
SIBLING artifact: it reuses the TSP crypto substrate (canonicalize / Ed25519)
and nothing of the TrustEnvelope semantics. The license and issuer-credential
bodies are CLOSED allowlists (see license_schema.py), so each signature covers
its ENTIRE validated body -- schema validation MUST run before signature
verification so an injected unknown field is rejected structurally.
"""
from __future__ import annotations


def build_license_signing_domain(license: dict) -> dict:
    """Domain for the issuer-signed license signature: the whole license body."""
    return license


def build_issuer_credential_signing_domain(credential: dict) -> dict:
    """Domain for the root-signed issuer-credential signature: the whole credential body."""
    return credential
