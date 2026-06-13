"""tsp_verify -- Python port of the TSP v3.0 reference verifier core.

Normative authority is Lexi-TSP/tsp-spec (ADR-0008): this port is conformant
because it reproduces the spec's fixture verdicts, not because it is trusted.
Run conformance/run_conformance.py to prove it on your machine.
"""
from .canonical import canonicalize
from .hash import sha256_hex
from .schema import validate_trust_envelope_shape
from .manifest import validate_trust_manifest
from .verify_local import verify_local
from .license_schema import validate_license_bundle_shape
from .verify_license import verify_license

__version__ = "0.1.0"
__all__ = [
    "canonicalize", "sha256_hex", "validate_trust_envelope_shape",
    "validate_trust_manifest", "verify_local",
    "validate_license_bundle_shape", "verify_license",
]
