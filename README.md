> ## ⚠️ TSP public alpha preview
>
> This repository contains historical TSP alpha-preview materials. It is not a final TSP release, is not certified for production use, and does not grant any right to claim TSP compatibility, TSP certification, TrustBadge authorization, or participation in the official TSP integrity domain.
>
> TSP v3.1+ is governed by the LexiCo TSP License and official conformance process.

<!-- tsp-alpha-banner:end -->

# tsp-verify — Python port of the TSP reference verifier core

Verify [Trust Standard Protocol](https://truststandardprotocol.com) v3.0
evidence from Python: canonicalization (RFC 8785-style, byte-identical to the
JS reference), trust envelope and trust manifest validation, and Ed25519
local verification with the granular check profile.

## Install

```bash
python -m pip install tsp-verify
# For the current public alpha pin:
python -m pip install tsp-verify==0.1.0
```

Requires Python >=3.10 and installs one runtime dependency,
`cryptography>=42`, because Python's standard library has no Ed25519.

```python
import json
from tsp_verify import verify_local

envelope = json.load(open("envelope.json"))
public_key = json.load(open("publickey.json"))

result = verify_local(envelope, public_key)
print(result["valid"])                    # True / False — fail-closed
print(result["checks"]["ledgerHash"])     # granular per-check verdicts
```

It also verifies **commercial licenses** (TSP License Artifact v1, ADR-0010) —
a sibling artifact validated fully offline through `license -> issuer -> pinned
license-root`, reusing the same crypto substrate:

```python
from tsp_verify import verify_license

result = verify_license(
    bundle,                                   # a tsp.license-bundle.v1
    {"origin": "https://customer.example",    # this deployment's manifest origin
     "trustedRootKeys": [pinned_root],        # {"rootKeyId", "publicKey"} set
     "requiredModules": ["gateway-pro"]},     # default-deny per module
    now="2026-07-01T00:00:00.000Z",
)
print(result["ok"], result["reason"])         # e.g. True "valid", or False "license_expired"
```

## Conformance is the correctness claim

This port is correct because it reproduces the normative verdicts of the
[tsp-spec](https://github.com/Lexi-TSP/tsp-spec) fixture suite — including
the ADR-0002 tamper-rejection vectors, the ADR-0010 license vectors, and
byte-identical canonical forms —
not because anyone says so. Prove it on your machine:

```bash
python conformance/run_conformance.py
# integrity: 10 fixtures match pinned SHA256SUMS
# ... all 23 conformance vectors pass against the Python port (v3.0 + license)
```

A failure of that runner is a bug in this port, never grounds to adjust the
fixtures (ADR-0008: the spec owns the truth).

## One dependency, declared honestly

Python's standard library has no Ed25519, so this port carries exactly one
runtime dependency: [`cryptography`](https://cryptography.io). Everything
else — canonicalization, hashing, schema and manifest validation — is
stdlib. Verification only: this package holds no private keys and signs
nothing.

## Scope

Local verification (schema, content hash, ledger hash, signatures). The
online plane (manifest resolution, key binding, revocation, rollback) is
implemented in the JS reference core and specified by tsp-spec's online
vectors; a Python online port follows. Local-only caveat: `signature.keyRef`
is carried but **not** authenticated — key binding is an online-mode
property.

## Releasing

Publishing is automated through GitHub Actions and PyPI Trusted Publishing.
To cut a release:

1. Keep `pyproject.toml` and `tsp_verify/__init__.py` on the same version.
2. Merge the release workflow changes to `main` after CI and conformance pass.
3. Tag the `main` commit with `v0.1.0` and push the tag.

The `Release (PyPI)` workflow runs unit tests, fixture conformance,
`python -m build`, `twine check`, verifies that the tag matches
`pyproject.toml`, and publishes to PyPI using the repository's trusted
publisher identity. PyPI versions are immutable, so every future release
needs a new version number.

Trust is not earned. It is given — to what can be verified.
