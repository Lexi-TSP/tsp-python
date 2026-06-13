# tsp-verify — Python port of the TSP reference verifier core

Verify [Trust Standard Protocol](https://truststandardprotocol.com) v3.0
evidence from Python: canonicalization (RFC 8785-style, byte-identical to the
JS reference), trust envelope and trust manifest validation, and Ed25519
local verification with the granular check profile.

```python
import json
from tsp_verify import verify_local

envelope = json.load(open("envelope.json"))
public_key = json.load(open("publickey.json"))

result = verify_local(envelope, public_key)
print(result["valid"])                    # True / False — fail-closed
print(result["checks"]["ledgerHash"])     # granular per-check verdicts
```

## Conformance is the correctness claim

This port is correct because it reproduces the normative verdicts of the
[tsp-spec](https://github.com/Lexi-TSP/tsp-spec) fixture suite — including
the ADR-0002 tamper-rejection vectors and byte-identical canonical forms —
not because anyone says so. Prove it on your machine:

```bash
python conformance/run_conformance.py
# integrity: 10 fixtures match pinned SHA256SUMS
# ... all 7 conformance vectors pass against the Python port
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

Trust is not earned. It is given — to what can be verified.
