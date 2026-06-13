#!/usr/bin/env python3
"""TSP conformance runner for the Python port.

Runs the checksum-pinned tsp-spec fixture suites through this port and asserts
the normative per-vector profiles. Two SEPARATE suites (ADR-0010): the v3.0
TrustEnvelope vectors and the tsp.license.v1 vectors, each with its own
SHA256SUMS, never mixed. Exit 0 only if every snapshot is intact AND every
vector matches. A failure here means THIS PORT is wrong (ADR-0008) -- fix the
port, never the fixtures.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tsp_verify import (  # noqa: E402
    canonicalize, sha256_hex, validate_trust_envelope_shape, verify_local, verify_license,
)

SNAPSHOT = HERE / "spec-snapshot"
FIXTURES = SNAPSHOT / "fixtures" / "v3.0"
LICENSE_FIXTURES = SNAPSHOT / "fixtures" / "license-v1"


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_sums(sums_path: Path):
    """Verify a SHA256SUMS file; rel paths are resolved against SNAPSHOT."""
    mismatches = []
    lines = [l.strip() for l in sums_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for line in lines:
        m = re.match(r"^([a-f0-9]{64})\s+(.+)$", line)
        if not m:
            mismatches.append(f"unparseable SHA256SUMS line: {line}")
            continue
        expected, rel = m.groups()
        target = SNAPSHOT / Path(*rel.split("/"))
        try:
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError as error:
            mismatches.append(f"{rel}: cannot read ({error})")
            continue
        if actual != expected:
            mismatches.append(f"{rel}: checksum drift -- expected {expected}, got {actual}")
    return len(lines), mismatches


def root_keys_in_document_order(raw: str):
    keys, depth, i = [], 0, 0
    while i < len(raw):
        ch = raw[i]
        if ch == '"':
            j, escaped = i + 1, False
            while j < len(raw):
                c = raw[j]
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    break
                j += 1
            if depth == 1:
                m = j + 1
                while m < len(raw) and raw[m].isspace():
                    m += 1
                if m < len(raw) and raw[m] == ":":
                    keys.append(raw[i + 1:j])
            i = j
        elif ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        i += 1
    return keys


def run_vector(vec):
    raw = (FIXTURES / vec["file"]).read_text(encoding="utf-8")
    envelope = json.loads(raw)
    fails = []
    kind = vec["kind"]

    if kind == "cryptographic":
        key = read_json(FIXTURES / vec["key"])
        result = verify_local(envelope, key)
        expect = vec["expect"]
        if result["valid"] != expect["valid"]:
            fails.append(f"valid: expected {expect['valid']}, got {result['valid']}")
        for name, want in expect["checks"].items():
            if name == "signatures":
                for i, w in enumerate(want):
                    got = result["checks"]["signatures"][i]["status"] if i < len(result["checks"]["signatures"]) else None
                    if got != w:
                        fails.append(f"signatures[{i}]: expected {w}, got {got}")
            else:
                got = result["checks"].get(name, {}).get("status")
                if got != want:
                    fails.append(f"{name}: expected {want}, got {got}")
        return fails

    if kind == "canonical-hash":
        got = sha256_hex(canonicalize(envelope["content"]["value"]))
        if got != vec["expect"]["contentValueHash"]:
            fails.append(f"sha256(canonicalize(content.value)): expected {vec['expect']['contentValueHash']}, got {got}")
        if vec["expect"].get("schema") == "passed" and validate_trust_envelope_shape(envelope):
            fails.append("schema: expected passed, got failed")
        return fails

    if kind == "canonical-equivalence":
        ref = read_json(FIXTURES / vec["reference"])
        a, b = canonicalize(envelope), canonicalize(ref)
        if a != b:
            fails.append(f"canonicalize({vec['file']}) != canonicalize({vec['reference']})")
        if sha256_hex(a) != sha256_hex(b):
            fails.append("sha256 of canonical forms differ")
        return fails

    if kind == "schema-invalid":
        errors = validate_trust_envelope_shape(envelope)
        if not errors:
            fails.append("schema: expected failed, got passed")
        needle = vec.get("expect", {}).get("errorContains")
        if needle and not any(needle in e for e in errors):
            fails.append(f'expected a schema error containing "{needle}"; got: {"; ".join(errors)}')
        return fails

    if kind == "structural-unsorted":
        keys = root_keys_in_document_order(raw)
        if keys == sorted(keys, key=lambda k: k.encode("utf-16-be")):
            fails.append("document order equals canonical order -- JCS sort trap not exercised")
        return fails

    return [f"unknown kind: {kind}"]


def run_license_vector(vec, trusted_root_keys):
    bundle = read_json(LICENSE_FIXTURES / vec["file"])
    config = {
        "origin": vec["origin"],
        "trustedRootKeys": trusted_root_keys,
        "requiredModules": vec.get("requiredModules", []),
    }
    result = verify_license(bundle, config, vec["now"])
    fails = []
    if result["ok"] != vec["expect"]["ok"]:
        fails.append(f"ok: expected {vec['expect']['ok']}, got {result['ok']} ({result['reason']}: {result['detail']})")
    if result["reason"] != vec["expect"]["reason"]:
        fails.append(f"reason: expected {vec['expect']['reason']}, got {result['reason']}")
    return fails


def main():
    failed = 0

    # ----- v3.0 TrustEnvelope suite -----
    spec = read_json(SNAPSHOT / "expectations.json")
    print(f"TSP Python-port conformance -- wire tsp \"{spec['tsp']}\" - maturity \"{spec['specMaturity']}\"")
    count, mismatches = verify_sums(FIXTURES / "SHA256SUMS")
    if mismatches:
        print(f"v3.0 snapshot integrity FAILED ({len(mismatches)}/{count}):")
        for m in mismatches:
            print("   ", m)
        sys.exit(1)
    print(f"integrity: {count} v3.0 fixtures match pinned SHA256SUMS")
    for vec in spec["vectors"]:
        fails = run_vector(vec)
        if fails:
            failed += 1
            print(f"FAIL  {vec['file']}  [{vec['kind']}]")
            for f in fails:
                print("       ", f)
        else:
            print(f"PASS  {vec['file']}  [{vec['kind']}]")

    # ----- TSP License Artifact v1 suite (ADR-0010; separate track) -----
    lic = read_json(SNAPSHOT / "license-expectations.json")
    print(f"\nlicense conformance -- artifact \"{lic['artifact']}\"")
    lcount, lmismatches = verify_sums(LICENSE_FIXTURES / "SHA256SUMS")
    if lmismatches:
        print(f"license snapshot integrity FAILED ({len(lmismatches)}/{lcount}):")
        for m in lmismatches:
            print("   ", m)
        sys.exit(1)
    print(f"integrity: {lcount} license fixtures match pinned SHA256SUMS")
    root_file = read_json(LICENSE_FIXTURES / lic["rootKey"])
    trusted_root_keys = [{"rootKeyId": root_file["rootKeyId"], "publicKey": root_file["publicKey"]}]
    for vec in lic["vectors"]:
        fails = run_license_vector(vec, trusted_root_keys)
        if fails:
            failed += 1
            print(f"FAIL  {vec['file']}  [{vec['expect']['reason']}]")
            for f in fails:
                print("       ", f)
        else:
            print(f"PASS  {vec['file']}  [{vec['expect']['reason']}]")

    total = len(spec["vectors"]) + len(lic["vectors"])
    if failed == 0:
        print(f"\nall {total} conformance vectors pass against the Python port")
        sys.exit(0)
    print(f"\n{failed}/{total} vectors diverge -- this port is wrong until fixed (ADR-0008)")
    sys.exit(1)


if __name__ == "__main__":
    main()
