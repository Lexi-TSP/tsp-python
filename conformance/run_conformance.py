#!/usr/bin/env python3
"""TSP v3.0 conformance runner for the Python port.

Runs the checksum-pinned tsp-spec fixture suite through this port and asserts
the normative per-vector profiles from expectations.json. Exit 0 only if the
snapshot is intact AND every vector matches. A failure here means THIS PORT
is wrong (ADR-0008) -- fix the port, never the fixtures.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from tsp_verify import canonicalize, sha256_hex, validate_trust_envelope_shape, verify_local  # noqa: E402

SNAPSHOT = HERE / "spec-snapshot"
FIXTURES = SNAPSHOT / "fixtures" / "v3.0"


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_snapshot_integrity():
    mismatches = []
    lines = [l.strip() for l in (FIXTURES / "SHA256SUMS").read_text(encoding="utf-8").splitlines() if l.strip()]
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


def main():
    spec = read_json(SNAPSHOT / "expectations.json")
    print(f"TSP Python-port conformance -- wire tsp \"{spec['tsp']}\" - maturity \"{spec['specMaturity']}\"")
    count, mismatches = verify_snapshot_integrity()
    if mismatches:
        print(f"snapshot integrity FAILED ({len(mismatches)}/{count}):")
        for m in mismatches:
            print("   ", m)
        sys.exit(1)
    print(f"integrity: {count} fixtures match pinned SHA256SUMS")

    failed = 0
    for vec in spec["vectors"]:
        fails = run_vector(vec)
        if fails:
            failed += 1
            print(f"FAIL  {vec['file']}  [{vec['kind']}]")
            for f in fails:
                print("       ", f)
        else:
            print(f"PASS  {vec['file']}  [{vec['kind']}]")

    if failed == 0:
        print(f"\nall {len(spec['vectors'])} conformance vectors pass against the Python port")
        sys.exit(0)
    print(f"\n{failed}/{len(spec['vectors'])} vectors diverge -- this port is wrong until fixed (ADR-0008)")
    sys.exit(1)


if __name__ == "__main__":
    main()
