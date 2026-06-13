import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from tsp_verify import verify_license

FIXTURES = Path(__file__).resolve().parent.parent / "conformance" / "spec-snapshot" / "fixtures" / "license-v1"


def _load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _roots():
    rf = _load("license-root-key.json")
    return [{"rootKeyId": rf["rootKeyId"], "publicKey": rf["publicKey"]}]


class TestVerifyLicense(unittest.TestCase):
    def cfg(self, **over):
        base = {"origin": "https://customer.example", "trustedRootKeys": _roots(), "requiredModules": []}
        base.update(over)
        return base

    def test_valid_pro(self):
        r = verify_license(_load("valid-pro.json"), self.cfg(), "2026-07-01T00:00:00.000Z")
        self.assertTrue(r["ok"])
        self.assertEqual(r["reason"], "valid")
        self.assertEqual(r["license"]["origin"], "https://customer.example")

    def test_allowed_origin_and_module_gate(self):
        self.assertTrue(verify_license(_load("valid-pro.json"), self.cfg(origin="https://staging.customer.example"), "2026-07-01T00:00:00.000Z")["ok"])
        self.assertEqual(verify_license(_load("valid-pro.json"), self.cfg(requiredModules=["enterprise-policy"]), "2026-07-01T00:00:00.000Z")["reason"], "module_not_licensed")

    def test_failure_modes(self):
        self.assertEqual(verify_license(_load("valid-pro.json"), self.cfg(origin="https://evil.example"), "2026-07-01T00:00:00.000Z")["reason"], "origin_mismatch")
        self.assertEqual(verify_license(_load("valid-pro.json"), self.cfg(), "2026-10-01T00:00:00.000Z")["reason"], "license_expired")
        self.assertEqual(verify_license(_load("valid-pro.json"), self.cfg(), "2027-01-01T00:00:00.000Z")["reason"], "issuer_expired")
        self.assertEqual(verify_license(_load("tampered-license.json"), self.cfg(), "2026-07-01T00:00:00.000Z")["reason"], "license_signature_invalid")
        self.assertEqual(verify_license(_load("untrusted-root.json"), self.cfg(), "2026-07-01T00:00:00.000Z")["reason"], "untrusted_root")
        self.assertEqual(verify_license(_load("issuer-mismatch.json"), self.cfg(), "2026-07-01T00:00:00.000Z")["reason"], "issuer_mismatch")

    def test_grace(self):
        r = verify_license(_load("in-grace.json"), self.cfg(), "2026-06-10T00:00:00.000Z")
        self.assertTrue(r["ok"])
        self.assertEqual(r["reason"], "valid_in_grace")
        self.assertTrue(r["in_grace"])

    def test_now_as_datetime(self):
        r = verify_license(_load("valid-pro.json"), self.cfg(), datetime(2026, 7, 1, tzinfo=timezone.utc))
        self.assertTrue(r["ok"])

    def test_misconfig_raises(self):
        with self.assertRaises(ValueError):
            verify_license(_load("valid-pro.json"), {"origin": "", "trustedRootKeys": _roots()}, "2026-07-01T00:00:00.000Z")
        with self.assertRaises(ValueError):
            verify_license(_load("valid-pro.json"), {"origin": "https://x", "trustedRootKeys": []}, "2026-07-01T00:00:00.000Z")


if __name__ == "__main__":
    unittest.main()
