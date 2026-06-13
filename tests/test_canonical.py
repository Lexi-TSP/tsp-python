import unittest
from tsp_verify.canonical import canonicalize, es_number


class TestNumbers(unittest.TestCase):
    def test_es_number_matches_javascript(self):
        # (python value, exact JSON.stringify output in JS)
        cases = [
            (0.0, "0"), (-0.0, "0"), (1.0, "1"), (-7.0, "-7"),
            (0.7, "0.7"), (3.14159, "3.14159"), (1.5e-5, "0.000015"),
            (1e-6, "0.000001"), (1e-7, "1e-7"), (1.2e-8, "1.2e-8"),
            (1e21, "1e+21"), (1.5e22, "1.5e+22"), (123456789012345680000.0, "123456789012345680000"),
            (100000.0, "100000"), (1e20, "100000000000000000000"),
        ]
        for value, expected in cases:
            self.assertEqual(es_number(value), expected, f"for {value!r}")

    def test_non_finite_raises(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                es_number(bad)


class TestCanonicalize(unittest.TestCase):
    def test_scalars_and_sorting(self):
        self.assertEqual(canonicalize(None), "null")
        self.assertEqual(canonicalize(True), "true")
        self.assertEqual(canonicalize({"b": 1, "a": "x"}), '{"a":"x","b":1}')

    def test_escapes_match_reference(self):
        self.assertEqual(canonicalize("a\tb\n\x01"), '"a\\tb\\n\\u0001"')

    def test_utf16_code_unit_sort(self):
        # U+1D306 (astral, surrogates D834 DF06) must sort BEFORE U+FF01
        # under UTF-16 order; code-point order would reverse them.
        d = {"！": 1, "\U0001d306": 2}
        self.assertEqual(canonicalize(d), '{"\U0001d306":2,"！":1}')

    def test_unsupported_raises(self):
        with self.assertRaises(ValueError):
            canonicalize({"a": object()})
