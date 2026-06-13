"""TSP canonicalization (RFC 8785-style JCS), ported from the reference core.

Port notes (the two traps):
- Numbers must serialize exactly as ECMAScript's Number::toString (shortest
  round-trip; integral floats without ".0"; exponential form at >= 1e21 and
  < 1e-6). Python's repr() is also shortest-round-trip but formats integral
  floats and exponent thresholds differently -- es_number() bridges the gap.
- Object keys sort by UTF-16 code units (JS string comparison), not Unicode
  code points. For astral characters these orders differ; sorting by the
  UTF-16-BE encoding reproduces JS exactly.

Fail-closed: non-finite numbers and unsupported types raise ValueError.
"""
from __future__ import annotations

import math

_ESCAPE_MAP = {
    "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r",
    '"': '\\"', "\\": "\\\\",
}


def _canonical_string(value: str) -> str:
    out = ['"']
    for ch in value:
        if ch in _ESCAPE_MAP:
            out.append(_ESCAPE_MAP[ch])
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def es_number(value: float) -> str:
    """Serialize a float exactly as ECMAScript Number::toString."""
    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"canonicalize: non-finite number not allowed: {value!r}")
    if value == 0:
        return "0"  # covers -0.0 as well, matching the reference core
    r = repr(value)  # shortest round-trip digits (matches JS, unlike int())
    if value.is_integer() and abs(value) < 1e21:
        if "e" in r:
            mantissa, exp = r.split("e")
            return _expand_exponential(mantissa, int(exp))
        return r[:-2] if r.endswith(".0") else r
    if "e" in r or "E" in r:
        mantissa, exp = r.split("e")
        exp_int = int(exp)
        # ES uses exponential only for >= 1e21 or < 1e-6; otherwise expand
        if -7 < exp_int < 21:
            return _expand_exponential(mantissa, exp_int)
        if mantissa.endswith(".0"):
            mantissa = mantissa[:-2]
        sign = "+" if exp_int >= 0 else "-"
        return f"{mantissa}e{sign}{abs(exp_int)}"
    return r


def _expand_exponential(mantissa: str, exp: int) -> str:
    neg = mantissa.startswith("-")
    if neg:
        mantissa = mantissa[1:]
    int_part, _, frac_part = mantissa.partition(".")
    digits = int_part + frac_part
    point = len(int_part) + exp
    if point <= 0:
        s = "0." + "0" * (-point) + digits
    elif point >= len(digits):
        s = digits + "0" * (point - len(digits))
    else:
        s = digits[:point] + "." + digits[point:]
    s = s.rstrip("0").rstrip(".") if "." in s else s
    return ("-" + s) if neg else s


def canonicalize(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):  # before int: bool is a subclass of int
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return es_number(value)
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(
            f"{_canonical_string(k)}:{canonicalize(value[k])}" for k in keys
        ) + "}"
    raise ValueError(f"canonicalize: unsupported value type: {type(value).__name__}")
