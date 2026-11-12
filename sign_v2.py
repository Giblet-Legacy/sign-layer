"""
sign_v2.py — P2 Sign v2, strict layer over the frozen v1 primitive

Function:
    The layer new code imports instead of sign.py. It finds P1 from
    its own location rather than the working directory, rejects
    malformed signature objects and sidecars (returning False instead
    of crashing), raises where SPEC.md §3.4 required, and writes LF
    sidecars on every platform (SPEC_V2.md §2). It never reimplements
    a primitive: every signature it produces or checks goes through
    sign.py, so every v1 capsule and sidecar verifies through v2
    (SPEC_V2.md §1, §3).

    sign.py is not edited (Immutable Rule). This file is the
    "add a layer" half of that rule.

Public API (same names and numbering as P2 v1.0.0):
    1. sign_capsule    — re-exported from v1 unchanged
    2. verify_capsule  — key type check, strict shape, then v1
    3. sign_artifact   — v1, then sidecar rewritten with LF
    4. verify_artifact — key type check, missing files raise,
                         strict shape, then v1

Internal helpers (not exported):
    5. _require_public_key — TypeError unless Ed25519PublicKey
    6. _is_lower_hex       — str of exact length, chars 0-9a-f only

Layer:    P2 — Sign, v2 (strict)
Depends:  sign.py (P2 v1.0.0), envelope_v2.py (P1 v2.0.0)
Consumed: P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify
Spec:     SPEC_V2.md 2.0.0 (over SPEC.md v1.0.0)
Version:  2.0.0
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import json
import os
import sys

# Locate P1 from this file, not the working directory (SPEC_V2 §2.1).
# Must run before importing sign.py, whose own path insert is
# cwd-relative and only correct when run from inside sign-layer.
_HERE = os.path.dirname(os.path.abspath(__file__))
_P1 = os.path.join(os.path.dirname(_HERE), "envelope-layer")
if _P1 not in sys.path:
    sys.path.insert(0, _P1)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import sign as _v1

_ALGORITHM = "Ed25519"
_CAPSULE_SIG_FIELDS = {"algorithm", "key_id", "value"}
_SIDECAR_FIELDS = {"algorithm", "key_id", "file_sha256", "value"}
_HEX_LOWER = frozenset("0123456789abcdef")


# ---------------------------------------------------------------------------
# 5. _require_public_key
#    TypeError unless public_key is an Ed25519PublicKey (SPEC_V2 §2.6).
# ---------------------------------------------------------------------------
def _require_public_key(public_key):
    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError(f"public_key must be Ed25519PublicKey, got {type(public_key).__name__}")


# ---------------------------------------------------------------------------
# 6. _is_lower_hex
#    True only for a str of exactly `length` lowercase hex characters.
# ---------------------------------------------------------------------------
def _is_lower_hex(value, length):
    return isinstance(value, str) and len(value) == length and set(value) <= _HEX_LOWER


# ---------------------------------------------------------------------------
# 1. sign_capsule
#    v1 already conforms to SPEC.md (SPEC_V2 §2.7). Re-exported.
# ---------------------------------------------------------------------------
sign_capsule = _v1.sign_capsule


# ---------------------------------------------------------------------------
# 2. verify_capsule
#    Key type check, then strict signature-object shape (SPEC_V2 §2.2).
#    Any malformed input is False, never an exception. Then v1.
# ---------------------------------------------------------------------------
def verify_capsule(capsule, public_key):
    _require_public_key(public_key)
    if not isinstance(capsule, dict):
        return False

    sig_obj = capsule.get("signature")
    if not isinstance(sig_obj, dict) or set(sig_obj) != _CAPSULE_SIG_FIELDS:
        return False
    if sig_obj["algorithm"] != _ALGORITHM:
        return False
    if not isinstance(sig_obj["key_id"], str):
        return False
    if not _is_lower_hex(sig_obj["value"], 128):
        return False

    return _v1.verify_capsule(capsule, public_key)


# ---------------------------------------------------------------------------
# 3. sign_artifact
#    v1 writes the sidecar, then it is rewritten with CRLF -> LF
#    (SPEC_V2 §2.5, §3). JSON strings cannot hold a raw CR, so only
#    line endings change.
# ---------------------------------------------------------------------------
def sign_artifact(file_path, private_key, signature_path=None):
    sig_path = _v1.sign_artifact(file_path, private_key, signature_path)

    with open(sig_path, "rb") as f:
        raw = f.read()
    lf = raw.replace(b"\r\n", b"\n")
    if lf != raw:
        with open(sig_path, "wb") as f:
            f.write(lf)

    return sig_path


# ---------------------------------------------------------------------------
# 4. verify_artifact
#    Key type check; FileNotFoundError for a missing file or sidecar
#    (SPEC_V2 §2.4); strict sidecar shape, False on anything
#    malformed (SPEC_V2 §2.3). Then v1.
# ---------------------------------------------------------------------------
def verify_artifact(file_path, signature_path, public_key):
    _require_public_key(public_key)
    for path in (file_path, signature_path):
        if not os.path.isfile(path):
            raise FileNotFoundError(f"No such file: {path}")

    try:
        with open(signature_path, "r", encoding="utf-8") as f:
            sig_obj = json.load(f)
    except (ValueError, OSError):
        # ValueError covers JSONDecodeError and UnicodeDecodeError.
        return False

    if not isinstance(sig_obj, dict) or set(sig_obj) != _SIDECAR_FIELDS:
        return False
    if sig_obj["algorithm"] != _ALGORITHM:
        return False
    if not isinstance(sig_obj["key_id"], str):
        return False
    if not _is_lower_hex(sig_obj["file_sha256"], 64):
        return False
    if not _is_lower_hex(sig_obj["value"], 128):
        return False

    return _v1.verify_artifact(file_path, signature_path, public_key)
