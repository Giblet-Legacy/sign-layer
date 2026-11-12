"""
test_sign_v2.py — P2 Sign v2 (strict layer) test suite

Function:
    Executable expression of SPEC_V2.md §5. Written before sign_v2.py
    and run red first. Proves two things: (1) v2 stays compatible with
    the frozen v1 primitive, so old capsules and sidecars still
    verify; (2) v2 rejects, returns False or raises where SPEC
    requires and v1 did not (NOTES.md D1–D7).

Functions in this file:
    Fixtures:
    1.  key                                 — fresh Ed25519 private key
    2.  capsule                             — nested test capsule
    3.  artefact                            — temp file with known bytes
    Tests (pytest-collected):
    4.  test_public_api                     — four names, all callable
    5.  test_sign_capsule_identity_with_v1  — same dict as v1
    6.  test_capsules_cross_verify          — v1 ⇄ v2
    7.  test_verify_capsule_false_results   — tamper, wrong key, bad shape
    8.  test_verify_capsule_malformed_value — D2, D4: False, never raises
    9.  test_verify_capsule_algorithm       — D3
    10. test_verify_capsule_fields_exact    — extra / missing fields
    11. test_verify_key_type_errors         — §2.6 TypeError
    12. test_no_mutation_nested             — sign and verify are pure
    13. test_sign_artifact_lf_bytes         — D7: exact LF bytes
    14. test_sign_artifact_identity_with_v1 — same parsed sidecar as v1
    15. test_sign_artifact_missing_file     — FileNotFoundError
    16. test_verify_artifact_results        — valid, tamper, wrong key
    17. test_verify_artifact_missing_files  — D5: FileNotFoundError
    18. test_verify_artifact_malformed      — D6: False, never raises
    19. test_v1_sidecar_verifies_under_v2   — compatibility
    20. test_import_from_any_cwd            — D1

Layer:    P2 — Sign, v2 (strict)
Spec:     SPEC_V2.md 2.0.0 (over SPEC.md v1.0.0)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import copy
import json
import os
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import sign
import sign_v2

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# 1. key
# ---------------------------------------------------------------------------
@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


# ---------------------------------------------------------------------------
# 2. capsule
# ---------------------------------------------------------------------------
@pytest.fixture
def capsule():
    return {
        "scp_id": "test-123",
        "declaration": "This is a test.",
        "created": "2026-11-12T00:00:00Z",
        "nested": {"list": [1, 2, {"deep": "value"}]},
    }


# ---------------------------------------------------------------------------
# 3. artefact
# ---------------------------------------------------------------------------
@pytest.fixture
def artefact(tmp_path):
    p = tmp_path / "doc.html"
    p.write_bytes(b"<p>Hello, Forge Stack!</p>\n")
    return str(p)


# ---------------------------------------------------------------------------
# 4. test_public_api
# ---------------------------------------------------------------------------
def test_public_api():
    for name in ("sign_capsule", "verify_capsule", "sign_artifact", "verify_artifact"):
        assert callable(getattr(sign_v2, name))
    assert sign_v2.sign_capsule is sign.sign_capsule


# ---------------------------------------------------------------------------
# 5. test_sign_capsule_identity_with_v1
# ---------------------------------------------------------------------------
def test_sign_capsule_identity_with_v1(key, capsule):
    assert sign_v2.sign_capsule(capsule, key) == sign.sign_capsule(capsule, key)


# ---------------------------------------------------------------------------
# 6. test_capsules_cross_verify
# ---------------------------------------------------------------------------
def test_capsules_cross_verify(key, capsule):
    pk = key.public_key()
    assert sign_v2.verify_capsule(sign.sign_capsule(capsule, key), pk) is True
    assert sign.verify_capsule(sign_v2.sign_capsule(capsule, key), pk) is True


# ---------------------------------------------------------------------------
# 7. test_verify_capsule_false_results
# ---------------------------------------------------------------------------
def test_verify_capsule_false_results(key, capsule):
    pk = key.public_key()
    signed = sign_v2.sign_capsule(capsule, key)

    tampered = copy.deepcopy(signed)
    tampered["nested"]["list"][2]["deep"] = "changed"
    assert sign_v2.verify_capsule(tampered, pk) is False

    other = Ed25519PrivateKey.generate().public_key()
    assert sign_v2.verify_capsule(signed, other) is False

    no_sig = copy.deepcopy(signed)
    del no_sig["signature"]
    assert sign_v2.verify_capsule(no_sig, pk) is False

    for bad in (None, "sig", [], 0):
        c = copy.deepcopy(signed)
        c["signature"] = bad
        assert sign_v2.verify_capsule(c, pk) is False

    for not_dict in (None, [], "capsule", 42):
        assert sign_v2.verify_capsule(not_dict, pk) is False


# ---------------------------------------------------------------------------
# 8. test_verify_capsule_malformed_value
# ---------------------------------------------------------------------------
def test_verify_capsule_malformed_value(key, capsule):
    pk = key.public_key()
    signed = sign_v2.sign_capsule(capsule, key)
    good = signed["signature"]["value"]
    for bad in (123, None, good.upper(), good[:-2], good + "00", "zz" * 64, ""):
        c = copy.deepcopy(signed)
        c["signature"]["value"] = bad
        assert sign_v2.verify_capsule(c, pk) is False


# ---------------------------------------------------------------------------
# 9. test_verify_capsule_algorithm
# ---------------------------------------------------------------------------
def test_verify_capsule_algorithm(key, capsule):
    pk = key.public_key()
    signed = sign_v2.sign_capsule(capsule, key)
    for alg in ("RSA", "ed25519", "", None):
        c = copy.deepcopy(signed)
        c["signature"]["algorithm"] = alg
        assert sign_v2.verify_capsule(c, pk) is False


# ---------------------------------------------------------------------------
# 10. test_verify_capsule_fields_exact
# ---------------------------------------------------------------------------
def test_verify_capsule_fields_exact(key, capsule):
    pk = key.public_key()
    signed = sign_v2.sign_capsule(capsule, key)

    extra = copy.deepcopy(signed)
    extra["signature"]["note"] = "unsigned extra field"
    assert sign_v2.verify_capsule(extra, pk) is False

    for field in ("algorithm", "key_id", "value"):
        c = copy.deepcopy(signed)
        del c["signature"][field]
        assert sign_v2.verify_capsule(c, pk) is False

    c = copy.deepcopy(signed)
    c["signature"]["key_id"] = 7
    assert sign_v2.verify_capsule(c, pk) is False


# ---------------------------------------------------------------------------
# 11. test_verify_key_type_errors
# ---------------------------------------------------------------------------
def test_verify_key_type_errors(key, capsule, artefact):
    signed = sign_v2.sign_capsule(capsule, key)
    sig_path = sign_v2.sign_artifact(artefact, key)
    raw_pk = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    for bad in (key, raw_pk, None, "did:key:z6Mk"):
        with pytest.raises(TypeError):
            sign_v2.verify_capsule(signed, bad)
        with pytest.raises(TypeError):
            sign_v2.verify_artifact(artefact, sig_path, bad)


# ---------------------------------------------------------------------------
# 12. test_no_mutation_nested
# ---------------------------------------------------------------------------
def test_no_mutation_nested(key, capsule):
    before = copy.deepcopy(capsule)
    signed = sign_v2.sign_capsule(capsule, key)
    assert capsule == before

    signed_before = copy.deepcopy(signed)
    sign_v2.verify_capsule(signed, key.public_key())
    assert signed == signed_before


# ---------------------------------------------------------------------------
# 13. test_sign_artifact_lf_bytes
# ---------------------------------------------------------------------------
def test_sign_artifact_lf_bytes(key, artefact):
    sig_path = sign_v2.sign_artifact(artefact, key)
    assert sig_path == artefact + ".sig"
    raw = open(sig_path, "rb").read()
    assert b"\r" not in raw
    obj = json.loads(raw.decode("utf-8"))
    assert list(obj) == ["algorithm", "key_id", "file_sha256", "value"]
    assert raw == json.dumps(obj, indent=2).encode("utf-8")


# ---------------------------------------------------------------------------
# 14. test_sign_artifact_identity_with_v1
# ---------------------------------------------------------------------------
def test_sign_artifact_identity_with_v1(key, artefact, tmp_path):
    p1 = sign.sign_artifact(artefact, key, str(tmp_path / "v1.sig"))
    p2 = sign_v2.sign_artifact(artefact, key, str(tmp_path / "v2.sig"))
    assert p2 == str(tmp_path / "v2.sig")
    assert json.load(open(p1)) == json.load(open(p2))


# ---------------------------------------------------------------------------
# 15. test_sign_artifact_missing_file
# ---------------------------------------------------------------------------
def test_sign_artifact_missing_file(key, tmp_path):
    with pytest.raises(FileNotFoundError):
        sign_v2.sign_artifact(str(tmp_path / "nope.txt"), key)


# ---------------------------------------------------------------------------
# 16. test_verify_artifact_results
# ---------------------------------------------------------------------------
def test_verify_artifact_results(key, artefact):
    pk = key.public_key()
    sig_path = sign_v2.sign_artifact(artefact, key)
    assert sign_v2.verify_artifact(artefact, sig_path, pk) is True

    other = Ed25519PrivateKey.generate().public_key()
    assert sign_v2.verify_artifact(artefact, sig_path, other) is False

    original = open(artefact, "rb").read()
    flipped = bytes([original[0] ^ 0x01]) + original[1:]
    open(artefact, "wb").write(flipped)
    assert sign_v2.verify_artifact(artefact, sig_path, pk) is False

    open(artefact, "wb").write(original + b"x")
    assert sign_v2.verify_artifact(artefact, sig_path, pk) is False


# ---------------------------------------------------------------------------
# 17. test_verify_artifact_missing_files
# ---------------------------------------------------------------------------
def test_verify_artifact_missing_files(key, artefact, tmp_path):
    pk = key.public_key()
    sig_path = sign_v2.sign_artifact(artefact, key)
    with pytest.raises(FileNotFoundError):
        sign_v2.verify_artifact(str(tmp_path / "nope.txt"), sig_path, pk)
    with pytest.raises(FileNotFoundError):
        sign_v2.verify_artifact(artefact, str(tmp_path / "nope.sig"), pk)


# ---------------------------------------------------------------------------
# 18. test_verify_artifact_malformed
# ---------------------------------------------------------------------------
def test_verify_artifact_malformed(key, artefact):
    pk = key.public_key()
    sig_path = sign_v2.sign_artifact(artefact, key)
    good = json.load(open(sig_path))

    def variant(**changes):
        obj = dict(good)
        for k, v in changes.items():
            if v is KeyError:
                del obj[k]
            else:
                obj[k] = v
        return json.dumps(obj).encode("utf-8")

    bad_payloads = [
        b"[1, 2]",
        b'"just a string"',
        b"{not json",
        b"\xff\xfe\x00garbage",
        b"",
        variant(value=good["value"].upper()),
        variant(value=123),
        variant(value=good["value"][:-2]),
        variant(algorithm="RSA"),
        variant(algorithm=KeyError),
        variant(file_sha256=good["file_sha256"].upper()),
        variant(file_sha256=None),
        variant(key_id=KeyError),
        variant(extra="field"),
    ]
    for payload in bad_payloads:
        open(sig_path, "wb").write(payload)
        assert sign_v2.verify_artifact(artefact, sig_path, pk) is False, payload


# ---------------------------------------------------------------------------
# 19. test_v1_sidecar_verifies_under_v2
# ---------------------------------------------------------------------------
def test_v1_sidecar_verifies_under_v2(key, artefact):
    sig_path = sign.sign_artifact(artefact, key)
    assert sign_v2.verify_artifact(artefact, sig_path, key.public_key()) is True


# ---------------------------------------------------------------------------
# 20. test_import_from_any_cwd
# ---------------------------------------------------------------------------
def test_import_from_any_cwd(tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = HERE
    result = subprocess.run(
        [sys.executable, "-c", "import sign_v2; print('ok')"],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
