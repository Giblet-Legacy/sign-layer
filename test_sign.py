"""
test_sign.py — P2 Sign test suite

Function:
    Executable expression of SPEC.md. Written before sign.py
    per build discipline.

Layer:    P2 — Sign
Spec:     SPEC.md v1.0.0
Licence:  MSL-1.0
"""

import os
import sys
import json
import tempfile
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Add P1 to path
sys.path.insert(0, os.path.abspath('../envelope-layer'))

import sign

@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()

@pytest.fixture
def capsule():
    return {
        "scp_id": "test-123",
        "declaration": "This is a test.",
        "created": "2026-11-11T00:00:00Z",
    }

def test_sign_capsule(key, capsule):
    signed = sign.sign_capsule(capsule, key)
    assert "signature" in signed
    assert signed["signature"]["algorithm"] == "Ed25519"
    assert signed["signature"]["key_id"].startswith("did:key:z6Mk")
    assert len(signed["signature"]["value"]) == 128  # 64 bytes in hex

def test_sign_capsule_does_not_mutate(key, capsule):
    original = capsule.copy()
    sign.sign_capsule(capsule, key)
    assert capsule == original

def test_verify_capsule_valid(key, capsule):
    signed = sign.sign_capsule(capsule, key)
    assert sign.verify_capsule(signed, key.public_key()) is True

def test_verify_capsule_tampered_data(key, capsule):
    signed = sign.sign_capsule(capsule, key)
    signed["declaration"] = "Tampered!"
    assert sign.verify_capsule(signed, key.public_key()) is False

def test_verify_capsule_wrong_key(key, capsule):
    signed = sign.sign_capsule(capsule, key)
    other_key = Ed25519PrivateKey.generate()
    assert sign.verify_capsule(signed, other_key.public_key()) is False

def test_sign_artifact(key):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        f.write(b"Hello, Forge Stack!")
        f_path = f.name
    
    try:
        sig_path = sign.sign_artifact(f_path, key)
        assert os.path.exists(sig_path)
        assert sig_path.endswith(".sig")
        
        with open(sig_path) as f:
            sig_data = json.load(f)
            assert sig_data["algorithm"] == "Ed25519"
            assert "file_sha256" in sig_data
            assert "value" in sig_data
            
        assert sign.verify_artifact(f_path, sig_path, key.public_key()) is True
        
        # Tamper with the file
        with open(f_path, "ab") as f:
            f.write(b"tampered")
        assert sign.verify_artifact(f_path, sig_path, key.public_key()) is False
        
    finally:
        if os.path.exists(f_path): os.remove(f_path)
        if os.path.exists(f_path + ".sig"): os.remove(f_path + ".sig")
