"""
sign.py — P2 Sign primitive layer

Function:
    Implements the capsule signing rule and the detached artefact
    sidecar rule. Consumes envelope_v2 (P1) for raw cryptographic
    primitives.

Public API:
    1. sign_capsule    — Canonicalise dict, sign raw bytes, return signed dict
    2. verify_capsule  — Verify dict signature against its public key
    3. sign_artifact   — Sign raw file bytes, write detached `.sig` sidecar
    4. verify_artifact — Verify `.sig` sidecar against raw file bytes

Layer:    P2 — Sign
Depends:  P1 Envelope v2 (envelope_v2.py)
Consumed: P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify
Version:  1.0.0 (on freeze; 0.0.0-dev until then)
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
"""

import os
import copy
import json

# Import from the sibling directory (P1)
import sys
sys.path.insert(0, os.path.abspath('../envelope-layer'))
import envelope_v2 as envelope

# ---------------------------------------------------------------------------
# 1. sign_capsule
#    Deep copies the dict, sets "signature": None, canonicalises,
#    signs, and returns the new signed dict.
# ---------------------------------------------------------------------------
def sign_capsule(capsule, private_key):
    if not isinstance(capsule, dict):
        raise ValueError("Capsule must be a dictionary")
    
    # Deep copy so we never mutate the caller's dict
    signed = copy.deepcopy(capsule)
    signed["signature"] = None
    
    # Get canonical bytes and sign
    payload_bytes = envelope.canonical_bytes(signed)
    sig_bytes = envelope.sign_bytes(payload_bytes, private_key)
    
    # Build the signature object
    did_key = envelope.did_key_encode(private_key.public_key())
    signed["signature"] = {
        "algorithm": "Ed25519",
        "key_id": did_key,
        "value": sig_bytes.hex()
    }
    
    return signed

# ---------------------------------------------------------------------------
# 2. verify_capsule
#    Extracts the signature, sets it to None, canonicalises, and verifies.
# ---------------------------------------------------------------------------
def verify_capsule(capsule, public_key):
    if not isinstance(capsule, dict) or "signature" not in capsule:
        return False
    
    sig_obj = capsule.get("signature")
    if not isinstance(sig_obj, dict):
        return False
    
    # Ensure the key_id matches the provided public key
    expected_did = envelope.did_key_encode(public_key)
    if sig_obj.get("key_id") != expected_did:
        return False
        
    try:
        sig_bytes = bytes.fromhex(sig_obj.get("value", ""))
    except ValueError:
        return False
        
    # Reconstruct the payload (signature set to None)
    payload = copy.deepcopy(capsule)
    payload["signature"] = None
    payload_bytes = envelope.canonical_bytes(payload)
    
    return envelope.verify_bytes(payload_bytes, sig_bytes, public_key)

# ---------------------------------------------------------------------------
# 3. sign_artifact
#    Reads raw file bytes, signs them, and writes a .sig sidecar.
# ---------------------------------------------------------------------------
def sign_artifact(file_path, private_key, signature_path=None):
    if signature_path is None:
        signature_path = file_path + ".sig"
        
    with open(file_path, "rb") as f:
        data = f.read()
        
    sig_bytes = envelope.sign_bytes(data, private_key)
    file_hash = envelope.sha256_hex(data)
    did_key = envelope.did_key_encode(private_key.public_key())
    
    sig_obj = {
        "algorithm": "Ed25519",
        "key_id": did_key,
        "file_sha256": file_hash,
        "value": sig_bytes.hex()
    }
    
    with open(signature_path, "w") as f:
        json.dump(sig_obj, f, indent=2)
        
    return signature_path

# ---------------------------------------------------------------------------
# 4. verify_artifact
#    Reads the file and .sig sidecar, verifies the hash and signature.
# ---------------------------------------------------------------------------
def verify_artifact(file_path, signature_path, public_key):
    if not os.path.exists(file_path) or not os.path.exists(signature_path):
        return False
        
    with open(file_path, "rb") as f:
        data = f.read()
        
    try:
        with open(signature_path, "r") as f:
            sig_obj = json.load(f)
    except (json.JSONDecodeError, IOError):
        return False
        
    expected_did = envelope.did_key_encode(public_key)
    if sig_obj.get("key_id") != expected_did:
        return False
        
    if sig_obj.get("file_sha256") != envelope.sha256_hex(data):
        return False
        
    try:
        sig_bytes = bytes.fromhex(sig_obj.get("value", ""))
    except ValueError:
        return False
        
    return envelope.verify_bytes(data, sig_bytes, public_key)
