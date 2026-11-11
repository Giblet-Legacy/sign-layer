# SPEC — sign-layer (P2 Sign)

SPEC.md — the complete layer specification for P2 Sign.

Function:
    This document is the authoritative specification for primitive
    layer P2 of the Forge Stack. It defines the capsule signing rule
    and the detached artefact sidecar rule.

Layer:     P2 — Sign
Depends:   P1 Envelope v2 (envelope_v2.py)
Consumed:  P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify
Version:   SPEC 1.0.0
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

## 1. The Capsule Signing Rule

The v1.2.1 architecture states: "Signing is over the raw UTF-8
canonical bytes, no pre-hash, excluding the signature object itself.
The signature payload is the capsule with `"signature": null`."

`sign_capsule(capsule: dict, private_key: Ed25519PrivateKey) -> dict`

The exact algorithm:
1. Deep copy the input `capsule` dict. P2 must never mutate the
   caller's dictionary in place.
2. Set `"signature": None` in the copy.
3. Pass the copy to `envelope_v2.canonical_bytes()`.
4. Sign the resulting bytes via `envelope_v2.sign_bytes()`.
5. Construct the signature object:
   {
     "algorithm": "Ed25519",
     "key_id": "did:key:z6Mk...",
     "value": "hex-encoded-signature-bytes"
   }
6. Insert this object into the copied `capsule` under `"signature"`.
7. Return the signed capsule.

Invariants:
- The original input dictionary is untouched.
- The `value` field is the lowercase hex representation of the 64-byte signature.
- The `key_id` field is generated via `envelope_v2.did_key_encode(private_key.public_key())`.
- `verify_capsule(sign_capsule(c, k), k.public_key())` returns `True`.

## 2. The Artefact Signing Rule

The architecture states: "Non-JSON artefacts (docs, HTML) get a
capsule hash-pin and a detached signature over the raw file bytes
(`.sig` sidecar) — two independent verification paths per file, no
exceptions."

`sign_artifact(file_path: str, private_key: Ed25519PrivateKey, signature_path: str = None) -> str`

The exact algorithm:
1. Read the raw bytes of `file_path`.
2. Sign the raw bytes via `envelope_v2.sign_bytes()`.
3. If `signature_path` is `None`, default to `file_path + ".sig"`.
4. Write the `.sig` sidecar. The sidecar format is a JSON object:
   {
     "algorithm": "Ed25519",
     "key_id": "did:key:z6Mk...",
     "file_sha256": "hex-encoded-sha256-of-the-file",
     "value": "hex-encoded-signature-bytes"
   }
5. Return the path to the `.sig` file.

Invariants:
- `verify_artifact(file_path, sig_path, public_key)` returns `True`.
- If the file is modified by even one byte, verification returns `False`.

## 3. Function Contracts

### 3.1 sign_capsule(capsule: dict, private_key) -> dict
- Input: A dictionary, an unlocked Ed25519 private key.
- Output: A new dictionary with the "signature" key populated.
- Failure modes: ValueError if the capsule is not a dict. TypeError if the key is wrong.
- Purity: Pure function.

### 3.2 verify_capsule(capsule: dict, public_key) -> bool
- Input: A signed capsule dictionary.
- Output: True if valid, False otherwise.
- Failure modes: Returns False if "signature" is missing, malformed, or the key_id doesn't match the provided public_key.
- Purity: Pure function.

### 3.3 sign_artifact(file_path: str, private_key, signature_path: str = None) -> str
- Input: A path to a file on disk.
- Output: The path to the written .sig file.
- Failure modes: FileNotFoundError if the file doesn't exist.
- Purity: Impure (file I/O).

### 3.4 verify_artifact(file_path: str, signature_path: str, public_key) -> bool
- Input: Paths to the file and its .sig sidecar.
- Output: True if the signature is valid for the raw bytes, False otherwise.
- Failure modes: FileNotFoundError if either file is missing. Returns False if the signature is invalid.
