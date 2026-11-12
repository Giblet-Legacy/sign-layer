# SPEC V2 — sign-layer (P2 Sign, strict layer)

SPEC_V2.md — specification for sign_v2.py, the layer above P2 v1.0.0.

Function:
    Specifies sign_v2.py, a thin strict layer over the frozen P2
    v1.0.0 primitive (sign.py). It closes the divergences D1–D7
    recorded in NOTES.md without editing sign.py (Immutable Rule).

    SPEC.md v1.0.0 remains authoritative for everything this document
    does not change. Where this document is silent, SPEC.md v1.0.0
    applies unchanged.

Layer:     P2 — Sign, v2 (strict)
Depends:   sign.py (P2 v1.0.0), envelope_v2.py (P1 v2.0.0)
Consumed:  P3 Freeze onward — new code imports sign_v2, not sign
Version:   SPEC V2 2.0.0
Licence:   MSL-1.0
Author:    James Gilbert (Giblets Forge)

---

## 1. Compatibility guarantee

- sign_capsule is v1's function, re-exported unchanged. It returns
  the same dict for the same capsule and key (Ed25519 is
  deterministic).
- sign_artifact writes a sidecar whose parsed JSON object is
  identical to v1's. On POSIX the sidecar bytes are identical too; on
  Windows v2 writes LF where v1 wrote CRLF (§2.5).
- Every capsule and sidecar produced by v1 verifies under v2,
  including v1 sidecars written with CRLF on Windows.

v2 differs from v1 only by **rejecting** inputs that v1 accepted
outside the contract, by **returning False** where v1 crashed, and
by **raising** where SPEC.md §3.4 already said it should. That
narrowing is why the major version is 2.

## 2. Changes from SPEC.md v1.0.0

### 2.1 Location-independent import of P1 (resolves D1)

sign_v2 locates P1 relative to its own file, not the current working
directory: `<dir of sign_v2.py>/../envelope-layer`. Importing sign_v2
works from any working directory as long as sign-layer is on
sys.path.

### 2.2 Signature object shape (resolves D2, D3, D4)

verify_capsule returns False — never raises — unless the
`"signature"` value is a dict with **exactly** the keys
`algorithm`, `key_id`, `value`, where:

- `algorithm` == `"Ed25519"`;
- `key_id` is a str;
- `value` is a str of exactly 128 characters from `0-9a-f`
  (lowercase hex of 64 bytes, SPEC.md §1 invariant).

Only then does v2 delegate to v1 verify_capsule. A capsule that is
not a dict, or has no `"signature"` key, returns False as in v1.

### 2.3 Sidecar object shape (resolves D6)

verify_artifact returns False — never raises — unless the sidecar
file is UTF-8 JSON whose top-level value is a dict with **exactly**
the keys `algorithm`, `key_id`, `file_sha256`, `value`, where:

- `algorithm` == `"Ed25519"`;
- `key_id` is a str;
- `file_sha256` is a str of exactly 64 characters from `0-9a-f`;
- `value` is a str of exactly 128 characters from `0-9a-f`.

Only then does v2 delegate to v1 verify_artifact.

### 2.4 Missing files raise (resolves D5)

verify_artifact raises FileNotFoundError if `file_path` or
`signature_path` does not exist, as SPEC.md §3.4 already required.
v1 returned False. sign_artifact already raised FileNotFoundError in
v1 and is unchanged in that respect.

### 2.5 LF sidecars (resolves D7)

sign_artifact writes the sidecar with LF line endings on every
platform. The bytes are `json.dumps(obj, indent=2)` encoded as UTF-8,
with no trailing newline — v1's POSIX output.

### 2.6 Key type checks

verify_capsule and verify_artifact raise TypeError unless
`public_key` is an Ed25519PublicKey. This matches envelope_v2's rule
(P1 SPEC_V2 §2.2): a wrong key type is a caller bug, not a failed
verification.

### 2.7 Unchanged

sign_capsule already conforms to SPEC.md v1.0.0 (ValueError for a
non-dict capsule, TypeError for a wrong key type, no mutation). v2
re-exports it from v1 unchanged.

## 3. Construction rule

sign_v2 delegates to sign.py for every signature it produces or
checks. It never reimplements a primitive:

- sign_capsule is sign.sign_capsule.
- verify_capsule / verify_artifact check shape and key type, then
  call their v1 counterparts.
- sign_artifact calls sign.sign_artifact, then rewrites the sidecar
  it wrote with CRLF normalised to LF. JSON text cannot contain a raw
  CR inside a string, so this changes only line endings.

## 4. Public API

Same four names as P2 v1.0.0, same numbering:

1. sign_capsule    — re-exported from v1
2. verify_capsule  — v2: key type check, strict shape, then v1
3. sign_artifact   — v2: v1, then LF sidecar
4. verify_artifact — v2: key type check, missing files raise, strict shape, then v1

## 5. Test plan (test_sign_v2.py)

- Public API: four names, all callable; sign_capsule is v1's object.
- sign_capsule output equals v1 output; v1 ⇄ v2 capsules cross-verify.
- verify_capsule False results: tampered, wrong key, non-dict
  capsule, missing / null / non-dict signature.
- verify_capsule malformed `value` (int, None, uppercase, short,
  long, non-hex) → False, never raises.
- verify_capsule wrong / missing algorithm, extra or missing
  signature fields → False.
- verify_capsule / verify_artifact with private key, bytes or None
  as public key → TypeError.
- No mutation of a nested capsule by sign or verify.
- sign_artifact: default `.sig` path, no CR in sidecar bytes, exact
  bytes as §2.5, parsed object equal to v1's, FileNotFoundError on a
  missing file.
- verify_artifact: valid → True; one byte changed, byte appended,
  wrong key → False; missing file or sidecar → FileNotFoundError.
- verify_artifact malformed sidecar (list, string, invalid JSON,
  non-UTF-8 bytes, uppercase value, wrong algorithm, extra field,
  non-str value, bad file_sha256) → False, never raises.
- A v1 sidecar verifies under v2.
- `import sign_v2` succeeds from an unrelated working directory.
