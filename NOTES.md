# NOTES — sign-layer (P2 Sign)

NOTES.md — open questions, divergences and decisions for P2 Sign.

Function:
    Records open questions and divergences between sign.py v1.0.0
    and SPEC.md v1.0.0. sign.py is never edited (Immutable Rule), so
    a fix means a new layer above it, after a SPEC version describes
    it. Each divergence below names the layer and section that
    resolves it.

## Open questions

- (none)

## Divergences — sign.py v1.0.0 vs SPEC.md v1.0.0

Found in review 2026-11-12. Each was reproduced by a probe before the
fix. D1–D7 are resolved by `sign_v2.py` (SPEC_V2.md 2.0.0); sign.py is
unchanged.

- **D1 — CWD-relative P1 import.** `sign.py:28` and `test_sign.py:21`
  insert `os.path.abspath('../envelope-layer')`, which resolves
  against the working directory. Importing or testing from any other
  directory fails with `ModuleNotFoundError: envelope_v2`. P3–P6 will
  import from their own directories. **Resolved:** SPEC_V2 §2.1;
  sign_v2 locates P1 from `__file__`. `conftest.py` does the same for
  pytest, so the frozen test_sign.py also runs from anywhere.
- **D2 — verify_capsule crashes on a non-str value.** A `"value"` of
  `123` raised `TypeError` from `bytes.fromhex`. SPEC §3.2 says
  malformed → False. **Resolved:** SPEC_V2 §2.2.
- **D3 — verify_capsule ignores algorithm.** A signature object with
  `"algorithm": "RSA"` verified True. **Resolved:** SPEC_V2 §2.2.
- **D4 — verify_capsule accepts non-canonical hex.** Uppercase
  `"value"` verified True, though SPEC §1 requires lowercase, so the
  same signature had more than one accepted encoding.
  **Resolved:** SPEC_V2 §2.2 (exactly 128 lowercase hex chars).
- **D5 — verify_artifact returns False for missing files.** SPEC §3.4
  says FileNotFoundError. **Resolved:** SPEC_V2 §2.4.
- **D6 — verify_artifact crashes on a non-object sidecar.** A sidecar
  of `[1,2]` raised `AttributeError`; non-UTF-8 bytes could raise
  `UnicodeDecodeError`. It also ignored `algorithm` and accepted
  uppercase hex, as in D3/D4. **Resolved:** SPEC_V2 §2.3.
- **D7 — sidecars written with platform newlines.** `open(..., "w")`
  writes CRLF on Windows, so the S24 and the laptop produced
  different sidecar bytes for the same signature. Verification was
  unaffected (it parses JSON). **Resolved:** SPEC_V2 §2.5.
- **D8 — Documentation drift in frozen files (not fixed).**
  `sign.py`'s header still reads `Version: 1.0.0 (on freeze;
  0.0.0-dev until then)`, and the functions in test_sign.py have no
  numbered headers (CLAUDE.md Header Discipline). Both files are
  frozen and left as they are; sign_v2.py and test_sign_v2.py follow
  the discipline.

## Divergences from v1.2.1 specification

- (none)

## Decisions

- Depends on `envelope_v2`. P1 is frozen, so P2 imports the strict
  layer.
- v1 tests pull in P1 with `sys.path.insert(0, '../envelope-layer')`
  (cwd-relative, see D1) instead of a pip install, keeping P2
  zero-dependency. From v2, `conftest.py` and `sign_v2.py` locate P1
  from their own file location instead.
- 2026-11-12 — v2 shape checks are **exact**: the capsule signature
  object must have exactly `algorithm`, `key_id`, `value`; the
  sidecar exactly `algorithm`, `key_id`, `file_sha256`, `value`.
  Reason: fields in the signature object are not covered by the
  signature, so extra ones would be unauthenticated. Decided by the
  VS Code AI on James's delegation ("please update all"). Adding
  fields later means a new layer.
- 2026-11-12 — a wrong public-key type raises TypeError in v2
  verify_capsule / verify_artifact, matching envelope_v2 (P1 SPEC_V2
  §2.2). A bad key type is a caller bug, not a failed verification.
  Decided by the VS Code AI on James's delegation.
- 2026-11-12 — v2 sign_artifact delegates to v1 and then normalises
  CRLF → LF, rather than writing the sidecar itself, so every
  signature byte still comes from sign.py (SPEC_V2 §3).
