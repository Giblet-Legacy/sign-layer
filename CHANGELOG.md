# CHANGELOG — sign-layer (P2 Sign)

CHANGELOG.md — build history for P2 Sign, latest entry at top.

Function:
    Records the Good / Bad / Ugly of every build step for this layer.
    Updated at every sign-off. The format never changes shape, even
    when a section is empty.

## [Unreleased]

### Good

- (none)

### Bad

- (none)

### Ugly

- (none)

## [v2.0.0] — 2026-11-12

### Good

- `sign_v2.py`: strict layer above the frozen P2 v1.0.0, specified in
  `SPEC_V2.md` before any code. It passes every signature through
  sign.py, so v1 capsules and sidecars still verify (tested both ways).
- Resolves NOTES D1–D7: P1 is imported from the file's own location;
  malformed signatures and sidecars return False instead of crashing;
  the algorithm is checked; signatures must be exactly 128 lowercase
  hex characters; field sets must match exactly; missing files raise
  FileNotFoundError as SPEC §3.4 requires; sidecars use LF on every
  platform.
- `test_sign_v2.py`: 17 tests, written before sign_v2.py and run red
  first. The full suite passes 23/23 from inside the repo and from its
  parent directory.
- `conftest.py`: pytest finds P1 from its own location, so the frozen
  test_sign.py also runs from any working directory.

### Bad

- Review found sign.py v1.0.0 diverged from its own SPEC in seven
  places (NOTES D1–D7). The v1.0.0 tests covered only the happy path
  and simple tamper cases.

### Ugly

- sign.py's header and test_sign.py's missing function headers are
  stale but frozen (NOTES D8). They stay as they are.
- On Windows, v2 sign_artifact writes the sidecar twice (v1 writes
  CRLF, then v2 rewrites it with LF). This is not atomic: a crash
  between the two writes leaves a CRLF sidecar, which still verifies.

## [v1.0.0] — 2026-11-11

### Good

- `sign.py` implemented to SPEC v1.0.0.
- 6/6 pytest tests pass.
- Implements capsule signing (deep copy, null signature, canonical
  bytes).
- Implements detached `.sig` sidecar signing for raw artefacts.
- Layer frozen at v1.0.0.

### Bad

- (none recorded at the time; see v2.0.0 Bad)

### Ugly

- (none)

## [v0.0.0-dev] — 2026-11-11

### Good

- Repository scaffolded: `Giblet-Legacy/sign-layer` created for P2.
- Depends on P1 Envelope v2.0.0 (frozen).

### Bad

- (none)

### Ugly

- (none)
