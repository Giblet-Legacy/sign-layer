# sign-layer — P2 Sign

README.md — repository purpose and layer contract for P2 Sign.

Function:
    This repository implements primitive layer P2 of the Forge Stack:
    capsule signing and detached sidecar signatures. It consumes P1
    Envelope v2 for the underlying cryptographic primitives.

Layer:    P2 — Sign
Depends:  P1 Envelope v2 (envelope_v2.py), expected at ../envelope-layer
Consumed: P3 Freeze, P4 Ledger, P5 Genesis, P6 Canon Verify
Licence:  MSL-1.0
Author:   James Gilbert (Giblets Forge)
Status:   2.0.0 (frozen)

## Files

| File | Role |
| --- | --- |
| `sign_v2.py` | **Import this.** P2 v2 strict layer (SPEC_V2.md) |
| `sign.py` | P2 v1.0.0 primitive, frozen, never edited |
| `SPEC.md` / `SPEC_V2.md` | v1 spec / v2 changes over it |
| `test_sign.py` / `test_sign_v2.py` | v1 / v2 test suites |
| `conftest.py` | pytest path setup (finds P1 from its own location, not the working directory) |
| `NOTES.md` | Open questions, divergences (D1–D8), decisions |
| `CHANGELOG.md` | Good / Bad / Ugly, latest at top |

## Run the tests

    python -m pytest -q

This works from this directory or any parent, as long as
`envelope-layer` sits beside this repository.
