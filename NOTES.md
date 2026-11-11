# NOTES — sign-layer (P2 Sign)

NOTES.md — open questions, divergences and decisions for P2 Sign.

## Open questions
- (none)

## Divergences from v1.2.1 specification
- (none)

## Decisions
- Depends on `envelope_v2`. P1 is frozen, so P2 imports the strict layer.
- Tests use `sys.path.append('../envelope-layer')` to pull in the
  primitive locally without requiring a pip install, keeping P2
  strictly zero-dependency.
