# Forge Stack Context — P2 Sign

CLAUDE.md — Context briefing for AI assistants working in this repository.

Function:
    Instructs the AI assistant on the strict architectural rules of the
    Forge Stack. Do not hallucinate external frameworks. Reason strictly
    within these boundaries.

## The Immutable Rule
Never rewrite a primitive. Add a layer.
If `sign.py` needs a change, we do NOT edit it. We create a v2 layer above it.

## Dual-Device Workflow
We build on an S24 (Termux) and a laptop (VS Code). State is confirmed, never assumed. Always use LF line endings. Commit messages must be clear. We use the Good/Bad/Ugly CHANGELOG format (latest at top).

## Header Discipline
Every file MUST have a top header paragraph explaining its function.
Every function MUST have a numbered header (e.g., `# 1. sign_capsule`).

## P2 Architecture Specifics
- Depends on `envelope_v2` (P1 v2.0.0).
- Implements the capsule rule: "signature": null, canonicalise, sign raw bytes.
- Implements detached `.sig` sidecars for non-JSON artefacts.
- Never logs or prints secrets. Key injection is via function argument.
