# AGENTS.md — AI-assisted development guide

## Roles
- Maintainer: owns architecture, release decisions, threat model.
- Implementer: writes code for assigned prompt, adds tests, updates docs.
- Reviewer: enforces invariants (determinism, serialization, safety), blocks risky changes.
- Security reviewer: audits constraint correctness, serialization, trusted setup handling.

## Allowed actions
- Modify Rust/TS/shell code in-repo.
- Add tests and fixtures (keep fixtures minimal; no huge keys committed).
- Add CI workflows, formatting, lint, deny/audit configs.
- Refactor with mechanical commits (no semantic changes mixed with formatting).

## Disallowed actions
- Introducing nonstandard Groth16 variants (e.g., commitments) without explicit security signoff.
- Changing wire ordering / public input conventions without migration notes + fixtures update.
- Adding heavy cryptography dependencies without justification and license review.

## Safety and correctness rules
- Every opcode lowering must have:
  - a satisfiable witness test
  - a negative test (tamper witness → constraints fail)
- Deterministic outputs:
  - stable ordering of constraints and wires
  - stable encodings (endianness explicitly specified)
- Underconstrained warning:
  - if Brillig outputs are not transitively constrained by AssertZero/blackboxes, fail in “strict” mode.

## Testing commands
- `cargo fmt --all`
- `cargo clippy --all-targets --all-features -D warnings`
- `cargo test --workspace`
- Optional interop:
  - `npm i -g snarkjs`
  - `cargo test -p noir-cli --features interop-test -- --ignored`

## Commit message style
- Conventional commits:
  - `feat(r1cs): ...`
  - `fix(wtns): ...`
  - `test(poseidon2): ...`
  - `docs(spec): ...`
- Separate commits for:
  - formatting
  - refactors
  - behavior changes

## Review checklist
- Does the change alter public input ordering or wire indexing?
- Are constraints sound (no missing constraint for a “computed” value)?
- Are coefficients reduced mod field? Any overflow paths?
- Are encodings and endianness consistent across Rust/TS/Soroban?
- Do tests include tampering/negative cases?
- Any new dependency: license and security audit status checked.

## When to request human review
- Before merging:
  - Poseidon2Permutation constraint implementation
  - `.r1cs` / `.wtns` binary encoders
  - Soroban verifier encoding + contract integration
  - Any cryptography primitive changes