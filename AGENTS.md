# AGENTS.md - Contributor Guide for Noir-Groth16

This document is the default operating guide for AI and human contributors in this repository.
Use it to understand where to edit, what must stay stable, and how to validate changes before review.

## 1) What this repository does

Noir-Groth16 is a workspace that bridges Noir artifacts to Groth16-compatible outputs.
The practical pipeline is:

1. Load Noir artifact JSON and ABI metadata.
2. Build witnesses from user inputs via ACVM.
3. Lower supported ACIR opcodes into R1CS.
4. Emit deterministic `.r1cs` / `.wtns` artifacts for interop (`snarkjs`) and downstream verifiers.

Primary target assumptions:
- Field: BN254.
- Interop format: iden3 `.r1cs` and `.wtns`.
- Constraint lowering covers `AssertZero`, memory ops, guarded `Call`/`Brillig`, and selected native blackboxes, with strict handling of unsupported or underconstrained behavior.

## 2) Workspace map

- `crates/noir-acir`
  - Parses Noir artifact JSON (including base64/legacy bytecode compatibility upgrades).
  - Exposes program summary, ABI layout, witness metadata, and deterministic witness layout assignment checks.

- `crates/noir-witness`
  - Converts ABI-shaped user input into ACVM initial witness values.
  - Runs witness solving (pedantic by default).
  - Writes deterministic witness outputs (`witness_map.json`, `witness.bin`, `.wtns`).

- `crates/noir-r1cs`
  - Lowers supported ACIR opcodes to R1CS constraints with strict/diagnostic unsupported modes.
  - Natively lowers `AND`, `XOR`, `RANGE`, `Blake2s`, `Blake3`, `EcdsaSecp256k1`, `EcdsaSecp256r1`, `Poseidon2Permutation`, `Sha256Compression`, `MultiScalarMul`, and `EmbeddedCurveAdd`.
  - Owns wire mapping and iden3 `.r1cs` serialization.

- `crates/noir-cli`
  - User-facing command surface.
  - Main commands: `compile-r1cs`, `witness`, `r1cs-json`, `interop`.
  - `r1cs-json`/`interop` with `--allow-unsupported` emit `unsupported_opcodes.json` diagnostics but still exit non-zero on unsupported lowering.

- `test-vectors/`
  - Minimal fixtures used by CLI and interop tests.

## 3) Roles and responsibilities

- Maintainer
  - Owns architecture, threat model, release boundaries, and migration decisions.

- Implementer
  - Delivers scoped code changes, tests, and docs updates.
  - Must preserve invariants listed below.

- Reviewer
  - Blocks regressions in determinism, encoding, and constraint soundness.

- Security reviewer
  - Audits cryptographic and serialization changes, trusted setup handling, and verifier interface safety.

## 4) Non-negotiable invariants

### Constraint soundness
- Any value treated as "computed" must be transitively constrained.
- Every opcode lowering path must include:
  - Satisfiable witness test.
  - Negative/tamper test proving constraints fail when witness is altered.

### Determinism
- Constraint ordering must be stable.
- Wire indexing must be stable.
- Public input ordering must be stable and documented.

### Serialization and encoding
- Endianness must be explicit and consistent across all emitters and consumers.
- Binary encoders (`.r1cs`, `.wtns`, witness encodings) must remain backward-compatible unless a migration is included.

### Underconstrained behavior
- In strict mode, if Brillig outputs are not transitively constrained by `AssertZero` or supported blackboxes, fail loudly.

## 5) Allowed and disallowed changes

Allowed:
- Modify Rust/TypeScript/shell code in-repo.
- Add focused tests and small fixtures.
- Improve CI, lint, format, deny/audit configuration.
- Mechanical refactors in separate commits from behavior changes.

Disallowed without explicit security signoff:
- Introducing nonstandard Groth16 variants (for example commitment variants).
- Changing wire ordering or public input conventions without migration notes and fixture updates.
- Adding heavy cryptography dependencies without technical justification and license/security review.

## 6) Required local workflow

Run these before opening a PR:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

Optional interop validation (requires `snarkjs`):

```bash
npm i -g snarkjs
cargo test -p noir-cli --features interop-test -- --ignored
```

## 7) Change-specific test expectations

- Opcode lowering changes:
  - Add satisfiable and tamper-fail tests.
  - Validate no missing constraints for derived values.

- Wire/public-input mapping changes:
  - Add fixture coverage proving stable, expected ordering.
  - Document migration impact.

- Serialization changes:
  - Round-trip or fixture tests for `.r1cs`, `.wtns`, and witness encodings.
  - Explicitly verify endianness expectations.

- CLI behavior changes:
  - Add/update integration tests under CLI test suites and fixture paths.

## 8) PR and commit policy

Use Conventional Commits:
- `feat(r1cs): ...`
- `fix(wtns): ...`
- `test(poseidon2): ...`
- `docs(spec): ...`

Keep commits separated by intent:
- Formatting only.
- Refactor only.
- Behavior change.

## 9) Review checklist

Reviewers must check:

- Does this alter public input ordering or wire indexing?
- Are all computed values properly constrained?
- Are coefficients reduced correctly modulo the field?
- Are encoding and endianness consistent across Rust/TS/Soroban boundaries?
- Are tamper/negative tests present where required?
- Were any new dependencies license-reviewed and security-reviewed?

## 10) Mandatory human/security review triggers

Request explicit human review before merging:

- Poseidon2 permutation constraint implementation changes.
- `.r1cs` or `.wtns` binary encoder changes.
- Soroban verifier encoding or contract integration changes.
- Any cryptographic primitive change.

## 11) Practical guidance for AI contributors

- Prefer minimal, targeted patches.
- Do not mix broad refactors with semantic changes.
- Preserve deterministic maps/orderings unless change is deliberate and documented.
- If you detect unexpected unrelated modifications during your task, pause and ask for direction.

When in doubt, optimize for:
1. Constraint soundness.
2. Determinism.
3. Backward-compatible encodings.
4. Clear tests proving both success and failure paths.
