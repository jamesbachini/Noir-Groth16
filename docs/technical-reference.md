---
title: Technical Reference
nav_order: 5
---

# Technical Reference

## Workspace architecture

- `crates/noir-acir`
  - Parses Noir artifact JSON, including base64 and legacy bytecode compatibility decoding.
  - Exposes ABI/program metadata and witness layout helpers.
  - Enforces deterministic witness assignment ordering and ABI arity checks before solving.

- `crates/noir-witness`
  - Converts ABI-shaped input JSON into ACVM witness assignments.
  - Solves witnesses and emits deterministic witness artifacts.

- `crates/noir-r1cs`
  - Lowers supported ACIR operations into R1CS constraints.
  - Owns wire mapping and iden3 `.r1cs` binary serialization.
  - Produces unsupported-opcode diagnostics when requested.

- `crates/noir-cli`
  - End-user command surface for parsing, witness generation, debug R1CS JSON, and interop emission.

## Lowering coverage snapshot

Opcode families handled in strict mode:

- `AssertZero`
- `MemoryInit`
- `MemoryOp`
- Guarded `Call` and `BrilligCall` paths (with predicate/output-constrained checks)
- `BlackBoxFuncCall` with native lowerings for `AND`, `XOR`, `RANGE`, `Blake2s`, `Blake3`, `EcdsaSecp256k1`, `EcdsaSecp256r1`, `Poseidon2Permutation`, `Sha256Compression`, `MultiScalarMul`, and `EmbeddedCurveAdd`

Unsupported blackboxes/opcodes can be diagnosed with `--allow-unsupported`, but final strict lowering still fails non-zero.

## Core invariants

Constraint soundness:

- Computed values must be transitively constrained.
- Unsupported or underconstrained behavior must fail loudly in strict mode.

Determinism:

- Constraint ordering is stable.
- Wire indexing is stable.
- Public input ordering is stable.

Serialization consistency:

- Endianness must be explicit and consistent across emitters/consumers.
- Binary encodings (`.r1cs`, `.wtns`, witness encodings) should remain backward-compatible unless migration is intentional and documented.

## Artifact contracts

`compile-r1cs` contract:

- Input: Noir artifact JSON.
- Parser behavior: accepts current artifact encoding and legacy-compatible/base64 program bytecode encodings.
- Output: `parsed.json` with deterministic parse summary details.

`witness` contract:

- Inputs: artifact JSON + ABI-shaped user input JSON.
- ABI checks: validates field counts and nested shape arity before witness assignment.
- Witness layout: deterministic private/public/databus ordering from artifact metadata.
- Outputs: `witness_map.json`, `witness.bin`, `witness.wtns`.

`r1cs-json` contract:

- Input: artifact JSON.
- Output: a JSON file containing debug R1CS form (`n_wires`, `n_constraints`, matrix rows, and metadata).
- Failure mode: unsupported operations fail compilation; diagnostics may be emitted with `--allow-unsupported`.

`interop` contract:

- Inputs: artifact JSON + ABI-shaped user input JSON.
- Outputs: `circuit.r1cs` and `witness.wtns` for downstream proving stacks such as `snarkjs`.

## Strictness and diagnostics

- Pedantic witness solving is enabled by default.
- `--no-pedantic` relaxes pedantic checks but does not change lowering semantics.
- `--allow-unsupported` enables unsupported-opcode reporting, but unsupported lowering still exits non-zero.
- For `interop`, `--allow-unsupported` writes `<OUT_DIR>/unsupported_opcodes.json` diagnostics.
- Unsupported reports are intended for debugging lowering gaps, not for producing proving artifacts.

## Test expectations for contributors

For opcode-lowering changes:

- Add satisfiable witness tests.
- Add tamper/negative tests proving constraints fail with altered witness values.

For mapping/serialization changes:

- Add fixture coverage for stable wire/public input ordering.
- Add round-trip or fixture tests for `.r1cs`, `.wtns`, and witness encodings.
