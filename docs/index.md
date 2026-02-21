---
title: Overview
nav_order: 1
---

# Noir-Groth16

Noir-Groth16 converts Noir ACIR artifacts into deterministic witness and Groth16-compatible outputs.

Primary target assumptions:

- Field: BN254
- R1CS/WTNS format: iden3 (`.r1cs`, `.wtns`)
- Lowering focus: `AssertZero` constraints with explicit handling of unsupported operations

Pipeline:

1. Parse Noir artifact JSON and ABI metadata.
2. Build witnesses from ABI-shaped inputs via ACVM.
3. Lower supported ACIR assertions to R1CS.
4. Emit deterministic artifacts for `snarkjs` and downstream verifiers.

## Documentation map

- [Quickstart](quickstart): build and run the CLI in a few commands.
- [CLI Reference](cli-reference): command-by-command interface and outputs.
- [snarkjs Interop](snarkjs-interop): end-to-end proving and verification flow.
- [Technical Reference](technical-reference): crate boundaries, invariants, and format notes.
- [Troubleshooting](troubleshooting): common failure modes and fixes.

## Repository scope

This workspace is organized around these crates:

- `crates/noir-acir`: Noir artifact parsing, ABI metadata, and witness layout.
- `crates/noir-witness`: ABI input flattening, ACVM solving, and witness emitters.
- `crates/noir-r1cs`: ACIR to R1CS lowering and `.r1cs` serialization.
- `crates/noir-cli`: command-line interface for parse, witness, debug R1CS, and interop outputs.
