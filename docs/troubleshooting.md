---
title: Troubleshooting
nav_order: 6
---

# Troubleshooting

## `unexpected input value ... that is not present in ABI`

Cause:

- Input JSON keys do not match the Noir ABI expected by the artifact.

Fix:

- Regenerate or inspect artifact/ABI metadata and align input keys and shapes.
- Keep fixture pairs (`artifact`, `inputs`) from the same compile target.

## `strict lowering failed: unsupported opcode ...`

Cause:

- The artifact contains an ACIR opcode path not yet supported by strict R1CS lowering.

Fix:

- Refactor Noir code toward currently supported opcode/lowering paths when possible.
- Run with `--allow-unsupported` to generate diagnostics and identify exact opcode/function index.
- Treat diagnostics as debugging output; proving artifacts are not emitted for unsupported lowering.

## Witness generation fails under pedantic mode

Cause:

- Pedantic solver checks detected inconsistent or invalid witness construction conditions.

Fix:

- Verify input ranges and shapes match ABI constraints.
- Retry with `--no-pedantic` only when you intentionally want relaxed witness solving behavior.

## `snarkjs` verification fails

Checklist:

- Confirm `circuit.r1cs` and `witness.wtns` came from the same `interop` run.
- Confirm `.ptau` and `.zkey` correspond to that exact circuit.
- Re-run `npx snarkjs wtns check` before proving.
- Re-export verification key from the final contributed `.zkey`.

## Local validation commands

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```
