---
title: CLI Reference
nav_order: 3
---

# CLI Reference

Root help:

```bash
noir-cli --help
```

Subcommands:

- `compile-r1cs`: parse a Noir artifact and emit deterministic parse summary JSON.
- `witness`: solve witnesses from artifact + ABI-shaped input JSON.
- `r1cs-json`: compile supported ACIR into debug R1CS JSON.
- `interop`: emit iden3 `.r1cs` and `.wtns` for `snarkjs`.

## `compile-r1cs`

Usage:

```bash
noir-cli compile-r1cs --out <OUT_DIR> <ARTIFACT>
```

Writes:

- `<OUT_DIR>/parsed.json`

Notes:

- Creates the output directory if needed.
- Prints opcode and witness summary to stdout.

## `witness`

Usage:

```bash
noir-cli witness [--no-pedantic] --out <OUT_DIR> <ARTIFACT> <INPUTS>
```

Writes:

- `<OUT_DIR>/witness_map.json`
- `<OUT_DIR>/witness.bin`
- `<OUT_DIR>/witness.wtns`

Options:

- `--no-pedantic`: disables pedantic witness solving checks. Default behavior is pedantic.

## `r1cs-json`

Usage:

```bash
noir-cli r1cs-json [--allow-unsupported] --out <OUT_FILE> <ARTIFACT>
```

Writes on success:

- `<OUT_FILE>` (JSON payload with R1CS matrices and metadata)

Options:

- `--allow-unsupported`: writes diagnostics for unsupported opcodes before exiting.

Important behavior:

- Unsupported opcodes are still treated as a failure.
- When `--allow-unsupported` is set, a diagnostics file named `unsupported_opcodes.json` is emitted for debugging.

## `interop`

Usage:

```bash
noir-cli interop [--allow-unsupported] [--no-pedantic] \
  --out <OUT_DIR> <ARTIFACT> <INPUTS>
```

Writes on success:

- `<OUT_DIR>/circuit.r1cs`
- `<OUT_DIR>/witness.wtns`

Options:

- `--no-pedantic`: disables pedantic witness solving checks.
- `--allow-unsupported`: enables unsupported-opcode diagnostics.

Important behavior:

- If unsupported opcodes are encountered in strict lowering, the command exits non-zero.
- When `--allow-unsupported` is set, `<OUT_DIR>/unsupported_opcodes.json` is written for debugging.
- `.r1cs`/`.wtns` are only emitted on successful lowering and witness generation.
