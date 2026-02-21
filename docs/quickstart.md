---
title: Quickstart
nav_order: 2
---

# Quickstart

This project includes a starter Noir circuit in `circuits/` and a single script that compiles, proves, and verifies end-to-end.

## Prerequisites

- Rust toolchain with `cargo`
- Noir tooling with `nargo`
- Node.js + npm (used via `npx snarkjs`)

## 1) Edit the circuit and inputs

Update these files:

- `circuits/src/main.nr`
- `circuits/inputs.json`

The default starter circuit checks `x * x == y` with `y` public.

## 2) Run the full Groth16 flow

From repository root:

```bash
./scripts/run_circuit.sh
```

The script runs:

1. `cargo build -p noir-cli`
2. `nargo compile` for `circuits/`
3. `noir-cli interop` to emit `.r1cs` and `.wtns`
4. `snarkjs wtns check`
5. Powers of Tau setup (reused on later runs)
6. Groth16 setup, prove, and verify

## 3) Read outputs

Outputs are written to `target/groth16/`:

- `target/groth16/interop/circuit.r1cs`
- `target/groth16/interop/witness.wtns`
- `target/groth16/proof/proof.json`
- `target/groth16/proof/public.json`
- `target/groth16/proof/verification_key.json`

## Optional overrides

```bash
CIRCUIT_DIR=/path/to/circuit OUT_DIR=/path/to/output PTAU_POWER=14 ./scripts/run_circuit.sh
```
