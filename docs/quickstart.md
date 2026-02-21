---
title: Quickstart
nav_order: 2
---

# Quickstart

This guide uses included fixtures so you can validate the full pipeline quickly.

## Prerequisites

- Rust toolchain with `cargo`
- Optional for proving flow: Node.js + `snarkjs`

## 1) Build the CLI

```bash
cargo build -p noir-cli
```

You can run commands through Cargo (`cargo run -p noir-cli -- ...`) or call the built binary directly.

## 2) Parse an artifact

```bash
cargo run -p noir-cli -- compile-r1cs \
  --out demo/quickstart/compile \
  test-vectors/fixture_artifact.json
```

Output:

- `demo/quickstart/compile/parsed.json`

## 3) Generate witnesses

```bash
cargo run -p noir-cli -- witness \
  --out demo/quickstart/witness \
  test-vectors/fixture_artifact.json \
  test-vectors/fixture_inputs.json
```

Outputs:

- `demo/quickstart/witness/witness_map.json`
- `demo/quickstart/witness/witness.bin`
- `demo/quickstart/witness/witness.wtns`

## 4) Emit debug R1CS JSON

```bash
cargo run -p noir-cli -- r1cs-json \
  --out demo/quickstart/r1cs.json \
  test-vectors/fixture_artifact.json
```

Output:

- `demo/quickstart/r1cs.json` (JSON file)

## 5) Emit interop artifacts (`.r1cs` + `.wtns`)

```bash
cargo run -p noir-cli -- interop \
  --out demo/quickstart/interop \
  test-vectors/fixture_artifact.json \
  test-vectors/fixture_inputs.json
```

Outputs:

- `demo/quickstart/interop/circuit.r1cs`
- `demo/quickstart/interop/witness.wtns`

## 6) Validate locally

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```
