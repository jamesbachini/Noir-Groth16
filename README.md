# Noir Groth16 Backend
### Noir Lang > ACIR > R1CS > Groth16

Noir-Groth16 is a Rust workspace that turns Noir artifacts into deterministic witness and R1CS outputs for Groth16 tooling.

Pipeline:
1. Parse Noir artifact JSON + ABI metadata.
2. Build and solve witnesses with ACVM from ABI-shaped inputs.
3. Lower supported ACIR constraints into R1CS.
4. Emit deterministic artifacts (`.r1cs`, `.wtns`, JSON/bin debug outputs).

## Current Scope

- Field target: BN254.
- Interop target: iden3 `.r1cs` and `.wtns` (snarkjs-compatible).
- R1CS lowering support: `AssertZero` opcodes.
- Non-`AssertZero` ACIR opcodes in `noir-r1cs` are rejected with an explicit `UnsupportedOpcode` error.
- Witness generation uses ACVM and includes a BN254 Poseidon2 permutation blackbox solver.

## Workspace Layout

- `crates/noir-acir`: Noir artifact parsing, ABI modeling, witness layout helpers.
- `crates/noir-witness`: ABI input flattening, ACVM witness solving, witness emitters.
- `crates/noir-r1cs`: ACIR `AssertZero` to R1CS lowering, `.r1cs` and JSON writers.
- `crates/noir-cli`: CLI entrypoints for parsing, witness generation, R1CS debug output, and interop outputs.
- `test-vectors/`: minimal fixture artifact + inputs used by tests and examples.

## CLI Commands

Binary:

```bash
cargo run -p noir-cli --bin noir-groth16 -- <command> ...
```

### `compile-r1cs`

Parses the artifact and writes a deterministic summary JSON.

```bash
cargo run -p noir-cli --bin noir-groth16 -- \
  compile-r1cs test-vectors/fixture_artifact.json --out out/parse
```

Output:
- `out/parse/parsed.json`

### `witness`

Generates witness outputs from artifact + ABI-shaped inputs.

```bash
cargo run -p noir-cli --bin noir-groth16 -- \
  witness test-vectors/fixture_artifact.json test-vectors/fixture_inputs.json --out out/witness
```

Outputs:
- `out/witness/witness_map.json`
- `out/witness/witness.bin`
- `out/witness/witness.wtns`

### `r1cs-json`

Compiles supported ACIR into debug R1CS JSON.

```bash
cargo run -p noir-cli --bin noir-groth16 -- \
  r1cs-json test-vectors/fixture_artifact.json --out out/circuit.r1cs.json
```

Output:
- `out/circuit.r1cs.json`

### `interop`

Emits snarkjs-friendly iden3 binaries (`.r1cs` and `.wtns`).

```bash
cargo run -p noir-cli --bin noir-groth16 -- \
  interop test-vectors/fixture_artifact.json test-vectors/fixture_inputs.json --out out/interop
```

Outputs:
- `out/interop/circuit.r1cs`
- `out/interop/witness.wtns`

## Development Workflow

Run these before opening a PR:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
cargo test --workspace
```

Optional snarkjs interop smoke test:

```bash
npm i -g snarkjs
cargo test -p noir-cli --features interop-test -- --ignored
```

## Project Invariants

- Constraint soundness: computed values must be transitively constrained.
- Determinism: stable constraint ordering, wire indexing, and public input ordering.
- Encoding discipline: explicit, consistent endianness across emitters/consumers.
- Underconstrained behavior: unsupported or unconstrained paths should fail loudly in strict flows.

## Disclaimer

Please note code is experimental in nature and not currently suitable for production.

## License

MIT
