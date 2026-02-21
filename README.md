# Noir Groth16 Backend

Noir-Groth16 is a Rust workspace that turns Noir artifacts into deterministic witness and R1CS outputs for Groth16 tooling.

Pipeline:
1. Parse Noir artifact JSON + ABI metadata.
2. Build and solve witnesses with ACVM from ABI-shaped inputs.
3. Lower supported ACIR constraints into R1CS.
4. Emit deterministic artifacts (`.r1cs`, `.wtns`, JSON/bin debug outputs).


## Docs

Full documentation available at:
https://jamesbachini.github.io/Noir-Groth16/


## Workspace Layout

- `crates/noir-acir`: Noir artifact parsing, ABI modeling, witness layout helpers.
- `crates/noir-witness`: ABI input flattening, ACVM witness solving, witness emitters.
- `crates/noir-r1cs`: ACIR lowering and `.r1cs` / debug JSON writers.
- `crates/noir-cli`: CLI entrypoints.
- `examples/`: Noir example packages (including `examples/demo`).
- `test-vectors/`: Fixture artifacts + inputs used by tests.


## Getting Started

Prerequisites:

```bash
cargo --version
node --version
npm --version
```

Build the CLI:

```bash
cargo build -p noir-cli
```

Run from workspace root:

```bash
./target/debug/noir-cli <command> ...
```

Optional: install as a normal shell command:

```bash
cargo install --path crates/noir-cli --force
noir-cli --help
```

You can also run without building manually:

```bash
cargo run -p noir-cli -- <command> ...
```


## CLI Commands

### `compile-r1cs`

Parse artifact and write deterministic parse summary JSON.

```bash
noir-cli compile-r1cs test-vectors/fixture_artifact.json --out out/parse
```

Output:
- `out/parse/parsed.json`

### `witness`

Generate witness outputs from artifact + ABI-shaped inputs.

```bash
noir-cli witness test-vectors/fixture_artifact.json test-vectors/fixture_inputs.json --out out/witness
```

Pedantic solving is enabled by default. Pass `--no-pedantic` to disable strict predicate/selector checks.

Outputs:
- `out/witness/witness_map.json`
- `out/witness/witness.bin`
- `out/witness/witness.wtns`

### `r1cs-json`

Compile supported ACIR into debug R1CS JSON.

```bash
noir-cli r1cs-json test-vectors/fixture_artifact.json --out out/circuit.r1cs.json
```

Output:
- `out/circuit.r1cs.json`

### `interop`

Emit snarkjs-friendly iden3 binaries (`.r1cs` and `.wtns`).

```bash
noir-cli interop test-vectors/fixture_artifact.json test-vectors/fixture_inputs.json --out out/interop
```

Pedantic solving is enabled by default. Pass `--no-pedantic` to disable strict predicate/selector checks.

Outputs:
- `out/interop/circuit.r1cs`
- `out/interop/witness.wtns`


## Example Process (Groth16 End-to-End)

### 1) Build CLI

```bash
cd /mnt/c/code/Noir-Groth16
cargo build -p noir-cli
```

### 2) Compile fixture to interop artifacts

```bash
./target/debug/noir-cli interop test-vectors/fixture_artifact.json \
  test-vectors/fixture_inputs.json --out demo
```

Produces:
- `demo/circuit.r1cs`
- `demo/witness.wtns`

### 3) Generate and verify proof with `snarkjs`

```bash
cd /mnt/c/code/Noir-Groth16/demo
npx snarkjs wtns check circuit.r1cs witness.wtns
npx snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
npx snarkjs powersoftau prepare phase2 pot12_0000.ptau pot12_final.ptau -v
npx snarkjs groth16 setup circuit.r1cs pot12_final.ptau circuit_0000.zkey
npx snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="demo" -v -e="demo entropy"
npx snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
npx snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json
npx snarkjs groth16 verify verification_key.json public.json proof.json
```

### Optional: compile bundled Noir demo package

Source lives at `examples/demo/src/main.nr`.

```bash
cd /mnt/c/code/Noir-Groth16/examples/demo
nargo compile
cd /mnt/c/code/Noir-Groth16
./target/debug/noir-cli interop examples/demo/target/demo.json \
  examples/demo/inputs.json --out demo
```

### Optional: run full example suite

```bash
./examples/run_test_suite.sh
```

## Current ACIR Support (crates/noir-r1cs)

Target assumptions:
- Field: BN254
- Output format: iden3 `.r1cs` and `.wtns`

### Program opcode variants

| ACIR opcode | Status | Notes |
|---|---|---|
| `AssertZero(Expression)` | Supported | Canonical lowering with deterministic row/wire ordering. |
| `MemoryInit { .. }` | Supported | Deterministic memory block initialization. |
| `MemoryOp { .. }` | Supported (with checks) | Static/dynamic memory access lowering; invalid block/index forms fail loudly. |
| `BlackBoxFuncCall(BlackBoxFuncCall)` | Partially supported | Native lowering for `AND`, `XOR`, and `RANGE` (exact for `num_bits <= 253`; tautological acceptance for `num_bits >= 254` on BN254). Other blackboxes are hint-lowered and require downstream constraints on outputs. |
| `BrilligCall { .. }` | Supported (guarded) | Lowered via hint plumbing; predicates must be boolean and outputs must be transitively constrained by non-hint rows. |
| `Call { .. }` | Supported (guarded) | Non-recursive nested calls supported with predicate gating and output binding constraints. |

### Unsupported / rejected cases

- Predicates for `Call` / `BrilligCall` that are not 0/1.
- Recursive `Call` and invalid call targets (including function id 0 / main).
- Blackbox or Brillig opcodes that expose no outputs when their predicate is not provably false.
- Hint outputs not constrained by non-hint R1CS rows.

### Execution modes

- Strict mode (default): fails immediately on unsupported/underconstrained behavior.
- `--allow-unsupported`: collects unsupported opcode diagnostics and writes `unsupported_opcodes.json`, but still fails and does not emit final `.r1cs` / `.wtns`.
- Witness solving mode defaults to pedantic predicate/selector validation. Use `--no-pedantic` on `witness`/`interop` only when intentionally matching legacy non-pedantic ACVM behavior.


## Development Workflow

Run before PRs:

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

Optional interop smoke test:

```bash
npm i -g snarkjs
cargo test -p noir-cli --features interop-test -- --ignored
```

Compatibility corpus differential test (compiles all real Noir projects under `examples/`, solves via ACVM, lowers to R1CS, checks satisfaction, then tamper-fails constrained wires):

```bash
nargo --version
cargo test -p noir-cli compatibility_corpus_differential_checks -- --ignored --nocapture
```


## Disclaimer

Experimental software; not currently suitable for production use.


## License

MIT
