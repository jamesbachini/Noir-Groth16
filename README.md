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

# Opcode Support

# ACIR Opcode Support Plan (acir 0.46.0)

This repository targets ACIR `0.46.0` and BN254/iden3-compatible R1CS output.
The table below tracks opcode coverage in `crates/noir-r1cs`.

## Program opcode variants

| ACIR opcode variant | Encountered in current `test-vectors/*.json` artifacts | Status | Lowering / handling plan |
|---|---:|---|---|
| `AssertZero(Expression)` | Yes (`fixture_artifact.json`) | Supported | Keep canonical lowering to R1CS with deterministic row/wire ordering and stronger invariants. |
| `BlackBoxFuncCall(BlackBoxFuncCall)` | Yes (`blackbox_bool_artifact.json`) | Partially supported | Implemented: boolean-safe `AND`/`XOR` and `RANGE(num_bits=1)`. All other blackboxes fail loudly with opcode index/context. |
| `Directive(Directive)` | Not yet in committed artifact fixtures | Unsupported | Add explicit diagnostic error with opcode index/span context. Future: evaluate safe lowering for selected directives only. |
| `MemoryOp { block_id, op, predicate }` | Yes (`memory_mux_artifact.json`) | Partially supported | Implemented static indexing/operation (`read`/`write`) and predicate=`1`/None path. Dynamic index/op/predicate is rejected with explicit errors. |
| `MemoryInit { block_id, init }` | Yes (`memory_mux_artifact.json`) | Supported (for static memory path) | Deterministic memory state initialization for subsequent static `MemoryOp` lowering. |
| `BrilligCall { .. }` | Not yet in committed artifact fixtures | Unsupported | Strict mode error; permissive diagnostics mode can report coverage gaps but must not emit unsound R1CS. |
| `Call { .. }` | Not yet in committed artifact fixtures | Unsupported | Strict mode error; future support requires deterministic cross-function lowering and argument/output binding constraints. |

## Blackbox function coverage (inside `Opcode::BlackBoxFuncCall`)

| Blackbox function | Status | Notes |
|---|---|---|
| `AND` | Partially supported | Implemented for `num_bits == 1` with booleanity checks on inputs/output and `out = lhs * rhs`. |
| `XOR` | Partially supported | Implemented for `num_bits == 1` with booleanity checks and `out = lhs + rhs - 2*lhs*rhs`. |
| `RANGE` | Partially supported | Implemented for `num_bits == 1` (boolean). Multi-bit range remains unsupported. |
| `Poseidon2Permutation` | Unsupported in R1CS lowering | Witness solver supports it; lowering must remain strict and fail unless a sound constraint strategy is added. |
| Other blackboxes (`SHA256`, `Keccak`, ECDSA, Pedersen, bigint, etc.) | Unsupported in R1CS lowering | Must not be silently accepted. Future support requires complete constraint system or an explicitly trusted proving strategy. |

## Expression-level patterns (inside `AssertZero`)

`Add`/`Sub`/`Mul` and mux/select patterns are represented as `Expression` terms in this ACIR version, not distinct top-level opcodes.

| Pattern | Status | Lowering form |
|---|---|---|
| Linear arithmetic (`a + b - c`, `a - b`) | Supported | Single `AssertZero` linear row |
| Multiplication (`a * b - c`) | Supported | Introduce constrained intermediate for each mul term, then final linear row |
| AssertEq (`a == b`) | Supported via equivalence | Lower as `AssertZero(a - b)` |
| Select / mux (`result = cond ? a : b`) | Supported via equivalence | Lowered through expression identity `result - (b + cond*(a-b)) == 0`; booleanity of `cond` must be separately constrained |

## Execution modes

- Strict mode (default): unsupported/underconstrained behavior is an error.
- Diagnostics mode (`--allow-unsupported`): still fails compilation, but emits coverage diagnostics and does **not** emit `.r1cs`/`.wtns`.

## Disclaimer

Please note code is experimental in nature and not currently suitable for production.

## License

MIT
