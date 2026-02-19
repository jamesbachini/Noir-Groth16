```markdown
<!-- prompt1.md -->
# Prompt 1: Repo scaffold + ACIR artifact parser (Rust)

## Task
Create a Rust workspace implementing:
- `noir-acir` crate: parse Noir compiled artifact JSON into:
  - ACIR program bytes / opcodes (using `acir` types)
  - ABI (public/private inputs, return values)
- `noir-cli` binary: `noir-groth16 compile-r1cs <artifact.json> --out <dir>`

## Inputs
- `artifact.json` produced by `nargo compile` (fixture committed under `test-vectors/`).

## Expected outputs
- `out/parsed.json` with:
  - opcode count
  - witness count
  - list of opcode variants present (AssertZero, BlackBoxFuncCall, ...)

## Tests
- Unit: parse fixture; assert `Opcode::AssertZero` exists.
- Snapshot: stable JSON output ordering.

## Completion criteria
- `cargo test` passes
- CLI prints deterministic summary for the fixture
```

```markdown
<!-- prompt2.md -->
# Prompt 2: Witness generation via ACVM + BN254 blackbox solver

## Task
Implement `noir-witness` crate:
- Given `artifact.json` + `inputs.json`:
  - encode inputs into ACVM witness map
  - execute partial witness generation
  - output `witness_map.json` and `witness.vec` (binary Fr elements)

Use Noir’s BN254 Poseidon2 blackbox solver when Poseidon2Permutation is present.

## Inputs
- `artifact.json`
- `inputs.json` (matching Noir ABI)

## Expected outputs
- `witness_map.json`: map witness index → field element
- `witness.bin`: vector encoding with `w[0]=1`

## Tests
- Determinism: same inputs produce identical witness.bin.
- Smoke: Poseidon2 blackbox circuit matches expected output value (fixture).

## Completion criteria
- `cargo test` passes
- `noir-groth16 witness artifact.json inputs.json --out out/` produces the two files
```

```markdown
<!-- prompt3.md -->
# Prompt 3: ACIR AssertZero(Expression) → R1CS compiler (MVP)

## Task
Implement `noir-r1cs` crate with:
- `compile_r1cs(acir_program) -> R1csSystem { n_wires, n_constraints, A/B/C sparse rows }`
- Support only `Opcode::AssertZero(Expression)` initially.

Constraint lowering:
- emit `a*b=t` constraints for every mul term
- emit `1*L=0` linear constraint for the accumulated expression

## Inputs
- ACIR program from Prompt 1

## Expected outputs
- In-memory R1CS matrices + a debug `r1cs.json` export

## Tests
- Unit: simple Noir circuit `fn main(x: Field) { assert(x*x + 3 == y) }` compiled to ACIR fixture:
  - check constraint count equals (mul_terms + 1)
  - check that plugging witness vector satisfies all constraints

## Completion criteria
- `cargo test` passes
- `noir-groth16 r1cs-json artifact.json --out out/r1cs.json`
```

```markdown
<!-- prompt4.md -->
# Prompt 4: Interop writers (.r1cs + .wtns) and snarkjs validation

## Task
Add serializers:
- `.r1cs` writer for iden3 binary format (header + constraints + wire map)
- `.wtns` writer compatible with snarkjs

Add an integration test (behind `--features interop-test`) that:
- emits `circuit.r1cs` and `witness.wtns`
- runs:
  - `snarkjs wtns check circuit.r1cs witness.wtns`
  - `snarkjs groth16 setup` + prove + verify (small circuit only)

## Inputs
- small fixture circuit (<= 2^12 constraints)

## Expected outputs
- snarkjs prints `OK` for verification.

## Tests
- Rust: roundtrip parse `.r1cs` with a known parser if available; parse `.wtns` with `wtns-file`.
- Node: snarkjs integration test in CI.

## Completion criteria
- `cargo test --features interop-test` passes locally (requires node+snarkjs)
- CI runs Rust-only tests by default
```

