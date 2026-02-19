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
