# Noir to Groth16 Backend
### Noir Lang > ACIR > R1CS > Groth16

Noir compiles programs into an intermediate bytecode format called ACIR, intended to be backend-agnostic. citeturn13search21turn29search23 ACIR’s core constraint opcode is `AssertZero(Expression)` where `Expression` is a quadratic polynomial represented as a sum of multiplication terms, linear terms, and a constant. citeturn14view0turn18view0 This makes an ACIR→R1CS compiler feasible by translating each quadratic `Expression` into (a) a small set of multiplication constraints plus (b) one linear “sum-to-zero” constraint—exactly the approach taken by prior Noir→R1CS work (e.g., pluto/edge and lambdaclass’ experimental backend). citeturn4view2turn3view1

For Stellar/Soroban integration, the limiting factor is not Groth16 itself but on-chain resource ceilings (notably 100M CPU instructions and 40MB RAM per transaction) and the availability of BN254 pairing host functions. citeturn8search1turn7view0 CAP-0074 proposes `bn254_g1_add`, `bn254_g1_mul`, and `bn254_multi_pairing_check` with explicit uncompressed point encodings (G1=64 bytes, G2=128 bytes) and states the curve “no longer offers 128-bit security,” which must be accepted as a tradeoff for ecosystem compatibility. citeturn7view0 Groth16 proofs are “3 points only and 3 pairings,” so a straightforward uncompressed proof payload is ~256 bytes (64+128+64), plus public inputs. citeturn10view0turn7view0

The most pragmatic build is: reuse Noir’s ACVM tooling for witness generation (including Noir’s BN254 Poseidon2 blackbox solver), compile ACIR→R1CS, then produce Groth16 proofs using a Rust library (arkworks or bellman), with optional `.r1cs/.wtns` emission for snarkjs interoperability. citeturn27view1turn20search10turn19view0turn5search34turn25search2

## System Goals and Constraints

| Aspect | Spec target | Rationale / source |
|---|---|---|
| Proof system | Groth16 | Small proof and pairing-based verification; snarkjs describes Groth16 as “3 points only and 3 pairings.” citeturn10view0 |
| Curve | BN254 | CAP-0074 proposes native BN254 host functions for Soroban, motivated by EVM compatibility. citeturn7view0 |
| Soroban transaction limits | 100M CPU instr, 40MB RAM, tx size 132KB | Hard ceiling for verifier contract. citeturn8search1 |
| Proof encoding for on-chain | Uncompressed G1/G2 bytes | CAP-0074 specifies G1 serialization as `X||Y` (32-byte big-endian coords), G2 as 4×32 bytes. citeturn7view0 |
| Expected proof size | ~256 bytes (uncompressed) + public inputs | 2×G1 + 1×G2; sizes from CAP-0074; proof structure from snarkjs. citeturn7view0turn10view0 |
| Hash strategy in-circuit | Prefer Poseidon2; Keccak optional/expensive | Noir exposes `keccakf1600` and Poseidon2 permutation as backends/blackboxes. citeturn28search8turn17view0 Keccak permutation is extremely constraint-heavy in common R1CS gadgets (e.g., gnark). citeturn21search32 |

If you need strict EVM/snarkjs/Circom interoperability, generate `.r1cs` and `.wtns` in the iden3 binary formats. citeturn19view0turn12search1 If you only need a Stellar verifier, you can skip those files and drive Groth16 directly from Rust constraint matrices + witness vectors.

## Architecture and Interfaces

ACIR is the compilation target for Noir and is designed to sit between frontends and proving backends. citeturn13search21turn29search23 The opcode surface area you must handle is small but non-trivial: `AssertZero`, `BlackBoxFuncCall`, `BrilligCall`, `Call`, `Directive`, `MemoryInit`, `MemoryOp`. citeturn18view0turn18view1 In practice, most arithmetic is in `AssertZero(Expression)`; `BlackBoxFuncCall` covers hashes/range/bitwise/etc.; and `BrilligCall` represents unconstrained computation used for witness generation (and must be treated carefully for soundness). citeturn18view1turn29search5

For Poseidon2 specifically, Noir already ships a BN254 Poseidon2 permutation blackbox solver (and constants) that can be reused for witness generation and as the “golden” reference for constraint generation. citeturn27view0turn27view1

A proven pattern for ACIR→R1CS is:
- emit R1CS multiplication constraints for each multiplication term, introducing intermediate variables; then
- emit one linear constraint that the weighted sum of intermediates + linear terms + constant equals zero.
This is visible in pluto/edge’s conversion strategy and lambdaclass’ partial implementation. citeturn4view2turn3view1

On-chain, Soroban has explicit per-transaction budgets; Groth16 verification must lean on pairing host functions to fit. citeturn8search1turn7view0

image_group{"layout":"carousel","aspect_ratio":"16:9","query":["Groth16 proof structure pairing check diagram","BN254 pairing friendly curve diagram","Stellar Soroban smart contract architecture diagram","R1CS constraint system diagram"],"num_per_query":1}

## ACIR to R1CS Compilation Mapping

### Opcode coverage scope

ACIR opcode variants (per `acir` crate) include `AssertZero(Expression)`, `BlackBoxFuncCall`, `BrilligCall`, `Call`, `Directive`, `MemoryInit`, and `MemoryOp`. citeturn18view0turn18view1 `Expression` is a quadratic polynomial with:
- `mul_terms: Vec<(coef, Witness, Witness)>`
- `linear_combinations: Vec<(coef, Witness)>`
- `q_c: constant` citeturn14view0

### Mapping table

| ACIR opcode | R1CS compilation template | MVP support |
|---|---|---|
| `AssertZero(expr)` | For each `(q, a, b)` in `mul_terms`: allocate `t` and add constraint `(a) * (b) = t`. Then build linear combination `L = Σ(q·t) + Σ(q·w) + q_c` and constrain `1 * L = 0`. citeturn14view0turn4view2 | Yes |
| `BlackBoxFuncCall(AND/XOR)` | Bit-decompose operands with boolean constraints, compute bitwise op per bit, recompose. (Can share range gadget infra.) citeturn17view0turn15view0 | Optional (after RANGE) |
| `BlackBoxFuncCall(RANGE)` | Bit-decompose value to `n` bits: enforce each bit boolean and enforce `x = Σ(2^i·b_i)`. citeturn15view0turn17view0 | Yes |
| `BlackBoxFuncCall(Poseidon2Permutation)` | Expand Poseidon2 round function into field constraints using Noir’s BN254 Poseidon2 reference algorithm/constants. citeturn27view0turn17view0 | Yes (recommended) |
| `BlackBoxFuncCall(Keccakf1600)` | Either unsupported or behind feature flag; a single Keccak-f permutation can cost ~193,650 Groth16 constraints in gnark’s gadget, so expect very large circuits. citeturn21search32turn28search8 | No (initially) |
| `BrilligCall` | Adds **no constraints**; only used during witness generation. Treat as “hint”: keep outputs as witnesses, rely on later constraints to bind them. citeturn18view1turn29search5 | Pass-through + warnings |
| `Call` | Inline sub-circuits or build a flattening pass. ACIR defines `Call` as invoking a separate circuit with its own inputs/outputs/predicate. citeturn18view1 | Later milestone |
| `MemoryInit`, `MemoryOp` | Requires modeling memory consistency; non-trivial in R1CS. citeturn18view1 | No (initially) |
| `Directive` | Backend directive; often treated like a hint / compilation-time op. citeturn18view1 | No (initially) |

## Implementation Plan and Repository Layout

### Backend choices and interoperability

- **Rust Groth16 proving**: `ark-groth16` is a widely used Groth16 implementation in the arkworks ecosystem. citeturn5search34turn23search25
- **Alternative Rust Groth16**: `bellman` exposes a `groth16` module with parameter generation, proof creation, and verification utilities. citeturn25search2turn25search1
- **snarkjs interoperability**: Circom docs describe `.r1cs` (constraints) and `.wtns` (witness) as the inputs into snarkjs Groth16 flows, and show commands for trusted setup (`powersoftau`, `groth16 setup`), proving, and verification. citeturn12search0turn11view0turn12search1
- **Binary formats**: iden3 specifies a standard `.r1cs` binary format with sections (header/constraints/wire map) and requires wire 0 be constant 1. citeturn19view0 The `.wtns` format has Rust parsers/serializers available (`wtns-file`). citeturn20search10
- **Existing reference work**: pluto/edge compiles Noir/ACIR constraints to R1CS for folding, demonstrating an `AssertZero`→R1CS strategy. citeturn4view2 Lambdaclass’ Noir backend for gnark contains an `acir_to_r1cs` scaffold and highlights endianness/serialization pitfalls between ecosystems. citeturn3view1turn28search11
- **Additional ecosystem reference**: ProveKit explicitly integrates Noir compilation artifacts and includes “circuit_stats” analysis plus an R1CS JSON export path, useful as a design reference even if you do not adopt their formats. citeturn30view0

### Soroban verification constraints

Soroban’s resource limits are fixed per transaction. citeturn8search1 To verify BN254 Groth16 efficiently, rely on BN254 host functions that mirror EVM precompiles (pairing check, G1 ops) as proposed in CAP-0074. citeturn7view0 If those host functions are not activated on the target network yet (CAP status is “Awaiting Decision” in the draft), you must either (a) verify on a different curve already supported, or (b) implement pairing in WASM (unlikely to fit the 100M CPU budget). citeturn7view0turn8search1

### Security considerations baseline

- **Underconstrained risks**: ACIR supports unconstrained computation (`BrilligCall`), and Noir docs explicitly describe unconstrained functions as not constraining computation (non-deterministic). citeturn18view1turn29search5 Your backend should surface warnings and optionally run underconstraint detection tests.
- **Curve security**: CAP-0074 notes BN254 “no longer offers 128-bit security.” citeturn7view0 Treat as an explicit acceptance criterion for ecosystem compatibility.
- **Library pitfalls**: Groth16 extensions (e.g., “commitments”) have had real soundness issues in widely used libraries; avoid nonstandard variants unless audited. citeturn23search14

## Testing, Security, and Reproducibility

Testing must validate three independent equivalences:

1) **ACIR semantics vs your witness generator**: using ACVM + noir-provided blackbox solvers (Poseidon2) should reproduce expected witnesses for sample Noir programs. citeturn27view1turn13search18

2) **ACIR→R1CS correctness**: every `AssertZero(Expression)` must become constraints that accept the same satisfying assignments; prior art (pluto/edge) provides a concrete checkable pattern. citeturn4view2turn14view0

3) **Interop formats**: `.r1cs` and `.wtns` must be accepted by snarkjs, and/or roundtrip through known parsers (iden3 r1csfile spec; Rust `wtns-file`). citeturn19view0turn12search1turn20search10

Reproducibility requirements:
- pin Rust toolchain, commit `Cargo.lock`, and ensure deterministic serialization ordering for wires/constraints;
- CI should run unit tests + a minimal end-to-end fixture that compiles a Noir program, generates witness, emits `.r1cs/.wtns`, and (optionally) runs snarkjs verify in Node. citeturn11view0turn12search1turn10view0
