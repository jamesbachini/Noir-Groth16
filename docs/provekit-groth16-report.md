# Provekit Noir Examples Groth16 Report

Date: 2026-06-12

Source corpus: `worldfnd/provekit` `017f115f30cf98e29ed2da99d7ed6b6429d676f3`

Imported location: `examples/provekit/`

Command run:

```bash
EXAMPLES_DIR=examples/provekit PTAU_POWER=16 STAGE_TIMEOUT=60 \
  ./examples/run_test_suite.sh --out target/provekit-full-suite
```

Toolchain:

- `nargo 1.0.0-beta.19`
- `snarkjs 0.7.6`
- `node v24.13.0`
- `cargo 1.94.0-nightly`

The suite compiles each Noir package, runs `noir-cli r1cs-json --allow-unsupported` as a preflight, emits `.r1cs` and `.wtns` with `noir-cli interop`, then runs `snarkjs wtns check`, Groth16 setup, contribution, verification-key export, proof generation, and proof verification.

## Summary

Result: improved, but not production-ready for broad Noir coverage.

Update from the implementation pass:

- ABI input filtering and boolean/signed-integer parsing are now implemented.
- `basic-2`, `basic-3`, and `basic-4` pass `noir-cli interop` in focused reruns.
- SHA-256 lowering now seeds many more derived wires, but `sha256` still times out during witness materialization under a 90 second focused cap.
- The remaining SHA/memory issue is no longer input parsing; it is materializing memory update/delta wires efficiently without making lowering prohibitively slow.

- Total input cases: 72
- Passed full Groth16 verification: 25
- Failed: 44
- Unsupported by current R1CS lowering: 1
- Skipped because package is a library, not a standalone circuit: 2

Raw results and logs:

- `target/provekit-full-suite/results.tsv`
- `target/provekit-full-suite/logs/`

## Passing Circuits

These completed witness generation, R1CS/WTNS emission, `snarkjs wtns check`, Groth16 setup, proof generation, and proof verification:

- `basic-3`
- `basic-4`
- `csp-benchmarks/poseidon2_4`
- `csp-benchmarks/poseidon_2`
- `csp-benchmarks/poseidon_4`
- `csp-benchmarks/poseidon_8`
- `csp-benchmarks/poseidon_12`
- `csp-benchmarks/poseidon_16`
- `noir-r1cs-test-programs/acir_assert_zero`
- `noir-r1cs-test-programs/bin-opcode`
- `noir-r1cs-test-programs/bin-opcode-u8`
- `noir-r1cs-test-programs/bin-opcode-u16`
- `noir-r1cs-test-programs/bin-opcode-u64`
- `noir-r1cs-test-programs/bin-opcode-u64-large-const`
- `noir-r1cs-test-programs/bin-opcode-u128`
- `noir-r1cs-test-programs/brillig-unconstrained`
- `noir-r1cs-test-programs/conditional-write`
- `noir-r1cs-test-programs/range-check-mixed-bases`
- `noir-r1cs-test-programs/range-check-u8`
- `noir-r1cs-test-programs/range-check-u16`
- `noir-r1cs-test-programs/read-only-memory`
- `noir-r1cs-test-programs/read-write-memory`
- `noir-r1cs-test-programs/simplest-read-only-memory`
- `power`
- `zkchase`

## Non-Passing Circuits

### Compile Failures

These never reached the backend because `nargo compile` failed with the current compiler/dependency set:

- `basic`: `TaceoLabs/noir-poseidon v0.5.0-beta.0` imports `std::collections::vec::Vec`, which this Nargo toolchain cannot resolve.
- `csp-benchmarks/poseidon2_2`
- `csp-benchmarks/poseidon2_8`
- `csp-benchmarks/poseidon2_12`
- `csp-benchmarks/poseidon2_16`
- `many_poseidons`: `noir-lang/poseidon v0.1.1` uses comptime global `RATE` in non-comptime code.
- `noir-passport-monolithic/complete_age_check`: same `noir-lang/poseidon v0.1.1` comptime `RATE` issue.
- `oprf`: both `TaceoLabs/noir-poseidon` `Vec` resolution errors and `babyjubjub` comptime global `Z` usage.
- `poseidon2`: mixed `noir-lang/poseidon v0.1.1` comptime `RATE` and `TaceoLabs/noir-poseidon` `Vec` errors.

Required work:

- Pin or patch upstream Noir dependencies to versions compatible with `nargo 1.0.0-beta.19`, or move this repository to the compiler version those examples target.
- Add a dependency-compatibility CI job for imported examples so compiler/library drift is caught before backend testing.

### Input/ABI Conversion Status

Implemented in this pass:

- `interop` now filters imported JSON inputs to the compiled ABI parameter set.
- Boolean inputs accept JSON booleans, `0`/`1`, and string `"0"`/`"1"`/`"true"`/`"false"`.
- Signed ABI integer inputs are range-checked and encoded as Noir two's-complement field values.

Remaining work:

- Rerun the complete provekit suite to refresh all counts after these fixes.
- Add broader fixture coverage for signed integers across all widths used by the imported programs.

### Witness Materialization And Timeout Failures

These solved far enough to produce a large R1CS shape but failed materializing the witness vector:

- `sha256`: focused rerun still times out during `noir-cli interop` at 90 seconds.
- `csp-benchmarks/sha256_128`: previously failed materializing witness for `280424` wires.
- `csp-benchmarks/sha256_256`: previously failed materializing witness for `423206` wires.

Required work:

- Finish efficient materialization for dynamic-memory update/delta wires used by SHA-related programs.
- Ensure every allocated R1CS wire has either a source ACIR witness value, a deterministic derived assignment, or an efficient materializer pattern before `.wtns` emission.
- Add SHA-256 compression/full-hash tests with tamper failures at these sizes.

### Unsupported Opcode

- `p256_std`: unsupported `BlackBoxFuncCall` for `ECDSA_SECP256R1`; diagnostics say witness-driven native lowering is not implemented.

Required work:

- Implement sound native lowering for witness-driven `ECDSA_SECP256R1`, or constrain an equivalent in-circuit implementation.
- Add satisfiable and tamper-fail tests for all ECDSA output and predicate paths.

### Preflight Timeouts

These did not complete `noir-cli r1cs-json --allow-unsupported` within 60 seconds:

- `csp-benchmarks/ecdsa_p256`
- `csp-benchmarks/keccak_128`
- `csp-benchmarks/keccak_256`
- `csp-benchmarks/keccak_512`
- `csp-benchmarks/keccak_1024`
- `csp-benchmarks/keccak_2048`
- `csp-benchmarks/sha256_512`
- `csp-benchmarks/sha256_1024`
- `csp-benchmarks/sha256_2048`
- `noir_sha256`
- `p256_bigcurve`

Required work:

- Profile R1CS lowering for large hash and curve circuits.
- Add early unsupported-opcode detection that does not require expensive full lowering.
- Add performance budgets to CI and record constraint/wire counts per circuit.
- For circuits that are genuinely large but supported, run with a larger ptau and timeout after profiling confirms expected runtimes.

### Interop Timeouts

These passed compile/preflight but did not complete `noir-cli interop` within 60 seconds:

- `embedded_curve_msm`
- `embedded_curve_msm#near_identity`
- `embedded_curve_msm#near_order`
- `embedded_curve_msm#single_nonzero`
- `embedded_curve_msm#zero_scalars`
- `msm_conditional`
- `msm_conditional#inactive`
- `msm_conditional#scalar2`
- `msm_conditional_nested`
- `msm_conditional_nested#inner_false`
- `msm_conditional_nested#outer_false`
- `native_msm`
- `noir-r1cs-test-programs/bounded-vec`
- `noir-r1cs-test-programs/small-sha`
- `poseidon-rounds`
- `rangechecks`

Required work:

- Profile witness solving, R1CS lowering, and witness materialization separately for these cases.
- Investigate MSM and embedded-curve native lowering scaling, especially guarded/inactive predicates.
- Add progress metrics and per-stage timing output to `noir-cli interop`.
- After performance fixes, rerun with higher `STAGE_TIMEOUT` to distinguish slow-but-valid circuits from non-terminating paths.

### Skipped Libraries

These are library packages, not standalone binary circuits:

- `eddsa_poseidon2`
- `noir-native-sha256`

Required work:

- Add explicit binary harness circuits for these libraries if they should be part of production compatibility testing.

## Production Readiness Notes

- Do not treat the current backend as broadly compatible with Noir production workloads yet.
- The existing backend handles many arithmetic, range, memory, Poseidon, and simple Brillig cases.
- Current blockers are broad enough to affect common real circuits: SHA-256, Keccak, ECDSA/P256, MSM/embedded-curve operations, large bounded vectors, and dependency/version drift.
- The highest-priority engineering work is ABI-aware input conversion, SHA witness materialization, ECDSA/P256 support, and profiling/scaling of large blackbox/native lowering paths.
