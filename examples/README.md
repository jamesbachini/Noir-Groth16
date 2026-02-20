# Noir Example Suite

This directory contains Noir example circuits for validating the `tutorial.md` pipeline end-to-end.

Each example package includes:
- `Nargo.toml`
- `src/main.nr`
- `inputs.json` (for `noir-groth16 interop`)

Current examples:
- `arithmetic_assert`
- `array_struct_lookup`
- `blake2s_digest`
- `inequality_check`
- `fixed_loop_sum`
- `bounded_loop_partial_sum`
- `struct_transfer`
- `tuple_flag`
- `tuple_inputs_complex`
- `bitwise_u8`
- `shift_and_mask`
- `range_u32`
- `dynamic_index_lookup` (branch-based indexed selection)
- `nested_matrix_index`
- `multi_function_chain`
- `boolean_logic`
- `poseidon2_state_word`
- `pedersen_hash`
- `string_ascii_sum`

## Run the full tutorial pipeline on all examples

From repository root:

```bash
./examples/run_tutorial_suite.sh
```

This runs:
1. `nargo compile` for each example package.
2. `noir-groth16 interop` to emit `.r1cs` and `.wtns`.
3. `snarkjs wtns check`.
4. `snarkjs groth16 setup/prove/verify`.

Artifacts and logs are written under `target/example-suite/`.
