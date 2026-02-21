---
title: snarkjs Interop
nav_order: 4
---

# snarkjs Interop

This section shows the standard flow from Noir artifact to Groth16 proof verification with `snarkjs`.

## 1) Emit interop artifacts

```bash
cargo run -p noir-cli -- interop \
  --out demo \
  test-vectors/fixture_artifact.json \
  test-vectors/fixture_inputs.json
```

Expected files:

- `demo/circuit.r1cs`
- `demo/witness.wtns`

## 2) Optional witness consistency check

```bash
npx snarkjs wtns check demo/circuit.r1cs demo/witness.wtns
```

## 3) Powers of Tau ceremony

```bash
npx snarkjs powersoftau new bn128 12 demo/pot12_0000.ptau -v
npx snarkjs powersoftau prepare phase2 demo/pot12_0000.ptau demo/pot12_final.ptau -v
```

## 4) Groth16 setup and key material

```bash
npx snarkjs groth16 setup demo/circuit.r1cs demo/pot12_final.ptau demo/circuit_0000.zkey
npx snarkjs zkey contribute demo/circuit_0000.zkey demo/circuit_final.zkey \
  --name="First contribution" -v -e="some random text"
npx snarkjs zkey export verificationkey demo/circuit_final.zkey demo/verification_key.json
```

## 5) Prove and verify

```bash
npx snarkjs groth16 prove demo/circuit_final.zkey demo/witness.wtns demo/proof.json demo/public.json
npx snarkjs groth16 verify demo/verification_key.json demo/public.json demo/proof.json
```

## Notes

- Noir-Groth16 targets BN254 (`bn128` in `snarkjs` CLI naming).
- Keep trusted setup artifacts (`.ptau`, `.zkey`) versioned and traceable in real deployments.
- For CI-level interoperability checks, see the ignored interop tests in `crates/noir-cli/tests/interop.rs`.
