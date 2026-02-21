---
title: snarkjs Interop
nav_order: 4
---

# snarkjs Interop

The recommended path is the one-command script:

```bash
./scripts/run_circuit.sh
```

That script emits interop artifacts and runs proof generation + verification with `snarkjs`.

## Manual equivalent (advanced)

If you need to run commands manually, this is the equivalent flow.
The script auto-detects `<package-name>` from `circuits/Nargo.toml`.

### 1) Compile Noir and emit interop artifacts

```bash
cargo build -p noir-cli
(cd circuits && nargo compile)
./target/debug/noir-cli interop circuits/target/<package-name>.json circuits/inputs.json --out target/groth16/interop
```

Expected files:

- `target/groth16/interop/circuit.r1cs`
- `target/groth16/interop/witness.wtns`

### 2) Witness consistency check

```bash
npx snarkjs wtns check target/groth16/interop/circuit.r1cs target/groth16/interop/witness.wtns
```

### 3) Powers of Tau ceremony

```bash
npx snarkjs powersoftau new bn128 12 target/groth16/pot12_0000.ptau
npx snarkjs powersoftau prepare phase2 target/groth16/pot12_0000.ptau target/groth16/pot12_final.ptau
```

### 4) Groth16 setup and key material

```bash
mkdir -p target/groth16/proof
cp target/groth16/interop/circuit.r1cs target/groth16/interop/witness.wtns target/groth16/proof/
npx snarkjs groth16 setup target/groth16/proof/circuit.r1cs target/groth16/pot12_final.ptau target/groth16/proof/circuit_0000.zkey
npx snarkjs zkey contribute target/groth16/proof/circuit_0000.zkey target/groth16/proof/circuit_final.zkey --name="local" -e="local deterministic entropy"
npx snarkjs zkey export verificationkey target/groth16/proof/circuit_final.zkey target/groth16/proof/verification_key.json
```

### 5) Prove and verify

```bash
npx snarkjs groth16 prove target/groth16/proof/circuit_final.zkey target/groth16/proof/witness.wtns target/groth16/proof/proof.json target/groth16/proof/public.json
npx snarkjs groth16 verify target/groth16/proof/verification_key.json target/groth16/proof/public.json target/groth16/proof/proof.json
```

## Notes

- Noir-Groth16 targets BN254 (`bn128` in `snarkjs` CLI naming).
- Keep trusted setup artifacts (`.ptau`, `.zkey`) versioned and traceable in real deployments.
- For CI-level interoperability checks, see the ignored interop tests in `crates/noir-cli/tests/interop.rs`.
