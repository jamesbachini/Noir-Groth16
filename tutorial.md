This tutorial shows how to:
1. Compile a Noir artifact into `circuit.r1cs` and `witness.wtns` with this repo.
2. Generate a Groth16 proof with `snarkjs`.

## 1) Prerequisites

```bash
cargo --version
node --version
npm --version
```

Install required CLIs:

```bash
npm i snarkjs
cargo install --locked soroban-verifier-gen
```

## 2) Build `noir-groth16`

```bash
cd /mnt/c/code/Noir-Groth16
cargo build -p noir-cli
```

## 3) Compile circuit + witness artifacts

Use the included fixture artifact and inputs:

```bash
./target/debug/noir-groth16 interop test-vectors/fixture_artifact.json \
  test-vectors/fixture_inputs.json --out demo
```

Outputs:
- `demo/circuit.r1cs`
- `demo/witness.wtns`

## 4) Generate a Groth16 proof with `snarkjs`

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

## Optional: use your own Noir project artifact

After running `nargo compile` in your Noir project:

```bash
./target/debug/noir-groth16 interop path/to/target/<package_name>.json path/to/inputs.json --out demo
```

