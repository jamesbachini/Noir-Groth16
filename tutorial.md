# Quick tutorial: Groth16 proof for a Noir circuit

This repo’s CLI generates `circuit.r1cs` + `witness.wtns`; `snarkjs` uses those to run Groth16 setup/prove/verify.

## 1) Prereqs

```bash
# Rust (for this repo)
cargo --version

# snarkjs (for Groth16 ceremony/proving)
npm i -g snarkjs

# optional: Noir compiler (only needed if you want to compile your own .nr circuit)
nargo --version
```

## 2) Build the CLI

```bash
cd /mnt/c/code/Noir-Groth16
cargo build -p noir-cli
```

## 3) Generate `.r1cs` and `.wtns`

Fastest demo (uses included Noir artifact + inputs):

```bash
./target/debug/noir-groth16 interop \
  test-vectors/fixture_artifact.json \
  test-vectors/fixture_inputs.json \
  --out demo
```

This writes:
- `demo/circuit.r1cs`
- `demo/witness.wtns`

## 4) Run Groth16 with snarkjs

```bash
cd demo
snarkjs wtns check circuit.r1cs witness.wtns
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau prepare phase2 pot12_0000.ptau pot12_final.ptau -v
snarkjs groth16 setup circuit.r1cs pot12_final.ptau circuit_0000.zkey
snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="demo" -v -e="demo entropy"
snarkjs zkey export verificationkey circuit_final.zkey verification_key.json
snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json
snarkjs groth16 verify verification_key.json public.json proof.json
```

If verify succeeds, `snarkjs` prints `OK`.

## 5) Using your own Noir circuit (optional)

Example circuit (`src/main.nr`):

```rust
fn main(x: Field, y: pub Field) {
    assert(x * x == y);
}
```

`assert(x != y)` currently lowers through `BrilligCall`, which this repo rejects in strict R1CS lowering.

Compile with Noir (`nargo compile`), then run:

```bash
./target/debug/noir-groth16 interop target/<package_name>.json inputs.json --out demo
```

Example `inputs.json` (field elements as strings):

```json
{"x":"3","y":"9"}
```
