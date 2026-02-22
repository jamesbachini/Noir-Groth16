#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK="${NETWORK:-testnet}"

cd "$ROOT_DIR"
mkdir -p build

echo "Installing Node dependencies (snarkjs)..."
npm install --silent --no-audit --no-fund

echo "Building Soroban contract..."
(cd contract && stellar contract build --optimize)

echo "Deploying verifier contract to $NETWORK"
DEPLOY_OUTPUT="$(stellar contract deploy --wasm "$ROOT_DIR/target/wasm32v1-none/release/soroban_groth16_verifier.wasm" --network "$NETWORK")"
CONTRACT_ID="$(echo "$DEPLOY_OUTPUT" | grep -Eo 'C[A-Z0-9]{55}' | tail -n1)"
test -n "$CONTRACT_ID"
echo "Contract ID: $CONTRACT_ID"

echo "Generating Groth16 proof from witness..."
npx --yes snarkjs groth16 prove "$ROOT_DIR/proving/multiplier2_final.zkey" "$ROOT_DIR/proving/witness.wtns" "$ROOT_DIR/build/proof.json" "$ROOT_DIR/build/public.json"
npx --yes snarkjs zkey export verificationkey "$ROOT_DIR/proving/multiplier2_final.zkey" "$ROOT_DIR/build/verification_key.json"

echo "Checking proof locally with snarkjs..."
npx --yes snarkjs groth16 verify "$ROOT_DIR/build/verification_key.json" "$ROOT_DIR/build/public.json" "$ROOT_DIR/build/proof.json"

echo "Encoding verification artifacts into Soroban byte format..."
cargo run --quiet -p circom-to-soroban-hex -- vk "$ROOT_DIR/build/verification_key.json" > "$ROOT_DIR/build/vk.hex"
cargo run --quiet -p circom-to-soroban-hex -- proof "$ROOT_DIR/build/proof.json" > "$ROOT_DIR/build/proof.hex"
cargo run --quiet -p circom-to-soroban-hex -- public "$ROOT_DIR/build/public.json" > "$ROOT_DIR/build/public.hex"

VK_HEX="$(tr -d '\r\n' < "$ROOT_DIR/build/vk.hex")"
PROOF_HEX="$(tr -d '\r\n' < "$ROOT_DIR/build/proof.hex")"
PUBLIC_HEX="$(tr -d '\r\n' < "$ROOT_DIR/build/public.hex")"

echo "Storing verification key in contract..."
stellar contract invoke --id "$CONTRACT_ID" --network "$NETWORK" -- set_vk --vk_bytes "$VK_HEX" >/dev/null

echo "Verifying proof on-chain..."
VERIFY_RESULT="$(stellar contract invoke --id "$CONTRACT_ID" --network "$NETWORK" -- verify --proof_bytes "$PROOF_HEX" --pub_signals_bytes "$PUBLIC_HEX")"

echo "On-chain verification result: $VERIFY_RESULT"
test "$VERIFY_RESULT" = "true"

echo "Success: Groth16 proof verified on Stellar testnet."
