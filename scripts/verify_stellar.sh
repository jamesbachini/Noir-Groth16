#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NETWORK="${NETWORK:-testnet}"
SOURCE_ACCOUNT="${SOURCE_ACCOUNT:-${STELLAR_ACCOUNT:-}}"
RUN_CIRCUIT_SCRIPT="${ROOT_DIR}/scripts/run_circuit.sh"
CONTRACTS_DIR="${ROOT_DIR}/contracts"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/target/groth16}"
PROOF_DIR="${OUT_DIR}/proof"
BUILD_DIR="${OUT_DIR}/stellar"
LOCAL_VERIFY_KEY_PATH="${PROOF_DIR}/verification_key.json"
LOCAL_PUBLIC_PATH="${PROOF_DIR}/public.json"
LOCAL_PROOF_PATH="${PROOF_DIR}/proof.json"
LOCAL_ENCODER_SCRIPT="${ROOT_DIR}/scripts/encode_bn254_for_soroban.mjs"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "missing required file: $1" >&2
    exit 1
  fi
}

run_converter() {
  local mode="$1"
  local input_path="$2"
  local output_path="$3"

  if [[ "${CONVERTER_MODE}" == "node" ]]; then
    node "${LOCAL_ENCODER_SCRIPT}" "$mode" "$input_path" >"$output_path"
    return
  fi

  if [[ "${CONVERTER_MODE}" == "path" ]]; then
    circom-to-soroban-hex "$mode" "$input_path" >"$output_path"
    return
  fi

  if [[ "${CONVERTER_MODE}" == "cargo" ]]; then
    cargo run --quiet -p circom-to-soroban-hex -- "$mode" "$input_path" >"$output_path"
    return
  fi

  echo "internal error: unsupported converter mode ${CONVERTER_MODE}" >&2
  exit 1
}

require_cmd cargo
require_cmd npx
require_cmd stellar
require_cmd node
require_cmd mktemp
require_cmd cp

require_file "${RUN_CIRCUIT_SCRIPT}"
require_file "${CONTRACTS_DIR}/Cargo.toml"
require_file "${LOCAL_ENCODER_SCRIPT}"

echo "[1/7] Running circuit pipeline via scripts/run_circuit.sh"
"${RUN_CIRCUIT_SCRIPT}"

require_file "${LOCAL_VERIFY_KEY_PATH}"
require_file "${LOCAL_PUBLIC_PATH}"
require_file "${LOCAL_PROOF_PATH}"

echo "[2/7] Re-checking proof locally with snarkjs before deploy"
LOCAL_VERIFY_OUTPUT="$(npx --yes snarkjs groth16 verify "${LOCAL_VERIFY_KEY_PATH}" "${LOCAL_PUBLIC_PATH}" "${LOCAL_PROOF_PATH}")"
printf '%s\n' "${LOCAL_VERIFY_OUTPUT}"
if [[ "${LOCAL_VERIFY_OUTPUT}" != *"OK"* && "${LOCAL_VERIFY_OUTPUT}" != *"ok"* ]]; then
  echo "local snarkjs verification did not report success" >&2
  exit 1
fi

VK_CURVE="$(
  node -e '
const fs = require("fs");
const vk = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
process.stdout.write(String(vk.curve || "").toLowerCase());
' "${LOCAL_VERIFY_KEY_PATH}"
)"
if [[ "${VK_CURVE}" != "bn128" && "${VK_CURVE}" != "bn254" ]]; then
  cat >&2 <<EOF
verification key curve is '${VK_CURVE}', but this script expects BN254/bn128 artifacts.
run_circuit.sh should emit a bn128 verification key for this contract flow.
EOF
  exit 1
fi

if [[ -f "${LOCAL_ENCODER_SCRIPT}" ]]; then
  CONVERTER_MODE="node"
elif command -v circom-to-soroban-hex >/dev/null 2>&1; then
  CONVERTER_MODE="path"
elif cargo run --quiet -p circom-to-soroban-hex -- --help >/dev/null 2>&1; then
  CONVERTER_MODE="cargo"
else
  CONVERTER_MODE="missing"
fi

if [[ "${CONVERTER_MODE}" == "missing" ]]; then
  cat >&2 <<'EOF'
missing required encoder.
expected scripts/encode_bn254_for_soroban.mjs, or circom-to-soroban-hex on PATH, or circom-to-soroban-hex in the cargo workspace.
EOF
  exit 1
fi

mkdir -p "${BUILD_DIR}"

echo "[3/7] Building Soroban contract (using temporary copy to avoid workspace conflict)"
TEMP_CONTRACT_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "${TEMP_CONTRACT_DIR}"
}
trap cleanup EXIT
cp -R "${CONTRACTS_DIR}/." "${TEMP_CONTRACT_DIR}/"
TEMP_CONTRACT_MANIFEST="${TEMP_CONTRACT_DIR}/Cargo.toml"
if ! grep -q '^\[profile\.release\]' "${TEMP_CONTRACT_MANIFEST}"; then
  cat >>"${TEMP_CONTRACT_MANIFEST}" <<'EOF'

[profile.release]
overflow-checks = true
EOF
fi
if ! grep -q '^\[profile\.dev\]' "${TEMP_CONTRACT_MANIFEST}"; then
  cat >>"${TEMP_CONTRACT_MANIFEST}" <<'EOF'

[profile.dev]
overflow-checks = true
EOF
fi
stellar contract build --manifest-path "${TEMP_CONTRACT_MANIFEST}" --package soroban-groth16-verifier --optimize
WASM_PATH="${TEMP_CONTRACT_DIR}/target/wasm32v1-none/release/soroban_groth16_verifier.wasm"
require_file "${WASM_PATH}"

echo "[4/7] Deploying verifier contract to ${NETWORK}"
deploy_cmd=(stellar contract deploy --wasm "${WASM_PATH}" --network "${NETWORK}")
if [[ -n "${SOURCE_ACCOUNT:-}" ]]; then
  deploy_cmd+=(--source "${SOURCE_ACCOUNT}")
fi
DEPLOY_OUTPUT="$("${deploy_cmd[@]}")"
printf '%s\n' "${DEPLOY_OUTPUT}"
CONTRACT_ID="$(printf '%s\n' "${DEPLOY_OUTPUT}" | grep -Eo 'C[A-Z2-7]{55}' | tail -n1 || true)"
if [[ -z "${CONTRACT_ID}" ]]; then
  echo "failed to parse contract id from deploy output" >&2
  exit 1
fi
echo "Contract ID: ${CONTRACT_ID}"

echo "[5/7] Encoding verification artifacts for Soroban contract input"
run_converter vk "${LOCAL_VERIFY_KEY_PATH}" "${BUILD_DIR}/vk.hex"
run_converter proof "${LOCAL_PROOF_PATH}" "${BUILD_DIR}/proof.hex"
run_converter public "${LOCAL_PUBLIC_PATH}" "${BUILD_DIR}/public.hex"

VK_HEX="$(tr -d '\r\n' < "${BUILD_DIR}/vk.hex")"
PROOF_HEX="$(tr -d '\r\n' < "${BUILD_DIR}/proof.hex")"
PUBLIC_HEX="$(tr -d '\r\n' < "${BUILD_DIR}/public.hex")"

echo "[6/7] Storing verification key in contract"
set_vk_cmd=(stellar contract invoke --id "${CONTRACT_ID}" --network "${NETWORK}" -- set_vk --vk_bytes "${VK_HEX}")
if [[ -n "${SOURCE_ACCOUNT:-}" ]]; then
  set_vk_cmd=(stellar contract invoke --id "${CONTRACT_ID}" --network "${NETWORK}" --source "${SOURCE_ACCOUNT}" -- set_vk --vk_bytes "${VK_HEX}")
fi
"${set_vk_cmd[@]}" >/dev/null

echo "[7/7] Verifying proof on-chain"
verify_cmd=(stellar contract invoke --id "${CONTRACT_ID}" --network "${NETWORK}" -- verify --proof_bytes "${PROOF_HEX}" --pub_signals_bytes "${PUBLIC_HEX}")
if [[ -n "${SOURCE_ACCOUNT:-}" ]]; then
  verify_cmd=(stellar contract invoke --id "${CONTRACT_ID}" --network "${NETWORK}" --source "${SOURCE_ACCOUNT}" -- verify --proof_bytes "${PROOF_HEX}" --pub_signals_bytes "${PUBLIC_HEX}")
fi
VERIFY_RESULT="$("${verify_cmd[@]}")"
echo "On-chain verification result: ${VERIFY_RESULT}"
if [[ "${VERIFY_RESULT}" != "true" ]]; then
  echo "on-chain verification did not return true" >&2
  exit 1
fi

echo "Success: Groth16 proof verified on-chain on ${NETWORK}."
