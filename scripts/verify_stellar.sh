#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMON_SH="${ROOT_DIR}/scripts/lib/common.sh"
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
MIN_CARGO_VERSION="${MIN_CARGO_VERSION:-1.89.0}"
MIN_RUSTC_VERSION="${MIN_RUSTC_VERSION:-1.89.0}"
MIN_NODE_VERSION="${MIN_NODE_VERSION:-18.0.0}"
MIN_NPM_VERSION="${MIN_NPM_VERSION:-8.0.0}"
MIN_SNARKJS_VERSION="${MIN_SNARKJS_VERSION:-0.7.0}"
MIN_STELLAR_VERSION="${MIN_STELLAR_VERSION:-22.0.0}"
SOROBAN_RUST_TARGET="${SOROBAN_RUST_TARGET:-wasm32v1-none}"

if [[ ! -f "${COMMON_SH}" ]]; then
  echo "missing required helper script: ${COMMON_SH}" >&2
  exit 1
fi
# shellcheck source=./lib/common.sh
source "${COMMON_SH}"

run_converter() {
  local mode="$1"
  local input_path="$2"
  local output_path="$3"

  if [[ "${CONVERTER_MODE}" == "node" ]]; then
    node "${LOCAL_ENCODER_SCRIPT}" "${mode}" "${input_path}" >"${output_path}"
    return
  fi

  if [[ "${CONVERTER_MODE}" == "path" ]]; then
    circom-to-soroban-hex "${mode}" "${input_path}" >"${output_path}"
    return
  fi

  if [[ "${CONVERTER_MODE}" == "cargo" ]]; then
    cargo run --quiet -p circom-to-soroban-hex -- "${mode}" "${input_path}" >"${output_path}"
    return
  fi

  ng16_error "internal error: unsupported converter mode ${CONVERTER_MODE}"
}

ng16_detect_platform

ng16_require_cmd cargo "$(ng16_hint_cargo)"
ng16_require_cmd rustc "$(ng16_hint_cargo)"
ng16_require_cmd node "$(ng16_hint_node)"
ng16_require_cmd npm "$(ng16_hint_node)"
ng16_require_cmd mktemp
ng16_require_cmd cp
ng16_require_cmd tr
ng16_require_cmd grep
ng16_require_cmd tail

ng16_require_min_version "cargo" "$(cargo --version 2>&1 | head -n1)" "${MIN_CARGO_VERSION}" "$(ng16_hint_cargo)"
ng16_require_min_version "rustc" "$(rustc --version 2>&1 | head -n1)" "${MIN_RUSTC_VERSION}" "$(ng16_hint_cargo)"
ng16_require_min_version "node" "$(node --version 2>&1 | head -n1)" "${MIN_NODE_VERSION}" "$(ng16_hint_node)"
ng16_require_min_version "npm" "$(npm --version 2>&1 | head -n1)" "${MIN_NPM_VERSION}" "$(ng16_hint_node)"

ng16_ensure_stellar "${MIN_STELLAR_VERSION}"
ng16_ensure_snarkjs "${MIN_SNARKJS_VERSION}"
ng16_ensure_rust_target "${SOROBAN_RUST_TARGET}"

ng16_require_file "${RUN_CIRCUIT_SCRIPT}"
ng16_require_file "${CONTRACTS_DIR}/Cargo.toml"
ng16_require_file "${LOCAL_ENCODER_SCRIPT}"

echo "[1/7] Running circuit pipeline via scripts/run_circuit.sh"
bash "${RUN_CIRCUIT_SCRIPT}"

ng16_require_file "${LOCAL_VERIFY_KEY_PATH}"
ng16_require_file "${LOCAL_PUBLIC_PATH}"
ng16_require_file "${LOCAL_PROOF_PATH}"

echo "[2/7] Re-checking proof locally with snarkjs before deploy"
LOCAL_VERIFY_OUTPUT="$(ng16_snarkjs groth16 verify "${LOCAL_VERIFY_KEY_PATH}" "${LOCAL_PUBLIC_PATH}" "${LOCAL_PROOF_PATH}")"
printf '%s\n' "${LOCAL_VERIFY_OUTPUT}"
if [[ "${LOCAL_VERIFY_OUTPUT}" != *"OK"* && "${LOCAL_VERIFY_OUTPUT}" != *"ok"* ]]; then
  ng16_error "local snarkjs verification did not report success."
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
error: verification key curve is '${VK_CURVE}', but this script expects BN254/bn128 artifacts.
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
error: missing required encoder.
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
WASM_PATH="${TEMP_CONTRACT_DIR}/target/${SOROBAN_RUST_TARGET}/release/soroban_groth16_verifier.wasm"
ng16_require_file "${WASM_PATH}"

echo "[4/7] Deploying verifier contract to ${NETWORK}"
deploy_cmd=(stellar contract deploy --wasm "${WASM_PATH}" --network "${NETWORK}")
if [[ -n "${SOURCE_ACCOUNT:-}" ]]; then
  deploy_cmd+=(--source "${SOURCE_ACCOUNT}")
fi
DEPLOY_OUTPUT="$("${deploy_cmd[@]}")"
printf '%s\n' "${DEPLOY_OUTPUT}"
CONTRACT_ID="$(printf '%s\n' "${DEPLOY_OUTPUT}" | grep -Eo 'C[A-Z2-7]{55}' | tail -n1 || true)"
if [[ -z "${CONTRACT_ID}" ]]; then
  ng16_error "failed to parse contract id from deploy output."
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
  ng16_error "on-chain verification did not return true."
fi

echo "Success: Groth16 proof verified on-chain on ${NETWORK}."
