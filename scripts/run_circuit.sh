#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMON_SH="${ROOT_DIR}/scripts/lib/common.sh"
CIRCUIT_DIR="${CIRCUIT_DIR:-${ROOT_DIR}/circuits}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/target/groth16}"
PTAU_POWER="${PTAU_POWER:-12}"
MIN_CARGO_VERSION="${MIN_CARGO_VERSION:-1.75.0}"
MIN_NARGO_VERSION="${MIN_NARGO_VERSION:-1.0.0}"
MIN_NODE_VERSION="${MIN_NODE_VERSION:-18.0.0}"
MIN_NPM_VERSION="${MIN_NPM_VERSION:-8.0.0}"
MIN_SNARKJS_VERSION="${MIN_SNARKJS_VERSION:-0.7.0}"

if [[ ! -f "${COMMON_SH}" ]]; then
  echo "missing required helper script: ${COMMON_SH}" >&2
  exit 1
fi
# shellcheck source=./lib/common.sh
source "${COMMON_SH}"

ng16_detect_platform

ng16_require_cmd awk
ng16_require_cmd cargo "$(ng16_hint_cargo)"
ng16_require_cmd nargo "$(ng16_hint_nargo)"
ng16_require_cmd node "$(ng16_hint_node)"
ng16_require_cmd npm "$(ng16_hint_node)"

ng16_require_min_version "cargo" "$(cargo --version 2>&1 | head -n1)" "${MIN_CARGO_VERSION}" "$(ng16_hint_cargo)"
ng16_require_min_version "nargo" "$(nargo --version 2>&1 | head -n1)" "${MIN_NARGO_VERSION}" "$(ng16_hint_nargo)"
ng16_require_min_version "node" "$(node --version 2>&1 | head -n1)" "${MIN_NODE_VERSION}" "$(ng16_hint_node)"
ng16_require_min_version "npm" "$(npm --version 2>&1 | head -n1)" "${MIN_NPM_VERSION}" "$(ng16_hint_node)"
ng16_ensure_snarkjs "${MIN_SNARKJS_VERSION}"

ng16_require_file "${CIRCUIT_DIR}/Nargo.toml"
ng16_require_file "${CIRCUIT_DIR}/inputs.json"

PACKAGE_NAME="$(
  awk -F '=' '
    /^[[:space:]]*name[[:space:]]*=/ {
      gsub(/[[:space:]]|"/, "", $2);
      print $2;
      exit
    }
  ' "${CIRCUIT_DIR}/Nargo.toml"
)"

if [[ -z "${PACKAGE_NAME}" ]]; then
  ng16_error "failed to parse package name from ${CIRCUIT_DIR}/Nargo.toml"
fi

ARTIFACT_PATH="${CIRCUIT_DIR}/target/${PACKAGE_NAME}.json"
PTAU_INITIAL="${OUT_DIR}/pot${PTAU_POWER}_0000.ptau"
PTAU_FINAL="${OUT_DIR}/pot${PTAU_POWER}_final.ptau"
INTEROP_DIR="${OUT_DIR}/interop"
PROOF_DIR="${OUT_DIR}/proof"
VERIFY_KEY_PATH="${PROOF_DIR}/verification_key.json"
PUBLIC_PATH="${PROOF_DIR}/public.json"
PROOF_PATH="${PROOF_DIR}/proof.json"

echo "[1/6] Building noir-cli"
cargo build -p noir-cli >/dev/null
NOIR_CLI="${ROOT_DIR}/target/debug/noir-cli"

echo "[2/6] Compiling Noir circuit (${CIRCUIT_DIR})"
(cd "${CIRCUIT_DIR}" && nargo compile)

if [[ ! -f "${ARTIFACT_PATH}" ]]; then
  ng16_error "compiled artifact not found: ${ARTIFACT_PATH}"
fi

rm -rf "${INTEROP_DIR}" "${PROOF_DIR}"
mkdir -p "${OUT_DIR}"

echo "[3/6] Emitting interop artifacts (.r1cs + .wtns)"
"${NOIR_CLI}" interop "${ARTIFACT_PATH}" "${CIRCUIT_DIR}/inputs.json" --out "${INTEROP_DIR}"

echo "[4/6] Checking witness consistency"
ng16_snarkjs wtns check "${INTEROP_DIR}/circuit.r1cs" "${INTEROP_DIR}/witness.wtns"

if [[ ! -f "${PTAU_FINAL}" ]]; then
  echo "[5/6] Preparing powers of tau (bn128, power=${PTAU_POWER})"
  ng16_snarkjs powersoftau new bn128 "${PTAU_POWER}" "${PTAU_INITIAL}"
  ng16_snarkjs powersoftau prepare phase2 "${PTAU_INITIAL}" "${PTAU_FINAL}"
else
  echo "[5/6] Reusing existing powers of tau: ${PTAU_FINAL}"
fi

mkdir -p "${PROOF_DIR}"
cp "${INTEROP_DIR}/circuit.r1cs" "${INTEROP_DIR}/witness.wtns" "${PROOF_DIR}/"

echo "[6/6] Running Groth16 setup, prove, and verify"
ng16_snarkjs groth16 setup "${PROOF_DIR}/circuit.r1cs" "${PTAU_FINAL}" "${PROOF_DIR}/circuit_0000.zkey"
ng16_snarkjs zkey contribute "${PROOF_DIR}/circuit_0000.zkey" "${PROOF_DIR}/circuit_final.zkey" --name="local" -e="local deterministic entropy"
ng16_snarkjs zkey export verificationkey "${PROOF_DIR}/circuit_final.zkey" "${VERIFY_KEY_PATH}"
ng16_snarkjs groth16 prove "${PROOF_DIR}/circuit_final.zkey" "${PROOF_DIR}/witness.wtns" "${PROOF_PATH}" "${PUBLIC_PATH}"

VERIFY_OUTPUT="$(ng16_snarkjs groth16 verify "${VERIFY_KEY_PATH}" "${PUBLIC_PATH}" "${PROOF_PATH}")"
printf '%s\n' "${VERIFY_OUTPUT}"
if [[ "${VERIFY_OUTPUT}" != *"OK"* && "${VERIFY_OUTPUT}" != *"ok"* ]]; then
  ng16_error "verification did not report success."
fi

echo
echo "Proof verified."
echo "Artifacts written to: ${OUT_DIR}"
