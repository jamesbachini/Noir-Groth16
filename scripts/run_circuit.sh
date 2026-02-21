#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_DIR="${CIRCUIT_DIR:-${ROOT_DIR}/circuits}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/target/groth16}"
PTAU_POWER="${PTAU_POWER:-12}"

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

snarkjs() {
  npx -y snarkjs "$@"
}

require_cmd cargo
require_cmd nargo
require_cmd npx

require_file "${CIRCUIT_DIR}/Nargo.toml"
require_file "${CIRCUIT_DIR}/inputs.json"

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
  echo "failed to parse package name from ${CIRCUIT_DIR}/Nargo.toml" >&2
  exit 1
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
  echo "compiled artifact not found: ${ARTIFACT_PATH}" >&2
  exit 1
fi

rm -rf "${INTEROP_DIR}" "${PROOF_DIR}"
mkdir -p "${OUT_DIR}"

echo "[3/6] Emitting interop artifacts (.r1cs + .wtns)"
"${NOIR_CLI}" interop "${ARTIFACT_PATH}" "${CIRCUIT_DIR}/inputs.json" --out "${INTEROP_DIR}"

echo "[4/6] Checking witness consistency"
snarkjs wtns check "${INTEROP_DIR}/circuit.r1cs" "${INTEROP_DIR}/witness.wtns"

if [[ ! -f "${PTAU_FINAL}" ]]; then
  echo "[5/6] Preparing powers of tau (bn128, power=${PTAU_POWER})"
  snarkjs powersoftau new bn128 "${PTAU_POWER}" "${PTAU_INITIAL}"
  snarkjs powersoftau prepare phase2 "${PTAU_INITIAL}" "${PTAU_FINAL}"
else
  echo "[5/6] Reusing existing powers of tau: ${PTAU_FINAL}"
fi

mkdir -p "${PROOF_DIR}"
cp "${INTEROP_DIR}/circuit.r1cs" "${INTEROP_DIR}/witness.wtns" "${PROOF_DIR}/"

echo "[6/6] Running Groth16 setup, prove, and verify"
snarkjs groth16 setup "${PROOF_DIR}/circuit.r1cs" "${PTAU_FINAL}" "${PROOF_DIR}/circuit_0000.zkey"
snarkjs zkey contribute "${PROOF_DIR}/circuit_0000.zkey" "${PROOF_DIR}/circuit_final.zkey" --name="local" -e="local deterministic entropy"
snarkjs zkey export verificationkey "${PROOF_DIR}/circuit_final.zkey" "${VERIFY_KEY_PATH}"
snarkjs groth16 prove "${PROOF_DIR}/circuit_final.zkey" "${PROOF_DIR}/witness.wtns" "${PROOF_PATH}" "${PUBLIC_PATH}"

VERIFY_OUTPUT="$(snarkjs groth16 verify "${VERIFY_KEY_PATH}" "${PUBLIC_PATH}" "${PROOF_PATH}")"
printf '%s\n' "${VERIFY_OUTPUT}"
if [[ "${VERIFY_OUTPUT}" != *"OK"* && "${VERIFY_OUTPUT}" != *"ok"* ]]; then
  echo "verification did not report success" >&2
  exit 1
fi

echo
echo "Proof verified."
echo "Artifacts written to: ${OUT_DIR}"
