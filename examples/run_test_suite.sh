#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="${ROOT_DIR}/examples"
OUT_DIR="${ROOT_DIR}/target/example-suite"

if [[ "${1:-}" == "--out" ]]; then
  OUT_DIR="${2:?missing output directory}"
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd nargo
require_cmd npx

mkdir -p "${OUT_DIR}" "${OUT_DIR}/interop" "${OUT_DIR}/snarkjs" "${OUT_DIR}/logs"

if [[ ! -x "${ROOT_DIR}/target/debug/noir-cli" ]]; then
  echo "Building noir-cli..."
  cargo build -p noir-cli >/dev/null
fi

NOIR_CLI="${ROOT_DIR}/target/debug/noir-cli"

snarkjs() {
  npx -y snarkjs "$@"
}

if [[ ! -f "${OUT_DIR}/pot12_final.ptau" ]]; then
  echo "Preparing Powers of Tau file..."
  snarkjs powersoftau new bn128 12 "${OUT_DIR}/pot12_0000.ptau" -v >"${OUT_DIR}/logs/ptau.log" 2>&1
  snarkjs powersoftau prepare phase2 "${OUT_DIR}/pot12_0000.ptau" "${OUT_DIR}/pot12_final.ptau" -v >>"${OUT_DIR}/logs/ptau.log" 2>&1
fi

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

pass_count=0
fail_count=0
skip_count=0

for example_dir in "${EXAMPLES_DIR}"/*; do
  [[ -d "${example_dir}" ]] || continue
  [[ -f "${example_dir}/Nargo.toml" ]] || continue
  [[ -f "${example_dir}/inputs.json" ]] || continue

  name="$(basename "${example_dir}")"
  echo "==> ${name}"

  compile_dir="${TMP_ROOT}/${name}"
  rm -rf "${compile_dir}"
  mkdir -p "${compile_dir}"
  cp -r "${example_dir}"/* "${compile_dir}/"

  if ! (cd "${compile_dir}" && nargo compile >"${OUT_DIR}/logs/${name}.compile.log" 2>&1); then
    echo "  compile failed (see ${OUT_DIR}/logs/${name}.compile.log)"
    ((fail_count+=1))
    continue
  fi

  artifact_path="${compile_dir}/target/${name}.json"
  interop_dir="${OUT_DIR}/interop/${name}"
  rm -rf "${interop_dir}"

  if ! "${NOIR_CLI}" interop "${artifact_path}" "${example_dir}/inputs.json" --out "${interop_dir}" >"${OUT_DIR}/logs/${name}.interop.log" 2>&1; then
    if grep -q "unsupported opcode" "${OUT_DIR}/logs/${name}.interop.log" || \
       grep -q "unsupported opcodes encountered" "${OUT_DIR}/logs/${name}.interop.log"; then
      echo "  skipped (unsupported opcodes for R1CS lowering)"
      ((skip_count+=1))
      continue
    fi
    echo "  interop failed (see ${OUT_DIR}/logs/${name}.interop.log)"
    ((fail_count+=1))
    continue
  fi

  run_dir="${OUT_DIR}/snarkjs/${name}"
  rm -rf "${run_dir}"
  mkdir -p "${run_dir}"
  cp "${interop_dir}/circuit.r1cs" "${interop_dir}/witness.wtns" "${run_dir}/"

  log_path="${OUT_DIR}/logs/${name}.snarkjs.log"
  : >"${log_path}"

  if ! snarkjs wtns check "${run_dir}/circuit.r1cs" "${run_dir}/witness.wtns" >>"${log_path}" 2>&1; then
    echo "  witness check failed (see ${log_path})"
    ((fail_count+=1))
    continue
  fi

  if ! snarkjs groth16 setup "${run_dir}/circuit.r1cs" "${OUT_DIR}/pot12_final.ptau" "${run_dir}/circuit_0000.zkey" >>"${log_path}" 2>&1; then
    echo "  groth16 setup failed (see ${log_path})"
    ((fail_count+=1))
    continue
  fi

  if ! snarkjs zkey contribute "${run_dir}/circuit_0000.zkey" "${run_dir}/circuit_final.zkey" --name="example-suite" -v -e="example-suite entropy" >>"${log_path}" 2>&1; then
    echo "  zkey contribute failed (see ${log_path})"
    ((fail_count+=1))
    continue
  fi

  if ! snarkjs zkey export verificationkey "${run_dir}/circuit_final.zkey" "${run_dir}/verification_key.json" >>"${log_path}" 2>&1; then
    echo "  verification key export failed (see ${log_path})"
    ((fail_count+=1))
    continue
  fi

  if ! snarkjs groth16 prove "${run_dir}/circuit_final.zkey" "${run_dir}/witness.wtns" "${run_dir}/proof.json" "${run_dir}/public.json" >>"${log_path}" 2>&1; then
    echo "  proof generation failed (see ${log_path})"
    ((fail_count+=1))
    continue
  fi

  if ! snarkjs groth16 verify "${run_dir}/verification_key.json" "${run_dir}/public.json" "${run_dir}/proof.json" >>"${log_path}" 2>&1; then
    echo "  proof verification failed (see ${log_path})"
    ((fail_count+=1))
    continue
  fi

  echo "  ok"
  ((pass_count+=1))
done

echo
echo "Example suite results: pass=${pass_count} skip=${skip_count} fail=${fail_count}"
if [[ "${fail_count}" -ne 0 ]]; then
  exit 1
fi
