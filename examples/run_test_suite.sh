#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXAMPLES_DIR="${EXAMPLES_DIR:-${ROOT_DIR}/examples}"
OUT_DIR="${ROOT_DIR}/target/example-suite"
PTAU_POWER="${PTAU_POWER:-12}"
STAGE_TIMEOUT="${STAGE_TIMEOUT:-0}"

if [[ "${1:-}" == "--out" ]]; then
  OUT_DIR="${2:?missing output directory}"
fi

if [[ "${EXAMPLES_DIR}" != /* ]]; then
  EXAMPLES_DIR="${ROOT_DIR}/${EXAMPLES_DIR}"
fi
if [[ "${OUT_DIR}" != /* ]]; then
  OUT_DIR="${ROOT_DIR}/${OUT_DIR}"
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
if [[ "${STAGE_TIMEOUT}" != "0" ]]; then
  require_cmd timeout
fi

mkdir -p "${OUT_DIR}" "${OUT_DIR}/interop" "${OUT_DIR}/snarkjs" "${OUT_DIR}/logs"
RESULTS_TSV="${OUT_DIR}/results.tsv"
printf 'case\tstatus\tstage\treason\tlog\n' >"${RESULTS_TSV}"

if [[ ! -x "${ROOT_DIR}/target/debug/noir-cli" ]]; then
  echo "Building noir-cli..."
  cargo build -p noir-cli >/dev/null
fi

NOIR_CLI="${ROOT_DIR}/target/debug/noir-cli"

snarkjs() {
  npx -y snarkjs "$@"
}

run_maybe_timeout() {
  if [[ "${STAGE_TIMEOUT}" == "0" ]]; then
    "$@"
  else
    timeout "${STAGE_TIMEOUT}" "$@"
  fi
}

failure_reason() {
  local default_reason="$1"
  local rc="$2"
  if [[ "${rc}" -eq 124 ]]; then
    printf 'timed out after %s' "${STAGE_TIMEOUT}"
  else
    printf '%s' "${default_reason}"
  fi
}

PTAU_PATH="${OUT_DIR}/pot${PTAU_POWER}_final.ptau"
if [[ ! -f "${PTAU_PATH}" ]]; then
  echo "Preparing Powers of Tau file (power ${PTAU_POWER})..."
  snarkjs powersoftau new bn128 "${PTAU_POWER}" "${OUT_DIR}/pot${PTAU_POWER}_0000.ptau" -v >"${OUT_DIR}/logs/ptau.log" 2>&1
  snarkjs powersoftau prepare phase2 "${OUT_DIR}/pot${PTAU_POWER}_0000.ptau" "${PTAU_PATH}" -v >>"${OUT_DIR}/logs/ptau.log" 2>&1
fi

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT

pass_count=0
fail_count=0
skip_count=0
unsupported_count=0

record_result() {
  local case_name="$1"
  local status="$2"
  local stage="$3"
  local reason="$4"
  local log_path="$5"
  printf '%s\t%s\t%s\t%s\t%s\n' "${case_name}" "${status}" "${stage}" "${reason}" "${log_path}" >>"${RESULTS_TSV}"
}

safe_name_for() {
  local rel="$1"
  local variant="$2"
  local name="${rel//\//__}"
  if [[ "${variant}" != "inputs.json" ]]; then
    name="${name}__${variant%.json}"
  fi
  printf '%s' "${name}" | tr -c 'A-Za-z0-9_.-' '_'
}

find_artifact_json() {
  local target_dir="$1"
  find "${target_dir}" -maxdepth 1 -type f -name '*.json' | sort | head -n 1
}

is_library_package() {
  local nargo_toml="$1"
  grep -Eq '^[[:space:]]*type[[:space:]]*=[[:space:]]*"lib"' "${nargo_toml}"
}

CORPUS_DIR="${TMP_ROOT}/examples"
cp -R "${EXAMPLES_DIR}" "${CORPUS_DIR}"

while IFS= read -r -d '' nargo_toml; do
  example_dir="$(dirname "${nargo_toml}")"
  rel_dir="${example_dir#${CORPUS_DIR}/}"

  input_files=()
  if [[ -f "${example_dir}/inputs.json" ]]; then
    input_files+=("${example_dir}/inputs.json")
  fi
  if [[ -d "${example_dir}/inputs" ]]; then
    while IFS= read -r -d '' input_file; do
      input_files+=("${input_file}")
    done < <(find "${example_dir}/inputs" -maxdepth 1 -type f -name '*.json' -print0 | sort -z)
  fi

  if [[ "${#input_files[@]}" -eq 0 ]]; then
    continue
  fi

  if is_library_package "${nargo_toml}"; then
    echo "==> ${rel_dir}"
    echo "  skipped (library package, not a standalone circuit)"
    record_result "${rel_dir}" "skip" "discover" "library package" ""
    ((skip_count+=1))
    continue
  fi

  echo "==> ${rel_dir}"

  compile_log="${OUT_DIR}/logs/$(safe_name_for "${rel_dir}" "inputs.json").compile.log"

  if (cd "${example_dir}" && run_maybe_timeout nargo compile >"${compile_log}" 2>&1); then
    rc=0
  else
    rc=$?
  fi
  if [[ "${rc}" -ne 0 ]]; then
    echo "  compile failed (see ${compile_log})"
    record_result "${rel_dir}" "fail" "compile" "$(failure_reason "nargo compile failed" "${rc}")" "${compile_log}"
    ((fail_count+=1))
    continue
  fi

  artifact_path="$(find_artifact_json "${example_dir}/target")"
  if [[ -z "${artifact_path}" ]]; then
    echo "  compile failed (no artifact json emitted)"
    record_result "${rel_dir}" "fail" "compile" "no artifact json emitted" "${compile_log}"
    ((fail_count+=1))
    continue
  fi

  preflight_dir="${OUT_DIR}/r1cs-json/$(safe_name_for "${rel_dir}" "inputs.json")"
  preflight_log="${OUT_DIR}/logs/$(safe_name_for "${rel_dir}" "inputs.json").preflight.log"
  rm -rf "${preflight_dir}"
  mkdir -p "${preflight_dir}"
  if run_maybe_timeout "${NOIR_CLI}" r1cs-json "${artifact_path}" --out "${preflight_dir}/circuit.r1cs.json" --allow-unsupported >"${preflight_log}" 2>&1; then
    preflight_rc=0
  else
    preflight_rc=$?
  fi

  if [[ "${preflight_rc}" -eq 124 ]]; then
    for input_path in "${input_files[@]}"; do
      if [[ "${input_path}" == "${example_dir}/inputs.json" ]]; then
        case_name="${rel_dir}"
      else
        variant="$(basename "${input_path}")"
        case_name="${rel_dir}#${variant%.json}"
      fi
      echo "  -> ${case_name}"
      echo "    preflight timed out (see ${preflight_log})"
      record_result "${case_name}" "fail" "preflight" "$(failure_reason "R1CS preflight failed" "${preflight_rc}")" "${preflight_log}"
      ((fail_count+=1))
    done
    continue
  fi

  if [[ "${preflight_rc}" -ne 0 ]] && {
    grep -q "unsupported opcode" "${preflight_log}" || \
    grep -q "unsupported opcodes encountered" "${preflight_log}"
  }; then
    for input_path in "${input_files[@]}"; do
      if [[ "${input_path}" == "${example_dir}/inputs.json" ]]; then
        case_name="${rel_dir}"
      else
        variant="$(basename "${input_path}")"
        case_name="${rel_dir}#${variant%.json}"
      fi
      echo "  -> ${case_name}"
      echo "    unsupported (see ${preflight_log})"
      record_result "${case_name}" "unsupported" "preflight" "unsupported opcodes for R1CS lowering" "${preflight_log}"
      ((unsupported_count+=1))
    done
    continue
  fi

  for input_path in "${input_files[@]}"; do
    if [[ "${input_path}" == "${example_dir}/inputs.json" ]]; then
      variant="inputs.json"
      case_name="${rel_dir}"
    else
      variant="$(basename "${input_path}")"
      case_name="${rel_dir}#${variant%.json}"
    fi

    safe_name="$(safe_name_for "${rel_dir}" "${variant}")"
    echo "  -> ${case_name}"

    interop_dir="${OUT_DIR}/interop/${safe_name}"
    rm -rf "${interop_dir}"

    interop_log="${OUT_DIR}/logs/${safe_name}.interop.log"
    if run_maybe_timeout "${NOIR_CLI}" interop "${artifact_path}" "${input_path}" --out "${interop_dir}" >"${interop_log}" 2>&1; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${rc}" -ne 0 ]]; then
      if grep -q "unsupported opcode" "${interop_log}" || \
         grep -q "unsupported opcodes encountered" "${interop_log}"; then
        echo "    unsupported (see ${interop_log})"
        record_result "${case_name}" "unsupported" "interop" "unsupported opcodes for R1CS lowering" "${interop_log}"
        ((unsupported_count+=1))
        continue
      fi
      echo "    interop failed (see ${interop_log})"
      record_result "${case_name}" "fail" "interop" "$(failure_reason "noir-cli interop failed" "${rc}")" "${interop_log}"
      ((fail_count+=1))
      continue
    fi

    run_dir="${OUT_DIR}/snarkjs/${safe_name}"
    rm -rf "${run_dir}"
    mkdir -p "${run_dir}"
    cp "${interop_dir}/circuit.r1cs" "${interop_dir}/witness.wtns" "${run_dir}/"

    log_path="${OUT_DIR}/logs/${safe_name}.snarkjs.log"
    : >"${log_path}"

    if run_maybe_timeout npx -y snarkjs wtns check "${run_dir}/circuit.r1cs" "${run_dir}/witness.wtns" >>"${log_path}" 2>&1; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${rc}" -ne 0 ]]; then
      echo "    witness check failed (see ${log_path})"
      record_result "${case_name}" "fail" "wtns-check" "$(failure_reason "snarkjs witness check failed" "${rc}")" "${log_path}"
      ((fail_count+=1))
      continue
    fi

    if run_maybe_timeout npx -y snarkjs groth16 setup "${run_dir}/circuit.r1cs" "${PTAU_PATH}" "${run_dir}/circuit_0000.zkey" >>"${log_path}" 2>&1; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${rc}" -ne 0 ]]; then
      echo "    groth16 setup failed (see ${log_path})"
      record_result "${case_name}" "fail" "groth16-setup" "$(failure_reason "snarkjs groth16 setup failed" "${rc}")" "${log_path}"
      ((fail_count+=1))
      continue
    fi

    if run_maybe_timeout npx -y snarkjs zkey contribute "${run_dir}/circuit_0000.zkey" "${run_dir}/circuit_final.zkey" --name="example-suite" -v -e="example-suite entropy" >>"${log_path}" 2>&1; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${rc}" -ne 0 ]]; then
      echo "    zkey contribute failed (see ${log_path})"
      record_result "${case_name}" "fail" "zkey-contribute" "$(failure_reason "snarkjs zkey contribute failed" "${rc}")" "${log_path}"
      ((fail_count+=1))
      continue
    fi

    if run_maybe_timeout npx -y snarkjs zkey export verificationkey "${run_dir}/circuit_final.zkey" "${run_dir}/verification_key.json" >>"${log_path}" 2>&1; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${rc}" -ne 0 ]]; then
      echo "    verification key export failed (see ${log_path})"
      record_result "${case_name}" "fail" "vk-export" "$(failure_reason "snarkjs verification key export failed" "${rc}")" "${log_path}"
      ((fail_count+=1))
      continue
    fi

    if run_maybe_timeout npx -y snarkjs groth16 prove "${run_dir}/circuit_final.zkey" "${run_dir}/witness.wtns" "${run_dir}/proof.json" "${run_dir}/public.json" >>"${log_path}" 2>&1; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${rc}" -ne 0 ]]; then
      echo "    proof generation failed (see ${log_path})"
      record_result "${case_name}" "fail" "prove" "$(failure_reason "snarkjs groth16 prove failed" "${rc}")" "${log_path}"
      ((fail_count+=1))
      continue
    fi

    if run_maybe_timeout npx -y snarkjs groth16 verify "${run_dir}/verification_key.json" "${run_dir}/public.json" "${run_dir}/proof.json" >>"${log_path}" 2>&1; then
      rc=0
    else
      rc=$?
    fi
    if [[ "${rc}" -ne 0 ]]; then
      echo "    proof verification failed (see ${log_path})"
      record_result "${case_name}" "fail" "verify" "$(failure_reason "snarkjs groth16 verify failed" "${rc}")" "${log_path}"
      ((fail_count+=1))
      continue
    fi

    echo "    ok"
    record_result "${case_name}" "pass" "verify" "groth16 proof verified" "${log_path}"
    ((pass_count+=1))
  done
done < <(find "${CORPUS_DIR}" -name Nargo.toml -print0 | sort -z)

echo
echo "Example suite results: pass=${pass_count} unsupported=${unsupported_count} skip=${skip_count} fail=${fail_count}"
echo "Results written to ${RESULTS_TSV}"
if [[ "${fail_count}" -ne 0 || "${unsupported_count}" -ne 0 ]]; then
  exit 1
fi
