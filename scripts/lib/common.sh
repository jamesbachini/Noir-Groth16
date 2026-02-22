#!/usr/bin/env bash

# Shared helper functions for scripts in this repository.

NOIR_GROTH16_AUTO_INSTALL="${NOIR_GROTH16_AUTO_INSTALL:-1}"
NOIR_GROTH16_TOOLING_DIR="${NOIR_GROTH16_TOOLING_DIR:-${ROOT_DIR:-$(pwd)}/target/tooling}"

NG16_PLATFORM=""
NG16_IS_WSL=0
NG16_SNARKJS_MODE=""
NG16_SNARKJS_BIN=""

ng16_detect_platform() {
  local uname_s
  uname_s="$(uname -s 2>/dev/null || printf 'unknown')"

  case "${uname_s}" in
    Darwin*)
      NG16_PLATFORM="macos"
      ;;
    Linux*)
      NG16_PLATFORM="linux"
      if [[ -f /proc/version ]] && grep -qi 'microsoft' /proc/version; then
        NG16_PLATFORM="wsl"
        NG16_IS_WSL=1
      fi
      ;;
    *)
      NG16_PLATFORM="unknown"
      ;;
  esac
}

ng16_error() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

ng16_warn() {
  printf 'warning: %s\n' "$*" >&2
}

ng16_auto_install_enabled() {
  case "${NOIR_GROTH16_AUTO_INSTALL}" in
    1|true|TRUE|yes|YES)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

ng16_require_cmd() {
  local cmd="$1"
  local hint="${2:-}"
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    if [[ -n "${hint}" ]]; then
      ng16_error "missing required command '${cmd}'. ${hint}"
    fi
    ng16_error "missing required command '${cmd}'."
  fi
}

ng16_require_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    ng16_error "missing required file '${path}'."
  fi
}

ng16_first_line() {
  local input="$1"
  printf '%s\n' "${input}" | head -n1
}

ng16_extract_semver() {
  local raw="$1"
  local token
  local major
  local minor
  local patch

  token="$(printf '%s\n' "${raw}" | grep -Eo '[0-9]+([.][0-9]+){0,2}' | head -n1 || true)"
  if [[ -z "${token}" ]]; then
    return 1
  fi

  IFS='.' read -r major minor patch <<<"${token}"
  printf '%s.%s.%s\n' "${major:-0}" "${minor:-0}" "${patch:-0}"
}

ng16_version_ge() {
  local left="$1"
  local right="$2"
  local left_norm
  local right_norm
  local l1 l2 l3
  local r1 r2 r3

  left_norm="$(ng16_extract_semver "${left}")" || return 1
  right_norm="$(ng16_extract_semver "${right}")" || return 1

  IFS='.' read -r l1 l2 l3 <<<"${left_norm}"
  IFS='.' read -r r1 r2 r3 <<<"${right_norm}"

  if (( l1 > r1 )); then return 0; fi
  if (( l1 < r1 )); then return 1; fi
  if (( l2 > r2 )); then return 0; fi
  if (( l2 < r2 )); then return 1; fi
  if (( l3 >= r3 )); then return 0; fi
  return 1
}

ng16_require_min_version() {
  local label="$1"
  local observed="$2"
  local minimum="$3"
  local hint="${4:-}"
  local observed_norm

  observed_norm="$(ng16_extract_semver "${observed}" || true)"
  if [[ -z "${observed_norm}" ]]; then
    if [[ -n "${hint}" ]]; then
      ng16_error "unable to parse ${label} version from '${observed}'. ${hint}"
    fi
    ng16_error "unable to parse ${label} version from '${observed}'."
  fi

  if ! ng16_version_ge "${observed_norm}" "${minimum}"; then
    if [[ -n "${hint}" ]]; then
      ng16_error "${label} ${observed_norm} is too old; require >= ${minimum}. ${hint}"
    fi
    ng16_error "${label} ${observed_norm} is too old; require >= ${minimum}."
  fi
}

ng16_hint_cargo() {
  printf 'Install Rust + Cargo from https://rustup.rs and restart your shell.'
}

ng16_hint_nargo() {
  printf 'Install Noir tooling with noirup: https://noir-lang.org/docs/getting_started/quick_start'
}

ng16_hint_node() {
  case "${NG16_PLATFORM}" in
    macos)
      printf "Install Node.js with 'brew install node' or from https://nodejs.org/"
      ;;
    linux|wsl)
      printf "Install Node.js + npm from your package manager or https://nodejs.org/"
      ;;
    *)
      printf "Install Node.js + npm from https://nodejs.org/"
      ;;
  esac
}

ng16_hint_stellar() {
  printf "Install Stellar CLI with 'cargo install --locked stellar-cli' or see https://developers.stellar.org/docs/tools/cli/install-cli"
}

ng16_hint_snarkjs() {
  printf "Install snarkjs with 'npm i -g snarkjs' or keep NOIR_GROTH16_AUTO_INSTALL=1 to allow local auto-install."
}

ng16_install_snarkjs_local() {
  local package_dir
  local bin_path
  local npm_spec

  package_dir="${NOIR_GROTH16_TOOLING_DIR}/snarkjs"
  npm_spec="${SNARKJS_NPM_SPEC:-snarkjs@^0.7.5}"

  mkdir -p "${package_dir}"
  ng16_warn "snarkjs not found; attempting local npm install (${npm_spec}) into ${package_dir}"
  if ! npm --prefix "${package_dir}" install --no-save "${npm_spec}"; then
    ng16_warn "automatic snarkjs installation failed."
    return 1
  fi

  bin_path="${package_dir}/node_modules/.bin/snarkjs"
  if [[ ! -x "${bin_path}" ]]; then
    ng16_warn "snarkjs binary not found after install at ${bin_path}."
    return 1
  fi

  NG16_SNARKJS_MODE="local"
  NG16_SNARKJS_BIN="${bin_path}"
  return 0
}

ng16_ensure_snarkjs() {
  local minimum="${1:-0.7.0}"
  local hint
  local version_output

  hint="$(ng16_hint_snarkjs)"

  if command -v snarkjs >/dev/null 2>&1; then
    NG16_SNARKJS_MODE="cmd"
    NG16_SNARKJS_BIN="$(command -v snarkjs)"
  elif command -v npx >/dev/null 2>&1 && npx --yes snarkjs --version >/dev/null 2>&1; then
    NG16_SNARKJS_MODE="npx"
    NG16_SNARKJS_BIN=""
  elif ng16_auto_install_enabled && command -v npm >/dev/null 2>&1; then
    ng16_install_snarkjs_local || true
  fi

  if [[ -z "${NG16_SNARKJS_MODE}" ]]; then
    ng16_error "snarkjs is required but was not found. ${hint}"
  fi

  version_output="$(ng16_snarkjs --version 2>&1 || true)"
  version_output="$(ng16_first_line "${version_output}")"
  if [[ -z "${version_output}" ]]; then
    ng16_error "snarkjs is available but '--version' failed. ${hint}"
  fi
  ng16_require_min_version "snarkjs" "${version_output}" "${minimum}" "${hint}"
}

ng16_snarkjs() {
  case "${NG16_SNARKJS_MODE}" in
    cmd|local)
      "${NG16_SNARKJS_BIN}" "$@"
      ;;
    npx)
      npx --yes snarkjs "$@"
      ;;
    *)
      ng16_error "snarkjs runner is not configured."
      ;;
  esac
}

ng16_ensure_stellar() {
  local minimum="${1:-22.0.0}"
  local hint
  local version_output

  hint="$(ng16_hint_stellar)"

  if ! command -v stellar >/dev/null 2>&1 && ng16_auto_install_enabled && command -v cargo >/dev/null 2>&1; then
    ng16_warn "stellar CLI not found; attempting install with cargo."
    if ! cargo install --locked stellar-cli; then
      ng16_warn "automatic Stellar CLI installation failed."
    fi
  fi

  ng16_require_cmd stellar "${hint}"
  version_output="$(stellar --version 2>&1 || true)"
  version_output="$(ng16_first_line "${version_output}")"
  if [[ -z "${version_output}" ]]; then
    ng16_error "unable to read Stellar CLI version output."
  fi
  ng16_require_min_version "stellar" "${version_output}" "${minimum}" "${hint}"
}

ng16_ensure_rust_target() {
  local target="$1"
  local installed

  ng16_require_cmd rustup "$(ng16_hint_cargo)"

  installed="$(rustup target list --installed 2>/dev/null || true)"
  if printf '%s\n' "${installed}" | grep -Fxq "${target}"; then
    return 0
  fi

  if ng16_auto_install_enabled; then
    ng16_warn "Rust target '${target}' is missing; attempting installation."
    if rustup target add "${target}"; then
      return 0
    fi
    ng16_error "failed to install Rust target '${target}'. Install manually: rustup target add ${target}"
  fi

  ng16_error "missing Rust target '${target}'. Install it with: rustup target add ${target}"
}
